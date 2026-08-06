package zkauthn

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/go-pg/pg/v10"
	"github.com/go-pg/pg/v10/orm"

	"github.com/ulas96/kal/authz"
	"github.com/ulas96/kal/kalerr"
	"github.com/ulas96/kal/session"
)

const (
	challengeKnowledge = "knowledge"
	challengeLogin     = "login"
	challengeClaim     = "claim"
)

// KnowledgeRequest @notice Proof bytes plus the server challenge for MFA step-up.
type KnowledgeRequest struct {
	Proof     []byte `json:"proof"`
	Challenge string `json:"challenge"`
}

// MembershipRequest @notice Attacker-supplied proof fields; policy values are deliberately absent.
type MembershipRequest struct {
	Proof     []byte `json:"proof"`
	Root      []byte `json:"root"`
	Nullifier []byte `json:"nullifier"`
	Challenge string `json:"challenge"`
	Claim     string `json:"claim"`
}

// EnrollKnowledge @notice Generates a knowledge secret and returns it exactly once. Replacing an
// existing commitment requires re-authentication.
//
// @dev A session cookie alone used to be enough to overwrite the commitment, so an attacker who
// stole one enrolled their own secret, proved it, set mfa_at and satisfied every @auth(mfa: true)
// field — the second factor defeated by the first, which is the definition of not being one.
// First enrolment stays open; replacement takes the other factor the account still has:
//
//	existing commitment | account has a password | required
//	none                | —                      | an authenticated session
//	yes                 | yes                    | the current password, re-verified
//	yes                 | no                     | MFAAt within the MFA window
//
// The third row exists because re-enrolment is the documented recovery path for a lost secret, so
// it must be reachable without the old factor. An account with neither cannot self-serve, which is
// the operator's problem in the same way an unaccepted invite is.
//
// Replacement revokes every other session rather than rotating like ChangePassword: a routine
// password change should keep other devices signed in, but replacing a second factor under a
// possibly-stolen session is the reset case.
//
// @param currentPassword the account's current password; ignored on first enrolment
// @return Secret the new secret, returned once and never stored
func (z *ZK) EnrollKnowledge(ctx context.Context, db orm.DB, currentPassword string) (Secret, error) {
	p, err := authz.Require(ctx)
	if err != nil {
		return Secret{}, err
	}

	var existing []byte
	_, err = db.QueryOneContext(ctx, pg.Scan(&existing), z.sql.commitmentByUser, p.UserID)
	replacing := true
	if errors.Is(err, pg.ErrNoRows) {
		replacing = false
	} else if err != nil {
		return Secret{}, err
	}

	if replacing {
		if err := z.authorizeReplacement(ctx, db, p, currentPassword); err != nil {
			return Secret{}, err
		}
	}

	secret, err := generateSecret()
	if err != nil {
		return Secret{}, err
	}
	commitment, err := knowledgeCommitment(secret)
	if err != nil {
		return Secret{}, err
	}
	if _, err := db.ExecContext(ctx, z.sql.upsertCommitment, p.UserID, commitment[:]); err != nil {
		return Secret{}, err
	}
	if replacing {
		if err := z.sessions.RevokeAllForUser(ctx, db, p.UserID); err != nil {
			return Secret{}, err
		}
	}
	return secret, nil
}

// authorizeReplacement runs the second and third rows of EnrollKnowledge's decision table.
//
// @dev VerifyDummy on the no-password branch is not decoration: returning early there would make
// "this account has no password" measurably faster than "that password was wrong", which is an
// account-shape oracle any authenticated caller can read (gotcha 30). It is the same argument
// dummyCommitment already answers on the verification path.
func (z *ZK) authorizeReplacement(ctx context.Context, db orm.DB, p *authz.Principal, currentPassword string) error {
	var storedHash string
	if _, err := db.QueryOneContext(ctx, pg.Scan(&storedHash), z.sql.passwordHashByUser, p.UserID); err != nil {
		if errors.Is(err, pg.ErrNoRows) {
			return &kalerr.Error{Code: kalerr.CodeUnauthenticated, Message: "authentication required", Internal: err}
		}
		return err
	}
	if storedHash == "" {
		if err := z.hasher.VerifyDummy(ctx, currentPassword); err != nil {
			return err
		}
		if p.MFAAt.IsZero() || time.Since(p.MFAAt) > z.mfaWindow {
			return &kalerr.Error{Code: kalerr.CodeInvalidCredentials,
				Message: "recent multi-factor authentication is required to replace this credential"}
		}
		return nil
	}
	ok, _, err := z.hasher.Verify(ctx, currentPassword, storedHash)
	if err != nil {
		return err
	}
	if !ok {
		return &kalerr.Error{Code: kalerr.CodeInvalidCredentials, Message: "invalid credentials"}
	}
	return nil
}

// KnowledgeChallenge @notice Issues a 60-second challenge bound to the current session.
func (z *ZK) KnowledgeChallenge(ctx context.Context, db orm.DB) (string, error) {
	p, err := authz.Require(ctx)
	if err != nil {
		return "", err
	}
	return z.issueChallenge(ctx, db, challengeKnowledge, p.SessionID)
}

// LoginChallenge @notice Issues a 60-second challenge usable only for anonymous membership login.
func (z *ZK) LoginChallenge(ctx context.Context, db orm.DB) (string, error) {
	return z.issueChallenge(ctx, db, challengeLogin, "")
}

// ClaimChallenge @notice Issues a 60-second membership challenge bound to the current session.
func (z *ZK) ClaimChallenge(ctx context.Context, db orm.DB) (string, error) {
	p, err := authz.Require(ctx)
	if err != nil {
		return "", err
	}
	return z.issueChallenge(ctx, db, challengeClaim, p.SessionID)
}

func (z *ZK) issueChallenge(ctx context.Context, db orm.DB, purpose, sessionID string) (string, error) {
	token, field, hash, err := newChallengeToken()
	if err != nil {
		return "", err
	}
	var sid any
	if sessionID != "" {
		sid = sessionID
	}
	if _, err := db.ExecContext(ctx, z.sql.issueChallenge, hash[:], sid, purpose, field[:]); err != nil {
		return "", err
	}
	return token, nil
}

// peekChallenge reads the field a proof was built against without burning the challenge.
//
// @dev This is not the freshness check. It fetches a public input so verification can run outside
// any transaction; consumeChallenge's UPDATE remains the sole arbiter of single use, and a proof
// verified against a challenge another request burns concurrently is still refused when its own
// UPDATE returns no rows. Treating this SELECT as the decision would be gotcha 36 exactly.
func (z *ZK) peekChallenge(ctx context.Context, db orm.DB, token, purpose, sessionID string) (Field, error) {
	field, hash, err := challengeField(token)
	if err != nil {
		return Field{}, invalidProof(err)
	}
	var sid any
	if sessionID != "" {
		sid = sessionID
	}
	var stored []byte
	if _, err := db.QueryOneContext(ctx, pg.Scan(&stored), z.sql.peekChallenge,
		hash[:], purpose, sid); err != nil {
		return Field{}, noRowsInvalid(err)
	}
	if !bytes.Equal(stored, field[:]) {
		return Field{}, invalidProof(errors.New("challenge field mismatch"))
	}
	return field, nil
}

func (z *ZK) consumeChallenge(ctx context.Context, db orm.DB, token, purpose, sessionID string) (Field, error) {
	field, hash, err := challengeField(token)
	if err != nil {
		return Field{}, invalidProof(err)
	}
	var sid any
	if sessionID != "" {
		sid = sessionID
	}
	var stored []byte
	if _, err := db.QueryOneContext(ctx, pg.Scan(&stored), z.sql.consumeChallenge,
		hash[:], purpose, sid); err != nil {
		return Field{}, noRowsInvalid(err)
	}
	if !bytes.Equal(stored, field[:]) {
		return Field{}, invalidProof(errors.New("challenge field mismatch"))
	}
	return field, nil
}

// VerifyKnowledge @notice Verifies step-up, timestamps MFA and rotates the session credential.
//
// @dev Three phases, and the split is the point. Phase 1 reads and phase 2 verifies, both outside
// any transaction: pairing arithmetic queued behind a semaphore used to run with an open
// transaction, a pooled connection and the challenge row's lock all held, so CPU pressure on an
// unauthenticated endpoint turned into connection-pool exhaustion for every other query. Phase 3
// opens the transaction and burns the challenge with the single-use UPDATE, which is still the only
// thing deciding freshness. Do not collapse these back together for atomicity — phases 1 and 2
// write nothing.
func (z *ZK) VerifyKnowledge(ctx context.Context, db orm.DB, req KnowledgeRequest) error {
	p, err := authz.Require(ctx)
	if err != nil {
		return err
	}

	challenge, err := z.peekChallenge(ctx, db, req.Challenge, challengeKnowledge, p.SessionID)
	if err != nil {
		return err
	}
	commitment := z.dummyCommitment
	enrolled := true
	var raw []byte
	_, err = db.QueryOneContext(ctx, pg.Scan(&raw), z.sql.commitmentByUser, p.UserID)
	if errors.Is(err, pg.ErrNoRows) {
		enrolled = false
	} else if err != nil {
		return err
	} else if commitment, err = parseField(raw); err != nil {
		return err
	}

	public := &KnowledgeCircuit{Commitment: fieldBig(commitment), Challenge: fieldBig(challenge)}
	if err := z.verify(ctx, z.knowledge, req.Proof, public); err != nil {
		var ae *kalerr.Error
		if errors.As(err, &ae) && ae.Code == kalerr.CodeRateLimited {
			return err
		}
		return invalidProof(err)
	}
	// After the pairing, never before: an early return here would time-distinguish an account with
	// no commitment from one whose proof was wrong, which is an enrolment oracle (gotcha 63).
	if !enrolled {
		return invalidProof(errors.New("knowledge commitment not enrolled"))
	}

	var rotated string
	err = withTx(ctx, db, func(tx orm.DB) error {
		if _, err := z.consumeChallenge(ctx, tx, req.Challenge, challengeKnowledge, p.SessionID); err != nil {
			return err
		}
		var sessionID string
		if _, err := tx.QueryOneContext(ctx, pg.Scan(&sessionID), z.sql.setMFA, p.SessionID, p.UserID); err != nil {
			return noRowsInvalid(err)
		}
		rotated, err = z.sessions.Rotate(ctx, tx, p.SessionID)
		return err
	})
	if err != nil {
		return err
	}
	return session.SetCookie(ctx, session.Cookie(z.cookieName, rotated))
}

// Login @notice Verifies recurring membership and issues an ordinary pseudonymous kal session.
func (z *ZK) Login(ctx context.Context, db orm.DB, req MembershipRequest) (*authz.Principal, error) {
	claim, _, nullifier, err := z.verifyMembershipRequest(ctx, db, req, challengeLogin, "")
	if err != nil {
		return nil, err
	}
	if claim.Kind != ClaimRecurring {
		return nil, invalidProof(errors.New("one-shot claim cannot create a session"))
	}
	// CodeInvalidProof like every other refusal: which claims a deployment lets log in is policy an
	// unauthenticated caller has no business enumerating.
	if !claim.AllowsLogin {
		return nil, invalidProof(errors.New("claim is not a login endpoint"))
	}

	var principal *authz.Principal
	var issued string
	err = withTx(ctx, db, func(tx orm.DB) error {
		if _, err := z.consumeChallenge(ctx, tx, req.Challenge, challengeLogin, ""); err != nil {
			return err
		}
		userID, err := z.resolvePseudonym(ctx, tx, nullifier, claim.Audience)
		if err != nil {
			return err
		}
		if prior, ok := authz.From(ctx); ok {
			if err := z.sessions.Revoke(ctx, tx, prior.SessionID); err != nil {
				return err
			}
		}
		issued, err = z.sessions.Issue(ctx, tx, userID, session.Meta{})
		if err != nil {
			return err
		}
		principal, err = z.sessions.Lookup(ctx, tx, issued)
		if err != nil {
			return err
		}
		if principal == nil {
			return errors.New("zkauthn: freshly issued ZK session did not resolve")
		}
		if _, err := tx.ExecContext(ctx, z.sql.storeSessionClaim, principal.SessionID, claim.Name); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err := session.SetCookie(ctx, session.Cookie(z.cookieName, issued)); err != nil {
		return nil, err
	}
	return principal, nil
}

// resolvePseudonym returns the account a recurring nullifier names, creating it on first sight.
//
// @dev Two statements rather than one data-modifying CTE. Every sub-statement of a WITH runs
// against the snapshot taken when the statement began, so an outer join cannot see the row the
// CTE inserted alongside it — the combined statement resolved to nothing on a first-ever login,
// rolled its own insert back, and could never self-heal. Separate statements each take their own
// snapshot under READ COMMITTED, which is what makes the created row visible to the re-resolve.
//
// @param nullifier the recurring pseudonym proven for this audience
// @param audience the claim audience the nullifier was derived under
// @return the user id of the pseudonymous account, or invalidProof if none may have a session
func (z *ZK) resolvePseudonym(ctx context.Context, tx orm.DB, nullifier, audience Field) (string, error) {
	email := "zk-" + hex.EncodeToString(nullifier[:]) + "@invalid"
	resolve := func() (string, error) {
		var userID string
		_, err := tx.QueryOneContext(ctx, pg.Scan(&userID), z.sql.resolveNullifier,
			nullifier[:], audience[:], email)
		return userID, err
	}
	userID, err := resolve()
	if err == nil {
		return userID, nil
	}
	if !errors.Is(err, pg.ErrNoRows) {
		return "", fmt.Errorf("zkauthn: resolve pseudonym: %w", err)
	}
	if _, err := tx.QueryOneContext(ctx, pg.Scan(&userID), z.sql.createNullifier,
		email, nullifier[:], audience[:]); err == nil {
		return userID, nil
	} else if !errors.Is(err, pg.ErrNoRows) {
		return "", fmt.Errorf("zkauthn: create pseudonym: %w", err)
	}
	// Neither insert produced a row: either a concurrent first login committed this pseudonym
	// first, or the nullifier already names an account that may not have a session. One bounded
	// re-resolve tells those apart. A loop here would spin against a soft-deleted pseudonym.
	userID, err = resolve()
	if err != nil {
		return "", noRowsInvalid(err)
	}
	return userID, nil
}

// ProveClaim @notice Verifies membership for the current session and records its claim.
//
// @dev Recurring claims persist for the session. One-shot claims are atomically burned in
// Postgres and exist only in the request-local holder populated through ProofSink.
func (z *ZK) ProveClaim(ctx context.Context, db orm.DB, req MembershipRequest) error {
	p, err := authz.Require(ctx)
	if err != nil {
		return err
	}
	claim, _, nullifier, err := z.verifyMembershipRequest(ctx, db, req, challengeClaim, p.SessionID)
	if err != nil {
		return err
	}
	verified := VerifiedClaim{Name: claim.Name, Kind: claim.Kind}

	return withTx(ctx, db, func(tx orm.DB) error {
		if _, err := z.consumeChallenge(ctx, tx, req.Challenge, challengeClaim, p.SessionID); err != nil {
			return err
		}
		switch claim.Kind {
		case ClaimRecurring:
			var userID string
			if _, err := tx.QueryOneContext(ctx, pg.Scan(&userID), z.sql.bindRecurringNullifier,
				nullifier[:], claim.Audience[:], p.UserID); err != nil {
				return noRowsInvalid(err)
			}
			if _, err := tx.ExecContext(ctx, z.sql.storeSessionClaim, p.SessionID, claim.Name); err != nil {
				return err
			}
		case ClaimOneShot:
			var stored []byte
			if _, err := tx.QueryOneContext(ctx, pg.Scan(&stored), z.sql.oneShotNullifier,
				nullifier[:], claim.Audience[:]); err != nil {
				return noRowsInvalid(err)
			}
		default:
			return invalidProof(errors.New("unknown claim kind"))
		}
		// Inside the transaction, before commit. Delivered after commit, a Claims.Add that errors
		// because the middleware is not mounted leaves a one-shot allowance burned permanently for
		// an action that never ran. Add touches a context value and a mutex — no I/O — so holding
		// the transaction across it costs nothing, and failing here rolls the burn back.
		return z.proofSink(ctx, verified)
	})
}

// verifyMembershipRequest runs phases 1 and 2: resolve policy, check the root, read the challenge
// field, verify. It opens no transaction and burns nothing — the caller burns in phase 3.
//
// @dev The unknown-claim and unaccepted-root branches each spend a pairing against a dummy public
// witness before refusing. Returning early there made a claim name a deployment does not define,
// and a root it has retired, answer measurably faster than a genuine verification failure. The
// enrolment path already bought that indistinguishability with dummyCommitment; this applies the
// same reasoning to its two siblings.
func (z *ZK) verifyMembershipRequest(ctx context.Context, db orm.DB, req MembershipRequest,
	purpose, sessionID string) (Claim, Field, Field, error) {
	root, err := parseField(req.Root)
	if err != nil {
		return Claim{}, Field{}, Field{}, invalidProof(err)
	}
	nullifier, err := parseField(req.Nullifier)
	if err != nil {
		return Claim{}, Field{}, Field{}, invalidProof(err)
	}
	claim, err := z.claim(ctx, db, req.Claim)
	if err != nil {
		var ae *kalerr.Error
		if errors.As(err, &ae) && ae.Code == kalerr.CodeInvalidProof {
			z.verifyDummyMembership(ctx, req.Proof)
		}
		return Claim{}, Field{}, Field{}, err
	}
	accepted, err := z.rootAccepted(ctx, db, root)
	if err != nil {
		return Claim{}, Field{}, Field{}, err
	}
	if !accepted {
		z.verifyDummyMembership(ctx, req.Proof)
		return Claim{}, Field{}, Field{}, invalidProof(errors.New("root is not accepted"))
	}
	challenge, err := z.peekChallenge(ctx, db, req.Challenge, purpose, sessionID)
	if err != nil {
		return Claim{}, Field{}, Field{}, err
	}
	public := &MembershipCircuit{
		Root: fieldBig(root), Audience: fieldBig(claim.Audience), Threshold: claim.Threshold,
		Nullifier: fieldBig(nullifier), Challenge: fieldBig(challenge),
	}
	if err := z.verify(ctx, z.membership, req.Proof, public); err != nil {
		var ae *kalerr.Error
		if errors.As(err, &ae) && ae.Code == kalerr.CodeRateLimited {
			return Claim{}, Field{}, Field{}, err
		}
		return Claim{}, Field{}, Field{}, invalidProof(err)
	}
	return claim, root, nullifier, nil
}

// MembershipWitnessFor @notice Builds client prover inputs from a credential, path and policy.
func MembershipWitnessFor(credential Credential, path MerklePath, claim Claim,
	nullifier Field, challenge Field) MembershipWitness {
	return MembershipWitness{
		Secret: credential.Secret, Attribute: credential.Attribute, Path: path.Path,
		Index: path.Index, Root: path.Root, Audience: claim.Audience,
		Threshold: claim.Threshold, Nullifier: nullifier, Challenge: challenge,
	}
}

// Nullifier @notice Computes the recurring or one-shot public pseudonym for a credential audience.
func Nullifier(secret Secret, audience Field) (Field, error) { return nullifierFor(secret, audience) }

// ChallengeField @notice Converts a server challenge token into its canonical circuit input.
func ChallengeField(token string) (Field, error) {
	field, _, err := challengeField(token)
	if err != nil {
		return Field{}, fmt.Errorf("zkauthn: challenge: %w", err)
	}
	return field, nil
}
