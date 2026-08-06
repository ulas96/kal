package tests

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/go-pg/pg/v10"
	"github.com/go-pg/pg/v10/orm"
	"github.com/ulas96/luima"

	"github.com/ulas96/kal/authn"
	"github.com/ulas96/kal/authz"
	"github.com/ulas96/kal/kalerr"
	"github.com/ulas96/kal/session"
	"github.com/ulas96/kal/zkauthn"
	"github.com/ulas96/kal/zkauthz"
)

type zkArtifacts struct {
	knowledgePK, membershipPK     *zkauthn.ProvingKey
	knowledgeVK, membershipVK     *zkauthn.VerifyingKey
	knowledgeRaw, membershipRaw   []byte
	knowledgeHash, membershipHash [sha256.Size]byte
}

var (
	zkArtifactsOnce  sync.Once
	zkArtifactsValue zkArtifacts
	zkArtifactsErr   error
)

// testZKArtifacts performs the two test ceremonies once. Production setup is an operator task;
// tests need matching ephemeral keys and deliberately never write them to the repository.
func testZKArtifacts(t *testing.T) zkArtifacts {
	t.Helper()
	zkArtifactsOnce.Do(func() {
		setup := func(kind zkauthn.Circuit) (*zkauthn.ProvingKey, *zkauthn.VerifyingKey, []byte, [32]byte, error) {
			var pkRaw, vkRaw bytes.Buffer
			if err := zkauthn.Setup(kind, &pkRaw, &vkRaw); err != nil {
				return nil, nil, nil, [32]byte{}, err
			}
			pk, err := zkauthn.LoadProvingKey(kind, bytes.NewReader(pkRaw.Bytes()))
			if err != nil {
				return nil, nil, nil, [32]byte{}, err
			}
			raw := bytes.Clone(vkRaw.Bytes())
			hash := sha256.Sum256(raw)
			vk, err := zkauthn.LoadVerifyingKey(kind, bytes.NewReader(raw), hash[:])
			return pk, vk, raw, hash, err
		}
		zkArtifactsValue.knowledgePK, zkArtifactsValue.knowledgeVK,
			zkArtifactsValue.knowledgeRaw, zkArtifactsValue.knowledgeHash, zkArtifactsErr = setup(zkauthn.CircuitKnowledge)
		if zkArtifactsErr != nil {
			return
		}
		zkArtifactsValue.membershipPK, zkArtifactsValue.membershipVK,
			zkArtifactsValue.membershipRaw, zkArtifactsValue.membershipHash, zkArtifactsErr = setup(zkauthn.CircuitMembership)
	})
	if zkArtifactsErr != nil {
		t.Fatal(zkArtifactsErr)
	}
	return zkArtifactsValue
}

type zkFixture struct {
	db       *pg.DB
	sessions *session.Sessions
	claims   *zkauthz.Claims
	zk       *zkauthn.ZK
	keys     zkArtifacts
	hasher   *authn.Hasher
}

func newZKFixture(t *testing.T) *zkFixture {
	t.Helper()
	db := testDB(t)
	keys := testZKArtifacts(t)
	sessions, err := session.NewSessions(session.Options{Schema: testSchema})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := zkauthz.New(testSchema)
	if err != nil {
		t.Fatal(err)
	}
	hasher, err := authn.NewHasher(authn.Params{Memory: 8192, Time: 1}, 0)
	if err != nil {
		t.Fatal(err)
	}
	zk, err := zkauthn.New(zkauthn.Options{
		KnowledgeVK: keys.knowledgeVK, MembershipVK: keys.membershipVK,
		Sessions: sessions, Hasher: hasher, ProofSink: claims.Add, Schema: testSchema,
		MaxConcurrentVerifications: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &zkFixture{db: db, sessions: sessions, claims: claims, zk: zk, keys: keys, hasher: hasher}
}

// request mounts both middleware layers because proof completion can rotate or issue cookies,
// and one-shot authorization exists only in the holder for this exact request.
func (f *zkFixture) request(cookie string, fn func(context.Context) error) (*httptest.ResponseRecorder, error) {
	var innerErr error
	h := f.sessions.Middleware(f.db, session.MiddlewareOptions{})(
		f.claims.Middleware(f.db)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			innerErr = fn(r.Context())
			w.WriteHeader(http.StatusOK)
		})))
	req := httptest.NewRequest(http.MethodPost, "/graphql", nil)
	req.Header.Set("Content-Type", "application/json")
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: session.DefaultCookieName, Value: cookie})
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec, innerErr
}

func (f *zkFixture) memberRequest(credential zkauthn.Credential, path zkauthn.MerklePath,
	claim zkauthn.Claim, challenge string) (zkauthn.MembershipRequest, error) {
	challengeField, err := zkauthn.ChallengeField(challenge)
	if err != nil {
		return zkauthn.MembershipRequest{}, err
	}
	nullifier, err := zkauthn.Nullifier(credential.Secret, claim.Audience)
	if err != nil {
		return zkauthn.MembershipRequest{}, err
	}
	witness := zkauthn.MembershipWitnessFor(credential, path, claim, nullifier, challengeField)
	proof, err := f.keys.membershipPK.ProveMembership(witness)
	if err != nil {
		return zkauthn.MembershipRequest{}, err
	}
	return zkauthn.MembershipRequest{
		Proof: proof, Root: path.Root[:], Nullifier: nullifier[:],
		Challenge: challenge, Claim: claim.Name,
	}, nil
}

func issueSession(t *testing.T, f *zkFixture, userID string) string {
	t.Helper()
	token, err := f.sessions.Issue(context.Background(), f.db, userID, session.Meta{})
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func requireErrorCode(t *testing.T, err error, code string) {
	t.Helper()
	var typed *kalerr.Error
	if err == nil || !errors.As(err, &typed) || typed.Code != code {
		t.Fatalf("error = %v, want code %s", err, code)
	}
}

// TestDBZKChallengeReplay proves knowledge and membership proofs are fresh, not bearer tokens.
// Covers: ZK-CHL-001, ZK-SES-006
func TestDBZKChallengeReplay(t *testing.T) {
	f := newZKFixture(t)
	ctx := context.Background()

	t.Run("knowledge proof is single-use and session-bound", func(t *testing.T) {
		userID := createUser(t, f.db, "zk-knowledge@example.com")
		cookie := issueSession(t, f, userID)
		var secret zkauthn.Secret
		if _, err := f.request(cookie, func(ctx context.Context) error {
			var err error
			secret, err = f.zk.EnrollKnowledge(ctx, f.db, "")
			return err
		}); err != nil {
			t.Fatal(err)
		}
		var challenge string
		if _, err := f.request(cookie, func(ctx context.Context) error {
			var err error
			challenge, err = f.zk.KnowledgeChallenge(ctx, f.db)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		commitment, _ := zkauthn.KnowledgeCommitment(secret)
		field, _ := zkauthn.ChallengeField(challenge)
		proof, err := f.keys.knowledgePK.ProveKnowledge(zkauthn.KnowledgeWitness{
			Secret: secret, Commitment: commitment, Challenge: field,
		})
		if err != nil {
			t.Fatal(err)
		}
		rec, err := f.request(cookie, func(ctx context.Context) error {
			return f.zk.VerifyKnowledge(ctx, f.db, zkauthn.KnowledgeRequest{Proof: proof, Challenge: challenge})
		})
		if err != nil {
			t.Fatal(err)
		}
		rotated := sessionCookie(rec)
		if rotated == "" || rotated == cookie {
			t.Fatal("knowledge step-up did not rotate the session cookie")
		}
		principal, err := f.sessions.Lookup(ctx, f.db, rotated)
		if err != nil || principal == nil || principal.MFAAt.IsZero() {
			t.Fatalf("rotated session has no MFA timestamp: principal=%+v err=%v", principal, err)
		}
		_, err = f.request(rotated, func(ctx context.Context) error {
			return f.zk.VerifyKnowledge(ctx, f.db, zkauthn.KnowledgeRequest{Proof: proof, Challenge: challenge})
		})
		requireErrorCode(t, err, kalerr.CodeInvalidProof)
	})

	t.Run("membership proof cannot move to another challenge", func(t *testing.T) {
		issuer := createUser(t, f.db, "zk-replay-issuer@example.com")
		credential, err := f.zk.IssueCredential(ctx, f.db, issuer, 21)
		if err != nil {
			t.Fatal(err)
		}
		claim := zkauthn.Claim{Name: "replay-login", Audience: zkauthn.NewAudience("tests", "replay", "v1"), Threshold: 18, Kind: zkauthn.ClaimRecurring, AllowsLogin: true}
		if err := f.zk.EnsureClaim(ctx, f.db, claim); err != nil {
			t.Fatal(err)
		}
		first, _ := f.zk.LoginChallenge(ctx, f.db)
		second, _ := f.zk.LoginChallenge(ctx, f.db)
		req, err := f.memberRequest(*credential, credential.Path, claim, first)
		if err != nil {
			t.Fatal(err)
		}
		req.Challenge = second
		_, err = f.request("", func(ctx context.Context) error {
			_, err := f.zk.Login(ctx, f.db, req)
			return err
		})
		requireErrorCode(t, err, kalerr.CodeInvalidProof)
	})
}

// TestDBZKPseudonymRecurs asserts a recurring nullifier is a stable pseudonym, not one-shot state.
// Covers: ZK-NUL-001
func TestDBZKPseudonymRecurs(t *testing.T) {
	f := newZKFixture(t)
	ctx := context.Background()
	issuer := createUser(t, f.db, "zk-recurring-issuer@example.com")
	credential, err := f.zk.IssueCredential(ctx, f.db, issuer, 40)
	if err != nil {
		t.Fatal(err)
	}
	claim := zkauthn.Claim{Name: "member-login", Audience: zkauthn.NewAudience("tests", "login", "v1"), Threshold: 18, Kind: zkauthn.ClaimRecurring, AllowsLogin: true}
	if err := f.zk.EnsureClaim(ctx, f.db, claim); err != nil {
		t.Fatal(err)
	}
	var principals [2]*authz.Principal
	var cookies [2]string
	for i := range principals {
		challenge, err := f.zk.LoginChallenge(ctx, f.db)
		if err != nil {
			t.Fatal(err)
		}
		req, err := f.memberRequest(*credential, credential.Path, claim, challenge)
		if err != nil {
			t.Fatal(err)
		}
		rec, err := f.request("", func(ctx context.Context) error {
			principals[i], err = f.zk.Login(ctx, f.db, req)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		cookies[i] = sessionCookie(rec)
	}
	if principals[0].UserID != principals[1].UserID || principals[0].SessionID == principals[1].SessionID {
		t.Fatalf("recurring logins = %+v, %+v", principals[0], principals[1])
	}
	for _, cookie := range cookies {
		p, err := f.sessions.Lookup(ctx, f.db, cookie)
		if err != nil || p == nil || p.UserID != principals[0].UserID {
			t.Fatalf("recurring cookie does not resolve: principal=%+v err=%v", p, err)
		}
	}
}

// TestDBZKLoginNeedsLoginClaim proves a recurring claim is not automatically a login endpoint.
//
// A claim written for an @auth(proves: ["age_over_18"]) step-up is recurring because its nullifier
// is a lasting pseudonym, not because proving it should mint a session. Without allows_login every
// such row is a login endpoint, which is the precondition that made the bound-account path
// reachable. The sibling half matters as much as the refusal: the same credential, proof and
// challenge shape must succeed once the claim actually says it is a login.
func TestDBZKLoginNeedsLoginClaim(t *testing.T) {
	f := newZKFixture(t)
	ctx := context.Background()
	issuer := createUser(t, f.db, "zk-stepup-claim-issuer@example.com")
	credential, err := f.zk.IssueCredential(ctx, f.db, issuer, 40)
	if err != nil {
		t.Fatal(err)
	}
	stepUp := zkauthn.Claim{Name: "age_over_18", Audience: zkauthn.NewAudience("tests", "stepup", "v1"),
		Threshold: 18, Kind: zkauthn.ClaimRecurring}
	if err := f.zk.EnsureClaim(ctx, f.db, stepUp); err != nil {
		t.Fatal(err)
	}
	if stored, err := f.zk.Claim(ctx, f.db, stepUp.Name); err != nil {
		t.Fatal(err)
	} else if stored.AllowsLogin {
		t.Fatal("a claim written without AllowsLogin came back as a login endpoint")
	}

	challenge, err := f.zk.LoginChallenge(ctx, f.db)
	if err != nil {
		t.Fatal(err)
	}
	req, err := f.memberRequest(*credential, credential.Path, stepUp, challenge)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.request("", func(ctx context.Context) error {
		_, err := f.zk.Login(ctx, f.db, req)
		return err
	})
	requireErrorCode(t, err, kalerr.CodeInvalidProof)

	var sessions int
	if _, err := f.db.QueryOne(pg.Scan(&sessions), `select count(*) from auth_sessions`); err != nil {
		t.Fatal(err)
	}
	if sessions != 0 {
		t.Fatalf("sessions = %d, want 0 — a step-up claim minted one", sessions)
	}

	stepUp.AllowsLogin = true
	if err := f.zk.EnsureClaim(ctx, f.db, stepUp); err != nil {
		t.Fatal(err)
	}
	if challenge, err = f.zk.LoginChallenge(ctx, f.db); err != nil {
		t.Fatal(err)
	}
	if req, err = f.memberRequest(*credential, credential.Path, stepUp, challenge); err != nil {
		t.Fatal(err)
	}
	if _, err := f.request("", func(ctx context.Context) error {
		_, err := f.zk.Login(ctx, f.db, req)
		return err
	}); err != nil {
		t.Fatalf("the same proof against a login-eligible claim: %v", err)
	}
}

// TestDBZKOneShotSurvivesUnmountedMiddleware proves a one-shot allowance is not destroyed by a
// delivery failure.
//
// A one-shot nullifier is unreplaceable: burn it and the member cannot ever perform that action
// again. Delivering the verified claim after commit meant an unmounted zkauthz middleware — a
// wiring mistake, not an attack — consumed the allowance for an action that never ran. Failing
// closed is right; failing closed after destroying something unreplaceable is not. The thing that
// goes wrong is the burn, so the assertion is the absent nullifier row, not the returned error.
func TestDBZKOneShotSurvivesUnmountedMiddleware(t *testing.T) {
	f := newZKFixture(t)
	ctx := context.Background()
	userID := createUser(t, f.db, "zk-oneshot-unmounted@example.com")
	cookie := issueSession(t, f, userID)
	credential, err := f.zk.IssueCredential(ctx, f.db, userID, 30)
	if err != nil {
		t.Fatal(err)
	}
	claim := zkauthn.Claim{Name: "unmounted-vote", Audience: zkauthn.NewAudience("tests", "unmounted", "v1"),
		Threshold: 0, Kind: zkauthn.ClaimOneShot}
	if err := f.zk.EnsureClaim(ctx, f.db, claim); err != nil {
		t.Fatal(err)
	}
	nullifier, err := zkauthn.Nullifier(credential.Secret, claim.Audience)
	if err != nil {
		t.Fatal(err)
	}

	// Only the session middleware, deliberately: zkauthz.Claims.Middleware is the layer that
	// installs the holder ProofSink writes into, and this is a deployment that forgot it.
	h := f.sessions.Middleware(f.db, session.MiddlewareOptions{})(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			challenge, err := f.zk.ClaimChallenge(r.Context(), f.db)
			if err != nil {
				t.Error(err)
				return
			}
			req, err := f.memberRequest(*credential, credential.Path, claim, challenge)
			if err != nil {
				t.Error(err)
				return
			}
			if err := f.zk.ProveClaim(r.Context(), f.db, req); err == nil {
				t.Error("ProveClaim succeeded without the claims middleware mounted")
			}
			w.WriteHeader(http.StatusOK)
		}))
	req := httptest.NewRequest(http.MethodPost, "/graphql", nil)
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: session.DefaultCookieName, Value: cookie})
	h.ServeHTTP(httptest.NewRecorder(), req)

	var burned int
	if _, err := f.db.QueryOne(pg.Scan(&burned),
		`select count(*) from auth_zk_nullifiers where nullifier = ?`, nullifier[:]); err != nil {
		t.Fatal(err)
	}
	if burned != 0 {
		t.Fatal("the one-shot allowance was burned for an action that never ran")
	}
}

// TestDBZKChallengeSurvivesFailedProof pins the boundary between verification and the burn.
//
// A bad proof must not consume the challenge, because the challenge is the freshness control and
// spending it on an attacker's garbage turns a retryable failure into a denial of service against
// the honest holder. The success half is the load-bearing one: an implementation that burns nothing
// ever would satisfy the first assertion alone.
func TestDBZKChallengeSurvivesFailedProof(t *testing.T) {
	f := newZKFixture(t)
	ctx := context.Background()
	issuer := createUser(t, f.db, "zk-survives-issuer@example.com")
	credential, err := f.zk.IssueCredential(ctx, f.db, issuer, 40)
	if err != nil {
		t.Fatal(err)
	}
	claim := zkauthn.Claim{Name: "survives-login", Audience: zkauthn.NewAudience("tests", "survives", "v1"),
		Threshold: 18, Kind: zkauthn.ClaimRecurring, AllowsLogin: true}
	if err := f.zk.EnsureClaim(ctx, f.db, claim); err != nil {
		t.Fatal(err)
	}
	challenge, err := f.zk.LoginChallenge(ctx, f.db)
	if err != nil {
		t.Fatal(err)
	}
	good, err := f.memberRequest(*credential, credential.Path, claim, challenge)
	if err != nil {
		t.Fatal(err)
	}

	bad := good
	bad.Proof = bytes.Clone(good.Proof)
	bad.Proof[0] ^= 0xff
	_, err = f.request("", func(ctx context.Context) error {
		_, err := f.zk.Login(ctx, f.db, bad)
		return err
	})
	requireErrorCode(t, err, kalerr.CodeInvalidProof)

	var consumedAt pg.NullTime
	if _, err := f.db.QueryOne(pg.Scan(&consumedAt),
		`select consumed_at from auth_zk_challenges where consumed_at is not null limit 1`); err != nil &&
		!errors.Is(err, pg.ErrNoRows) {
		t.Fatal(err)
	}
	if !consumedAt.IsZero() {
		t.Fatal("a failed verification burned the challenge")
	}

	var principal *authz.Principal
	if _, err := f.request("", func(ctx context.Context) error {
		principal, err = f.zk.Login(ctx, f.db, good)
		return err
	}); err != nil {
		t.Fatalf("a good proof against the same challenge: %v", err)
	}
	if principal == nil {
		t.Fatal("the good proof produced no principal")
	}
}

// noTxDB is an orm.DB that cannot start a transaction. Embedding the interface delegates every
// query and promotes nothing else, so withTx's RunInTransaction assertion fails on it.
type noTxDB struct{ orm.DB }

// TestDBZKVerifyHoldsNoTransaction proves verification runs before any transaction is opened.
//
// Timing cannot show this: on a fast machine nothing queues long enough to observe, and a test that
// skips when it sees no contention reports an absent control as a green one. So this discriminates
// structurally. Handed a database that cannot begin a transaction, a Login whose verification still
// ran inside withTx would fail at the transaction for every input alike. Because verification is
// now phase 2, a bad proof is refused as CodeInvalidProof on its own merits, and only a *good*
// proof gets far enough to need the transaction it cannot have. Two different errors from the same
// handle is the proof that the pairing held no transaction, no connection and no row lock — which
// is what kept CPU pressure on an unauthenticated endpoint from draining the pool.
func TestDBZKVerifyHoldsNoTransaction(t *testing.T) {
	f := newZKFixture(t)
	ctx := context.Background()
	issuer := createUser(t, f.db, "zk-notx-issuer@example.com")
	credential, err := f.zk.IssueCredential(ctx, f.db, issuer, 40)
	if err != nil {
		t.Fatal(err)
	}
	claim := zkauthn.Claim{Name: "notx-login", Audience: zkauthn.NewAudience("tests", "notx", "v1"),
		Threshold: 18, Kind: zkauthn.ClaimRecurring, AllowsLogin: true}
	if err := f.zk.EnsureClaim(ctx, f.db, claim); err != nil {
		t.Fatal(err)
	}
	challenge, err := f.zk.LoginChallenge(ctx, f.db)
	if err != nil {
		t.Fatal(err)
	}
	good, err := f.memberRequest(*credential, credential.Path, claim, challenge)
	if err != nil {
		t.Fatal(err)
	}
	bad := good
	bad.Proof = bytes.Clone(good.Proof)
	bad.Proof[0] ^= 0xff

	_, err = f.request("", func(ctx context.Context) error {
		_, err := f.zk.Login(ctx, noTxDB{f.db}, bad)
		return err
	})
	requireErrorCode(t, err, kalerr.CodeInvalidProof)

	_, err = f.request("", func(ctx context.Context) error {
		_, err := f.zk.Login(ctx, noTxDB{f.db}, good)
		return err
	})
	var typed *kalerr.Error
	if errors.As(err, &typed) {
		t.Fatalf("a valid proof was refused as %s — verification decided before the transaction did",
			typed.Code)
	}
	if err == nil || !strings.Contains(err.Error(), "cannot start a transaction") {
		t.Fatalf("error = %v, want the transaction to be what a good proof fails on", err)
	}

	// The challenge is intact: neither attempt reached the burn.
	var consumed int
	if _, err := f.db.QueryOne(pg.Scan(&consumed),
		`select count(*) from auth_zk_challenges where consumed_at is not null`); err != nil {
		t.Fatal(err)
	}
	if consumed != 0 {
		t.Fatalf("challenges consumed = %d, want 0 — something burned outside phase 3", consumed)
	}
}

// TestDBZKEnrolmentNeedsStepUp proves a stolen session cannot replace the second factor.
//
// The thing that goes wrong is a silent overwrite, so what this reads is the stored commitment: it
// must still be byte-identical after the refused attempt. A test that only checked the error would
// pass against an implementation that refused and overwrote anyway.
// Covers: ZK-ENR-003
func TestDBZKEnrolmentNeedsStepUp(t *testing.T) {
	f := newZKFixture(t)
	ctx := context.Background()
	userID := createUser(t, f.db, "zk-stepup@example.com")
	hash, err := f.hasher.Hash(ctx, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec(`update auth_users set password_hash = ? where id = ?`, hash, userID); err != nil {
		t.Fatal(err)
	}
	cookie := issueSession(t, f, userID)

	// First enrolment is deliberately open — the account has no commitment to protect yet.
	if _, err := f.request(cookie, func(ctx context.Context) error {
		_, err := f.zk.EnrollKnowledge(ctx, f.db, "")
		return err
	}); err != nil {
		t.Fatalf("first enrolment: %v", err)
	}
	original := storedCommitment(t, f, userID)

	_, err = f.request(cookie, func(ctx context.Context) error {
		_, err := f.zk.EnrollKnowledge(ctx, f.db, "not the password")
		return err
	})
	requireErrorCode(t, err, kalerr.CodeInvalidCredentials)
	if after := storedCommitment(t, f, userID); !bytes.Equal(after, original) {
		t.Fatalf("commitment = %x, want the original %x — a wrong password replaced the factor", after, original)
	}

	// The sibling success path: a test that only asserts the refusal is satisfied by an
	// EnrollKnowledge that always refuses, which is how ZK-01 hid behind three green tests.
	if _, err := f.request(cookie, func(ctx context.Context) error {
		_, err := f.zk.EnrollKnowledge(ctx, f.db, "correct horse battery staple")
		return err
	}); err != nil {
		t.Fatalf("re-enrolment with the correct password: %v", err)
	}
	if after := storedCommitment(t, f, userID); bytes.Equal(after, original) {
		t.Fatal("the correct password did not replace the commitment")
	}
}

// TestDBZKReenrolmentRevokesSessions asserts replacement is treated as the reset case, not the
// routine one: every other session for the account stops resolving.
func TestDBZKReenrolmentRevokesSessions(t *testing.T) {
	f := newZKFixture(t)
	ctx := context.Background()
	userID := createUser(t, f.db, "zk-reenrol-sessions@example.com")
	hash, err := f.hasher.Hash(ctx, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec(`update auth_users set password_hash = ? where id = ?`, hash, userID); err != nil {
		t.Fatal(err)
	}
	enrolling := issueSession(t, f, userID)
	other := issueSession(t, f, userID)

	if _, err := f.request(enrolling, func(ctx context.Context) error {
		_, err := f.zk.EnrollKnowledge(ctx, f.db, "")
		return err
	}); err != nil {
		t.Fatalf("first enrolment: %v", err)
	}
	if p, err := f.sessions.Lookup(ctx, f.db, other); err != nil || p == nil {
		t.Fatalf("the other session should survive a first enrolment: principal=%+v err=%v", p, err)
	}

	if _, err := f.request(enrolling, func(ctx context.Context) error {
		_, err := f.zk.EnrollKnowledge(ctx, f.db, "correct horse battery staple")
		return err
	}); err != nil {
		t.Fatalf("re-enrolment: %v", err)
	}
	p, err := f.sessions.Lookup(ctx, f.db, other)
	if err != nil {
		t.Fatal(err)
	}
	if p != nil {
		t.Fatal("a session held elsewhere still resolves after the second factor was replaced")
	}
}

func storedCommitment(t *testing.T, f *zkFixture, userID string) []byte {
	t.Helper()
	var commitment []byte
	if _, err := f.db.QueryOne(pg.Scan(&commitment),
		`select commitment from auth_zk_commitments where user_id = ?`, userID); err != nil {
		t.Fatal(err)
	}
	return commitment
}

// TestDBZKLoginRejectsBoundAccount proves a membership credential cannot log into a real account.
//
// ProveClaim binds a recurring nullifier to whoever proved it. If Login then resolves that
// nullifier to the bound account rather than to the pseudonym its own hash derives, a credential
// holder receives a full session on somebody else's user id with no password, no email_verified,
// no backoff and no MFA. The breach that must not happen is a session row, so that is what this
// counts — and the orphan pseudonym, because a refusal that still writes rows is ZK-08.
func TestDBZKLoginRejectsBoundAccount(t *testing.T) {
	f := newZKFixture(t)
	ctx := context.Background()
	account := createUser(t, f.db, "zk-bound-account@example.com")
	credential, err := f.zk.IssueCredential(ctx, f.db, account, 40)
	if err != nil {
		t.Fatal(err)
	}
	claim := zkauthn.Claim{Name: "bound-login", Audience: zkauthn.NewAudience("tests", "bound", "v1"),
		Threshold: 18, Kind: zkauthn.ClaimRecurring, AllowsLogin: true}
	if err := f.zk.EnsureClaim(ctx, f.db, claim); err != nil {
		t.Fatal(err)
	}

	cookie := issueSession(t, f, account)
	if _, err := f.request(cookie, func(ctx context.Context) error {
		challenge, err := f.zk.ClaimChallenge(ctx, f.db)
		if err != nil {
			return err
		}
		req, err := f.memberRequest(*credential, credential.Path, claim, challenge)
		if err != nil {
			return err
		}
		return f.zk.ProveClaim(ctx, f.db, req)
	}); err != nil {
		t.Fatalf("binding the nullifier to a real account: %v", err)
	}

	sessionsBefore, usersBefore := countRows(t, f, account)
	challenge, err := f.zk.LoginChallenge(ctx, f.db)
	if err != nil {
		t.Fatal(err)
	}
	req, err := f.memberRequest(*credential, credential.Path, claim, challenge)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.request("", func(ctx context.Context) error {
		_, err := f.zk.Login(ctx, f.db, req)
		return err
	})
	requireErrorCode(t, err, kalerr.CodeInvalidProof)

	sessionsAfter, usersAfter := countRows(t, f, account)
	if sessionsAfter != sessionsBefore {
		t.Fatalf("sessions for the bound account = %d, want %d — the credential minted one",
			sessionsAfter, sessionsBefore)
	}
	if usersAfter != usersBefore {
		t.Fatalf("auth_users rows = %d, want %d — a refused login left a pseudonym behind",
			usersAfter, usersBefore)
	}
}

// TestDBZKLoginDoesNotGrowUsers is the sibling that keeps the refusal above honest: it asserts the
// success path still resolves to one account. A data-modifying CTE runs whether or not the outer
// query reads it, so the statement this replaced inserted an auth_users row on every attempt.
// Covers: ZK-PSD-001
func TestDBZKLoginDoesNotGrowUsers(t *testing.T) {
	f := newZKFixture(t)
	ctx := context.Background()
	issuer := createUser(t, f.db, "zk-growth-issuer@example.com")
	credential, err := f.zk.IssueCredential(ctx, f.db, issuer, 40)
	if err != nil {
		t.Fatal(err)
	}
	claim := zkauthn.Claim{Name: "growth-login", Audience: zkauthn.NewAudience("tests", "growth", "v1"),
		Threshold: 18, Kind: zkauthn.ClaimRecurring, AllowsLogin: true}
	if err := f.zk.EnsureClaim(ctx, f.db, claim); err != nil {
		t.Fatal(err)
	}

	_, usersBefore := countRows(t, f, issuer)
	var userID string
	for i := 0; i < 5; i++ {
		challenge, err := f.zk.LoginChallenge(ctx, f.db)
		if err != nil {
			t.Fatal(err)
		}
		req, err := f.memberRequest(*credential, credential.Path, claim, challenge)
		if err != nil {
			t.Fatal(err)
		}
		var principal *authz.Principal
		if _, err := f.request("", func(ctx context.Context) error {
			principal, err = f.zk.Login(ctx, f.db, req)
			return err
		}); err != nil {
			t.Fatalf("login %d: %v", i, err)
		}
		if userID == "" {
			userID = principal.UserID
		} else if principal.UserID != userID {
			t.Fatalf("login %d resolved to %s, want the same pseudonym %s", i, principal.UserID, userID)
		}
	}
	_, usersAfter := countRows(t, f, issuer)
	if usersAfter-usersBefore != 1 {
		t.Fatalf("auth_users grew by %d over five logins, want 1", usersAfter-usersBefore)
	}
}

func countRows(t *testing.T, f *zkFixture, userID string) (sessions, users int) {
	t.Helper()
	if _, err := f.db.QueryOne(pg.Scan(&sessions),
		`select count(*) from auth_sessions where user_id = ?`, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.QueryOne(pg.Scan(&users), `select count(*) from auth_users`); err != nil {
		t.Fatal(err)
	}
	return sessions, users
}

// TestDBZKNullifierSingleUse races eight valid, freshly challenged proofs for one allowance.
// Covers: ZK-NUL-002
func TestDBZKNullifierSingleUse(t *testing.T) {
	f := newZKFixture(t)
	ctx := context.Background()
	userID := createUser(t, f.db, "zk-one-shot-user@example.com")
	cookie := issueSession(t, f, userID)
	credential, err := f.zk.IssueCredential(ctx, f.db, userID, 30)
	if err != nil {
		t.Fatal(err)
	}
	claim := zkauthn.Claim{Name: "vote-once", Audience: zkauthn.NewAudience("tests", "vote", "2026"), Threshold: 18, Kind: zkauthn.ClaimOneShot}
	if err := f.zk.EnsureClaim(ctx, f.db, claim); err != nil {
		t.Fatal(err)
	}

	const contenders = 8
	requests := make([]zkauthn.MembershipRequest, contenders)
	for i := range requests {
		var challenge string
		if _, err := f.request(cookie, func(ctx context.Context) error {
			var err error
			challenge, err = f.zk.ClaimChallenge(ctx, f.db)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		requests[i], err = f.memberRequest(*credential, credential.Path, claim, challenge)
		if err != nil {
			t.Fatal(err)
		}
	}

	start := make(chan struct{})
	var ready sync.WaitGroup
	var done sync.WaitGroup
	var successes, actions atomic.Int32
	errs := make([]error, contenders)
	ready.Add(contenders)
	done.Add(contenders)
	for i := range requests {
		go func(i int) {
			defer done.Done()
			ready.Done()
			<-start
			_, errs[i] = f.request(cookie, func(ctx context.Context) error {
				if err := f.zk.ProveClaim(ctx, f.db, requests[i]); err != nil {
					return err
				}
				if err := f.claims.Proofs(ctx, []string{claim.Name}); err != nil {
					return err
				}
				actions.Add(1)
				return nil
			})
			if errs[i] == nil {
				successes.Add(1)
			}
		}(i)
	}
	ready.Wait()
	close(start)
	done.Wait()
	if successes.Load() != 1 || actions.Load() != 1 {
		t.Fatalf("successes=%d actions=%d errors=%v", successes.Load(), actions.Load(), errs)
	}
	var rows int
	if _, err := f.db.QueryOne(pg.Scan(&rows), `select count(*) from auth_zk_nullifiers where audience = ?`, claim.Audience[:]); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("one-shot nullifier rows = %d, want 1", rows)
	}
}

// TestDBZKThresholdFromPolicy proves the request cannot lower the policy's public threshold.
// Covers: ZK-INP-001
func TestDBZKThresholdFromPolicy(t *testing.T) {
	f := newZKFixture(t)
	ctx := context.Background()
	issuer := createUser(t, f.db, "zk-threshold-issuer@example.com")
	credential, err := f.zk.IssueCredential(ctx, f.db, issuer, 17)
	if err != nil {
		t.Fatal(err)
	}
	policy := zkauthn.Claim{Name: "adult", Audience: zkauthn.NewAudience("tests", "adult", "v1"), Threshold: 18, Kind: zkauthn.ClaimRecurring, AllowsLogin: true}
	if err := f.zk.EnsureClaim(ctx, f.db, policy); err != nil {
		t.Fatal(err)
	}
	challenge, _ := f.zk.LoginChallenge(ctx, f.db)
	weak := policy
	weak.Threshold = 0 // attacker proves the easier statement; the request has no policy field.
	req, err := f.memberRequest(*credential, credential.Path, weak, challenge)
	if err != nil {
		t.Fatal(err)
	}
	req.Claim = policy.Name
	resolverRan := false
	_, err = f.request("", func(ctx context.Context) error {
		if _, err := f.zk.Login(ctx, f.db, req); err != nil {
			return err
		}
		resolverRan = true
		return nil
	})
	requireErrorCode(t, err, kalerr.CodeInvalidProof)
	if resolverRan {
		t.Fatal("a threshold-zero proof reached the protected action")
	}
}

// TestDBZKRevokeRepublishesRoot revokes the highest live leaf, which is the mutation that returns
// the tree to a leaf set it has already published.
//
// The thing that goes wrong is not the duplicate-key error: it is that the error aborts the
// transaction and takes markRevoked down with it, so revoked_at stays null and the credential goes
// on proving membership. This asserts the revocation landed and that the current root is byte-equal
// to the one published when only the first credential existed — TestDBZKRevokedCredential revokes
// leaf 0 while leaf 1 is live, so the root it produces was never published and never collides.
func TestDBZKRevokeRepublishesRoot(t *testing.T) {
	f := newZKFixture(t)
	ctx := context.Background()
	issuer := createUser(t, f.db, "zk-republish-issuer@example.com")
	first, err := f.zk.IssueCredential(ctx, f.db, issuer, 30)
	if err != nil {
		t.Fatal(err)
	}
	rootWithOne := first.Path.Root

	second, err := f.zk.IssueCredential(ctx, f.db, issuer, 31)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(rootWithOne[:], second.Path.Root[:]) {
		t.Fatal("issuing a second credential did not move the root")
	}

	if err := f.zk.RevokeCredential(ctx, f.db, second.LeafIndex); err != nil {
		t.Fatalf("revoking the highest live leaf: %v", err)
	}

	var revokedAt pg.NullTime
	if _, err := f.db.QueryOne(pg.Scan(&revokedAt),
		`select revoked_at from auth_zk_credentials where leaf_index = ?`, second.LeafIndex); err != nil {
		t.Fatal(err)
	}
	if revokedAt.IsZero() {
		t.Fatal("revoked_at is null — the aborted root insert rolled the revocation back")
	}

	var current []byte
	if _, err := f.db.QueryOne(pg.Scan(&current),
		`select root from auth_zk_roots where retired_at is null`); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(current, rootWithOne[:]) {
		t.Fatalf("current root = %x, want the republished %x", current, rootWithOne)
	}
}

// TestDBZKRevokedCredential checks removal against the current root, not merely a revoked flag.
// Covers: ZK-TRE-006, ZK-INP-004
func TestDBZKRevokedCredential(t *testing.T) {
	f := newZKFixture(t)
	ctx := context.Background()
	issuer := createUser(t, f.db, "zk-revoke-issuer@example.com")
	revoked, err := f.zk.IssueCredential(ctx, f.db, issuer, 25)
	if err != nil {
		t.Fatal(err)
	}
	live, err := f.zk.IssueCredential(ctx, f.db, issuer, 25)
	if err != nil {
		t.Fatal(err)
	}
	oldPath, err := f.zk.Path(ctx, f.db, revoked.LeafIndex)
	if err != nil {
		t.Fatal(err)
	}
	claim := zkauthn.Claim{Name: "revocation-login", Audience: zkauthn.NewAudience("tests", "revoke", "v1"), Threshold: 18, Kind: zkauthn.ClaimRecurring, AllowsLogin: true}
	if err := f.zk.EnsureClaim(ctx, f.db, claim); err != nil {
		t.Fatal(err)
	}
	challenge, _ := f.zk.LoginChallenge(ctx, f.db)
	req, err := f.memberRequest(*revoked, *oldPath, claim, challenge)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.zk.RevokeCredential(ctx, f.db, revoked.LeafIndex); err != nil {
		t.Fatal(err)
	}
	current, err := f.zk.Path(ctx, f.db, live.LeafIndex)
	if err != nil {
		t.Fatal(err)
	}
	req.Root = current.Root[:]
	rec, err := f.request("", func(ctx context.Context) error {
		_, err := f.zk.Login(ctx, f.db, req)
		return err
	})
	requireErrorCode(t, err, kalerr.CodeInvalidProof)
	if sessionCookie(rec) != "" {
		t.Fatal("a revoked credential received a session")
	}
}

// TestDBZKConcurrentEnroll checks the database tree is one serial history across goroutines.
// Covers: ZK-TRE-001
func TestDBZKConcurrentEnroll(t *testing.T) {
	f := newZKFixture(t)
	ctx := context.Background()
	issuer := createUser(t, f.db, "zk-concurrent-issuer@example.com")
	var credentials [2]*zkauthn.Credential
	var errs [2]error
	var wg sync.WaitGroup
	wg.Add(len(credentials))
	for i := range credentials {
		go func(i int) {
			defer wg.Done()
			credentials[i], errs[i] = f.zk.IssueCredential(ctx, f.db, issuer, uint64(20+i))
		}(i)
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var root zkauthn.Field
	for i, credential := range credentials {
		path, err := f.zk.Path(ctx, f.db, credential.LeafIndex)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			root = path.Root
		} else if path.Root != root {
			t.Fatal("concurrent credentials did not converge on one current root")
		}
		audience := zkauthn.NewAudience("tests", "tree", fmt.Sprint(i))
		nullifier, _ := zkauthn.Nullifier(credential.Secret, audience)
		witness := zkauthn.MembershipWitness{
			Secret: credential.Secret, Attribute: credential.Attribute, Path: path.Path,
			Index: path.Index, Root: path.Root, Audience: audience, Threshold: 0,
			Nullifier: nullifier,
		}
		if !zkauthn.MembershipValid(witness) {
			t.Fatalf("credential %d has a path that does not verify", i)
		}
	}
	var credentialsCount, rootsCount int
	if _, err := f.db.QueryOne(pg.Scan(&credentialsCount, &rootsCount), `
		select (select count(*) from auth_zk_credentials),
		       (select count(*) from auth_zk_roots where retired_at is null)`); err != nil {
		t.Fatal(err)
	}
	if credentialsCount != 2 || rootsCount != 1 {
		t.Fatalf("credentials=%d current_roots=%d, want 2 and 1", credentialsCount, rootsCount)
	}
}

// TestDBZKLogin checks an anonymous proof becomes an ordinary scoped session without metadata.
func TestDBZKLogin(t *testing.T) {
	f := newZKFixture(t)
	ctx := context.Background()
	issuer := createUser(t, f.db, "zk-login-issuer@example.com")
	credential, err := f.zk.IssueCredential(ctx, f.db, issuer, 22)
	if err != nil {
		t.Fatal(err)
	}
	claim := zkauthn.Claim{Name: "scoped-login", Audience: zkauthn.NewAudience("tests", "scoped", "v1"), Threshold: 18, Kind: zkauthn.ClaimRecurring, AllowsLogin: true}
	if err := f.zk.EnsureClaim(ctx, f.db, claim); err != nil {
		t.Fatal(err)
	}
	challenge, _ := f.zk.LoginChallenge(ctx, f.db)
	req, err := f.memberRequest(*credential, credential.Path, claim, challenge)
	if err != nil {
		t.Fatal(err)
	}
	var principal *authz.Principal
	rec, err := f.request("", func(ctx context.Context) error {
		principal, err = f.zk.Login(ctx, f.db, req)
		return err
	})
	if err != nil || principal == nil {
		t.Fatalf("ZK login: principal=%+v err=%v", principal, err)
	}
	cookie := sessionCookie(rec)
	if cookie == "" {
		t.Fatal("ZK login set no cookie")
	}
	var userAgent, ip string
	if _, err := f.db.QueryOne(pg.Scan(&userAgent, &ip), `
		select coalesce(user_agent, ''), coalesce(host(ip), '') from auth_sessions where id = ?`, principal.SessionID); err != nil {
		t.Fatal(err)
	}
	if userAgent != "" || ip != "" {
		t.Fatalf("pseudonymous session metadata user_agent=%q ip=%q", userAgent, ip)
	}

	if _, err := f.db.Exec(`create table docs (
		id uuid primary key default gen_random_uuid(), owner_id uuid not null, title text not null)`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec(`insert into docs (owner_id, title) values (?, 'mine'), (?, 'theirs')`,
		principal.UserID, issuer); err != nil {
		t.Fatal(err)
	}
	var rows []*doc
	if _, err := f.request(cookie, func(ctx context.Context) error {
		var err error
		rows, err = luima.List[doc](ctx, f.db, authz.Scope(ctx, "owner_id"))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Title != "mine" {
		t.Fatalf("scoped rows = %+v, want only mine", rows)
	}
	var others int
	if _, err := f.db.QueryOne(pg.Scan(&others), `select count(*) from docs where owner_id = ?`, issuer); err != nil {
		t.Fatal(err)
	}
	if others != 1 {
		t.Fatal("the other owner's row changed during scoped access")
	}
}

// TestDBZKTREE005011012014 asserts tree state, rollback-facing invariants, monotonic leaf
// indices, and the database uniqueness control. The assertions intentionally inspect nodes and
// rows rather than treating a returned error as evidence of revocation.
// Covers: ZK-TRE-005, ZK-TRE-011, ZK-TRE-012, ZK-TRE-014
func TestDBZKTREE005011012014(t *testing.T) {
	f := newZKFixture(t)
	ctx := context.Background()
	issuer := createUser(t, f.db, "zk-tree-state-issuer@example.com")
	a, err := f.zk.IssueCredential(ctx, f.db, issuer, 20)
	if err != nil {
		t.Fatal(err)
	}
	b, err := f.zk.IssueCredential(ctx, f.db, issuer, 21)
	if err != nil {
		t.Fatal(err)
	}
	var rootsBefore int
	if _, err := f.db.QueryOne(pg.Scan(&rootsBefore), `select count(*) from auth_zk_roots`); err != nil {
		t.Fatal(err)
	}
	if err := f.zk.RevokeCredential(ctx, f.db, a.LeafIndex); err != nil {
		t.Fatal(err)
	}
	var revoked bool
	if _, err := f.db.QueryOne(pg.Scan(&revoked), `select revoked_at is not null from auth_zk_credentials where leaf_index = ?`, a.LeafIndex); err != nil {
		t.Fatal(err)
	}
	if !revoked {
		t.Fatal("revocation did not set revoked_at")
	}
	var levelZero []byte
	if _, err := f.db.QueryOne(pg.Scan(&levelZero), `select hash from auth_zk_nodes where level = 0 and idx = ?`, a.LeafIndex); !errors.Is(err, pg.ErrNoRows) {
		t.Fatalf("revoked leaf node = %x, err=%v; expected sparse deletion", levelZero, err)
	}
	pathB, err := f.zk.Path(ctx, f.db, b.LeafIndex)
	if err != nil {
		t.Fatal(err)
	}
	empty := independentZKHash(zkauthnDomainForTest("kal.zk.v1/empty"))
	if pathB.Path[1] != empty {
		t.Fatalf("revoked sibling = %x, want domain-separated empty leaf %x", pathB.Path[1], empty)
	}
	if !zkauthn.MembershipValid(zkauthn.MembershipWitness{Secret: b.Secret, Attribute: b.Attribute,
		Path: pathB.Path, Index: pathB.Index, Root: pathB.Root, Audience: zkauthn.NewAudience("tree", "live", "one"),
		Threshold: 0, Nullifier: mustNullifier(t, b.Secret, zkauthn.NewAudience("tree", "live", "one"))}) {
		t.Fatal("unrevoked sibling no longer has a valid path")
	}
	c, err := f.zk.IssueCredential(ctx, f.db, issuer, 22)
	if err != nil {
		t.Fatal(err)
	}
	if c.LeafIndex != 2 {
		t.Fatalf("reused leaf index after revocation = %d, want 2", c.LeafIndex)
	}
	if err := f.zk.RevokeCredential(ctx, f.db, c.LeafIndex); err != nil {
		t.Fatal(err)
	}
	d, err := f.zk.IssueCredential(ctx, f.db, issuer, 23)
	if err != nil {
		t.Fatal(err)
	}
	if d.LeafIndex != 3 {
		t.Fatalf("second reused leaf index = %d, want 3", d.LeafIndex)
	}
	var credentials int
	if _, err := f.db.QueryOne(pg.Scan(&credentials), `select count(*) from auth_zk_credentials`); err != nil {
		t.Fatal(err)
	}
	if credentials != 4 {
		t.Fatalf("credential rows = %d, want 4 including revoked rows", credentials)
	}
	if _, err := f.db.Exec(`insert into auth_zk_credentials (leaf_index, commitment, issued_to) values (?, ?, ?)`, 100, b.Path.Path[0][:], issuer); err == nil {
		t.Fatal("duplicate commitment was accepted")
	}
	var rootsAfter int
	if _, err := f.db.QueryOne(pg.Scan(&rootsAfter), `select count(*) from auth_zk_roots`); err != nil {
		t.Fatal(err)
	}
	if rootsAfter <= rootsBefore {
		t.Fatalf("successful tree mutations did not publish roots: before=%d after=%d", rootsBefore, rootsAfter)
	}
}

func mustNullifier(t *testing.T, secret zkauthn.Secret, audience zkauthn.Field) zkauthn.Field {
	t.Helper()
	nullifier, err := zkauthn.Nullifier(secret, audience)
	if err != nil {
		t.Fatal(err)
	}
	return nullifier
}
