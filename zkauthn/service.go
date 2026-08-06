package zkauthn

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"runtime"
	"time"

	"github.com/consensys/gnark/frontend"
	"github.com/go-pg/pg/v10"
	"github.com/go-pg/pg/v10/orm"
	"github.com/go-pg/pg/v10/types"
	"golang.org/x/sync/semaphore"

	"github.com/ulas96/kal/authn"
	"github.com/ulas96/kal/authz"
	"github.com/ulas96/kal/kalerr"
	"github.com/ulas96/kal/session"
)

const (
	// ChallengeTTL @notice Lifetime of a server-issued proof challenge.
	ChallengeTTL = time.Minute
	verifyWait   = 2 * time.Second
)

var identRe = regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)

// ClaimKind @notice Whether a nullifier is a recurring pseudonym or a one-shot allowance.
type ClaimKind string

const (
	ClaimRecurring ClaimKind = "recurring"
	ClaimOneShot   ClaimKind = "one_shot"
)

// Claim @notice Server policy supplying the audience and threshold for a schema claim name.
type Claim struct {
	Name      string
	Audience  Field
	Threshold uint64
	Kind      ClaimKind
	// AllowsLogin @notice Whether proving this claim may mint a session. False by default: Kind
	// distinguishes how long a nullifier lives, not what a proof is good for, so without this a
	// claim written for an @auth(proves:) step-up is also a login endpoint.
	AllowsLogin bool
}

// VerifiedClaim @notice A claim whose proof and server policy were verified for this request.
type VerifiedClaim struct {
	Name string
	Kind ClaimKind
}

// ProofSink adds a verified claim to the request-local authorization holder.
type ProofSink func(context.Context, VerifiedClaim) error

// Options @notice Dependencies and production defaults for New.
type Options struct {
	KnowledgeVK  *VerifyingKey
	MembershipVK *VerifyingKey
	Sessions     *session.Sessions
	// Hasher @notice Required. Re-verifies the password that gates replacing a commitment.
	Hasher     *authn.Hasher
	ProofSink  ProofSink
	CookieName string
	Schema     string
	RootGrace  time.Duration
	// MFAWindow @notice How recently MFA must have been satisfied for an account with no
	// password to replace its commitment. Zero means authz.DefaultMFAWindow.
	MFAWindow                  time.Duration
	MaxConcurrentVerifications int64
}

// ZK @notice Knowledge MFA, membership credentials, anonymous login and proof-backed claims.
type ZK struct {
	knowledge       *VerifyingKey
	membership      *VerifyingKey
	sessions        *session.Sessions
	hasher          *authn.Hasher
	proofSink       ProofSink
	cookieName      string
	rootGrace       time.Duration
	mfaWindow       time.Duration
	sem             *semaphore.Weighted
	zeros           [MerkleDepth + 1]Field
	dummyCommitment Field
	dummyMembership MembershipPublic
	sql             statements
}

// New @notice Validates dependencies, computes sparse-tree zeros and renders SQL once.
func New(opts Options) (*ZK, error) {
	if opts.KnowledgeVK == nil || opts.KnowledgeVK.circuit != CircuitKnowledge {
		return nil, errors.New("zkauthn: a knowledge verifying key is required")
	}
	if opts.MembershipVK == nil || opts.MembershipVK.circuit != CircuitMembership {
		return nil, errors.New("zkauthn: a membership verifying key is required")
	}
	if opts.Sessions == nil || opts.ProofSink == nil {
		return nil, errors.New("zkauthn: Sessions and ProofSink are required")
	}
	// Nil-checked like Sessions and ProofSink rather than defaulted: without a Hasher there is no
	// way to re-verify the password that gates replacing a commitment, and EnrollKnowledge would
	// silently fall back to letting any authenticated session overwrite the second factor.
	if opts.Hasher == nil {
		return nil, errors.New("zkauthn: Hasher is required — replacing a knowledge commitment re-verifies the current password")
	}
	if opts.RootGrace < 0 {
		return nil, &kalerr.Error{Code: kalerr.CodeInvalidInput, Message: "ZK root grace must not be negative"}
	}
	limit := opts.MaxConcurrentVerifications
	if limit <= 0 {
		limit = int64(runtime.GOMAXPROCS(0))
	}
	prefix := ""
	if opts.Schema != "" {
		if !identRe.MatchString(opts.Schema) {
			return nil, &kalerr.Error{Code: kalerr.CodeInvalidInput,
				Message: "table schema must match ^[a-z_][a-z0-9_]*$"}
		}
		prefix = string(types.AppendIdent(nil, opts.Schema, 1)) + "."
	}
	z := &ZK{
		knowledge: opts.KnowledgeVK, membership: opts.MembershipVK,
		sessions: opts.Sessions, hasher: opts.Hasher, proofSink: opts.ProofSink,
		cookieName: opts.CookieName, rootGrace: opts.RootGrace,
		mfaWindow: opts.MFAWindow,
		sem:       semaphore.NewWeighted(limit), sql: render(prefix),
	}
	if z.mfaWindow <= 0 {
		z.mfaWindow = authz.DefaultMFAWindow
	}
	if z.cookieName == "" {
		z.cookieName = session.DefaultCookieName
	}
	zero, err := emptyLeaf()
	if err != nil {
		return nil, err
	}
	z.zeros[0] = zero
	for i := 1; i <= MerkleDepth; i++ {
		z.zeros[i], err = nativeHash(z.zeros[i-1], z.zeros[i-1])
		if err != nil {
			return nil, err
		}
	}
	z.dummyCommitment, err = knowledgeCommitment(Secret{})
	if err != nil {
		return nil, err
	}
	// The membership counterpart of dummyCommitment. An unknown claim name and an unaccepted root
	// are both decided before any pairing runs, so without something to verify against they answer
	// milliseconds faster than a real verification failure — an oracle for which claims a
	// deployment defines and which roots are still live. Built once here so the branch that has
	// nothing to verify still spends a pairing and a semaphore slot like every other request.
	z.dummyMembership = MembershipPublic{
		Root: z.zeros[MerkleDepth], Audience: z.dummyCommitment,
		Nullifier: z.dummyCommitment, Challenge: z.dummyCommitment,
	}
	return z, nil
}

// verifyDummyMembership spends a pairing on a branch that has no real statement to check, then
// discards the result. Its error is deliberately dropped: the caller has already decided to refuse
// and the only thing this call buys is the time.
func (z *ZK) verifyDummyMembership(ctx context.Context, proof []byte) {
	_ = z.verify(ctx, z.membership, proof, &MembershipCircuit{
		Root: fieldBig(z.dummyMembership.Root), Audience: fieldBig(z.dummyMembership.Audience),
		Threshold: z.dummyMembership.Threshold, Nullifier: fieldBig(z.dummyMembership.Nullifier),
		Challenge: fieldBig(z.dummyMembership.Challenge),
	})
}

func (z *ZK) acquire(ctx context.Context) error {
	wait, cancel := context.WithTimeout(ctx, verifyWait)
	defer cancel()
	if err := z.sem.Acquire(wait, 1); err != nil {
		return &kalerr.Error{Code: kalerr.CodeRateLimited, Message: "please try again shortly", Internal: err}
	}
	return nil
}

func (z *ZK) verify(ctx context.Context, vk *VerifyingKey, proof []byte, public frontend.Circuit) error {
	if err := z.acquire(ctx); err != nil {
		return err
	}
	defer z.sem.Release(1)
	return vk.verify(proof, public)
}

// withTx reuses a caller's transaction and otherwise creates one on any go-pg DB/Conn runner.
func withTx(ctx context.Context, db orm.DB, fn func(orm.DB) error) error {
	if tx, ok := db.(*pg.Tx); ok {
		return fn(tx)
	}
	runner, ok := db.(interface {
		RunInTransaction(context.Context, func(*pg.Tx) error) error
	})
	if !ok {
		return errors.New("zkauthn: database handle cannot start a transaction")
	}
	return runner.RunInTransaction(ctx, func(tx *pg.Tx) error { return fn(tx) })
}

func invalidProof(cause error) error {
	return &kalerr.Error{Code: kalerr.CodeInvalidProof, Message: "invalid zero-knowledge proof", Internal: cause}
}

func invalidInput(message string) error {
	return &kalerr.Error{Code: kalerr.CodeInvalidInput, Message: message}
}

func noRowsInvalid(err error) error {
	if errors.Is(err, pg.ErrNoRows) {
		return invalidProof(err)
	}
	return fmt.Errorf("zkauthn: database operation: %w", err)
}
