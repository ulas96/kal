package tests

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-pg/pg/v10"
	"github.com/ulas96/luima"

	"github.com/ulas96/kal/authz"
	"github.com/ulas96/kal/kalerr"
	"github.com/ulas96/kal/session"
	"github.com/ulas96/kal/zkauthn"
	"github.com/ulas96/kal/zkauthz"
)

// attributedRequest is f.request with the two headers a real proxy supplies. The composite privacy
// cases turn on what survives from here into auth_sessions, so driving them through Go method calls
// would skip the only place that failure can happen.
func (f *zkFixture) attributedRequest(cookie string, fn func(context.Context) error) (*httptest.ResponseRecorder, error) {
	var innerErr error
	h := f.sessions.Middleware(f.db, session.MiddlewareOptions{})(
		f.claims.Middleware(f.db)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			innerErr = fn(r.Context())
			w.WriteHeader(http.StatusOK)
		})))
	req := httptest.NewRequest(http.MethodPost, "/graphql", nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "kal-e2e/1.0 (a very identifying string)")
	req.RemoteAddr = "203.0.113.47:51515"
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: session.DefaultCookieName, Value: cookie})
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec, innerErr
}

// zkLoginOnce enrols nothing and issues nothing: it drives one full anonymous login over HTTP and
// returns the principal and the cookie the response set.
func zkLoginOnce(t *testing.T, f *zkFixture, credential zkauthn.Credential, path zkauthn.MerklePath,
	claim zkauthn.Claim) (*authz.Principal, string) {
	t.Helper()
	challenge, err := f.zk.LoginChallenge(context.Background(), f.db)
	if err != nil {
		t.Fatal(err)
	}
	req, err := f.memberRequest(credential, path, claim, challenge)
	if err != nil {
		t.Fatal(err)
	}
	var principal *authz.Principal
	rec, err := f.attributedRequest("", func(ctx context.Context) error {
		principal, err = f.zk.Login(ctx, f.db, req)
		return err
	})
	if err != nil {
		t.Fatalf("zk login: %v", err)
	}
	return principal, sessionCookie(rec)
}

// TestDBZKE2E001LoginYieldsScopedSession drives the whole login path over HTTP and checks the six
// things that must all hold at once.
//
// Every one of them can pass individually while the product still leaks: assertion 3 is the one
// that fails when the cryptography worked and the plumbing did not, because a session row carrying
// the caller's IP and user agent re-identifies a pseudonym with one join (gotcha 62).
//
// Covers: ZK-E2E-001, ZK-SES-001, ZK-SES-005
func TestDBZKE2E001LoginYieldsScopedSession(t *testing.T) {
	f := newZKFixture(t)
	ctx := context.Background()
	issuer := createUser(t, f.db, "zk-e2e001-issuer@example.com")
	credential, err := f.zk.IssueCredential(ctx, f.db, issuer, 40)
	if err != nil {
		t.Fatal(err)
	}
	claim := zkauthn.Claim{Name: "e2e001-login", Audience: zkauthn.NewAudience("tests", "e2e001", "v1"),
		Threshold: 18, Kind: zkauthn.ClaimRecurring, AllowsLogin: true}
	if err := f.zk.EnsureClaim(ctx, f.db, claim); err != nil {
		t.Fatal(err)
	}

	principal, cookie := zkLoginOnce(t, f, *credential, credential.Path, claim)
	if cookie == "" {
		t.Fatal("the login response set no session cookie")
	}

	// 1 · the cookie resolves a principal on a subsequent request.
	var resolved *authz.Principal
	if _, err := f.attributedRequest(cookie, func(ctx context.Context) error {
		p, ok := authz.From(ctx)
		if !ok {
			return fmt.Errorf("the session cookie did not resolve a principal")
		}
		resolved = p
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if resolved.UserID != principal.UserID {
		t.Fatalf("resolved user %s, want %s", resolved.UserID, principal.UserID)
	}

	// 2 · Scope returns this pseudonym's rows and leaves the other three owners' rows in place.
	if _, err := f.db.Exec(`create table e2e_docs (
		id       uuid primary key default gen_random_uuid(),
		owner_id uuid not null references auth_users(id),
		title    text not null)`); err != nil {
		t.Fatal(err)
	}
	others := []string{
		createUser(t, f.db, "zk-e2e001-other-a@example.com"),
		createUser(t, f.db, "zk-e2e001-other-b@example.com"),
		createUser(t, f.db, "zk-e2e001-other-c@example.com"),
	}
	for i, owner := range append([]string{resolved.UserID}, others...) {
		if _, err := f.db.Exec(`insert into e2e_docs (owner_id, title) values (?, ?)`,
			owner, fmt.Sprintf("row-%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	mine, err := luima.List[e2eDoc](ctx, f.db, authz.Scope(authz.WithPrincipal(ctx, resolved), "owner_id"))
	if err != nil {
		t.Fatal(err)
	}
	if len(mine) != 1 || mine[0].OwnerID != resolved.UserID {
		t.Fatalf("scoped read returned %d rows, want exactly this pseudonym's one", len(mine))
	}
	// The negative variant: a different principal sees its own row, so a Scope that returns
	// nothing at all does not satisfy the assertion above.
	theirs, err := luima.List[e2eDoc](ctx, f.db,
		authz.Scope(authz.WithPrincipal(ctx, &authz.Principal{UserID: others[0]}), "owner_id"))
	if err != nil {
		t.Fatal(err)
	}
	if len(theirs) != 1 || theirs[0].OwnerID != others[0] {
		t.Fatalf("another principal's scoped read returned %d rows, want its own one", len(theirs))
	}
	var remaining int
	if _, err := f.db.QueryOne(pg.Scan(&remaining), `select count(*) from e2e_docs`); err != nil {
		t.Fatal(err)
	}
	if remaining != 4 {
		t.Fatalf("e2e_docs holds %d rows, want all 4 still present", remaining)
	}

	// 3 · the session carries no attribution, from a request that supplied both.
	var ip, agent string
	if _, err := f.db.QueryOne(pg.Scan(&ip, &agent),
		`select coalesce(ip::text, ''), coalesce(user_agent, '') from auth_sessions where user_id = ?`,
		principal.UserID); err != nil {
		t.Fatal(err)
	}
	if ip != "" || agent != "" {
		t.Fatalf("the pseudonymous session recorded ip=%q user_agent=%q — one join re-identifies it",
			ip, agent)
	}

	// 4 · one recurring nullifier, unconsumed, bound to the pseudonym.
	var nullifiers int
	var consumedAt pg.NullTime
	var boundTo string
	if _, err := f.db.QueryOne(pg.Scan(&nullifiers), `select count(*) from auth_zk_nullifiers`); err != nil {
		t.Fatal(err)
	}
	if nullifiers != 1 {
		t.Fatalf("auth_zk_nullifiers holds %d rows, want 1", nullifiers)
	}
	if _, err := f.db.QueryOne(pg.Scan(&consumedAt, &boundTo),
		`select consumed_at, coalesce(user_id::text, '') from auth_zk_nullifiers`); err != nil {
		t.Fatal(err)
	}
	if !consumedAt.IsZero() {
		t.Fatal("a recurring nullifier was consumed; it is a lasting pseudonym, not an allowance")
	}
	if boundTo != principal.UserID {
		t.Fatalf("nullifier bound to %q, want the pseudonym %q", boundTo, principal.UserID)
	}

	// 5 · exactly one derived pseudonym account.
	var pseudonyms int
	if _, err := f.db.QueryOne(pg.Scan(&pseudonyms),
		`select count(*) from auth_users where email like 'zk-%@invalid'`); err != nil {
		t.Fatal(err)
	}
	if pseudonyms != 1 {
		t.Fatalf("pseudonym accounts = %d, want 1", pseudonyms)
	}

	// 6 · the challenge was consumed.
	var unconsumed int
	if _, err := f.db.QueryOne(pg.Scan(&unconsumed),
		`select count(*) from auth_zk_challenges where consumed_at is null`); err != nil {
		t.Fatal(err)
	}
	if unconsumed != 0 {
		t.Fatalf("%d challenges are still unconsumed after a successful login", unconsumed)
	}
}

type e2eDoc struct {
	tableName struct{} `pg:"e2e_docs"` //nolint:unused // go-pg reads this by reflection
	ID        string   `pg:"id,pk"`
	OwnerID   string   `pg:"owner_id"`
	Title     string   `pg:"title"`
}

// TestDBZKE2E002KnowledgeFillsMFASeam checks that @auth(mfa: true) stops always-denying and starts
// meaning something, across four steps.
//
// Step (ii) is the negative variant: without it, the pre-existing always-deny behaviour satisfies
// (i), (iii) and (iv) perfectly and nothing was built. Step (iv) is the trap — an elevation that
// survives a re-login turns a second factor into a one-time formality, because mfa_at belongs to
// the session and not to the user.
//
// Covers: ZK-E2E-002, ZK-CHL-004, ZK-SES-004
func TestDBZKE2E002KnowledgeFillsMFASeam(t *testing.T) {
	f := newZKFixture(t)
	ctx := context.Background()
	userID := createUser(t, f.db, "zk-e2e002@example.com")

	var resolverRuns int
	guard := authz.Directive(authz.DirectiveOptions{})
	protected := func(ctx context.Context) error {
		mfa := true
		_, err := guard(ctx, nil, func(context.Context) (any, error) {
			resolverRuns++
			return nil, nil
		}, authz.LevelAuthenticated, nil, &mfa, nil)
		return err
	}

	// (i) authenticated, no proof.
	cookie := issueSession(t, f, userID)
	_, err := f.request(cookie, protected)
	requireErrorCode(t, err, kalerr.CodeMFARequired)
	if resolverRuns != 0 {
		t.Fatal("the protected resolver ran without a proof")
	}

	// (ii) enrol, prove, resubmit.
	var secret zkauthn.Secret
	if _, err := f.request(cookie, func(ctx context.Context) error {
		var err error
		secret, err = f.zk.EnrollKnowledge(ctx, f.db, "")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	elevated := zkProveKnowledge(t, f, cookie, secret)
	if _, err := f.request(elevated, protected); err != nil {
		t.Fatalf("after a verified knowledge proof: %v", err)
	}
	if resolverRuns != 1 {
		t.Fatalf("resolver runs = %d, want 1", resolverRuns)
	}

	// (iii) a second session for the same user is not elevated.
	second := issueSession(t, f, userID)
	_, err = f.request(second, protected)
	requireErrorCode(t, err, kalerr.CodeMFARequired)
	if resolverRuns != 1 {
		t.Fatalf("resolver runs = %d after a sibling session, want 1", resolverRuns)
	}

	// (iv) revoke and log in again: the elevation must not carry forward.
	if err := f.sessions.RevokeAllForUser(ctx, f.db, userID); err != nil {
		t.Fatal(err)
	}
	fresh := issueSession(t, f, userID)
	_, err = f.request(fresh, protected)
	requireErrorCode(t, err, kalerr.CodeMFARequired)
	if resolverRuns != 1 {
		t.Fatalf("resolver runs = %d after re-login, want 1 — mfa_at survived the session", resolverRuns)
	}
}

// zkProveKnowledge runs one full knowledge step-up and returns the rotated cookie.
func zkProveKnowledge(t *testing.T, f *zkFixture, cookie string, secret zkauthn.Secret) string {
	t.Helper()
	var challenge string
	if _, err := f.request(cookie, func(ctx context.Context) error {
		var err error
		challenge, err = f.zk.KnowledgeChallenge(ctx, f.db)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	commitment, err := zkauthn.KnowledgeCommitment(secret)
	if err != nil {
		t.Fatal(err)
	}
	field, err := zkauthn.ChallengeField(challenge)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := f.keys.knowledgePK.ProveKnowledge(zkauthn.KnowledgeWitness{
		Secret: secret, Commitment: commitment, Challenge: field})
	if err != nil {
		t.Fatal(err)
	}
	rec, err := f.request(cookie, func(ctx context.Context) error {
		return f.zk.VerifyKnowledge(ctx, f.db, zkauthn.KnowledgeRequest{Proof: proof, Challenge: challenge})
	})
	if err != nil {
		t.Fatal(err)
	}
	return sessionCookie(rec)
}

// TestDBZKE2E003MembershipSatisfiesProvesAndOnlyThat runs two claims through the directive, because
// cross-satisfaction is the failure and one claim cannot detect it.
//
// Covers: ZK-E2E-003, ZK-INP-003
func TestDBZKE2E003MembershipSatisfiesProvesAndOnlyThat(t *testing.T) {
	f := newZKFixture(t)
	ctx := context.Background()
	issuer := createUser(t, f.db, "zk-e2e003-issuer@example.com")

	member := zkauthn.Claim{Name: "is_member", Audience: zkauthn.NewAudience("tests", "e2e003-member", "v1"),
		Threshold: 0, Kind: zkauthn.ClaimRecurring}
	adult := zkauthn.Claim{Name: "age_over_18", Audience: zkauthn.NewAudience("tests", "e2e003-adult", "v1"),
		Threshold: 18, Kind: zkauthn.ClaimRecurring}
	for _, c := range []zkauthn.Claim{member, adult} {
		if err := f.zk.EnsureClaim(ctx, f.db, c); err != nil {
			t.Fatal(err)
		}
	}

	twentyOne, err := f.zk.IssueCredential(ctx, f.db, issuer, 21)
	if err != nil {
		t.Fatal(err)
	}
	userID := createUser(t, f.db, "zk-e2e003-holder@example.com")
	cookie := issueSession(t, f, userID)

	runs := map[string]int{}
	guard := authz.Directive(authz.DirectiveOptions{Proofs: f.claims.Proofs})
	field := func(ctx context.Context, name string) error {
		_, err := guard(ctx, nil, func(context.Context) (any, error) {
			runs[name]++
			return nil, nil
		}, authz.LevelAuthenticated, nil, nil, []string{name})
		return err
	}

	// (i) before any proof, both deny.
	if _, err := f.request(cookie, func(ctx context.Context) error {
		requireErrorCode(t, field(ctx, "is_member"), kalerr.CodeInvalidProof)
		requireErrorCode(t, field(ctx, "age_over_18"), kalerr.CodeInvalidProof)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if runs["is_member"] != 0 || runs["age_over_18"] != 0 {
		t.Fatalf("resolvers ran before any proof: %+v", runs)
	}

	// (ii) proving is_member grants that field and not the other.
	if _, err := f.request(cookie, func(ctx context.Context) error {
		if err := zkProveClaimIn(ctx, f, *twentyOne, member); err != nil {
			return err
		}
		if err := field(ctx, "is_member"); err != nil {
			t.Errorf("is_member denied after proving it: %v", err)
		}
		requireErrorCode(t, field(ctx, "age_over_18"), kalerr.CodeInvalidProof)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if runs["is_member"] != 1 || runs["age_over_18"] != 0 {
		t.Fatalf("after proving is_member: %+v", runs)
	}

	// (iii) proving age_over_18 as well grants both. is_member is recurring, so it persists for
	// the session and both fields resolve on this request.
	if _, err := f.request(cookie, func(ctx context.Context) error {
		if err := zkProveClaimIn(ctx, f, *twentyOne, adult); err != nil {
			return err
		}
		if err := field(ctx, "age_over_18"); err != nil {
			t.Errorf("age_over_18 denied after proving it: %v", err)
		}
		if err := field(ctx, "is_member"); err != nil {
			t.Errorf("is_member denied on a later request: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if runs["age_over_18"] != 1 || runs["is_member"] != 2 {
		t.Fatalf("after proving age_over_18: %+v", runs)
	}

	// (iv) a member below the threshold proves is_member only, and cannot reach age_over_18 —
	// including with a request-supplied Threshold of 0, which the server must ignore in favour of
	// its own policy row.
	twelve, err := f.zk.IssueCredential(ctx, f.db, issuer, 12)
	if err != nil {
		t.Fatal(err)
	}
	minor := createUser(t, f.db, "zk-e2e003-minor@example.com")
	minorCookie := issueSession(t, f, minor)
	if _, err := f.request(minorCookie, func(ctx context.Context) error {
		if err := zkProveClaimIn(ctx, f, *twelve, member); err != nil {
			return err
		}
		if err := field(ctx, "is_member"); err != nil {
			t.Errorf("is_member denied for a below-threshold member: %v", err)
		}
		// Attribute 12 against the server's threshold of 18: the proof cannot be built, and a
		// client that lies about the threshold in its own witness produces one that will not
		// verify against the policy the server looks up.
		forged := adult
		forged.Threshold = 0
		if err := zkProveClaimIn(ctx, f, *twelve, forged); err == nil {
			t.Error("a request-supplied threshold of 0 was accepted for age_over_18")
		}
		requireErrorCode(t, field(ctx, "age_over_18"), kalerr.CodeInvalidProof)
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// (v) revoke the credential: on the next session both deny again.
	if err := f.zk.RevokeCredential(ctx, f.db, twentyOne.LeafIndex); err != nil {
		t.Fatal(err)
	}
	after := issueSession(t, f, userID)
	if _, err := f.request(after, func(ctx context.Context) error {
		requireErrorCode(t, field(ctx, "is_member"), kalerr.CodeInvalidProof)
		requireErrorCode(t, field(ctx, "age_over_18"), kalerr.CodeInvalidProof)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// zkProveClaimIn proves one claim inside an already-running request, so the holder the middleware
// installed is the one ProofSink writes to.
func zkProveClaimIn(ctx context.Context, f *zkFixture, credential zkauthn.Credential, claim zkauthn.Claim) error {
	challenge, err := f.zk.ClaimChallenge(ctx, f.db)
	if err != nil {
		return err
	}
	path, err := f.zk.Path(ctx, f.db, credential.LeafIndex)
	if err != nil {
		return err
	}
	req, err := f.memberRequest(credential, *path, claim, challenge)
	if err != nil {
		return err
	}
	return f.zk.ProveClaim(ctx, f.db, req)
}

// TestDBZKE2E004FullRevocationStory checks that revocation removes the credential, its tree
// membership and the ability to log in — and pins what happens to a session issued before it.
//
// The register marks the session's fate [UNSPECIFIED]. The decision recorded in SECURITY.md is
// that credential revocation does not revoke live sessions: auth_sessions.revoked_at is a separate
// control and nothing couples them, so an operator who wants both calls RevokeAllForUser too. This
// asserts that decision rather than assuming it, which is the trap the register names.
//
// Covers: ZK-E2E-004, ZK-TRE-007
func TestDBZKE2E004FullRevocationStory(t *testing.T) {
	f := newZKFixture(t)
	ctx := context.Background()
	issuer := createUser(t, f.db, "zk-e2e004-issuer@example.com")
	revoked, err := f.zk.IssueCredential(ctx, f.db, issuer, 40)
	if err != nil {
		t.Fatal(err)
	}
	survivor, err := f.zk.IssueCredential(ctx, f.db, issuer, 41)
	if err != nil {
		t.Fatal(err)
	}
	claim := zkauthn.Claim{Name: "e2e004-login", Audience: zkauthn.NewAudience("tests", "e2e004", "v1"),
		Threshold: 18, Kind: zkauthn.ClaimRecurring, AllowsLogin: true}
	if err := f.zk.EnsureClaim(ctx, f.db, claim); err != nil {
		t.Fatal(err)
	}

	revokedPath, err := f.zk.Path(ctx, f.db, revoked.LeafIndex)
	if err != nil {
		t.Fatal(err)
	}
	_, sessionS := zkLoginOnce(t, f, *revoked, *revokedPath, claim)

	var rootsBefore int
	if _, err := f.db.QueryOne(pg.Scan(&rootsBefore), `select count(*) from auth_zk_roots`); err != nil {
		t.Fatal(err)
	}
	if err := f.zk.RevokeCredential(ctx, f.db, revoked.LeafIndex); err != nil {
		t.Fatal(err)
	}

	// (i) a new login with the revoked credential fails, against the current root.
	current, err := f.zk.Path(ctx, f.db, survivor.LeafIndex)
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := f.zk.LoginChallenge(ctx, f.db)
	if err != nil {
		t.Fatal(err)
	}
	req, err := f.memberRequest(*revoked, *revokedPath, claim, challenge)
	if err != nil {
		t.Fatal(err)
	}
	req.Root = current.Root[:]
	_, err = f.attributedRequest("", func(ctx context.Context) error {
		_, err := f.zk.Login(ctx, f.db, req)
		return err
	})
	requireErrorCode(t, err, kalerr.CodeInvalidProof)

	// (ii) the leaf is gone from the tree: it no longer yields a path at all.
	if _, err := f.zk.Path(ctx, f.db, revoked.LeafIndex); err == nil {
		t.Fatal("a revoked leaf still yields a path")
	}

	// (iii) a new root was published.
	var rootsAfter int
	if _, err := f.db.QueryOne(pg.Scan(&rootsAfter), `select count(*) from auth_zk_roots`); err != nil {
		t.Fatal(err)
	}
	if rootsAfter <= rootsBefore {
		t.Fatalf("roots before=%d after=%d — revocation published none", rootsBefore, rootsAfter)
	}

	// (iv) the documented decision: session S survives, because credential revocation is not
	// session revocation. RootGrace is zero here, so the login window closed immediately.
	p, err := f.sessions.Lookup(ctx, f.db, sessionS)
	if err != nil {
		t.Fatal(err)
	}
	if p == nil {
		t.Fatal("session S no longer resolves; SECURITY.md documents that it survives until expiry")
	}
	if f.zk.RootGrace() != 0 {
		t.Fatalf("RootGrace = %v, want 0 for an immediate close", f.zk.RootGrace())
	}

	// The negative variant: another member logs in perfectly well after the revocation, so (i) is
	// not satisfied by a Login that stopped working altogether.
	if _, cookie := zkLoginOnce(t, f, *survivor, *current, claim); cookie == "" {
		t.Fatal("an unrevoked member could not log in after somebody else's revocation")
	}
}

// TestDBZKE2E005TwoReplicasAgree runs two independently constructed services against one database
// and one pair of verifying keys.
//
// The tree lives in Postgres precisely so this holds; an in-memory tree would give each replica its
// own root (gotcha 53). Separate session stores and claim holders, so nothing is shared in process.
//
// Covers: ZK-E2E-005, ZK-TRE-004
func TestDBZKE2E005TwoReplicasAgree(t *testing.T) {
	f := newZKFixture(t)
	ctx := context.Background()
	replicaB := newZKReplica(t, f)

	issuer := createUser(t, f.db, "zk-e2e005-issuer@example.com")
	claim := zkauthn.Claim{Name: "e2e005-login", Audience: zkauthn.NewAudience("tests", "e2e005", "v1"),
		Threshold: 18, Kind: zkauthn.ClaimRecurring, AllowsLogin: true}
	if err := f.zk.EnsureClaim(ctx, f.db, claim); err != nil {
		t.Fatal(err)
	}

	// Issue on A, log in on B; issue on B, log in on A. No coordination between them.
	onA, err := f.zk.IssueCredential(ctx, f.db, issuer, 40)
	if err != nil {
		t.Fatal(err)
	}
	if _, cookie := zkLoginOnce(t, replicaB, *onA, mustPath(t, replicaB, onA.LeafIndex), claim); cookie == "" {
		t.Fatal("replica B could not serve a credential replica A issued")
	}
	onB, err := replicaB.zk.IssueCredential(ctx, f.db, issuer, 41)
	if err != nil {
		t.Fatal(err)
	}
	if _, cookie := zkLoginOnce(t, f, *onB, mustPath(t, f, onB.LeafIndex), claim); cookie == "" {
		t.Fatal("replica A could not serve a credential replica B issued")
	}

	// Both replicas serve the *same* member, which is the assertion that keeps this from passing
	// on a pair that simply both refuse.
	pathA := mustPath(t, f, onA.LeafIndex)
	pathB := mustPath(t, replicaB, onA.LeafIndex)
	if !bytes.Equal(pathA.Root[:], pathB.Root[:]) {
		t.Fatalf("replica roots differ: %x vs %x", pathA.Root, pathB.Root)
	}

	// Revoke on A; B refuses immediately, because RootGrace is zero on both.
	if err := f.zk.RevokeCredential(ctx, f.db, onA.LeafIndex); err != nil {
		t.Fatal(err)
	}
	challenge, err := replicaB.zk.LoginChallenge(ctx, f.db)
	if err != nil {
		t.Fatal(err)
	}
	req, err := replicaB.memberRequest(*onA, pathA, claim, challenge)
	if err != nil {
		t.Fatal(err)
	}
	currentB := mustPath(t, replicaB, onB.LeafIndex)
	req.Root = currentB.Root[:]
	_, err = replicaB.attributedRequest("", func(ctx context.Context) error {
		_, err := replicaB.zk.Login(ctx, f.db, req)
		return err
	})
	requireErrorCode(t, err, kalerr.CodeInvalidProof)

	// Both instances agree on circuit identity and on the verifying-key bytes they loaded.
	for _, kind := range []zkauthn.Circuit{zkauthn.CircuitKnowledge, zkauthn.CircuitMembership} {
		constraintsA, idA, err := zkauthn.CircuitInfo(kind)
		if err != nil {
			t.Fatal(err)
		}
		constraintsB, idB, err := zkauthn.CircuitInfo(kind)
		if err != nil {
			t.Fatal(err)
		}
		if constraintsA != constraintsB || idA != idB {
			t.Fatalf("%s circuit identity differs between replicas", kind)
		}
	}
	if !bytes.Equal(f.keys.membershipRaw, replicaB.keys.membershipRaw) ||
		f.keys.membershipHash != replicaB.keys.membershipHash {
		t.Fatal("the replicas loaded different membership verifying keys")
	}
}

// newZKReplica builds a second, independently constructed service over the same database: its own
// session store, claim holder and ZK instance, sharing only Postgres and the verifying keys.
func newZKReplica(t *testing.T, f *zkFixture) *zkFixture {
	t.Helper()
	sessions, err := session.NewSessions(session.Options{Schema: testSchema})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := zkauthz.New(testSchema)
	if err != nil {
		t.Fatal(err)
	}
	zk, err := zkauthn.New(zkauthn.Options{
		KnowledgeVK: f.keys.knowledgeVK, MembershipVK: f.keys.membershipVK,
		Sessions: sessions, Hasher: f.hasher, ProofSink: claims.Add, Schema: testSchema,
		MaxConcurrentVerifications: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &zkFixture{db: f.db, sessions: sessions, claims: claims, zk: zk, keys: f.keys, hasher: f.hasher}
}

func mustPath(t *testing.T, f *zkFixture, index uint32) zkauthn.MerklePath {
	t.Helper()
	path, err := f.zk.Path(context.Background(), f.db, index)
	if err != nil {
		t.Fatal(err)
	}
	return *path
}

// TestDBZKE2E006AnonymousAtTheDatabase is the composite privacy case: every individual control can
// pass and the join can still exist.
//
// Twelve members, because the anonymity set is the count of non-revoked leaves and at N=1 the
// attribution is exact and correct — a two-member run would "fail" for a reason that is not a
// defect. The columns examined are enumerated below so the analysis is repeatable, and they
// deliberately include auth_users and auth_sessions: the join that re-identifies a pseudonym runs
// through those, not through the zk tables (gotcha 62).
//
// Covers: ZK-E2E-006, ZK-PSD-003
func TestDBZKE2E006AnonymousAtTheDatabase(t *testing.T) {
	f := newZKFixture(t)
	ctx := context.Background()
	issuer := createUser(t, f.db, "zk-e2e006-issuer@example.com")
	claim := zkauthn.Claim{Name: "e2e006-login", Audience: zkauthn.NewAudience("tests", "e2e006", "v1"),
		Threshold: 18, Kind: zkauthn.ClaimRecurring, AllowsLogin: true}
	if err := f.zk.EnsureClaim(ctx, f.db, claim); err != nil {
		t.Fatal(err)
	}

	const members = 12
	credentials := make([]*zkauthn.Credential, members)
	for i := range credentials {
		var err error
		if credentials[i], err = f.zk.IssueCredential(ctx, f.db, issuer, 40); err != nil {
			t.Fatal(err)
		}
	}
	const actor = 6 // M₇, zero-indexed
	acting, cookie := zkLoginOnce(t, f, *credentials[actor],
		mustPath(t, f, credentials[actor].LeafIndex), claim)
	if _, err := f.attributedRequest(cookie, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}

	// The anonymity set: every non-revoked leaf could have produced this proof.
	var liveLeaves int
	if _, err := f.db.QueryOne(pg.Scan(&liveLeaves),
		`select count(*) from auth_zk_credentials where revoked_at is null`); err != nil {
		t.Fatal(err)
	}
	if liveLeaves != members {
		t.Fatalf("anonymity set = %d, want %d", liveLeaves, members)
	}

	// Columns examined, as the operator, with full access. Each must fail to narrow below 12.
	//
	//   auth_zk_credentials · leaf_index, commitment, issued_to, created_at, revoked_at
	//   auth_zk_nullifiers  · nullifier, audience, user_id, first_seen_at, consumed_at
	//   auth_zk_roots       · root, created_at, retired_at
	//   auth_zk_nodes       · level, idx, hash
	//   auth_users          · id, email, password_hash, email_verified, created_at, deleted_at
	//   auth_sessions       · id, user_id, ip, user_agent, auth_at, mfa_at
	//
	// 1 · the acting pseudonym is not any issued credential's issued_to.
	var linked int
	if _, err := f.db.QueryOne(pg.Scan(&linked),
		`select count(*) from auth_zk_credentials where issued_to = ?`, acting.UserID); err != nil {
		t.Fatal(err)
	}
	if linked != 0 {
		t.Fatalf("%d credentials name the acting pseudonym in issued_to", linked)
	}

	// 2 · the nullifier is not any credential's commitment, so it cannot be joined to a leaf.
	var joinable int
	if _, err := f.db.QueryOne(pg.Scan(&joinable), `
		select count(*) from auth_zk_nullifiers n
		  join auth_zk_credentials c on c.commitment = n.nullifier`); err != nil {
		t.Fatal(err)
	}
	if joinable != 0 {
		t.Fatalf("%d nullifiers join directly to a credential row", joinable)
	}

	// 3 · the session carries no network attribution to correlate against anything.
	var attributed int
	if _, err := f.db.QueryOne(pg.Scan(&attributed),
		`select count(*) from auth_sessions where ip is not null or user_agent is not null`); err != nil {
		t.Fatal(err)
	}
	if attributed != 0 {
		t.Fatalf("%d sessions carry ip or user_agent", attributed)
	}

	// 4 · the pseudonym's address is a pure function of the nullifier. Asserting equality rather
	// than absence of substrings is the point: it leaves no room for a future convenience field to
	// be appended to it (ZK-NUL-004), and a single hex digit "containing" a leaf index would make
	// a substring check pass or fail for no reason.
	var email string
	if _, err := f.db.QueryOne(pg.Scan(&email),
		`select email from auth_users where id = ?`, acting.UserID); err != nil {
		t.Fatal(err)
	}
	var storedNullifier []byte
	if _, err := f.db.QueryOne(pg.Scan(&storedNullifier),
		`select nullifier from auth_zk_nullifiers`); err != nil {
		t.Fatal(err)
	}
	if want := "zk-" + hex.EncodeToString(storedNullifier) + "@invalid"; email != want {
		t.Fatalf("pseudonym address = %q, want %q derived from the nullifier alone", email, want)
	}
	// And the commitment that identifies the leaf is nowhere in it.
	if bytes.Contains([]byte(email), []byte(hex.EncodeToString(credentials[actor].Path.Path[0][:]))) {
		t.Fatal("the pseudonym address carries the credential commitment")
	}

	// The negative variant: the design keeps what it is supposed to keep. The operator can still
	// tell that *a member* acted, and can still revoke by user. A system that reveals nothing at
	// all has broken revocation.
	var proofs int
	if _, err := f.db.QueryOne(pg.Scan(&proofs), `select count(*) from auth_zk_nullifiers`); err != nil {
		t.Fatal(err)
	}
	if proofs != 1 {
		t.Fatalf("nullifier rows = %d, want the single proof that a member acted", proofs)
	}
	if err := f.zk.RevokeCredentialsForUser(ctx, f.db, issuer); err != nil {
		t.Fatalf("revocation by user is broken: %v", err)
	}
	var stillLive int
	if _, err := f.db.QueryOne(pg.Scan(&stillLive),
		`select count(*) from auth_zk_credentials where revoked_at is null`); err != nil {
		t.Fatal(err)
	}
	if stillLive != 0 {
		t.Fatalf("%d credentials survived revocation by user", stillLive)
	}
}
