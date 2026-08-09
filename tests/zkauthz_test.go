package tests

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/99designs/gqlgen/graphql"
	"github.com/go-pg/pg/v10"
	"github.com/ulas96/luima"

	"github.com/ulas96/kal/authz"
	"github.com/ulas96/kal/kalerr"
	"github.com/ulas96/kal/zkauthn"
	"github.com/ulas96/kal/zkauthz"
)

type zkTextOwnerRow struct {
	tableName struct{} `pg:"zk_text_owner_rows"`
	ID        string   `pg:"id,pk"`
	OwnerID   string   `pg:"owner_id"`
}

// TestDBZKAUZ001ScopeEmptyUser tests the documented failure mode on a text owner column. A uuid
// column alone is a false pass because an empty string fails before it can match a row.
// Covers: ZK-AUZ-001
func TestDBZKAUZ001ScopeEmptyUser(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	if _, err := db.Exec(`create table zk_text_owner_rows (id uuid primary key default gen_random_uuid(), owner_id text not null)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`insert into zk_text_owner_rows (owner_id) values (''), ('a'), ('real')`); err != nil {
		t.Fatal(err)
	}
	empty := authz.WithPrincipal(ctx, &authz.Principal{UserID: ""})
	rows, err := luima.List[zkTextOwnerRow](ctx, db, authz.Scope(empty, "owner_id"))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("empty principal selected %d rows", len(rows))
	}
	var before int
	if _, err := db.QueryOne(pg.Scan(&before), `select count(*) from zk_text_owner_rows`); err != nil {
		t.Fatal(err)
	}
	var emptyID string
	if _, err := db.QueryOne(pg.Scan(&emptyID), `select id from zk_text_owner_rows where owner_id = ''`); err != nil {
		t.Fatal(err)
	}
	_, _ = luima.Delete(ctx, db, &zkTextOwnerRow{ID: emptyID}, authz.Scope(empty, "owner_id"))
	var after int
	if _, err := db.QueryOne(pg.Scan(&after), `select count(*) from zk_text_owner_rows`); err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("empty principal changed table: before=%d after=%d", before, after)
	}
	var emptyRows int
	if _, err := db.QueryOne(pg.Scan(&emptyRows), `select count(*) from zk_text_owner_rows where owner_id = ''`); err != nil {
		t.Fatal(err)
	}
	if emptyRows != 1 {
		t.Fatal("row owned by empty string was removed")
	}
}

// TestZKRequestClaims proves one-shot claims are request-local and consumed exactly once.
func TestZKRequestClaims(t *testing.T) {
	claims, err := zkauthz.New("")
	if err != nil {
		t.Fatal(err)
	}
	var requestErr error
	h := claims.Middleware(nil)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		if err := claims.Add(r.Context(), zkauthn.VerifiedClaim{Name: "member", Kind: zkauthn.ClaimRecurring}); err != nil {
			requestErr = err
			return
		}
		if err := claims.Add(r.Context(), zkauthn.VerifiedClaim{Name: "vote", Kind: zkauthn.ClaimOneShot}); err != nil {
			requestErr = err
			return
		}
		if err := claims.Proofs(r.Context(), []string{"member", "vote"}); err != nil {
			requestErr = err
			return
		}
		if err := claims.Proofs(r.Context(), []string{"member"}); err != nil {
			requestErr = err
			return
		}
		err := claims.Proofs(r.Context(), []string{"vote"})
		var ae *kalerr.Error
		if !errors.As(err, &ae) || ae.Code != kalerr.CodeInvalidProof {
			requestErr = errors.New("one-shot claim was not consumed")
		}
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/graphql", nil))
	if requestErr != nil {
		t.Fatal(requestErr)
	}
}

// TestZKRequestClaimsCountsDuplicates proves one grant does not satisfy two demands for it.
//
// @auth(proves: ["vote","vote"]) is a request for two allowances. Tested per entry rather than
// counted per name, a single grant answered both and drove the counter to -1, which then let a
// later field spend an allowance the member never had. The sibling case is the one that keeps this
// honest: two grants must satisfy the same field, so a Proofs that always refused would not pass.
func TestZKRequestClaimsCountsDuplicates(t *testing.T) {
	claims, err := zkauthz.New("")
	if err != nil {
		t.Fatal(err)
	}
	var requestErr error
	h := claims.Middleware(nil)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		if err := claims.Add(r.Context(), zkauthn.VerifiedClaim{Name: "vote", Kind: zkauthn.ClaimOneShot}); err != nil {
			requestErr = err
			return
		}
		err := claims.Proofs(r.Context(), []string{"vote", "vote"})
		var ae *kalerr.Error
		if !errors.As(err, &ae) || ae.Code != kalerr.CodeInvalidProof {
			requestErr = errors.New("one grant satisfied two demands for the same claim")
			return
		}
		// Check-all-before-consume-any: the refused request must not have spent the grant.
		if err := claims.Proofs(r.Context(), []string{"vote"}); err != nil {
			requestErr = errors.New("the refused duplicate consumed the single grant anyway")
			return
		}
		if err := claims.Add(r.Context(), zkauthn.VerifiedClaim{Name: "vote", Kind: zkauthn.ClaimOneShot}); err != nil {
			requestErr = err
			return
		}
		if err := claims.Add(r.Context(), zkauthn.VerifiedClaim{Name: "vote", Kind: zkauthn.ClaimOneShot}); err != nil {
			requestErr = err
			return
		}
		if err := claims.Proofs(r.Context(), []string{"vote", "vote"}); err != nil {
			requestErr = errors.New("two grants did not satisfy two demands")
		}
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/graphql", nil))
	if requestErr != nil {
		t.Fatal(requestErr)
	}
}

// TestZKRequestClaimsAnonymous proves an anonymous caller satisfies no proof requirement, at both
// of the layers that could let one through.
//
// The middleware runs before the graph decides and anonymous is never an error here, so an
// anonymous request reaches Proofs with a holder that was built and left empty — not with no
// holder at all. Only one of those two states goes through the ordinary count check, and it is the
// one that has to deny. One layer up, the directive's anonymous fast path exists so public fields
// resolve; a proves: requirement must not ride out on it.
//
// The register's revoked- and expired-session variants collapse into this one: session.Middleware
// puts no principal on the context for either, which TestDBMiddleware already pins. There is no
// path here on which a principal is constructed and then discarded.
//
// Covers: ZK-AUZ-008
func TestZKRequestClaimsAnonymous(t *testing.T) {
	claims, err := zkauthz.New("")
	if err != nil {
		t.Fatal(err)
	}
	var requestErr error
	h := claims.Middleware(nil)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		// The nil db is an assertion, not a shortcut: an anonymous request must never reach the
		// session-claims query, and a branch that ran it would panic here rather than pass.
		err := claims.Proofs(r.Context(), []string{"member"})
		var ae *kalerr.Error
		if !errors.As(err, &ae) || ae.Code != kalerr.CodeInvalidProof {
			requestErr = fmt.Errorf("anonymous request satisfied a claim: %w", err)
			return
		}
		// The holder is live, not inert: a Proofs that refused everything would pass the
		// assertion above and prove nothing.
		if err := claims.Add(r.Context(), zkauthn.VerifiedClaim{
			Name: "member", Kind: zkauthn.ClaimRecurring}); err != nil {
			requestErr = err
			return
		}
		if err := claims.Proofs(r.Context(), []string{"member"}); err != nil {
			requestErr = fmt.Errorf("a granted claim did not satisfy: %w", err)
		}
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/graphql", nil))
	if requestErr != nil {
		t.Fatal(requestErr)
	}

	// The directive is the other half, and the counter is the assertion: an error value alone does
	// not prove the field stayed unresolved. The code is UNAUTHENTICATED rather than INVALID_PROOF
	// because the directive stops at the missing principal — that is correct, and asserting the
	// narrower code here would pin the wrong layer.
	resolved := 0
	next := func(context.Context) (any, error) { resolved++; return "ok", nil }
	d := authz.Directive(authz.DirectiveOptions{Proofs: claims.Proofs})
	yes := true
	for _, c := range []struct {
		name     string
		requires authz.AuthLevel
		mfa      *bool
	}{
		{"anonymous field", authz.LevelAnonymous, nil},
		{"authenticated field", authz.LevelAuthenticated, nil},
		{"anonymous field with step-up", authz.LevelAnonymous, &yes},
	} {
		if _, err := d(context.Background(), nil, graphql.Resolver(next), c.requires, nil, c.mfa,
			[]string{"member"}); err == nil {
			t.Errorf("%s: an anonymous caller passed a proof requirement", c.name)
		}
	}
	if resolved != 0 {
		t.Fatalf("resolver ran %d times for an anonymous caller", resolved)
	}
}

// TestZKRequestClaimsPerRequest proves a grant does not outlive the request that earned it.
//
// The only thing keeping one caller's claims away from another is that the holder is built inside
// the handler. A package-level map, a sync.Map keyed on anything, or a holder hung off the *Claims
// value would serve the first request's grant to the second, and under load it would do it
// intermittently — which reads as a flake rather than as a bypass. The ordered pair below states
// the property; the concurrent round after it is the one that can see the race, under -race.
//
// The register's other half — that a recurring claim proven in one request *is* available to the
// same session's later requests, through auth_zk_session_claims — needs Postgres and is pinned by
// step (iii) of TestDBZKE2E003MembershipSatisfiesProvesAndOnlyThat.
//
// Covers: ZK-AUZ-006
func TestZKRequestClaimsPerRequest(t *testing.T) {
	claims, err := zkauthz.New("")
	if err != nil {
		t.Fatal(err)
	}

	grant := true
	var requestErr error
	h := claims.Middleware(nil)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		if grant {
			for _, c := range []zkauthn.VerifiedClaim{
				{Name: "vote", Kind: zkauthn.ClaimOneShot},
				{Name: "member", Kind: zkauthn.ClaimRecurring},
			} {
				if err := claims.Add(r.Context(), c); err != nil {
					requestErr = err
					return
				}
			}
			// The grant took, and the one-shot is left unspent so the second request is asking
			// about a claim that really is sitting in someone's holder.
			if err := claims.Proofs(r.Context(), []string{"member"}); err != nil {
				requestErr = fmt.Errorf("the granting request could not use its own grant: %w", err)
			}
			return
		}
		// Both kinds: recurring and oneShot are separate fields on the holder and a leak of
		// either is a bypass, so checking one leaves the other unwatched.
		for _, claim := range []string{"vote", "member"} {
			err := claims.Proofs(r.Context(), []string{claim})
			var ae *kalerr.Error
			if !errors.As(err, &ae) || ae.Code != kalerr.CodeInvalidProof {
				requestErr = fmt.Errorf("%q survived into a second request: %w", claim, err)
				return
			}
		}
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/graphql", nil))
	grant = false
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/graphql", nil))
	if requestErr != nil {
		t.Fatal(requestErr)
	}

	// Every request holds its own grant before any request checks, so a shared holder is populated
	// by all of them at the moment each one asks about a name it never granted.
	const rounds = 32
	var ready, wg sync.WaitGroup
	ready.Add(rounds)
	failures := make(chan error, rounds)
	race := claims.Middleware(nil)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		mine, theirs := r.Header.Get("X-Mine"), r.Header.Get("X-Theirs")
		addErr := claims.Add(r.Context(), zkauthn.VerifiedClaim{Name: mine, Kind: zkauthn.ClaimOneShot})
		ready.Done()
		ready.Wait()
		if addErr != nil {
			failures <- addErr
			return
		}
		err := claims.Proofs(r.Context(), []string{theirs})
		var ae *kalerr.Error
		if !errors.As(err, &ae) || ae.Code != kalerr.CodeInvalidProof {
			failures <- fmt.Errorf("%s satisfied %s, which it never granted: %w", mine, theirs, err)
			return
		}
		if err := claims.Proofs(r.Context(), []string{mine}); err != nil {
			failures <- fmt.Errorf("%s could not satisfy its own grant: %w", mine, err)
		}
	}))
	for i := range rounds {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodPost, "/graphql", nil)
			req.Header.Set("X-Mine", fmt.Sprintf("claim_%d", i))
			req.Header.Set("X-Theirs", fmt.Sprintf("claim_%d", (i+1)%rounds))
			race.ServeHTTP(httptest.NewRecorder(), req)
		}()
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
}

// TestAuthDirectiveProofs pins all-of callback wiring and nil fail-closed behavior.
//
// An explicit empty proves: is the third arm, and it is a decision rather than a discovery: an
// all-of over the empty set is vacuously true, so allowing is what the natural implementation
// does. kal denies, before the anonymous fast path, and authz.Directive's doc comment records it.
//
// Covers: ZK-AUZ-002, ZK-AUZ-003, ZK-AUZ-009
func TestAuthDirectiveProofs(t *testing.T) {
	ctx := authz.WithPrincipal(context.Background(), &authz.Principal{UserID: "u"})
	next := func(context.Context) (any, error) { return "ok", nil }

	d := authz.Directive(authz.DirectiveOptions{})
	if _, err := d(ctx, nil, next, authz.LevelAuthenticated, nil, nil, []string{"member"}); err == nil {
		t.Fatal("proof requirement passed without an implementation")
	}

	var got []string
	d = authz.Directive(authz.DirectiveOptions{Proofs: func(_ context.Context, claims []string) error {
		got = append(got, claims...)
		return nil
	}})
	if _, err := d(ctx, nil, graphql.Resolver(next), authz.LevelAuthenticated, nil, nil,
		[]string{"member", "age_over_18"}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "member" || got[1] != "age_over_18" {
		t.Errorf("proof callback got %v", got)
	}

	// ZK-AUZ-009's negative variant is the whole case: absent and empty must be separable, and a
	// test that only checks one of them cannot tell a decision from a coincidence.
	ran := false
	counting := func(context.Context) (any, error) { ran = true; return "ok", nil }
	d = authz.Directive(authz.DirectiveOptions{})

	if _, err := d(ctx, nil, graphql.Resolver(counting), authz.LevelAuthenticated, nil, nil, nil); err != nil {
		t.Errorf("an absent proves: added a requirement: %v", err)
	}
	if !ran {
		t.Error("an absent proves: stopped the resolver")
	}

	ran = false
	if _, err := d(ctx, nil, graphql.Resolver(counting), authz.LevelAuthenticated, nil, nil,
		[]string{}); err == nil {
		t.Error("an explicit empty proves: resolved")
	}
	if ran {
		t.Error("the resolver ran behind an explicit empty proves:")
	}

	// The same decision on an anonymous field, which is where a check placed after the anonymous
	// fast path would silently not fire.
	ran = false
	if _, err := d(context.Background(), nil, graphql.Resolver(counting), authz.LevelAnonymous, nil,
		nil, []string{}); err == nil {
		t.Error("an anonymous caller resolved a field with an explicit empty proves:")
	}
	if ran {
		t.Error("the resolver ran for an anonymous caller behind an explicit empty proves:")
	}
}
