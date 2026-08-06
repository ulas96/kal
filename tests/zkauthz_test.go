package tests

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
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

// TestAuthDirectiveProofs pins all-of callback wiring and nil fail-closed behavior.
// Covers: ZK-AUZ-002, ZK-AUZ-003
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
}
