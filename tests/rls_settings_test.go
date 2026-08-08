package tests

import (
	"context"
	"errors"
	"testing"

	"github.com/go-pg/pg/v10"
	"github.com/go-pg/pg/v10/orm"

	"github.com/ulas96/kal"
	"github.com/ulas96/kal/authz"
	"github.com/ulas96/kal/kalerr"
)

// currentSetting @notice Reads a GUC, tolerating unset — the `true` is mandatory or it raises.
func currentSetting(t *testing.T, db orm.DB, name string) string {
	t.Helper()
	var v string
	if _, err := db.QueryOneContext(context.Background(), pg.Scan(&v),
		`select coalesce(current_setting(?, true), '')`, name); err != nil {
		t.Fatal(err)
	}
	return v
}

// TestDBWithRLSSettingsAreTransactionLocal @notice Extra settings reach the policy and die at
// COMMIT.
//
// @dev Step two is the test. A setting that survives its transaction leaks to whichever request
// borrows that pooled connection next, which is a cross-tenant data leak that only appears under
// concurrency — trap 2 in WithRLS's doc comment, and the reason set_config's third argument is
// true. Asserting only that the setting is readable inside fn would pass on a plain session-scoped
// SET, which is exactly the bug.
//
// @param t the test handle
func TestDBWithRLSSettingsAreTransactionLocal(t *testing.T) {
	db := testDB(t)
	ctx := authz.WithPrincipal(context.Background(),
		&authz.Principal{UserID: "11111111-1111-1111-1111-111111111111", Roles: []string{"member"}})

	extra := map[string]string{
		"app.org_ids": "org-a,org-b",
		"app.region":  "eu-west-1",
	}

	var seen map[string]string
	err := authz.WithRLSSettings(ctx, db, extra, func(tx orm.DB) error {
		seen = map[string]string{
			"app.org_ids": currentSetting(t, tx, "app.org_ids"),
			"app.region":  currentSetting(t, tx, "app.region"),
			"app.user_id": currentSetting(t, tx, "app.user_id"),
			"app.roles":   currentSetting(t, tx, "app.roles"),
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WithRLSSettings: %v", err)
	}

	for k, want := range map[string]string{
		"app.org_ids": "org-a,org-b",
		"app.region":  "eu-west-1",
		"app.user_id": "11111111-1111-1111-1111-111111111111",
		"app.roles":   "member",
	} {
		if seen[k] != want {
			t.Errorf("inside the transaction %s = %q, want %q", k, seen[k], want)
		}
	}

	// The assertion. Same pool, fresh query: nothing the transaction set may still be readable,
	// or the next request on this connection inherits another tenant's scope.
	for _, name := range []string{"app.org_ids", "app.region", "app.user_id", "app.roles"} {
		if got := currentSetting(t, db, name); got != "" {
			t.Errorf("%s = %q after the transaction returned — the setting outlived its transaction and leaks to the next request on this connection", name, got)
		}
	}
}

// TestDBConfigRLSSettingsReachesWithRLS @notice Config.RLSSettings is resolved per request and
// carried by Auth.WithRLS.
//
// @dev The point of the config-level form: tenancy resolution lives in one place at construction,
// so a resolver cannot forget to pass it. The hook is called with the request context, so it must
// see the caller — a hook that resolves an org from the principal is the motivating case.
//
// @param t the test handle
func TestDBConfigRLSSettingsReachesWithRLS(t *testing.T) {
	db := testDB(t)

	var sawUser string
	cfg := newTestConfig(db)
	cfg.RLSSettings = func(ctx context.Context) map[string]string {
		if p, ok := kal.From(ctx); ok {
			sawUser = p.UserID
			return map[string]string{"app.org_id": "org-" + p.UserID}
		}
		return nil
	}
	auth, err := kal.New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	ctx := authz.WithPrincipal(context.Background(), &authz.Principal{UserID: "u-42"})
	var got string
	if err := auth.WithRLS(ctx, func(tx orm.DB) error {
		got = currentSetting(t, tx, "app.org_id")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if sawUser != "u-42" {
		t.Errorf("the hook saw user %q, want u-42 — it is not receiving the request context", sawUser)
	}
	if got != "org-u-42" {
		t.Errorf("app.org_id = %q inside the transaction, want org-u-42", got)
	}

	// A nil hook must still be the plain WithRLS, or every existing deployment changes behaviour.
	plain, err := kal.New(newTestConfig(db))
	if err != nil {
		t.Fatal(err)
	}
	if err := plain.WithRLS(ctx, func(tx orm.DB) error {
		if v := currentSetting(t, tx, "app.user_id"); v != "u-42" {
			t.Errorf("app.user_id = %q without an RLSSettings hook, want u-42", v)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// TestWithRLSSettingsRejectsBadKey @notice A key that is not app.-prefixed is an error, not a
// setting nobody reads.
//
// @dev The validation is deliberately not an injection control — set_config takes its name as a
// bound parameter. It is there because the failure it prevents is silent: a typo produces a
// setting no policy reads, and a policy reading a NULL setting either matches nothing or, if it
// was written with the fail-open shape trap 4 warns about, matches everything.
//
// The assertion is on INVALID_INPUT specifically, not on the error being non-nil. The pool here
// is deliberately unreachable — proving the rejection happens before a transaction is opened —
// which means "any error" would also be satisfied by the dial failure, and the test would pass
// with the validation deleted. It did, before this was tightened.
//
// @param t the test handle
func TestWithRLSSettingsRejectsBadKey(t *testing.T) {
	db := pg.Connect(&pg.Options{Addr: "127.0.0.1:1", User: "nobody"}) // never dialled
	t.Cleanup(func() { _ = db.Close() })

	for _, key := range []string{
		"org_ids",            // no app. prefix
		"app.org; drop",      // the injection shape
		"app.Org",            // uppercase
		"app.",               // prefix only
		"search_path",        // a real GUC — set_config on it would change backend behaviour
		"app.org-ids",        // hyphen
		"app.org ids",        // space
		`app.org", true) --`, // quote-escape attempt
	} {
		t.Run(key, func(t *testing.T) {
			ran := false
			err := authz.WithRLSSettings(context.Background(), db,
				map[string]string{key: "x"}, func(orm.DB) error {
					ran = true
					return nil
				})
			var ae *kalerr.Error
			if !errors.As(err, &ae) || ae.Code != kalerr.CodeInvalidInput {
				t.Errorf("WithRLSSettings(%q): err = %v, want INVALID_INPUT", key, err)
			}
			if ran {
				t.Errorf("the callback ran despite key %q being rejected", key)
			}
		})
	}

	// The control: a well-formed key must get past validation and fail on the connection instead.
	// Without this, tightening the assertion above could be satisfied by rejecting everything.
	err := authz.WithRLSSettings(context.Background(), db,
		map[string]string{"app.org_id": "x"}, func(orm.DB) error { return nil })
	var ae *kalerr.Error
	if errors.As(err, &ae) && ae.Code == kalerr.CodeInvalidInput {
		t.Errorf("a valid key was rejected as INVALID_INPUT: %v", err)
	}
}
