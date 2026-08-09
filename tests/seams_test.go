package tests

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/99designs/gqlgen/graphql"
	"github.com/go-pg/pg/v10"

	"github.com/ulas96/kal"
	"github.com/ulas96/kal/authn"
	"github.com/ulas96/kal/authz"
	"github.com/ulas96/kal/session"
)

// TestConfigProofsSeam @notice Config.Proofs reaches the @auth(proves:) check, and a nil one
// denies.
//
// @dev The seam a proof module plugs into, exercised with a stub rather than a real one — kal
// deliberately knows nothing about proofs, so a test that needed a proof module to prove the
// wiring would be testing the wrong module. Both halves matter: the positive shows the field is
// actually read, and the negative is the property an installed schema depends on. A future reader
// deciding an unset optional should default to permissive fails here.
//
// @param t the test handle
func TestConfigProofsSeam(t *testing.T) {
	db := pg.Connect(&pg.Options{Addr: "127.0.0.1:1", User: "nobody"}) // never dialled
	t.Cleanup(func() { _ = db.Close() })

	ctx := authz.WithPrincipal(context.Background(), &authz.Principal{UserID: "u"})
	next := func(context.Context) (any, error) { return "ok", nil }

	t.Run("an unset Proofs denies a non-empty proves requirement", func(t *testing.T) {
		auth, err := kal.New(newTestConfig(db))
		if err != nil {
			t.Fatal(err)
		}
		ran := false
		counting := func(context.Context) (any, error) { ran = true; return "ok", nil }
		if _, err := auth.Directive()(ctx, nil, graphql.Resolver(counting), kal.LevelAuthenticated,
			nil, nil, []string{"member"}); err == nil {
			t.Error("a proves: requirement resolved with no proof module wired")
		}
		if ran {
			t.Error("the resolver ran behind an unsatisfied proves:")
		}
	})

	t.Run("Config.Proofs is the value the directive calls", func(t *testing.T) {
		var got []string
		cfg := newTestConfig(db)
		cfg.Proofs = func(_ context.Context, claims []string) error {
			got = append(got, claims...)
			return nil
		}
		auth, err := kal.New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := auth.Directive()(ctx, nil, graphql.Resolver(next), kal.LevelAuthenticated,
			nil, nil, []string{"member", "age_over_18"}); err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 || got[0] != "member" || got[1] != "age_over_18" {
			t.Errorf("Config.Proofs received %v, want the two claim names in order", got)
		}
	})
}

// TestDefaultSensitiveFields @notice The defaults are readable and the copy is a copy.
//
// @dev Config.SensitiveFields replaces rather than extends, so a deployment adding one name of
// its own drops kal's entire list. This exists so appending is possible without restating it. The
// copy half is not decoration: a caller who appends to a shared backing array writes into kal's
// own defaults for every other instance in the process, and the symptom is a guard that protects
// a different set of fields than the source says it does.
//
// @param t the test handle
func TestDefaultSensitiveFields(t *testing.T) {
	first := kal.DefaultSensitiveFields()
	if len(first) == 0 {
		t.Fatal("DefaultSensitiveFields is empty")
	}
	for _, want := range []string{"login", "register", "changePassword"} {
		found := false
		for _, f := range first {
			if f == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("the defaults do not protect %q", want)
		}
	}

	first[0] = "clobbered"
	second := kal.DefaultSensitiveFields()
	if second[0] == "clobbered" {
		t.Error("DefaultSensitiveFields hands out kal's own slice — a caller's append writes through")
	}
}

// TestDBConfigExtraMiddleware @notice Index 0 is outermost, and every entry sees a resolved
// caller.
//
// @dev Both halves are the reason the field exists, and both fail silently. Reversed ordering
// still serves every request, so nothing errors and a middleware that must wrap another simply
// stops doing so. And an entry mounted *around* session.Middleware rather than inside it sees no
// Principal at all: authz.From returns not-ok, the middleware reads the caller as anonymous, and
// whatever it loads for that caller is empty — which for a claims-style middleware is an empty
// grant set that denies, and for anything else is a silent downgrade.
//
// This is DB-backed because a resolved Principal requires a real session, and the test is worth
// nothing against a synthesised one.
//
// @param t the test handle
func TestDBConfigExtraMiddleware(t *testing.T) {
	db := testDB(t)

	var order []string
	saw := map[string]bool{}
	record := func(name string) func(http.Handler) http.Handler {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				order = append(order, name)
				if _, ok := authz.From(r.Context()); ok {
					saw[name] = true
				}
				next.ServeHTTP(w, r)
			})
		}
	}

	auth, err := kal.New(kal.Config{
		DB:          db,
		BaseURL:     "https://app.example.test",
		Mailer:      &recordingMailer{},
		TableSchema: testSchema,
		Argon2:      authn.Params{Memory: 8192, Time: 1},
		ExtraMiddleware: []func(http.Handler) http.Handler{
			record("outer"), record("inner"),
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	userID := createUser(t, db, "extra-middleware@example.com")
	token, err := auth.Sessions.Issue(context.Background(), db, userID, session.Meta{})
	if err != nil {
		t.Fatal(err)
	}

	handlerRan := false
	h := auth.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerRan = true
		if _, ok := authz.From(r.Context()); !ok {
			t.Error("the wrapped handler saw no principal")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/graphql", nil)
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: session.DefaultCookieName, Value: token})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || !handlerRan {
		t.Fatalf("status = %d, handler ran = %v", rec.Code, handlerRan)
	}
	if len(order) != 2 || order[0] != "outer" || order[1] != "inner" {
		t.Errorf("entry order = %v, want [outer inner] — index 0 must be outermost", order)
	}
	if !saw["outer"] || !saw["inner"] {
		t.Errorf("resolved a principal for %v, want both — extra middleware must mount inside "+
			"session.Middleware, not around it", saw)
	}
}
