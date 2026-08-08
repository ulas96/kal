package tests

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/ulas96/kal"
	"github.com/ulas96/kal/authz"
	"github.com/ulas96/kal/session"
)

// auditSink @notice Collects events, safe for the concurrent emit the middleware does.
type auditSink struct {
	mu     sync.Mutex
	events []kal.Event
}

func (s *auditSink) hook() kal.Audit {
	return func(_ context.Context, e kal.Event) {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.events = append(s.events, e)
	}
}

// of @notice Every recorded event of one kind.
func (s *auditSink) of(kind string) []kal.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []kal.Event
	for _, e := range s.events {
		if e.Kind == kind {
			out = append(out, e)
		}
	}
	return out
}

// TestAuditNilIsSafe @notice The zero Config emits nothing and panics on nothing.
//
// @dev The test that matters most, and the reason Audit.Emit owns the nil check rather than each
// call site: a nil hook must be free everywhere, and "free" is not something a reviewer can see
// by reading eight emit sites. This drives the credential flows that carry emit calls with no
// hook configured at all, so a site that dereferenced a nil Audit would panic here.
//
// @param t the test handle
func TestDBAuditNilIsSafe(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()

	var cfg kal.Config
	if cfg.Audit != nil {
		t.Fatal("the zero Config has an audit hook")
	}

	auth, err := kal.New(newTestConfig(db)) // no Audit set
	if err != nil {
		t.Fatal(err)
	}

	// Every path that emits, with the hook nil.
	if err := auth.Accounts.Register(ctx, db, "nilaudit@example.test", "a good long password"); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.Accounts.Login(ctx, db, "nilaudit@example.test", "wrong password entirely"); err == nil {
		t.Error("login with a wrong password succeeded")
	}
	uid := createUser(t, db, "nilaudit2@example.test")
	token, err := auth.Sessions.Issue(ctx, db, uid, session.Meta{})
	if err != nil {
		t.Fatal(err)
	}
	p, err := auth.Sessions.Lookup(ctx, db, token)
	if err != nil || p == nil {
		t.Fatalf("Lookup: %v, %v", p, err)
	}
	if err := auth.Sessions.Revoke(ctx, db, p.SessionID); err != nil {
		t.Fatal(err)
	}
	if err := auth.Sessions.RevokeAllForUser(ctx, db, uid); err != nil {
		t.Fatal(err)
	}

	// And through the middleware, where the lookup-failure emit lives.
	h := auth.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.Header.Set("Content-Type", "application/json")
	r.AddCookie(&http.Cookie{Name: "__Host-kal_session", Value: token})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("middleware with a nil audit hook returned %d", w.Code)
	}
}

// TestDBAuditHookReceivesLogin @notice Login success and failure reach the hook, attributed.
//
// @dev Asserting on the lowercased Email because the hook is what a consumer writes to an audit
// row, and a trail that records Alice@x.com and alice@x.com as two subjects is a trail nobody can
// query. Login lowercases on the way in; this pins that the event carries the same form.
//
// The failure event deliberately carries no UserID on the unknown-account branch: telling a
// deployment's own audit trail apart from an enumeration oracle is easy, but resolving the
// address to say "no such user" would mean doing the lookup the identical-error-text defence
// exists to avoid mattering.
//
// @param t the test handle
func TestDBAuditHookReceivesLogin(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()

	sink := &auditSink{}
	cfg := newTestConfig(db)
	cfg.Audit = sink.hook()
	auth, err := kal.New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	const addr = "Audited@Example.test"
	const password = "a perfectly good password"
	if err := auth.Accounts.Register(ctx, db, addr, password); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`update auth_users set email_verified = true where lower(email) = ?`,
		strings.ToLower(addr)); err != nil {
		t.Fatal(err)
	}

	t.Run("a wrong password", func(t *testing.T) {
		if _, err := auth.Accounts.Login(ctx, db, addr, "not the password"); err == nil {
			t.Fatal("login succeeded with a wrong password")
		}
		got := sink.of("login.fail")
		if len(got) != 1 {
			t.Fatalf("login.fail events = %d, want 1", len(got))
		}
		if got[0].Email != strings.ToLower(addr) {
			t.Errorf("Email = %q, want the lowercased form", got[0].Email)
		}
		if got[0].At.IsZero() {
			t.Error("At is zero — Emit did not default it")
		}
		if got[0].UserID == "" {
			t.Error("a wrong password on a known account should attribute the user")
		}
	})

	t.Run("an unknown account", func(t *testing.T) {
		before := len(sink.of("login.fail"))
		if _, err := auth.Accounts.Login(ctx, db, "nobody@example.test", "irrelevant"); err == nil {
			t.Fatal("login succeeded for an unknown account")
		}
		got := sink.of("login.fail")
		if len(got) != before+1 {
			t.Fatalf("login.fail events = %d, want %d", len(got), before+1)
		}
		if last := got[len(got)-1]; last.UserID != "" {
			t.Errorf("UserID = %q for an unknown account — the audit trail must not resolve it", last.UserID)
		}
	})

	t.Run("a success", func(t *testing.T) {
		// Through the middleware: Login sets a cookie, which needs the jar on the context.
		var loginErr error
		h := auth.Middleware()(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			_, loginErr = auth.Accounts.Login(r.Context(), db, addr, password)
		}))
		r := httptest.NewRequest(http.MethodPost, "/", nil)
		r.Header.Set("Content-Type", "application/json")
		h.ServeHTTP(httptest.NewRecorder(), r)
		if loginErr != nil {
			t.Fatalf("Login: %v", loginErr)
		}

		got := sink.of("login.ok")
		if len(got) != 1 {
			t.Fatalf("login.ok events = %d, want 1", len(got))
		}
		if got[0].Email != strings.ToLower(addr) {
			t.Errorf("Email = %q, want the lowercased form", got[0].Email)
		}
		if got[0].UserID == "" {
			t.Error("login.ok carries no UserID")
		}
	})

	t.Run("session revocation", func(t *testing.T) {
		uid := createUser(t, db, "revoked@example.test")
		token, err := auth.Sessions.Issue(ctx, db, uid, session.Meta{})
		if err != nil {
			t.Fatal(err)
		}
		p, err := auth.Sessions.Lookup(ctx, db, token)
		if err != nil || p == nil {
			t.Fatalf("Lookup: %v, %v", p, err)
		}
		before := len(sink.of("session.revoked"))
		if err := auth.Sessions.Revoke(ctx, db, p.SessionID); err != nil {
			t.Fatal(err)
		}
		if got := sink.of("session.revoked"); len(got) != before+1 {
			t.Fatalf("session.revoked events = %d, want %d", len(got), before+1)
		}
		// Idempotent revocation must not emit again, or the trail records a revocation that did
		// not happen every time a client logs out twice.
		after := len(sink.of("session.revoked"))
		if err := auth.Sessions.Revoke(ctx, db, p.SessionID); err != nil {
			t.Fatal(err)
		}
		if got := sink.of("session.revoked"); len(got) != after {
			t.Errorf("revoking an already-revoked session emitted an event")
		}
	})
}

// TestDBAuditBackoffOpen @notice The backoff window opening is visible to the consumer.
//
// @dev The event kal is uniquely placed to emit: the throttle rejects before any hashing and
// before any resolver runs, so a consumer counting failed logins in their own resolvers sees
// nothing at all once the window is open. Which counter fired is in Detail because the ip scope
// is the spraying signal the per-account counter structurally cannot see.
//
// @param t the test handle
func TestDBAuditBackoffOpen(t *testing.T) {
	db := testDB(t)

	sink := &auditSink{}
	cfg := newTestConfig(db)
	cfg.Audit = sink.hook()
	auth, err := kal.New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	const addr = "backoff@example.test"
	createUser(t, db, addr)

	// Past userFreeFailures, then one more attempt to meet the closed window.
	h := auth.Middleware()(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		for range 4 {
			_, _ = auth.Accounts.Login(r.Context(), db, addr, "wrong")
		}
	}))
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(httptest.NewRecorder(), req)

	got := sink.of("backoff.open")
	if len(got) == 0 {
		t.Fatal("the backoff window opened and nothing reached the audit hook")
	}
	if got[0].Detail["scope"] == "" || got[0].Detail["failures"] == "" {
		t.Errorf("backoff.open carries no scope/failures detail: %+v", got[0].Detail)
	}
	if got[0].Email != addr {
		t.Errorf("Email = %q, want %q", got[0].Email, addr)
	}
}

// TestAuditEmitDefaultsAt @notice A zero At is filled once, centrally.
//
// @dev At defaults in Emit rather than at each site, which is what stops half the events arriving
// with a zero time — and a caller that sets it explicitly must keep it, because a consumer
// replaying a backlog through the hook is setting the original time on purpose.
//
// @param t the test handle
func TestAuditEmitDefaultsAt(t *testing.T) {
	var got []authz.Event
	hook := authz.Audit(func(_ context.Context, e authz.Event) { got = append(got, e) })

	hook.Emit(context.Background(), authz.Event{Kind: "test.zero"})
	fixed := got[0].At.Add(-1000)
	hook.Emit(context.Background(), authz.Event{Kind: "test.set", At: fixed})

	if got[0].At.IsZero() {
		t.Error("Emit did not default a zero At")
	}
	if !got[1].At.Equal(fixed) {
		t.Errorf("Emit overwrote an explicit At: %v, want %v", got[1].At, fixed)
	}

	// And nil must be free rather than a panic.
	var nilHook authz.Audit
	nilHook.Emit(context.Background(), authz.Event{Kind: "test.nil"})
}
