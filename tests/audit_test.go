package tests

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/go-pg/pg/v10/orm"

	"github.com/ulas96/kal"
	"github.com/ulas96/kal/authn"
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

// faultDB @notice An orm.DB that fails one statement and passes everything else through.
//
// @dev Three of the seven Event kinds are emitted only when a statement fails, on paths that log
// and continue — so from out here, where nothing can reach an unexported symbol, they are
// unreachable without a driver that can be made to fail on demand. Embedding the interface rather
// than implementing its fourteen methods is what keeps this to a dozen lines, and what stops it
// rotting when go-pg adds one.
//
// The match is on statement text because that is the only thing distinguishing the write kal is
// about to make from the four reads it made to get there.
type faultDB struct {
	orm.DB
	failOn string
	err    error
}

func (f faultDB) ExecContext(c context.Context, q any, p ...any) (orm.Result, error) {
	if s, ok := q.(string); ok && strings.Contains(s, f.failOn) {
		return nil, f.err
	}
	return f.DB.ExecContext(c, q, p...)
}

func (f faultDB) QueryOneContext(c context.Context, model, q any, p ...any) (orm.Result, error) {
	if s, ok := q.(string); ok && strings.Contains(s, f.failOn) {
		return nil, f.err
	}
	return f.DB.QueryOneContext(c, model, q, p...)
}

// failingMailer @notice A Mailer that refuses everything.
type failingMailer struct{ err error }

func (m failingMailer) Send(context.Context, string, kal.Message) error { return m.err }

// TestDBAuditFailureOnlyKinds @notice The three kinds emitted only when something breaks.
//
// @dev audit.go is explicit that password.rehash, mail.fail and session.lookup.fail fire on
// failure alone, so their absence means nothing went wrong rather than nothing happened. That
// makes them the kinds most worth a test and the ones least likely to get one: every path they
// sit on logs and continues, so a missing emit changes no return value and fails no other test.
//
// Each subtest asserts both halves — the event reached the hook, and the flow still succeeded.
// Asserting only the event would pass on an implementation that emitted and then propagated the
// error, which would turn three best-effort paths into request failures.
//
// @param t the test handle
func TestDBAuditFailureOnlyKinds(t *testing.T) {
	ctx := context.Background()

	t.Run("mail.fail", func(t *testing.T) {
		db := testDB(t)
		sink := &auditSink{}
		cfg := newTestConfig(db)
		cfg.Mailer = failingMailer{err: errors.New("smtp refused the message")}
		cfg.Audit = sink.hook()
		auth, err := kal.New(cfg)
		if err != nil {
			t.Fatal(err)
		}

		// Register must still succeed: a Mailer outage cannot be allowed to fail registration,
		// which is the reason notify swallows the error in the first place.
		if err := auth.Accounts.Register(ctx, db, "mailfail@example.test", "a good long password"); err != nil {
			t.Fatalf("Register with a failing Mailer: %v", err)
		}
		got := sink.of("mail.fail")
		if len(got) != 1 {
			t.Fatalf("mail.fail events = %d, want 1", len(got))
		}
		if got[0].Email != "mailfail@example.test" {
			t.Errorf("Email = %q", got[0].Email)
		}
		if got[0].Detail["message"] != string(authn.KindVerify) {
			t.Errorf("Detail[message] = %q, want %q", got[0].Detail["message"], authn.KindVerify)
		}
		if got[0].Detail["error"] == "" {
			t.Error("mail.fail carries no error detail — the operator cannot tell why it failed")
		}
	})

	t.Run("session.lookup.fail", func(t *testing.T) {
		db := testDB(t)
		sink := &auditSink{}
		cfg := newTestConfig(db)
		cfg.Audit = sink.hook()
		auth, err := kal.New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		uid := createUser(t, db, "lookupfail@example.test")
		token, err := auth.Sessions.Issue(ctx, db, uid, session.Meta{})
		if err != nil {
			t.Fatal(err)
		}

		// The lookup is the one place a database outage silently becomes a logged-out user: the
		// middleware never returns 401, so the request proceeds anonymous and nothing downstream
		// reports it.
		broken := faultDB{DB: db, failOn: "auth_sessions", err: errors.New("connection reset")}
		var sawPrincipal bool
		h := auth.Sessions.Middleware(broken, session.MiddlewareOptions{})(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, sawPrincipal = kal.From(r.Context())
				w.WriteHeader(http.StatusOK)
			}))
		r := httptest.NewRequest(http.MethodPost, "/", nil)
		r.Header.Set("Content-Type", "application/json")
		r.AddCookie(&http.Cookie{Name: "__Host-kal_session", Value: token})
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)

		if w.Code != http.StatusOK {
			t.Errorf("a failed lookup returned %d — the middleware must never decide the request", w.Code)
		}
		if sawPrincipal {
			t.Error("a failed lookup produced a principal")
		}
		got := sink.of("session.lookup.fail")
		if len(got) != 1 {
			t.Fatalf("session.lookup.fail events = %d, want 1 — a database outage logged the user out with nothing in the audit trail", len(got))
		}
		if got[0].Detail["error"] == "" {
			t.Error("session.lookup.fail carries no error detail")
		}
	})

	t.Run("password.rehash", func(t *testing.T) {
		db := testDB(t)
		sink := &auditSink{}
		cfg := newTestConfig(db)
		cfg.Audit = sink.hook()
		auth, err := kal.New(cfg)
		if err != nil {
			t.Fatal(err)
		}

		// A hash at weaker parameters than the configured ones, so Verify asks for a rehash.
		weak, err := kal.NewHasher(kal.Params{Memory: 8192, Time: 1, KeyLen: 16}, 2)
		if err != nil {
			t.Fatal(err)
		}
		const password = "a perfectly good password"
		stored, err := weak.Hash(ctx, password)
		if err != nil {
			t.Fatal(err)
		}
		uid := createUser(t, db, "rehashfail@example.test")
		if _, err := db.Exec(`update auth_users set password_hash = ? where id = ?`, stored, uid); err != nil {
			t.Fatal(err)
		}

		// The rehash write fails; the login must not.
		broken := faultDB{DB: db, failOn: "set password_hash", err: errors.New("disk full")}
		h := auth.Middleware()(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			if _, err := auth.Accounts.Login(r.Context(), broken, "rehashfail@example.test", password); err != nil {
				t.Errorf("Login: %v — a failed rehash must not fail the login", err)
			}
		}))
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set("Content-Type", "application/json")
		h.ServeHTTP(httptest.NewRecorder(), req)

		got := sink.of("password.rehash")
		if len(got) != 1 {
			t.Fatalf("password.rehash events = %d, want 1 — the account is still on the weaker hash and nothing recorded it", len(got))
		}
		if got[0].UserID != uid {
			t.Errorf("UserID = %q, want %q", got[0].UserID, uid)
		}
		if got[0].Detail["error"] == "" {
			t.Error("password.rehash carries no error detail")
		}
	})
}

// TestDBAuditRemainingDetail @notice The two attributed shapes the login and revocation tests
// leave uncovered.
//
// @dev Both are Detail keys a consumer would key an alert on: "logged in after N failures" and
// "every session of one user died at once". A Detail map is the easiest thing in this design to
// drop in a refactor, because nothing else reads it.
//
// @param t the test handle
func TestDBAuditRemainingDetail(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	sink := &auditSink{}
	cfg := newTestConfig(db)
	cfg.Audit = sink.hook()
	auth, err := kal.New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("login.fail carries the unverified reason", func(t *testing.T) {
		const addr = "unverified@example.test"
		const password = "a perfectly good password"
		if err := auth.Accounts.Register(ctx, db, addr, password); err != nil {
			t.Fatal(err)
		}
		// The correct password against an unverified account: the one login.fail branch that is
		// not a credential failure at all, and the only one whose reason a consumer can act on.
		if _, err := auth.Accounts.Login(ctx, db, addr, password); err == nil {
			t.Fatal("an unverified account logged in")
		}
		got := sink.of("login.fail")
		if len(got) != 1 {
			t.Fatalf("login.fail events = %d, want 1", len(got))
		}
		if got[0].Detail["reason"] != "unverified" {
			t.Errorf("Detail[reason] = %q, want unverified", got[0].Detail["reason"])
		}
		if got[0].UserID == "" {
			t.Error("the unverified branch resolved the account but did not attribute it")
		}
	})

	t.Run("session.revoked carries the scope and count", func(t *testing.T) {
		uid := createUser(t, db, "revokeall@example.test")
		for range 2 {
			if _, err := auth.Sessions.Issue(ctx, db, uid, session.Meta{}); err != nil {
				t.Fatal(err)
			}
		}
		before := len(sink.of("session.revoked"))
		if err := auth.Sessions.RevokeAllForUser(ctx, db, uid); err != nil {
			t.Fatal(err)
		}
		got := sink.of("session.revoked")
		if len(got) != before+1 {
			t.Fatalf("session.revoked events = %d, want %d — one event for the whole sweep", len(got), before+1)
		}
		last := got[len(got)-1]
		if last.UserID != uid {
			t.Errorf("UserID = %q, want %q", last.UserID, uid)
		}
		if last.Detail["scope"] != "all" {
			t.Errorf("Detail[scope] = %q, want all", last.Detail["scope"])
		}
		if last.Detail["count"] != "2" {
			t.Errorf("Detail[count] = %q, want 2", last.Detail["count"])
		}

		// A sweep that killed nothing must stay silent, the same rule Revoke follows.
		after := len(sink.of("session.revoked"))
		if err := auth.Sessions.RevokeAllForUser(ctx, db, uid); err != nil {
			t.Fatal(err)
		}
		if len(sink.of("session.revoked")) != after {
			t.Error("revoking an already-empty session set emitted an event")
		}
	})
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
