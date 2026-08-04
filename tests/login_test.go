package tests

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-pg/pg/v10"

	"github.com/ulas96/kal/authn"
	"github.com/ulas96/kal/authz"
	"github.com/ulas96/kal/kalerr"
	"github.com/ulas96/kal/session"
)

// recordingMailer @notice A Mailer that keeps what it was asked to send, so a test can assert
// on the branch taken rather than on the response alone.
//
// @dev The mutex matters: the notification paths are called from whatever goroutine the flow
// runs on, and the enumeration test drives two flows concurrently.
type recordingMailer struct {
	mu   sync.Mutex
	sent []sentMail
}

type sentMail struct {
	to  string
	msg authn.Message
}

func (m *recordingMailer) Send(_ context.Context, to string, msg authn.Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, sentMail{to: to, msg: msg})
	return nil
}

func (m *recordingMailer) take() []sentMail {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := m.sent
	m.sent = nil
	return out
}

// kinds @notice The kinds recorded so far, sorted, for a stable comparison.
func (m *recordingMailer) kinds() []string {
	var out []string
	for _, s := range m.take() {
		out = append(out, string(s.msg.Kind))
	}
	sort.Strings(out)
	return out
}

// authnFixture @notice A wired Accounts plus the pieces a test needs to drive it through the
// middleware, which is where Login expects to run.
type authnFixture struct {
	db       *pg.DB
	accounts *authn.Accounts
	sessions *session.Sessions
	mailer   *recordingMailer

	// lastErr @notice What the last request's resolver returned. ServeHTTP has nowhere to put
	// an error, so the fixture carries it out.
	lastErr error
}

// newAuthnFixture @notice Builds the fixture against the scratch schema.
//
// @dev Deliberately cheap Argon2 parameters: these tests exercise flow, not cost, and the
// pinned production parameters are asserted in password_test.go. At m=19456 the login tests
// would spend most of their wall clock hashing.
func newAuthnFixture(t *testing.T) *authnFixture {
	t.Helper()
	db := testDB(t)
	h, err := authn.NewHasher(authn.Params{Memory: 8192, Time: 1}, 0)
	if err != nil {
		t.Fatal(err)
	}
	s, err := session.NewSessions(session.Options{Schema: testSchema})
	if err != nil {
		t.Fatal(err)
	}
	m := &recordingMailer{}
	a, err := authn.NewAccounts(authn.AccountsOptions{
		Hasher: h, Sessions: s, Mailer: m, Schema: testSchema,
		BaseURL: "https://app.example.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	return &authnFixture{db: db, accounts: a, sessions: s, mailer: m}
}

// userID @notice The id of an account by address, for tests that need to reach past the flows.
func (f *authnFixture) userID(t *testing.T, email string) string {
	t.Helper()
	var id string
	if _, err := f.db.QueryOne(pg.Scan(&id),
		`select id from auth_users where lower(email) = ?`, strings.ToLower(email)); err != nil {
		t.Fatal(err)
	}
	return id
}

// request @notice Runs fn as if it were a resolver: inside the session middleware, with a
// cookie jar and request attribution present.
//
// @dev Everything Login touches beyond the database — the jar, the client address — comes from
// the middleware, so a test that skips it would be testing a configuration nobody runs.
func (f *authnFixture) request(t *testing.T, cookie, ip string, fn func(ctx context.Context) error) *httptest.ResponseRecorder {
	t.Helper()
	var inner error
	h := f.sessions.Middleware(f.db, session.MiddlewareOptions{})(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			inner = fn(r.Context())
			w.WriteHeader(http.StatusOK)
		}))

	req := httptest.NewRequest(http.MethodPost, "/graphql", nil)
	req.Header.Set("Content-Type", "application/json")
	if ip != "" {
		req.RemoteAddr = ip + ":40000"
	}
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: session.DefaultCookieName, Value: cookie})
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	f.lastErr = inner
	return rec
}

// sessionCookie @notice The session token from a recorder's Set-Cookie, or "".
func sessionCookie(rec *httptest.ResponseRecorder) string {
	for _, c := range rec.Result().Cookies() {
		if c.Name == session.DefaultCookieName {
			return c.Value
		}
	}
	return ""
}

// createPasswordUser @notice A verified account with a known password, inserted directly.
func (f *authnFixture) createPasswordUser(t *testing.T, email, password string) string {
	t.Helper()
	h, err := authn.NewHasher(authn.Params{Memory: 8192, Time: 1}, 0)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := h.Hash(context.Background(), password)
	if err != nil {
		t.Fatal(err)
	}
	var id string
	if _, err := f.db.QueryOne(pg.Scan(&id),
		`insert into auth_users (email, password_hash, email_verified) values (?, ?, true) returning id`,
		strings.ToLower(email), hash); err != nil {
		t.Fatal(err)
	}
	return id
}

// TestDBLogin @notice The credential path end to end: a correct password issues a session and
// sets the cookie, every failure mode returns the identical error, and the session the request
// arrived with does not survive a new login.
//
// @param t the test handle
func TestDBLogin(t *testing.T) {
	f := newAuthnFixture(t)
	uid := f.createPasswordUser(t, "Alice@Example.com", "correct horse battery staple")

	t.Run("success issues a session and sets the cookie", func(t *testing.T) {
		var p *authz.Principal
		rec := f.request(t, "", "192.0.2.10", func(ctx context.Context) error {
			var err error
			p, err = f.accounts.Login(ctx, f.db, "alice@example.com", "correct horse battery staple")
			return err
		})
		if f.lastErr != nil {
			t.Fatalf("Login: %v", f.lastErr)
		}
		// The stored address is lowercase: kal normalises on write, so the expression index
		// is belt and braces rather than the only thing preventing a duplicate.
		if p == nil || p.UserID != uid || p.Email != "alice@example.com" {
			t.Fatalf("principal = %+v", p)
		}
		token := sessionCookie(rec)
		if token == "" {
			t.Fatal("login set no session cookie")
		}
		// The cookie is a live credential: the next request resolves as this user.
		back, err := f.sessions.Lookup(context.Background(), f.db, token)
		if err != nil || back == nil || back.UserID != uid {
			t.Errorf("the issued cookie does not resolve: %v, %v", back, err)
		}
	})

	t.Run("email matching is case-insensitive", func(t *testing.T) {
		f.request(t, "", "192.0.2.11", func(ctx context.Context) error {
			_, err := f.accounts.Login(ctx, f.db, "  ALICE@EXAMPLE.COM  ", "correct horse battery staple")
			return err
		})
		if f.lastErr != nil {
			t.Errorf("uppercase login failed: %v", f.lastErr)
		}
	})

	// The four ways login fails must be one error on the wire. A client that can tell them
	// apart can enumerate accounts; ASVS 6.3.8.
	t.Run("every failure is the same error", func(t *testing.T) {
		f.createPasswordUser(t, "unverified@example.com", "a password worth using")
		if _, err := f.db.Exec(`update auth_users set email_verified = false where email = 'unverified@example.com'`); err != nil {
			t.Fatal(err)
		}
		f.createPasswordUser(t, "disabled@example.com", "a password worth using")
		if _, err := f.db.Exec(`update auth_users set deleted_at = now() where email = 'disabled@example.com'`); err != nil {
			t.Fatal(err)
		}

		cases := []struct{ name, email, password string }{
			{"unknown account", "nobody@example.com", "a password worth using"},
			{"wrong password", "alice@example.com", "not the right password"},
			{"unverified email", "unverified@example.com", "a password worth using"},
			{"disabled account", "disabled@example.com", "a password worth using"},
		}
		var messages []string
		for i, c := range cases {
			// A distinct IP per case, so one case's failures cannot throttle the next.
			f.request(t, "", "198.51.100."+string(rune('1'+i)), func(ctx context.Context) error {
				_, err := f.accounts.Login(ctx, f.db, c.email, c.password)
				return err
			})
			var ae *kalerr.Error
			if !errors.As(f.lastErr, &ae) {
				t.Fatalf("%s: error = %v, want a *kalerr.Error", c.name, f.lastErr)
			}
			if ae.Code != kalerr.CodeInvalidCredentials {
				t.Errorf("%s: code = %s, want INVALID_CREDENTIALS", c.name, ae.Code)
			}
			messages = append(messages, ae.Message)
		}
		for i, m := range messages {
			if m != messages[0] {
				t.Errorf("%s message = %q, want byte-identical to %q", cases[i].name, m, messages[0])
			}
		}
	})

	t.Run("logging in again replaces the old session", func(t *testing.T) {
		rec := f.request(t, "", "192.0.2.20", func(ctx context.Context) error {
			_, err := f.accounts.Login(ctx, f.db, "alice@example.com", "correct horse battery staple")
			return err
		})
		first := sessionCookie(rec)
		if first == "" {
			t.Fatal("no cookie from the first login")
		}
		rec2 := f.request(t, first, "192.0.2.20", func(ctx context.Context) error {
			_, err := f.accounts.Login(ctx, f.db, "alice@example.com", "correct horse battery staple")
			return err
		})
		second := sessionCookie(rec2)
		if second == "" || second == first {
			t.Fatalf("second login returned %q (first %q) — a re-login must mint a new credential", second, first)
		}
		if p, _ := f.sessions.Lookup(context.Background(), f.db, first); p != nil {
			t.Error("the pre-login session survived the new login")
		}
	})
}

// TestDBLogout @notice Logout revokes and clears; a second logout is not an error.
//
// @param t the test handle
func TestDBLogout(t *testing.T) {
	f := newAuthnFixture(t)
	f.createPasswordUser(t, "bob@example.com", "a password worth using")

	rec := f.request(t, "", "192.0.2.30", func(ctx context.Context) error {
		_, err := f.accounts.Login(ctx, f.db, "bob@example.com", "a password worth using")
		return err
	})
	token := sessionCookie(rec)
	if token == "" {
		t.Fatal("no cookie from login")
	}

	out := f.request(t, token, "192.0.2.30", func(ctx context.Context) error {
		return f.accounts.Logout(ctx, f.db)
	})
	if f.lastErr != nil {
		t.Fatalf("Logout: %v", f.lastErr)
	}
	if sc := out.Header().Get("Set-Cookie"); !strings.Contains(sc, "Max-Age=0") {
		t.Errorf("Set-Cookie = %q, want the deletion cookie", sc)
	}
	if p, _ := f.sessions.Lookup(context.Background(), f.db, token); p != nil {
		t.Error("the session survived logout")
	}

	f.request(t, "", "192.0.2.30", func(ctx context.Context) error {
		return f.accounts.Logout(ctx, f.db)
	})
	if f.lastErr != nil {
		t.Errorf("anonymous Logout = %v, want nil", f.lastErr)
	}
}

// TestDBChangePassword @notice A change re-verifies, rotates the session rather than killing
// every device, and leaves the old password dead.
//
// @param t the test handle
func TestDBChangePassword(t *testing.T) {
	f := newAuthnFixture(t)
	f.createPasswordUser(t, "carol@example.com", "the first password")

	rec := f.request(t, "", "192.0.2.40", func(ctx context.Context) error {
		_, err := f.accounts.Login(ctx, f.db, "carol@example.com", "the first password")
		return err
	})
	token := sessionCookie(rec)
	f.mailer.take()

	t.Run("wrong current password is rejected", func(t *testing.T) {
		f.request(t, token, "192.0.2.40", func(ctx context.Context) error {
			return f.accounts.ChangePassword(ctx, f.db, "not the first password", "the second password")
		})
		var ae *kalerr.Error
		if !errors.As(f.lastErr, &ae) || ae.Code != kalerr.CodeInvalidCredentials {
			t.Errorf("error = %v, want INVALID_CREDENTIALS", f.lastErr)
		}
	})

	t.Run("policy applies to the new password", func(t *testing.T) {
		f.request(t, token, "192.0.2.40", func(ctx context.Context) error {
			return f.accounts.ChangePassword(ctx, f.db, "the first password", "short")
		})
		var ae *kalerr.Error
		if !errors.As(f.lastErr, &ae) || ae.Code != kalerr.CodeInvalidInput {
			t.Errorf("error = %v, want INVALID_INPUT", f.lastErr)
		}
	})

	t.Run("anonymous callers cannot change a password", func(t *testing.T) {
		f.request(t, "", "192.0.2.40", func(ctx context.Context) error {
			return f.accounts.ChangePassword(ctx, f.db, "the first password", "the second password")
		})
		var ae *kalerr.Error
		if !errors.As(f.lastErr, &ae) || ae.Code != kalerr.CodeUnauthenticated {
			t.Errorf("error = %v, want UNAUTHENTICATED", f.lastErr)
		}
	})

	t.Run("success rotates the session and notifies", func(t *testing.T) {
		f.mailer.take()
		out := f.request(t, token, "192.0.2.40", func(ctx context.Context) error {
			return f.accounts.ChangePassword(ctx, f.db, "the first password", "the second password")
		})
		if f.lastErr != nil {
			t.Fatalf("ChangePassword: %v", f.lastErr)
		}
		rotated := sessionCookie(out)
		if rotated == "" || rotated == token {
			t.Fatalf("cookie after change = %q (was %q) — the credential must rotate", rotated, token)
		}
		if p, _ := f.sessions.Lookup(context.Background(), f.db, token); p != nil {
			t.Error("the pre-change token still resolves")
		}
		if p, _ := f.sessions.Lookup(context.Background(), f.db, rotated); p == nil {
			t.Error("the rotated token does not resolve — the caller was logged out of their own change")
		}
		if got := f.mailer.kinds(); len(got) != 1 || got[0] != string(authn.KindPasswordChanged) {
			t.Errorf("mail kinds = %v, want [password-changed]", got)
		}

		// The old password is gone, the new one works.
		f.request(t, "", "192.0.2.41", func(ctx context.Context) error {
			_, err := f.accounts.Login(ctx, f.db, "carol@example.com", "the first password")
			return err
		})
		if f.lastErr == nil {
			t.Error("the old password still logs in")
		}
		// Clear the counters the subtests above accumulated: a correct password inside an open
		// backoff window is refused, which is the throttle working (TestDBLoginBackoff pins
		// that behaviour) and would mask what this assertion is actually about.
		if _, err := f.db.Exec(`delete from auth_login_attempts`); err != nil {
			t.Fatal(err)
		}
		f.request(t, "", "192.0.2.42", func(ctx context.Context) error {
			_, err := f.accounts.Login(ctx, f.db, "carol@example.com", "the second password")
			return err
		})
		if f.lastErr != nil {
			t.Errorf("the new password does not log in: %v", f.lastErr)
		}
	})
}

// TestDBLoginBackoff @notice The throttle: repeated failures open a reject-until window per
// account, the window is enforced before any hashing, a success clears the counters, and the
// per-IP counter catches spraying that no per-account counter can see.
//
// @param t the test handle
func TestDBLoginBackoff(t *testing.T) {
	f := newAuthnFixture(t)
	f.createPasswordUser(t, "dave@example.com", "the real password")

	fail := func(ip string) error {
		f.request(t, "", ip, func(ctx context.Context) error {
			_, err := f.accounts.Login(ctx, f.db, "dave@example.com", "a wrong password")
			return err
		})
		return f.lastErr
	}
	codeOf := func(err error) string {
		var ae *kalerr.Error
		if errors.As(err, &ae) {
			return ae.Code
		}
		return ""
	}

	// One free failure, then the curve starts.
	if got := codeOf(fail("203.0.113.10")); got != kalerr.CodeInvalidCredentials {
		t.Fatalf("first failure = %s, want INVALID_CREDENTIALS (one free retry)", got)
	}
	if got := codeOf(fail("203.0.113.10")); got != kalerr.CodeInvalidCredentials {
		t.Fatalf("second failure = %s, want INVALID_CREDENTIALS", got)
	}
	if got := codeOf(fail("203.0.113.10")); got != kalerr.CodeRateLimited {
		t.Fatalf("third failure = %s, want RATE_LIMITED", got)
	}

	// Throttled, and throttled *before* the Argon2 work: the rejection is far faster than a
	// hash. Generous margin — this asserts "no hash happened", not a latency budget.
	start := time.Now()
	if got := codeOf(fail("203.0.113.10")); got != kalerr.CodeRateLimited {
		t.Fatalf("still-throttled attempt = %s, want RATE_LIMITED", got)
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Errorf("throttled attempt took %v — the backoff is running after the hash, not before", elapsed)
	}

	// The correct password is also refused while the window is open: the throttle is on the
	// account, not on the guess.
	f.request(t, "", "203.0.113.10", func(ctx context.Context) error {
		_, err := f.accounts.Login(ctx, f.db, "dave@example.com", "the real password")
		return err
	})
	if got := codeOf(f.lastErr); got != kalerr.CodeRateLimited {
		t.Errorf("correct password inside the window = %s, want RATE_LIMITED", got)
	}

	// Age the counters out of the window; the account recovers by itself — no admin unlock,
	// which is the point of a window over a lockout.
	if _, err := f.db.Exec(`update auth_login_attempts set last_fail = now() - interval '1 hour'`); err != nil {
		t.Fatal(err)
	}
	f.request(t, "", "203.0.113.10", func(ctx context.Context) error {
		_, err := f.accounts.Login(ctx, f.db, "dave@example.com", "the real password")
		return err
	})
	if f.lastErr != nil {
		t.Fatalf("after the window expired: %v", f.lastErr)
	}

	// A success clears both counters.
	var remaining int
	if _, err := f.db.QueryOne(pg.Scan(&remaining), `select count(*) from auth_login_attempts`); err != nil {
		t.Fatal(err)
	}
	if remaining != 0 {
		t.Errorf("%d counter rows survived a successful login", remaining)
	}

	t.Run("a successful login after a streak notifies the owner", func(t *testing.T) {
		f.mailer.take()
		for i := 0; i < 3; i++ {
			_ = fail("203.0.113.20")
			if _, err := f.db.Exec(`update auth_login_attempts set last_fail = now() - interval '1 hour'`); err != nil {
				t.Fatal(err)
			}
		}
		f.request(t, "", "203.0.113.20", func(ctx context.Context) error {
			_, err := f.accounts.Login(ctx, f.db, "dave@example.com", "the real password")
			return err
		})
		if f.lastErr != nil {
			t.Fatalf("login after the streak: %v", f.lastErr)
		}
		if got := f.mailer.kinds(); len(got) != 1 || got[0] != string(authn.KindSuspiciousLogin) {
			t.Errorf("mail kinds = %v, want [suspicious-login]", got)
		}
	})

	// Credential stuffing: one attempt against each of many accounts. Every per-account
	// counter stays at one — the per-IP counter is the only thing that sees the attack.
	t.Run("per-IP counting catches spraying", func(t *testing.T) {
		const attacker = "203.0.113.99"
		for i := 0; i < 12; i++ {
			victim := "victim" + string(rune('a'+i)) + "@example.com"
			f.createPasswordUser(t, victim, "a password worth using")
			f.request(t, "", attacker, func(ctx context.Context) error {
				_, err := f.accounts.Login(ctx, f.db, victim, "guessed wrong")
				return err
			})
		}
		var maxUser int
		if _, err := f.db.QueryOne(pg.Scan(&maxUser),
			`select coalesce(max(failures), 0) from auth_login_attempts where scope = 'user'`); err != nil {
			t.Fatal(err)
		}
		if maxUser > 1 {
			t.Fatalf("a per-account counter reached %d — the spray test is not spraying", maxUser)
		}
		f.request(t, "", attacker, func(ctx context.Context) error {
			_, err := f.accounts.Login(ctx, f.db, "victima@example.com", "guessed wrong again")
			return err
		})
		if got := codeOf(f.lastErr); got != kalerr.CodeRateLimited {
			t.Errorf("spraying attempt = %s, want RATE_LIMITED from the per-IP counter", got)
		}
	})
}

// TestDBRehashOnLogin @notice A hash stored with weaker parameters is upgraded during a
// successful login — the only mechanism that raises cost without a password reset.
//
// @param t the test handle
func TestDBRehashOnLogin(t *testing.T) {
	db := testDB(t)
	weak, err := authn.NewHasher(authn.Params{Memory: 8192, Time: 1}, 0)
	if err != nil {
		t.Fatal(err)
	}
	strong, err := authn.NewHasher(authn.Params{Memory: 19456, Time: 2}, 0)
	if err != nil {
		t.Fatal(err)
	}
	s, err := session.NewSessions(session.Options{Schema: testSchema})
	if err != nil {
		t.Fatal(err)
	}
	a, err := authn.NewAccounts(authn.AccountsOptions{
		Hasher: strong, Sessions: s, Mailer: &recordingMailer{}, Schema: testSchema,
		BaseURL: "https://app.example.test",
	})
	if err != nil {
		t.Fatal(err)
	}

	old, err := weak.Hash(context.Background(), "a password worth using")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(
		`insert into auth_users (email, password_hash, email_verified) values ('eve@example.com', ?, true)`,
		old); err != nil {
		t.Fatal(err)
	}

	h := s.Middleware(db, session.MiddlewareOptions{})(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, err := a.Login(r.Context(), db, "eve@example.com", "a password worth using"); err != nil {
				t.Errorf("Login: %v", err)
			}
			w.WriteHeader(http.StatusOK)
		}))
	req := httptest.NewRequest(http.MethodPost, "/graphql", nil)
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(httptest.NewRecorder(), req)

	var stored string
	if _, err := db.QueryOne(pg.Scan(&stored),
		`select password_hash from auth_users where email = 'eve@example.com'`); err != nil {
		t.Fatal(err)
	}
	if stored == old {
		t.Fatal("the weak hash survived a successful login")
	}
	if !strings.HasPrefix(stored, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Errorf("upgraded hash = %q, want the configured parameters", stored)
	}
	// And the upgraded hash still verifies the same password.
	if ok, _, err := strong.Verify(context.Background(), "a password worth using", stored); err != nil || !ok {
		t.Errorf("the upgraded hash does not verify the password: %v, %v", ok, err)
	}
}
