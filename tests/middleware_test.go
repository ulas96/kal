package tests

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/ulas96/kal/authz"
	"github.com/ulas96/kal/session"
)

// TestTransportGuard @notice The CSRF matrix: every CORS-simple shape is blocked, everything
// that would force a preflight passes, and OPTIONS always reaches the handler.
//
// @dev db is nil on purpose — no request here carries a cookie, so the middleware must not
// touch the database at all.
//
// @param t the test handle
func TestTransportGuard(t *testing.T) {
	s, err := session.NewSessions(session.Options{})
	if err != nil {
		t.Fatal(err)
	}
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	h := s.Middleware(nil, session.MiddlewareOptions{})(inner)

	cases := []struct {
		name, method, contentType, header string
		want                              int
	}{
		{"json POST passes", "POST", "application/json", "", 200},
		{"json with charset passes", "POST", "application/json; charset=utf-8", "", 200},
		{"text/plain blocked", "POST", "text/plain", "", 403},
		{"urlencoded blocked", "POST", "application/x-www-form-urlencoded", "", 403},
		{"multipart blocked", "POST", "multipart/form-data; boundary=x", "", 403},
		{"bare GET blocked", "GET", "", "", 403},
		{"GET with X-Kal-Operation passes", "GET", "", "X-Kal-Operation", 200},
		{"text/plain with X-Requested-With passes", "POST", "text/plain", "X-Requested-With", 200},
		{"OPTIONS always passes", "OPTIONS", "", "", 200},
		{"unparseable content-type blocked", "POST", ";;;", "", 403},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(c.method, "/graphql", nil)
			if c.contentType != "" {
				req.Header.Set("Content-Type", c.contentType)
			}
			if c.header != "" {
				req.Header.Set(c.header, "1")
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != c.want {
				t.Errorf("%s %q header=%q → %d, want %d", c.method, c.contentType, c.header, rec.Code, c.want)
			}
			if c.want == 403 && !strings.Contains(rec.Body.String(), `"errors"`) {
				t.Errorf("blocked response is not GraphQL-shaped: %s", rec.Body.String())
			}
		})
	}
}

// TestSessionCookieAttributes @notice The Set-Cookie line, attribute by attribute: __Host-
// name, Path=/, Secure, HttpOnly, SameSite=Lax — and no Domain, no Max-Age, no Expires.
//
// @dev The banned list is as load-bearing as the required one: a Domain attribute would make
// the browser reject the __Host- cookie outright, and a Max-Age would hand lifetime decisions
// to an attribute the server cannot revoke.
//
// @param t the test handle
func TestSessionCookieAttributes(t *testing.T) {
	s, err := session.NewSessions(session.Options{})
	if err != nil {
		t.Fatal(err)
	}
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := session.SetCookie(r.Context(), session.Cookie(session.DefaultCookieName, "tok-value")); err != nil {
			t.Error(err)
		}
		w.WriteHeader(http.StatusOK)
	})
	h := s.Middleware(nil, session.MiddlewareOptions{})(inner)

	req := httptest.NewRequest(http.MethodPost, "/graphql", nil)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	sc := rec.Header().Get("Set-Cookie")
	for _, want := range []string{"__Host-kal_session=tok-value", "Path=/", "Secure", "HttpOnly", "SameSite=Lax"} {
		if !strings.Contains(sc, want) {
			t.Errorf("Set-Cookie = %q, missing %s", sc, want)
		}
	}
	for _, banned := range []string{"Domain=", "Max-Age=", "Expires="} {
		if strings.Contains(sc, banned) {
			t.Errorf("Set-Cookie = %q, must not carry %s", sc, banned)
		}
	}
}

// TestCookieJarFlushOnce @notice Eight goroutines add cookies, the handler writes twice and
// sets a status — every cookie arrives exactly once, ahead of the chosen status code.
//
// @param t the test handle
func TestCookieJarFlushOnce(t *testing.T) {
	s, err := session.NewSessions(session.Options{})
	if err != nil {
		t.Fatal(err)
	}
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				if err := session.SetCookie(r.Context(), session.Cookie(fmt.Sprintf("c%d", i), "v")); err != nil {
					t.Error(err)
				}
			}(i)
		}
		wg.Wait()
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("a"))
		_, _ = w.Write([]byte("b")) // a second Write must not re-flush
	})
	h := s.Middleware(nil, session.MiddlewareOptions{})(inner)

	req := httptest.NewRequest(http.MethodPost, "/graphql", nil)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Errorf("status = %d — the flush swallowed WriteHeader", rec.Code)
	}
	if got := len(rec.Header().Values("Set-Cookie")); got != 8 {
		t.Errorf("Set-Cookie count = %d, want exactly 8", got)
	}
}

// TestSetCookieWithoutMiddleware @notice A missing middleware is a loud server-side error, not
// a silently dropped cookie.
//
// @param t the test handle
func TestSetCookieWithoutMiddleware(t *testing.T) {
	if err := session.SetCookie(context.Background(), session.Cookie("x", "y")); err == nil {
		t.Error("SetCookie without the middleware returned nil — the cookie went nowhere, silently")
	}
}

// TestDBMiddleware @notice The resolution paths against a real store: a valid cookie becomes a
// Principal, a garbage cookie becomes anonymous plus a deletion Set-Cookie, no cookie stays
// anonymous and untouched — and the response is 200 in all three, because the middleware never
// 401s.
//
// @param t the test handle
func TestDBMiddleware(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	s, err := session.NewSessions(session.Options{Schema: testSchema})
	if err != nil {
		t.Fatal(err)
	}
	uid := createUser(t, db, "mw@example.com")
	token, err := s.Issue(ctx, db, uid, session.Meta{})
	if err != nil {
		t.Fatal(err)
	}

	var got *authz.Principal
	var gotMeta session.Meta
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = authz.From(r.Context())
		gotMeta = session.MetaFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	h := s.Middleware(db, session.MiddlewareOptions{})(inner)

	do := func(cookie string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/graphql", nil)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "tests/1.0")
		if cookie != "" {
			req.AddCookie(&http.Cookie{Name: session.DefaultCookieName, Value: cookie})
		}
		rec := httptest.NewRecorder()
		got, gotMeta = nil, session.Meta{}
		h.ServeHTTP(rec, req)
		return rec
	}

	t.Run("valid cookie resolves to the principal", func(t *testing.T) {
		rec := do(token)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d", rec.Code)
		}
		if got == nil || got.UserID != uid || got.Email != "mw@example.com" {
			t.Errorf("principal = %+v", got)
		}
		if sc := rec.Header().Get("Set-Cookie"); sc != "" {
			t.Errorf("a healthy session triggered Set-Cookie: %q", sc)
		}
		if gotMeta.IP != "192.0.2.1" || gotMeta.UserAgent != "tests/1.0" {
			t.Errorf("meta = %+v — RemoteAddr host and UA should be recorded", gotMeta)
		}
	})

	t.Run("garbage cookie proceeds anonymous and clears", func(t *testing.T) {
		rec := do("utterly-invalid-token")
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d — an invalid token must not be an error", rec.Code)
		}
		if got != nil {
			t.Errorf("principal = %+v, want anonymous", got)
		}
		sc := rec.Header().Get("Set-Cookie")
		if !strings.Contains(sc, session.DefaultCookieName+"=;") || !strings.Contains(sc, "Max-Age=0") {
			t.Errorf("Set-Cookie = %q, want the deletion cookie", sc)
		}
		if !strings.Contains(sc, "Secure") || !strings.Contains(sc, "Path=/") {
			t.Errorf("deletion cookie %q lacks __Host- attributes — the browser will ignore it", sc)
		}
	})

	t.Run("no cookie stays anonymous, nothing cleared", func(t *testing.T) {
		rec := do("")
		if rec.Code != http.StatusOK || got != nil {
			t.Errorf("status=%d principal=%+v", rec.Code, got)
		}
		if sc := rec.Header().Get("Set-Cookie"); sc != "" {
			t.Errorf("no-cookie request triggered Set-Cookie: %q", sc)
		}
	})

	t.Run("revocation makes the next request anonymous", func(t *testing.T) {
		fresh, err := s.Issue(ctx, db, uid, session.Meta{})
		if err != nil {
			t.Fatal(err)
		}
		if rec := do(fresh); rec.Code != http.StatusOK || got == nil {
			t.Fatal("fresh session did not resolve")
		}
		if err := s.Revoke(ctx, db, got.SessionID); err != nil {
			t.Fatal(err)
		}
		if rec := do(fresh); rec.Code != http.StatusOK || got != nil {
			t.Errorf("after Revoke: status=%d principal=%+v — revocation must land on the very next request", rec.Code, got)
		}
	})
}
