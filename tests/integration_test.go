package tests

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/99designs/gqlgen/graphql"
	"github.com/gofiber/fiber/v3"
	"github.com/ulas96/luima"
	"github.com/vektah/gqlparser/v2"
	"github.com/vektah/gqlparser/v2/ast"

	"github.com/ulas96/kal"
	"github.com/ulas96/kal/authn"
)

// fieldSchema @notice A hand-written ExecutableSchema that dispatches to one callback per
// top-level field.
//
// @dev kal's tests run no gqlgen codegen — it would drag a generate step and a nested module
// into a library that ships neither — so this implements the interface by hand. Enough to route,
// execute, and let a resolver body observe the context gqlgen handed it, which is the whole
// point of the test below.
type fieldSchema struct {
	sdl  string
	exec func(ctx context.Context, field string) error
}

func (fieldSchema) Complexity(context.Context, string, string, int, map[string]any) (int, bool) {
	return 0, false
}

func (s fieldSchema) Schema() *ast.Schema {
	return gqlparser.MustLoadSchema(&ast.Source{Name: "integration", Input: s.sdl})
}

func (s fieldSchema) Exec(context.Context) graphql.ResponseHandler {
	return func(rctx context.Context) *graphql.Response {
		field := ""
		if opCtx := graphql.GetOperationContext(rctx); opCtx != nil && opCtx.Operation != nil {
			if len(opCtx.Operation.SelectionSet) > 0 {
				if f, ok := opCtx.Operation.SelectionSet[0].(*ast.Field); ok {
					field = f.Name
				}
			}
		}
		if err := s.exec(rctx, field); err != nil {
			return graphql.ErrorResponse(rctx, "%s: %v", field, err)
		}
		return &graphql.Response{Data: []byte(`{"ok":"ok"}`)}
	}
}

// TestDBLuimaIntegration @notice kal mounted the way a consumer mounts it: through luima's own
// Config, on a real Fiber app, across all three seams luima 0.2.0 added.
//
// @dev This test could not exist before luima 0.2.0, and it proves the seams are the right
// shape rather than merely present. Each assertion below fails on 0.1.0 for a different reason:
//
//   - HTTPMiddleware must deliver a context the resolver actually sees. Before, the adaptor
//     handed gqlgen the raw *fasthttp.RequestCtx, so everything a middleware attached with
//     r.WithContext was silently discarded — the principal would resolve and then vanish.
//   - A Set-Cookie written by kal's jar must survive back through the adaptor, or login succeeds
//     server-side and the browser never receives a session.
//   - Configure must reach the built handler, or the anti-batching guard is never registered.
//
// @param t the test handle
func TestDBLuimaIntegration(t *testing.T) {
	db := testDB(t)
	auth, err := kal.New(kal.Config{
		DB:          db,
		BaseURL:     "https://app.example.test",
		Mailer:      &recordingMailer{},
		TableSchema: testSchema,
		Argon2:      authn.Params{Memory: 8192, Time: 1},
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	const email, password = "integration@example.com", "a password worth using"
	if err := auth.Accounts.Register(ctx, db, email, password); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`update auth_users set email_verified = true`); err != nil {
		t.Fatal(err)
	}

	var seen *kal.Principal
	var hadDeadline bool
	app := fiber.New()
	luima.Mount(app, luima.Config{
		Schema: fieldSchema{
			sdl: `type Query { me: String } type Mutation { login: String logout: String }`,
			exec: func(rctx context.Context, field string) error {
				switch field {
				case "login":
					_, err := auth.Accounts.Login(rctx, db, email, password)
					return err
				case "logout":
					return auth.Accounts.Logout(rctx, db)
				default:
					seen, _ = kal.From(rctx)
					_, hadDeadline = rctx.Deadline()
					return nil
				}
			},
		},
		HTTPMiddleware:    []func(http.Handler) http.Handler{auth.Middleware()},
		Configure:         auth.Configure(),
		ErrorPresenter:    kal.PresentError,
		DisablePlayground: true,
	})

	post := func(t *testing.T, query, cookie string) (*http.Response, string) {
		t.Helper()
		body, err := json.Marshal(map[string]string{"query": query})
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		if cookie != "" {
			req.AddCookie(&http.Cookie{Name: "__Host-kal_session", Value: cookie})
		}
		res, err := app.Test(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		out, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatal(err)
		}
		return res, string(out)
	}

	var token string

	t.Run("the login cookie survives the adaptor", func(t *testing.T) {
		res, body := post(t, `mutation { login }`, "")
		if strings.Contains(body, `"errors"`) {
			t.Fatalf("login failed: %s", body)
		}
		for _, c := range res.Cookies() {
			if c.Name == "__Host-kal_session" {
				token = c.Value
			}
		}
		if token == "" {
			t.Fatal("no session cookie reached the client — the jar's Set-Cookie did not survive fasthttpadaptor")
		}
		// The attributes must survive too, or a browser rejects a __Host- cookie outright.
		sc := res.Header.Get("Set-Cookie")
		for _, want := range []string{"Path=/", "Secure", "HttpOnly", "SameSite=Lax"} {
			if !strings.Contains(sc, want) {
				t.Errorf("Set-Cookie = %q, missing %s", sc, want)
			}
		}
		if strings.Contains(sc, "Domain=") {
			t.Errorf("Set-Cookie = %q carries Domain, which voids the __Host- prefix", sc)
		}
	})

	t.Run("the resolver sees the principal and a deadline", func(t *testing.T) {
		seen, hadDeadline = nil, false
		if _, body := post(t, `query { me }`, token); strings.Contains(body, `"errors"`) {
			t.Fatalf("query failed: %s", body)
		}
		if seen == nil {
			t.Fatal("the resolver saw no principal — HTTPMiddleware's context did not reach gqlgen")
		}
		if seen.Email != email {
			t.Errorf("principal = %+v", seen)
		}
		// luima 0.2.0's RequestTimeout. Without it the context never cancels, so a client
		// hang-up cannot stop a query and no middleware can impose a bound.
		if !hadDeadline {
			t.Error("the resolver context carries no deadline")
		}
	})

	t.Run("Configure registered the guard", func(t *testing.T) {
		if _, body := post(t, `mutation { a: login b: login }`, ""); !strings.Contains(body, "only once per document") {
			t.Errorf("the aliasing guard did not run: %s", body)
		}
	})

	t.Run("the transport guard rejects a cross-site shape", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(`{"query":"query { me }"}`))
		req.Header.Set("Content-Type", "text/plain")
		res, err := app.Test(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusForbidden {
			t.Errorf("status = %d, want 403", res.StatusCode)
		}
	})

	t.Run("logout makes the next request anonymous", func(t *testing.T) {
		if _, body := post(t, `mutation { logout }`, token); strings.Contains(body, `"errors"`) {
			t.Fatalf("logout failed: %s", body)
		}
		seen = nil
		if _, body := post(t, `query { me }`, token); strings.Contains(body, `"errors"`) {
			t.Fatalf("query after logout failed: %s", body)
		}
		if seen != nil {
			t.Error("the revoked session still resolved")
		}
	})
}
