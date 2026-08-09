package tests

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/99designs/gqlgen/graphql"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	"github.com/go-pg/pg/v10"
	"github.com/go-pg/pg/v10/orm"
	"github.com/ulas96/luima"
	"github.com/vektah/gqlparser/v2"
	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/gqlerror"

	"github.com/ulas96/kal"
	"github.com/ulas96/kal/authn"
	"github.com/ulas96/kal/authz"
	"github.com/ulas96/kal/e2ee"
	"github.com/ulas96/kal/kalerr"
	"github.com/ulas96/kal/session"
)

// The root package re-exports six sub-packages, so the thing worth asserting is that the two
// spellings are genuinely interchangeable rather than merely similar.
var (
	// Aliases, not definitions: were these `type Principal authz.Principal`, the round trip
	// below would not compile and a consumer could not pass one to the other's functions.
	_ authz.Principal = kal.Principal{}
	_ kal.Principal   = authz.Principal{}
	_ *kalerr.Error   = &kal.Error{}
	_ *kal.Error      = &kalerr.Error{}
	_ authz.AuthLevel = kal.LevelAuthenticated
	_ kal.AuthLevel   = authz.LevelAnonymous
	_ authn.Params    = kal.Params{}
	_ kal.Params      = authn.Params{}
	_ authn.Hasher    = kal.Hasher{}
	_ kal.Hasher      = authn.Hasher{}
	_ authz.Event     = kal.Event{}
	_ kal.Event       = authz.Event{}
	_ authz.Audit     = kal.Audit(nil)
	_ kal.Audit       = authz.Audit(nil)
	_ session.Info    = kal.SessionInfo{}
	_ kal.SessionInfo = session.Info{}
	_ authn.Message   = kal.Message{}
	_ kal.Message     = authn.Message{}
	_ authn.LogMailer = kal.LogMailer{}
	_ kal.Mailer      = authn.LogMailer{}
	_ authn.Mailer    = kal.LogMailer{}

	// The wrappers must instantiate to exactly the sub-package signature. Assigning both to one
	// typed var is the compile-time assertion — funcs cannot be compared to each other.
	_, _ fromFn        = kal.From, authz.From
	_, _ requireFn     = kal.Require, authz.Require
	_, _ hasRoleFn     = kal.HasRole, authz.HasRole
	_, _ scopeFn       = kal.Scope, authz.Scope
	_, _ coverageFn    = kal.AssertAuthCoverage, authz.AssertAuthCoverage
	_, _ wiredFn       = kal.AssertDirectivesWired, authz.AssertDirectivesWired
	_, _ presentFn     = kal.PresentError, kalerr.PresentError
	_, _ validateFn    = kal.ValidatePassword, authn.ValidatePassword
	_, _ newHasherFn   = kal.NewHasher, authn.NewHasher
	_, _ rlsSettingsFn = kal.WithRLSSettings, authz.WithRLSSettings

	// The e2ee surface. kal.VaultParams is the renamed one — kal.Params is authn's Argon2id cost,
	// and the two answer to entirely different limits, so the collision is resolved by renaming
	// rather than by hoping nobody passes one where the other belongs.
	_ e2ee.Params      = kal.VaultParams{}
	_ kal.VaultParams  = e2ee.Params{}
	_ e2ee.Options     = kal.VaultOptions{}
	_ kal.VaultOptions = e2ee.Options{}
	_ e2ee.Vault       = kal.Vault{}
	_ kal.Vault        = e2ee.Vault{}
	_ *e2ee.Vaults     = &kal.Vaults{}
	_ *kal.Vaults      = &e2ee.Vaults{}

	_, _ validateSecretFn = kal.ValidateAuthSecret, e2ee.ValidateAuthSecret
	_, _ recoveryCodeFn   = kal.NewRecoveryCode, e2ee.NewRecoveryCode
	_, _ newVaultsFn      = kal.NewVaults, e2ee.NewVaults

	_, _ vaultParamsFn  = (*kal.Vaults).Params, (*e2ee.Vaults).Params
	_, _ vaultGetFn     = (*kal.Vaults).Get, (*e2ee.Vaults).Get
	_, _ vaultPutFn     = (*kal.Vaults).Put, (*e2ee.Vaults).Put
	_, _ vaultDiscardFn = (*kal.Vaults).Discard, (*e2ee.Vaults).Discard
)

// The shapes the re-exported functions instantiate to.
type (
	fromFn        = func(context.Context) (*authz.Principal, bool)
	requireFn     = func(context.Context) (*authz.Principal, error)
	hasRoleFn     = func(context.Context, string) bool
	scopeFn       = func(context.Context, string) func(*orm.Query) *orm.Query
	coverageFn    = func(graphql.ExecutableSchema, ...string) error
	wiredFn       = func(any) error
	presentFn     = func(context.Context, error) *gqlerror.Error
	validateFn    = func(string) error
	newHasherFn   = func(authn.Params, int64) (*authn.Hasher, error)
	rlsSettingsFn = func(context.Context, *pg.DB, map[string]string, func(orm.DB) error) error

	validateSecretFn = func(string) error
	recoveryCodeFn   = func() (string, error)
	newVaultsFn      = func(e2ee.Options) (*e2ee.Vaults, error)

	vaultParamsFn  = func(*e2ee.Vaults, context.Context, orm.DB, string) (e2ee.Params, error)
	vaultGetFn     = func(*e2ee.Vaults, context.Context, orm.DB) (*e2ee.Vault, error)
	vaultPutFn     = func(*e2ee.Vaults, context.Context, orm.DB, e2ee.Vault) error
	vaultDiscardFn = func(*e2ee.Vaults, context.Context, orm.DB) error
)

// TestE2EEReExportedConstants checks the values the type assertions above cannot — a re-exported
// const is a fresh declaration, and a stale copy of a KDF name here would have kal writing a `kdf`
// column no client knows how to read.
func TestE2EEReExportedConstants(t *testing.T) {
	if kal.KDFArgon2id != e2ee.KDFArgon2id || kal.KDFPBKDF2 != e2ee.KDFPBKDF2 {
		t.Errorf("KDF names drifted: %q/%q, %q/%q",
			kal.KDFArgon2id, e2ee.KDFArgon2id, kal.KDFPBKDF2, e2ee.KDFPBKDF2)
	}
}

// newTestConfig @notice A minimal valid Config.
func newTestConfig(db *pg.DB) kal.Config {
	return kal.Config{
		DB:      db,
		BaseURL: "https://app.example.test",
		Mailer:  &recordingMailer{},
		Argon2:  authn.Params{Memory: 8192, Time: 1},
	}
}

// TestConfigValidation @notice Construction fails loudly on anything that cannot have a safe
// default, and succeeds on a Config that sets only what must be set.
//
// @dev The zero Config is the production posture, so everything absent from newTestConfig is a
// field with a safe default — which is what makes the success case meaningful.
//
// @param t the test handle
func TestConfigValidation(t *testing.T) {
	db := pg.Connect(&pg.Options{Addr: "127.0.0.1:1", User: "nobody"}) // never dialled
	t.Cleanup(func() { _ = db.Close() })

	t.Run("a minimal config is enough", func(t *testing.T) {
		auth, err := kal.New(newTestConfig(db))
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if auth.Sessions == nil || auth.Accounts == nil || auth.Roles == nil || auth.Hasher == nil {
			t.Error("New returned an incompletely wired Auth")
		}
		if auth.JWT != nil {
			t.Error("the JWT leg is on without an issuer — it must be opt-in")
		}
		if auth.Vaults != nil {
			t.Error("the vault is on without Config.E2EE — it must be opt-in")
		}
		// With E2EE off, the password policy is still the password policy. If enabling the vault
		// leaked its shape check into the default build, every existing deployment's registration
		// would start rejecting passwords on upgrade.
		if err := auth.Accounts.Register(context.Background(), db, "shape@example.test", "short"); err == nil {
			t.Error("an eight-character policy accepted a five-character password")
		}
	})

	t.Run("E2EE tightens the accepted secret", func(t *testing.T) {
		cfg := newTestConfig(db)
		cfg.E2EE = &kal.VaultOptions{Pepper: make([]byte, 32)}
		auth, err := kal.New(cfg)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if auth.Vaults == nil {
			t.Fatal("Config.E2EE is set and Auth.Vaults is nil")
		}
		// The single most likely way to break a deployment of this feature: one un-updated client
		// still sending the raw password logs in fine, and the vault silently never opens. The
		// registration path must refuse it before the account exists.
		err = auth.Accounts.Register(context.Background(), db, "raw@example.test", "a perfectly good password")
		var ae *kalerr.Error
		if !errors.As(err, &ae) || ae.Code != kalerr.CodeInvalidInput {
			t.Errorf("Register with a raw password: error = %v, want INVALID_INPUT", err)
		}
	})

	t.Run("E2EE without a pepper does not construct", func(t *testing.T) {
		cfg := newTestConfig(db)
		cfg.E2EE = &kal.VaultOptions{}
		if _, err := kal.New(cfg); err == nil {
			t.Error("New accepted an E2EE config with no pepper — a generated one differs per replica")
		}
	})

	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name   string
		mutate func(*kal.Config)
		want   string
	}{
		{"no DB", func(c *kal.Config) { c.DB = nil }, "DB"},
		{"no BaseURL", func(c *kal.Config) { c.BaseURL = "" }, "BaseURL"},
		{"http BaseURL", func(c *kal.Config) { c.BaseURL = "http://app.example.com" }, "https"},
		{"no Mailer", func(c *kal.Config) { c.Mailer = nil }, "Mailer"},
		{"absolute shorter than idle", func(c *kal.Config) {
			c.IdleTimeout, c.AbsoluteTimeout = 48*3600e9, 3600e9
		}, "absolute"},
		{"bad schema name", func(c *kal.Config) { c.TableSchema = "Robert'); DROP TABLE--" }, "schema"},
		{"JWT keys without an issuer", func(c *kal.Config) {
			c.JWTKeys = []ed25519.PrivateKey{key}
		}, "JWTIssuer"},
		{"JWT issuer without keys", func(c *kal.Config) { c.JWTIssuer = "https://kal.example" }, "JWTKeys"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := newTestConfig(db)
			c.mutate(&cfg)
			_, err := kal.New(cfg)
			if err == nil {
				t.Fatalf("New accepted a config with %s", c.name)
			}
			if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(c.want)) {
				t.Errorf("error %q does not mention %q", err, c.want)
			}
		})
	}

	t.Run("the JWT leg wires when both are set", func(t *testing.T) {
		cfg := newTestConfig(db)
		cfg.JWTIssuer = "https://kal.example"
		cfg.JWTKeys = []ed25519.PrivateKey{key}
		auth, err := kal.New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if auth.JWT == nil {
			t.Error("JWT is nil despite an issuer and a key")
		}
	})
}

// TestSharedHasherIsTheSameInstance @notice Config.Hasher makes the Argon2 bound process-wide.
//
// @dev Pointer identity is the whole assertion, and it is asserting about the semaphore rather
// than about the pointer. The bound lives on the Hasher, so two instances holding two Hashers
// hold two semaphores and the real ceiling is the sum — which is how a process running one kal
// per tenant schema ends up with N × MaxConcurrentHashes × ~19 MiB in flight (gotcha 79). Nothing
// weaker works here: comparing the configured limits would pass on two separate Hashers built
// from the same numbers, which is exactly the bug.
//
// @param t the test handle
func TestSharedHasherIsTheSameInstance(t *testing.T) {
	db := pg.Connect(&pg.Options{Addr: "127.0.0.1:1", User: "nobody"}) // never dialled
	t.Cleanup(func() { _ = db.Close() })

	shared, err := kal.NewHasher(kal.Params{Memory: 8192, Time: 1}, 4)
	if err != nil {
		t.Fatal(err)
	}

	newInstance := func(schema string) *kal.Auth {
		t.Helper()
		cfg := kal.Config{
			DB:          db,
			BaseURL:     "https://app.example.test",
			Mailer:      &recordingMailer{},
			TableSchema: schema,
			Hasher:      shared,
		}
		auth, err := kal.New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		return auth
	}

	a, b := newInstance("tenant_a"), newInstance("tenant_b")
	if a.Hasher != shared || b.Hasher != shared {
		t.Fatalf("Config.Hasher was not used: a=%p b=%p want %p", a.Hasher, b.Hasher, shared)
	}
	if a.Hasher != b.Hasher {
		t.Errorf("two instances hold two hashers (%p, %p) — the Argon2 bound is per instance", a.Hasher, b.Hasher)
	}

	// The default path must keep building its own, or every deployment that never sets the field
	// would start sharing a hasher it did not ask for.
	own, err := kal.New(newTestConfig(db))
	if err != nil {
		t.Fatal(err)
	}
	if own.Hasher == shared {
		t.Error("a Config without Hasher picked up the shared one")
	}
}

// TestHasherWithCostParamsErrors @notice A pre-built Hasher plus a cost parameter is refused, not
// silently resolved.
//
// @dev The zero Config is the production posture and nothing in it weakens quietly. A New that
// accepted both would ignore one of them, and the failure is invisible: an operator raises Argon2
// cost, redeploys, and hashes at the old parameters with nothing in any log. Asserting on the
// error being non-nil rather than on its text, so rewording the message is not a test failure.
//
// @param t the test handle
func TestHasherWithCostParamsErrors(t *testing.T) {
	db := pg.Connect(&pg.Options{Addr: "127.0.0.1:1", User: "nobody"}) // never dialled
	t.Cleanup(func() { _ = db.Close() })

	shared, err := kal.NewHasher(kal.Params{Memory: 8192, Time: 1}, 4)
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]func(*kal.Config){
		"Argon2 alongside Hasher":              func(c *kal.Config) { c.Argon2 = kal.Params{Memory: 65536} },
		"MaxConcurrentHashes alongside Hasher": func(c *kal.Config) { c.MaxConcurrentHashes = 8 },
		"both alongside Hasher": func(c *kal.Config) {
			c.Argon2, c.MaxConcurrentHashes = kal.Params{Time: 4}, 8
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := kal.Config{
				DB:      db,
				BaseURL: "https://app.example.test",
				Mailer:  &recordingMailer{},
				Hasher:  shared,
			}
			mutate(&cfg)
			if _, err := kal.New(cfg); err == nil {
				t.Error("New accepted a pre-built Hasher together with a cost parameter it would then ignore")
			}
		})
	}

	// The control: the same Hasher with no cost parameter beside it is the supported wiring.
	if _, err := kal.New(kal.Config{
		DB: db, BaseURL: "https://app.example.test", Mailer: &recordingMailer{}, Hasher: shared,
	}); err != nil {
		t.Errorf("New rejected a Hasher on its own: %v", err)
	}
}

// guardSchema @notice A schema with the field names the guard defends, and enough nesting to
// exceed a depth cap.
const guardSchema = `
type Query { me: User node: Node }
type Mutation { login(email: String!, password: String!): String register(email: String!): Boolean }
type User { id: ID! friend: User }
type Node { id: ID! child: Node }
`

// execSchema @notice An executable schema that reports the operation context back as data.
//
// @dev It answers with the DisableIntrospection flag rather than with fixed data, because that
// flag is precisely the boundary kal owns: kal decides it per request, and gqlgen's *generated*
// code is what refuses __schema when it is set. Asserting on real introspection here would be
// asserting on codegen this module deliberately does not run — so the test checks the thing kal
// actually controls.
type execSchema struct{ schema *ast.Schema }

func (s execSchema) Schema() *ast.Schema { return s.schema }
func (s execSchema) Complexity(context.Context, string, string, int, map[string]any) (int, bool) {
	return 0, false
}
func (s execSchema) Exec(context.Context) graphql.ResponseHandler {
	return func(ctx context.Context) *graphql.Response {
		disabled := true
		if opCtx := graphql.GetOperationContext(ctx); opCtx != nil {
			disabled = opCtx.DisableIntrospection
		}
		return &graphql.Response{Data: []byte(fmt.Sprintf(`{"introspectionDisabled":%t}`, disabled))}
	}
}

// newGuardedServer @notice A real gqlgen handler with kal's Configure applied.
func newGuardedServer(t *testing.T, cfg kal.Config) http.Handler {
	t.Helper()
	auth, err := kal.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := handler.New(execSchema{gqlparser.MustLoadSchema(&ast.Source{Name: "guard", Input: guardSchema})})
	srv.AddTransport(transport.POST{})
	auth.Configure()(srv)
	return srv
}

// postQuery @notice Sends a GraphQL document and returns the response body.
func postQuery(t *testing.T, h http.Handler, query string) (int, string) {
	t.Helper()
	body := `{"query":` + quoteJSON(query) + `}`
	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

// quoteJSON @notice Minimal JSON string quoting for the query payload.
func quoteJSON(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\t':
			b.WriteString(`\t`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// TestGuard @notice The aliasing attack is rejected before any resolver runs, and ordinary
// documents are not.
//
// @dev The attack this exists for: five hundred aliased logins in one document is one HTTP
// request, so every rate limiter that counts requests sees a single attempt. Rejection rather
// than throttling, because no legitimate client sends two logins at once.
//
// @param t the test handle
func TestGuard(t *testing.T) {
	db := pg.Connect(&pg.Options{Addr: "127.0.0.1:1", User: "nobody"})
	t.Cleanup(func() { _ = db.Close() })
	h := newGuardedServer(t, newTestConfig(db))

	t.Run("two aliased logins are rejected", func(t *testing.T) {
		_, body := postQuery(t, h, `mutation {
			a: login(email: "victim@example.com", password: "aaaa")
			b: login(email: "victim@example.com", password: "aaab")
		}`)
		if !strings.Contains(body, "only once per document") {
			t.Errorf("body = %s, want the guard's rejection", body)
		}
		if strings.Contains(body, `"ok":true`) {
			t.Error("the document executed despite being rejected")
		}
	})

	t.Run("a single login passes", func(t *testing.T) {
		_, body := postQuery(t, h, `mutation { login(email: "a@example.com", password: "hunter2hunter2") }`)
		if strings.Contains(body, "only once per document") {
			t.Errorf("a legitimate login was rejected: %s", body)
		}
	})

	t.Run("aliasing through a fragment is still counted", func(t *testing.T) {
		// The selections live in the fragment, so a walker that only visits operations counts
		// zero and the guard protects nothing.
		_, body := postQuery(t, h, `mutation {
			...Attack
		}
		fragment Attack on Mutation {
			a: login(email: "v@example.com", password: "aaaa")
			b: login(email: "v@example.com", password: "aaab")
		}`)
		if !strings.Contains(body, "only once per document") {
			t.Errorf("fragment-hidden aliasing slipped past: %s", body)
		}
	})

	t.Run("two different sensitive fields are fine", func(t *testing.T) {
		_, body := postQuery(t, h, `mutation {
			login(email: "a@example.com", password: "hunter2hunter2")
			register(email: "b@example.com")
		}`)
		if strings.Contains(body, "only once per document") {
			t.Errorf("distinct sensitive fields were rejected: %s", body)
		}
	})

	t.Run("depth is capped", func(t *testing.T) {
		deep := "query { node " + strings.Repeat("{ child ", 20) + "{ id }" + strings.Repeat("} ", 20) + "}"
		_, body := postQuery(t, h, deep)
		if !strings.Contains(body, "nested too deeply") {
			t.Errorf("a 20-deep query passed: %s", body)
		}
		// And a query inside the cap is not rejected.
		shallow := "query { node { child { id } } }"
		if _, body := postQuery(t, h, shallow); strings.Contains(body, "nested too deeply") {
			t.Errorf("a 3-deep query was rejected: %s", body)
		}
	})

	t.Run("selection count is capped", func(t *testing.T) {
		var sb strings.Builder
		sb.WriteString("query { ")
		for i := 0; i < 120; i++ {
			// Distinct aliases of a non-sensitive field, so this trips the count and not the
			// duplicate rule.
			sb.WriteString("f")
			sb.WriteString(strings.Repeat("x", i%5+1))
			sb.WriteString(string(rune('a' + i%26)))
			sb.WriteString(": me { id } ")
		}
		sb.WriteString("}")
		_, body := postQuery(t, h, sb.String())
		if !strings.Contains(body, "too many selections") {
			t.Errorf("120 selections passed: %s", body)
		}
	})

	t.Run("custom sensitive fields replace the defaults", func(t *testing.T) {
		cfg := newTestConfig(db)
		cfg.SensitiveFields = []string{"me"}
		custom := newGuardedServer(t, cfg)
		_, body := postQuery(t, custom, `query { a: me { id } b: me { id } }`)
		if !strings.Contains(body, "only once per document") {
			t.Errorf("the configured field was not guarded: %s", body)
		}
		// And login is no longer guarded, because the list replaces rather than extends.
		_, body = postQuery(t, custom, `mutation {
			a: login(email: "v@example.com", password: "aaaa")
			b: login(email: "v@example.com", password: "aaab")
		}`)
		if strings.Contains(body, "only once per document") {
			t.Error("the default list was still applied alongside the custom one")
		}
	})
}

// TestIntrospectionDefaultsOff @notice Introspection is off unless a predicate says otherwise —
// the inverse of luima's unconditional on.
//
// @dev Asserts on the DisableIntrospection flag kal sets per request. Enforcement past that
// point is gqlgen's generated code, which this module does not run; see execSchema.
//
// @param t the test handle
func TestIntrospectionDefaultsOff(t *testing.T) {
	db := pg.Connect(&pg.Options{Addr: "127.0.0.1:1", User: "nobody"})
	t.Cleanup(func() { _ = db.Close() })

	_, body := postQuery(t, newGuardedServer(t, newTestConfig(db)), `{ me { id } }`)
	if !strings.Contains(body, `"introspectionDisabled":true`) {
		t.Errorf("introspection was left enabled by default: %s", body)
	}

	cfg := newTestConfig(db)
	cfg.AllowIntrospection = func(context.Context) bool { return true }
	_, body = postQuery(t, newGuardedServer(t, cfg), `{ me { id } }`)
	if !strings.Contains(body, `"introspectionDisabled":false`) {
		t.Errorf("AllowIntrospection did not take effect: %s", body)
	}

	// The predicate sees the request context, which is what makes role-gating possible.
	cfg.AllowIntrospection = func(ctx context.Context) bool { return authz.HasRole(ctx, "admin") }
	_, body = postQuery(t, newGuardedServer(t, cfg), `{ me { id } }`)
	if !strings.Contains(body, `"introspectionDisabled":true`) {
		t.Errorf("an anonymous caller got introspection through a role gate: %s", body)
	}
}

// TestDBRootWiring @notice The root Auth drives a real request end to end: Migrate builds the
// schema, the middleware resolves a login's cookie, and Scope reads the bypass role the
// middleware installed.
//
// @param t the test handle
func TestDBRootWiring(t *testing.T) {
	db := testDB(t)
	mailer := &recordingMailer{}
	auth, err := kal.New(kal.Config{
		DB:          db,
		BaseURL:     "https://app.example.test",
		Mailer:      mailer,
		TableSchema: testSchema,
		Argon2:      authn.Params{Memory: 8192, Time: 1},
		BypassRole:  "root",
	})
	if err != nil {
		t.Fatal(err)
	}

	// The scratch schema already has the tables; Migrate against a clean one proves the
	// convenience path works at all.
	if _, err := db.Exec(`drop schema if exists kal_migrate_probe cascade; create schema kal_migrate_probe`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`drop schema if exists kal_migrate_probe cascade`) })

	ctx := context.Background()
	if err := auth.Accounts.Register(ctx, db, "root-wiring@example.com", "a password worth using"); err != nil {
		t.Fatalf("Register through the root: %v", err)
	}
	sent := mailer.take()
	if len(sent) != 1 {
		t.Fatalf("mail = %+v", sent)
	}
	if _, err := db.Exec(`update auth_users set email_verified = true`); err != nil {
		t.Fatal(err)
	}

	// A domain table to prove the bypass role reaches Scope through the middleware.
	if _, err := db.Exec(`create table docs (
		id       uuid primary key default gen_random_uuid(),
		owner_id uuid not null references auth_users(id),
		title    text not null)`); err != nil {
		t.Fatal(err)
	}
	owner := createUser(t, db, "doc-owner@example.com")
	if _, err := db.Exec(`insert into docs (owner_id, title) values (?, 'theirs')`, owner); err != nil {
		t.Fatal(err)
	}

	var adminRows, plainRows int
	h := auth.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rctx := r.Context()
		if _, err := auth.Accounts.Login(rctx, db, "root-wiring@example.com", "a password worth using"); err != nil {
			t.Errorf("Login: %v", err)
		}
		// Someone who owns nothing: with the bypass role they see every row, without it none.
		admin := authz.WithPrincipal(rctx, &kal.Principal{UserID: owner + "", Roles: []string{"root"}})
		plain := authz.WithPrincipal(rctx, &kal.Principal{UserID: "00000000-0000-0000-0000-000000000000"})
		a, err := luima.List[doc](rctx, db, kal.Scope(admin, "owner_id"))
		if err != nil {
			t.Error(err)
		}
		p, err := luima.List[doc](rctx, db, kal.Scope(plain, "owner_id"))
		if err != nil {
			t.Error(err)
		}
		adminRows, plainRows = len(a), len(p)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/graphql", nil)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if sc := rec.Header().Get("Set-Cookie"); !strings.Contains(sc, "__Host-kal_session=") {
		t.Errorf("Set-Cookie = %q, want the session cookie", sc)
	}
	if adminRows != 1 {
		t.Errorf("the bypass role saw %d rows, want 1 — Middleware is not installing it", adminRows)
	}
	if plainRows != 0 {
		t.Errorf("a non-owner saw %d rows, want 0", plainRows)
	}

	t.Run("PresentError carries the code through the root", func(t *testing.T) {
		ge := kal.PresentError(ctx, &kal.Error{Code: kalerr.CodeForbidden, Message: "nope"})
		if ge.Extensions["code"] != kalerr.CodeForbidden {
			t.Errorf("extensions = %v", ge.Extensions)
		}
	})

	t.Run("Require through the root", func(t *testing.T) {
		if _, err := kal.Require(ctx); err == nil {
			t.Error("Require on an empty context returned a principal")
		} else {
			var ae *kal.Error
			if !errors.As(err, &ae) || ae.Code != kalerr.CodeUnauthenticated {
				t.Errorf("error = %v", err)
			}
		}
	})
}
