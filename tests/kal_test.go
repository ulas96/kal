package tests

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
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
	"github.com/ulas96/kal/kalerr"
	"github.com/ulas96/kal/session"
	"github.com/ulas96/kal/zkauthn"
	"github.com/ulas96/kal/zkauthz"
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
	_ session.Info    = kal.SessionInfo{}
	_ kal.SessionInfo = session.Info{}
	_ authn.Message   = kal.Message{}
	_ kal.Message     = authn.Message{}
	_ authn.LogMailer = kal.LogMailer{}
	_ kal.Mailer      = authn.LogMailer{}
	_ authn.Mailer    = kal.LogMailer{}

	// The wrappers must instantiate to exactly the sub-package signature. Assigning both to one
	// typed var is the compile-time assertion — funcs cannot be compared to each other.
	_, _ fromFn     = kal.From, authz.From
	_, _ requireFn  = kal.Require, authz.Require
	_, _ hasRoleFn  = kal.HasRole, authz.HasRole
	_, _ scopeFn    = kal.Scope, authz.Scope
	_, _ coverageFn = kal.AssertAuthCoverage, authz.AssertAuthCoverage
	_, _ wiredFn    = kal.AssertDirectivesWired, authz.AssertDirectivesWired
	_, _ presentFn  = kal.PresentError, kalerr.PresentError
	_, _ validateFn = kal.ValidatePassword, authn.ValidatePassword

	// The zk surface, on the same terms. kal.go gained roughly fifty ZK* names by hand and none of
	// them had an assertion, so nothing stopped a future `type ZKClaim struct{…}` — a definition
	// rather than an alias — from silently breaking every consumer who passes a kal.ZKClaim to a
	// zkauthn function. Two-way, because a one-way assignment also compiles for a convertible type.
	_ zkauthn.Field             = kal.ZKField{}
	_ kal.ZKField               = zkauthn.Field{}
	_ zkauthn.Secret            = kal.ZKSecret{}
	_ kal.ZKSecret              = zkauthn.Secret{}
	_ zkauthn.Circuit           = kal.ZKCircuitKnowledge
	_ kal.ZKCircuit             = zkauthn.CircuitMembership
	_ zkauthn.VerifyingKey      = kal.ZKVerifyingKey{}
	_ kal.ZKVerifyingKey        = zkauthn.VerifyingKey{}
	_ zkauthn.ProvingKey        = kal.ZKProvingKey{}
	_ kal.ZKProvingKey          = zkauthn.ProvingKey{}
	_ zkauthn.KnowledgeCircuit  = kal.ZKKnowledgeCircuit{}
	_ kal.ZKKnowledgeCircuit    = zkauthn.KnowledgeCircuit{}
	_ zkauthn.MembershipCircuit = kal.ZKMembershipCircuit{}
	_ kal.ZKMembershipCircuit   = zkauthn.MembershipCircuit{}
	_ zkauthn.KnowledgeWitness  = kal.ZKKnowledgeWitness{}
	_ kal.ZKKnowledgeWitness    = zkauthn.KnowledgeWitness{}
	_ zkauthn.MembershipWitness = kal.ZKMembershipWitness{}
	_ kal.ZKMembershipWitness   = zkauthn.MembershipWitness{}
	_ zkauthn.MembershipPublic  = kal.ZKMembershipPublic{}
	_ kal.ZKMembershipPublic    = zkauthn.MembershipPublic{}
	_ zkauthn.ClaimKind         = kal.ZKClaimRecurring
	_ kal.ZKClaimKind           = zkauthn.ClaimOneShot
	_ zkauthn.Claim             = kal.ZKClaim{}
	_ kal.ZKClaim               = zkauthn.Claim{}
	_ zkauthn.VerifiedClaim     = kal.ZKVerifiedClaim{}
	_ kal.ZKVerifiedClaim       = zkauthn.VerifiedClaim{}
	_ zkauthn.Options           = kal.ZKOptions{}
	_ kal.ZKOptions             = zkauthn.Options{}
	_ zkauthn.ZK                = kal.ZKService{}
	_ kal.ZKService             = zkauthn.ZK{}
	_ zkauthn.Credential        = kal.ZKCredential{}
	_ kal.ZKCredential          = zkauthn.Credential{}
	_ zkauthn.MerklePath        = kal.ZKMerklePath{}
	_ kal.ZKMerklePath          = zkauthn.MerklePath{}
	_ zkauthn.KnowledgeRequest  = kal.ZKKnowledgeRequest{}
	_ kal.ZKKnowledgeRequest    = zkauthn.KnowledgeRequest{}
	_ zkauthn.MembershipRequest = kal.ZKMembershipRequest{}
	_ kal.ZKMembershipRequest   = zkauthn.MembershipRequest{}
	_ zkauthz.Claims            = kal.ZKClaims{}
	_ kal.ZKClaims              = zkauthz.Claims{}

	_, _ zkSetupFn           = kal.SetupZK, zkauthn.Setup
	_, _ zkLoadVKFn          = kal.LoadZKVerifyingKey, zkauthn.LoadVerifyingKey
	_, _ zkLoadPKFn          = kal.LoadZKProvingKey, zkauthn.LoadProvingKey
	_, _ zkCircuitInfoFn     = kal.ZKCircuitInfo, zkauthn.CircuitInfo
	_, _ zkProofSizeFn       = kal.ZKProofSize, zkauthn.ProofSize
	_, _ zkKnowledgeValidFn  = kal.ZKKnowledgeValid, zkauthn.KnowledgeValid
	_, _ zkMembershipValidFn = kal.ZKMembershipValid, zkauthn.MembershipValid
	_, _ zkKnowledgeCommitFn = kal.ZKKnowledgeCommitment, zkauthn.KnowledgeCommitment
	_, _ zkMemberCommitFn    = kal.ZKMembershipCommitment, zkauthn.MembershipCommitment
	_, _ zkSingleLeafPathFn  = kal.ZKSingleLeafPath, zkauthn.SingleLeafPath
	_, _ zkAudienceFn        = kal.NewZKAudience, zkauthn.NewAudience
	_, _ zkNewFn             = kal.NewZK, zkauthn.New
	_, _ zkNewClaimsFn       = kal.NewZKClaims, zkauthz.New
	_, _ zkNullifierFn       = kal.ZKNullifier, zkauthn.Nullifier
	_, _ zkChallengeFieldFn  = kal.ZKChallengeField, zkauthn.ChallengeField
	_, _ zkWitnessForFn      = kal.ZKMembershipWitnessFor, zkauthn.MembershipWitnessFor

	// Methods, reached through the alias, so a signature change on either side breaks the build.
	_, _ zkEnrollFn = (*kal.ZKService).EnrollKnowledge, (*zkauthn.ZK).EnrollKnowledge
	_, _ zkLoginFn  = (*kal.ZKService).Login, (*zkauthn.ZK).Login
	_, _ zkProveFn  = (*kal.ZKService).ProveClaim, (*zkauthn.ZK).ProveClaim
	_, _ zkVerifyFn = (*kal.ZKService).VerifyKnowledge, (*zkauthn.ZK).VerifyKnowledge
	_, _ zkIssueFn  = (*kal.ZKService).IssueCredential, (*zkauthn.ZK).IssueCredential
	_, _ zkPathFn   = (*kal.ZKService).Path, (*zkauthn.ZK).Path
	_, _ zkRevokeFn = (*kal.ZKService).RevokeCredential, (*zkauthn.ZK).RevokeCredential
	_, _ zkClaimFn  = (*kal.ZKService).Claim, (*zkauthn.ZK).Claim
	_, _ zkProofsFn = (*kal.ZKClaims).Proofs, (*zkauthz.Claims).Proofs
)

// TestZKReExportedConstants checks the values the type assertions above cannot.
//
// A re-exported const is a fresh declaration, so `ZKMerkleDepth = 32` written out by hand compiles
// and type-checks exactly like `ZKMerkleDepth = zkauthn.MerkleDepth` — right up until the circuit
// depth changes and only one of them moves. The circuit IDs matter most: they are the pinned
// statement identity, and a stale copy in the root package tells a consumer their key matches a
// circuit it does not.
// Covers: ZK-INV-001, ZK-TRE-013
func TestZKReExportedConstants(t *testing.T) {
	if kal.ZKMerkleDepth != zkauthn.MerkleDepth || kal.ZKSecretSize != zkauthn.SecretSize {
		t.Errorf("tree constants drifted: depth %d/%d, secret %d/%d",
			kal.ZKMerkleDepth, zkauthn.MerkleDepth, kal.ZKSecretSize, zkauthn.SecretSize)
	}
	if kal.ZKKnowledgeConstraints != zkauthn.KnowledgeConstraints ||
		kal.ZKMembershipConstraints != zkauthn.MembershipConstraints {
		t.Errorf("constraint counts drifted: knowledge %d/%d, membership %d/%d",
			kal.ZKKnowledgeConstraints, zkauthn.KnowledgeConstraints,
			kal.ZKMembershipConstraints, zkauthn.MembershipConstraints)
	}
	if kal.ZKKnowledgeCircuitID != zkauthn.KnowledgeCircuitID {
		t.Errorf("knowledge circuit id = %s, want %s", kal.ZKKnowledgeCircuitID, zkauthn.KnowledgeCircuitID)
	}
	if kal.ZKMembershipCircuitID != zkauthn.MembershipCircuitID {
		t.Errorf("membership circuit id = %s, want %s", kal.ZKMembershipCircuitID, zkauthn.MembershipCircuitID)
	}
}

// The shapes the re-exported functions instantiate to.
type (
	fromFn     = func(context.Context) (*authz.Principal, bool)
	requireFn  = func(context.Context) (*authz.Principal, error)
	hasRoleFn  = func(context.Context, string) bool
	scopeFn    = func(context.Context, string) func(*orm.Query) *orm.Query
	coverageFn = func(graphql.ExecutableSchema, ...string) error
	wiredFn    = func(any) error
	presentFn  = func(context.Context, error) *gqlerror.Error
	validateFn = func(string) error

	zkSetupFn           = func(zkauthn.Circuit, io.Writer, io.Writer) error
	zkLoadVKFn          = func(zkauthn.Circuit, io.Reader, []byte) (*zkauthn.VerifyingKey, error)
	zkLoadPKFn          = func(zkauthn.Circuit, io.Reader) (*zkauthn.ProvingKey, error)
	zkCircuitInfoFn     = func(zkauthn.Circuit) (int, [32]byte, error)
	zkProofSizeFn       = func() int
	zkKnowledgeValidFn  = func(zkauthn.KnowledgeWitness) bool
	zkMembershipValidFn = func(zkauthn.MembershipWitness) bool
	zkKnowledgeCommitFn = func(zkauthn.Secret) (zkauthn.Field, error)
	zkMemberCommitFn    = func(zkauthn.Secret, uint64) (zkauthn.Field, error)
	zkSingleLeafPathFn  = func(zkauthn.Field) (zkauthn.MerklePath, error)
	zkAudienceFn        = func(string, string, string) zkauthn.Field
	zkNewFn             = func(zkauthn.Options) (*zkauthn.ZK, error)
	zkNewClaimsFn       = func(string) (*zkauthz.Claims, error)
	zkNullifierFn       = func(zkauthn.Secret, zkauthn.Field) (zkauthn.Field, error)
	zkChallengeFieldFn  = func(string) (zkauthn.Field, error)
	zkWitnessForFn      = func(zkauthn.Credential, zkauthn.MerklePath, zkauthn.Claim,
		zkauthn.Field, zkauthn.Field) zkauthn.MembershipWitness

	zkEnrollFn = func(*zkauthn.ZK, context.Context, orm.DB, string) (zkauthn.Secret, error)
	zkLoginFn  = func(*zkauthn.ZK, context.Context, orm.DB, zkauthn.MembershipRequest) (*authz.Principal, error)
	zkProveFn  = func(*zkauthn.ZK, context.Context, orm.DB, zkauthn.MembershipRequest) error
	zkVerifyFn = func(*zkauthn.ZK, context.Context, orm.DB, zkauthn.KnowledgeRequest) error
	zkIssueFn  = func(*zkauthn.ZK, context.Context, orm.DB, string, uint64) (*zkauthn.Credential, error)
	zkPathFn   = func(*zkauthn.ZK, context.Context, orm.DB, uint32) (*zkauthn.MerklePath, error)
	zkRevokeFn = func(*zkauthn.ZK, context.Context, orm.DB, uint32) error
	zkClaimFn  = func(*zkauthn.ZK, context.Context, orm.DB, string) (zkauthn.Claim, error)
	zkProofsFn = func(*zkauthz.Claims, context.Context, []string) error
)

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
