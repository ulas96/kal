// Package kal @notice Authentication and authorization for gqlgen applications on Postgres,
// as an embedded library rather than a service.
//
// @dev Three positions, each argued against how the rest of the ecosystem does it:
//
// **Sessions in your database.** Opaque server-side sessions, so revoking one is an UPDATE and
// "log out everywhere" is one statement. Kratos, SuperTokens and Zitadel take your users table
// into a separate service, which costs you the JOIN, the shared transaction, and a second
// backup and migration story. Because the session cookie is the long-lived credential, kal
// ships no refresh token at all — the rotating-family subsystem every JWT-first library must
// build does not exist here.
//
// **Identity in the request context.** The middleware is net/http, mounted inside luima's
// adaptor, so a resolver reads a typed [Principal] from its own ctx. Anonymous is not an error:
// one endpoint serves public and private fields in the same document, and the graph decides.
//
// **Authorization in the WHERE clause.** [Scope] composes the caller's ownership predicate into
// the statement. A policy engine answers "may Alice read document 7"; it does not stop a list
// query returning everything, and it cannot apply to a DELETE without a read-then-check round
// trip that has a TOCTOU window.
//
// # The packages
//
// This package re-exports the ones below, so the common case needs one import:
//
//	[github.com/ulas96/kal/authn]      passwords, registration, login, recovery
//	[github.com/ulas96/kal/authz]      Principal, @auth, Scope, coverage, RLS
//	[github.com/ulas96/kal/session]    sessions, the cookie, the middleware, the JWT leg
//	[github.com/ulas96/kal/kalerr]     the error contract
//	[github.com/ulas96/kal/e2ee]       client-side encryption, which kal cannot undo
//	[github.com/ulas96/kal/migrations] the schema, as .sql behind an embed.FS
//
// The types below are aliases, not copies, so the two spellings are interchangeable. The cost,
// stated plainly: a genuinely new sub-package export is invisible from here until it is added
// by hand, and tests/ asserts the identity of the ones that exist.
//
// # Wiring
//
// Requires luima ≥ 0.2.0 for the HTTPMiddleware and Configure seams:
//
//	auth, err := kal.New(kal.Config{
//	    DB:      db,
//	    BaseURL: "https://app.example.com",
//	    Mailer:  myMailer,
//	})
//	app := luima.New(luima.Config{
//	    Schema:         generated.NewExecutableSchema(c),
//	    HTTPMiddleware: []func(http.Handler) http.Handler{auth.Middleware()},
//	    Configure:      auth.Configure(),
//	    ErrorPresenter: kal.PresentError,
//	})
//
// with `c.Directives.Auth = auth.Directive()` and [authz.DirectiveSDL] pasted into the schema.
package kal

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/99designs/gqlgen/graphql"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/go-pg/pg/v10"
	"github.com/go-pg/pg/v10/orm"
	"github.com/vektah/gqlparser/v2/gqlerror"

	"github.com/ulas96/kal/authn"
	"github.com/ulas96/kal/authz"
	"github.com/ulas96/kal/e2ee"
	"github.com/ulas96/kal/kalerr"
	"github.com/ulas96/kal/session"
)

// Config @notice Assembles kal.
//
// @dev The zero value is the good *production* configuration, and there is no development mode
// that weakens a security property. This is a deliberate inversion of luima's invariant, where
// a zero Config is the good development configuration with the playground and introspection on.
// For an auth library that polarity is wrong: a Dev bool that relaxes a cookie attribute or
// skips a check is a vulnerability shipped as a convenience, and it reaches production, because
// that is what environment flags do. Anything a developer needs is an ordinary field with an
// obvious name.
type Config struct {
	// DB @notice The pool everything runs on. Required.
	DB *pg.DB

	// BaseURL @notice The origin every emailed link is built under. Required.
	//
	// @dev Cannot be derived from the request: a link origin taken from the Host header is
	// Host-header injection, and a password-reset email is the last place to accept
	// attacker-controlled input. Must be https outside loopback.
	BaseURL string

	// Mailer @notice Delivers verification, reset and invite messages. Required.
	//
	// @dev No default, and deliberately no silent no-op: "I forgot to configure email" must
	// fail at construction, not at 3am when nobody can reset a password. [LogMailer] is the
	// development answer, and its name says not to ship it.
	Mailer Mailer

	// TableSchema @notice Postgres schema holding the auth_* tables. Empty means search_path.
	TableSchema string

	// IdleTimeout @notice Session inactivity timeout. Default 12h.
	IdleTimeout time.Duration

	// AbsoluteTimeout @notice Hard session lifetime, never extended. Default 14d.
	AbsoluteTimeout time.Duration

	// CookieName @notice The session cookie. Default "__Host-kal_session".
	//
	// @dev Change it only to run two kal instances on one origin. Keep the __Host- prefix: it
	// is what stops a sibling subdomain overwriting the cookie.
	CookieName string

	// Argon2 @notice Password hashing parameters. Zero fields take the OWASP defaults.
	Argon2 authn.Params

	// MaxConcurrentHashes @notice In-flight Argon2 ceiling. Zero means GOMAXPROCS.
	//
	// @dev Each hash holds ~19 MiB, so this is what stops concurrent logins from becoming a
	// remote OOM. Per replica: behind N replicas the real ceiling is N times this. Per *instance*
	// too — see Hasher below, which is the seam that makes it process-wide.
	MaxConcurrentHashes int64

	// Hasher @notice A pre-built password hasher to use instead of building one. Nil builds one
	// from Argon2 and MaxConcurrentHashes.
	//
	// @dev The seam multi-instance deployments need. Every New otherwise builds its own Hasher
	// with its own semaphore, so a process holding N instances — one per tenant schema, which is
	// what TableSchema exists for — holds N × MaxConcurrentHashes in-flight hashes at ~19 MiB
	// each. Zero means GOMAXPROCS *per instance*, so the parameter that bounds a remote OOM stops
	// bounding it at exactly the point a deployment gets big enough to care (gotcha 79).
	//
	// Sharing one Hasher makes the bound process-wide, and the cost is honest: one instance's
	// login storm queues another's. Take it. A queue recovers; an OOM kills every tenant in the
	// process.
	Hasher *authn.Hasher

	// BypassRole @notice A role for which [Scope] is a no-op and any @auth roles requirement
	// is satisfied. Empty means none — there is no implicit "admin".
	BypassRole string

	// Audit @notice Called for every security-relevant event kal sees. Nil discards them.
	//
	// @dev kal observes things a consumer structurally cannot — the backoff window opening, a
	// login succeeding after N failures, rehash-on-login firing, the session lookup failing on
	// the driver — and until this existed they went to log.Printf or nowhere. Grepping a log
	// stream for "kal/authn:" is not an audit trail.
	//
	// Same shape as Mailer: kal ships no sink, because a sink is a dependency and every
	// deployment already has one. Called synchronously, so an implementation that talks to the
	// network must queue internally. See [authz.Event] for the vocabulary.
	Audit authz.Audit

	// RLSSettings @notice Extra Postgres settings [Auth.WithRLS] carries, resolved per request.
	// Nil carries only app.user_id and app.roles.
	//
	// @dev The config-level form rather than a second entry point, so tenancy resolution lives in
	// one place at construction and a resolver cannot forget to pass it. Keys must be
	// app.-prefixed; see [authz.WithRLSSettings] for why that is checked.
	RLSSettings func(context.Context) map[string]string

	// MFAWindow @notice How recently MFA must have been satisfied for @auth(mfa: true).
	// Default 15m.
	MFAWindow time.Duration

	// AllowUnverifiedLogin @notice Lets accounts log in before verifying their email. Off by
	// default.
	AllowUnverifiedLogin bool

	// ClientIP @notice How to attribute a request to a client address. Default: the host part
	// of RemoteAddr.
	//
	// @dev Not X-Forwarded-For by default — that header is client-supplied unless a trusted
	// proxy overwrites it, and a spoofable address turns per-IP rate limiting into a bypass.
	ClientIP func(*http.Request) string

	// AllowIntrospection @notice Decides per request whether introspection is answered. Nil
	// means never.
	//
	// @dev luima turns introspection on and, since 0.2.0, offers Config.DisableIntrospection to
	// turn it off again — an all-or-nothing deploy-time switch. This is the per-request form, so
	// it can be role-gated: func(ctx) bool { return authz.HasRole(ctx, "admin") }. Off by
	// default, because the zero Config is the production posture.
	AllowIntrospection func(context.Context) bool

	// SensitiveFields @notice Fields that may be selected at most once per document. Nil takes
	// kal's defaults (login, register, the recovery mutations).
	//
	// @dev Set this if your login mutation has another name, or the aliasing guard protects
	// nothing.
	SensitiveFields []string

	// MaxAliases @notice Selections allowed per document. Zero means 100. Negative disables.
	MaxAliases int

	// MaxDepth @notice Nesting allowed per document. Zero means 15. Negative disables.
	MaxDepth int

	// JWTIssuer @notice The iss claim for the optional JWT leg. Empty disables it.
	JWTIssuer string

	// JWTKeys @notice Ed25519 signing keys, newest first. Required when JWTIssuer is set.
	//
	// @dev Two keys make rotation a deploy rather than an outage: the first signs, all verify.
	JWTKeys []ed25519.PrivateKey

	// Proofs @notice Satisfies @auth(proves:) requirements from request context. Nil denies
	// every non-empty proves requirement.
	//
	// @dev The seam a proof module plugs into, as a plain func so kal carries no dependency on
	// one. Nil failing closed is the point: an installed schema whose proof module was not wired
	// must refuse, not run unguarded. See [github.com/ulas96/kal-zk/zkauthz] for an implementation.
	Proofs func(context.Context, []string) error

	// ExtraMiddleware @notice Middleware mounted inside the session middleware, index 0
	// outermost. Nil mounts nothing.
	//
	// @dev Inside, not around: anything here that reads the caller runs after
	// session.Middleware has resolved the cookie into a Principal, and resolves to anonymous if
	// it runs first. Inside the session middleware and *outside* the BypassRole wrapper, so an
	// entry here sees the caller but not the bypass role — the same position the ZK claims
	// middleware held before it moved to its own module.
	ExtraMiddleware []func(http.Handler) http.Handler

	// E2EE @notice Optional client-side encryption. Nil keeps today's posture exactly: no vault,
	// and nothing about authn changes.
	//
	// @dev Non-nil *tightens* the accepted secret from an 8–64 character password to 32 bytes of
	// derived entropy, so this does not weaken the zero Config. What it removes is the server's
	// ability to judge password strength, which is a consequence of never seeing a password and is
	// documented as gotcha 76 rather than papered over. Schema is taken from TableSchema and
	// whatever is set here is ignored.
	E2EE *e2ee.Options
}

// Auth @notice Everything kal exposes to an application, wired and validated.
type Auth struct {
	// Sessions @notice Issue, look up, rotate, revoke and list sessions.
	Sessions *session.Sessions
	// Accounts @notice Register, log in, recover, change a password.
	Accounts *authn.Accounts
	// Roles @notice Grant and revoke role membership.
	Roles *authz.Roles
	// Hasher @notice Password hashing, for importing an existing user base.
	Hasher *authn.Hasher
	// JWT @notice The optional bearer-token leg. Nil unless JWTIssuer was set.
	JWT *session.JWT
	// Vaults @notice The optional client-encryption vault. Nil unless Config.E2EE was set.
	Vaults *e2ee.Vaults

	db     *pg.DB
	cfg    Config
	mwOpts session.MiddlewareOptions
}

// New @notice Validates the configuration and wires everything up.
//
// @dev Fails loudly on anything that cannot have a safe default. Every other field has one, and
// every default is the production posture.
//
// @param cfg the configuration; DB, BaseURL and Mailer are required
// @return *Auth the wired library
// @return error a description of what is missing or contradictory
func New(cfg Config) (*Auth, error) {
	if cfg.DB == nil {
		return nil, errors.New("kal: Config.DB is required")
	}
	if err := authn.ValidateBaseURL(cfg.BaseURL); err != nil {
		return nil, err
	}
	if cfg.Mailer == nil {
		return nil, errors.New("kal: Config.Mailer is required — a silent no-op means password reset fails at 3am with nothing in any log; use kal.LogMailer{} in development")
	}

	// Rejected rather than ignored: a pre-built Hasher already carries its own cost parameters, so
	// honouring these too would mean a deployment that raises Argon2 cost, observes no change, and
	// has nothing in any log to explain it. Invariant: nothing here weakens quietly.
	if cfg.Hasher != nil && (cfg.Argon2 != (authn.Params{}) || cfg.MaxConcurrentHashes != 0) {
		return nil, errors.New("kal: Config.Hasher is set together with Argon2 or MaxConcurrentHashes — the pre-built hasher already carries both, and silently ignoring a cost parameter is how a deployment ends up hashing at parameters nobody chose")
	}

	var err error
	hasher := cfg.Hasher
	if hasher == nil {
		if hasher, err = authn.NewHasher(cfg.Argon2, cfg.MaxConcurrentHashes); err != nil {
			return nil, fmt.Errorf("kal: %w", err)
		}
	}
	sessions, err := session.NewSessions(session.Options{
		Idle:     cfg.IdleTimeout,
		Absolute: cfg.AbsoluteTimeout,
		Schema:   cfg.TableSchema,
		Audit:    cfg.Audit,
	})
	if err != nil {
		return nil, err
	}
	// Built before Accounts rather than beside ZK below, because enabling it changes what Accounts
	// will accept as a secret — and a pepper that fails validation must fail here, not after the
	// credential flows have been wired to expect derived secrets they will never receive.
	var vaults *e2ee.Vaults
	var secretShape func(string) error
	if cfg.E2EE != nil {
		// A copy: the schema is kal's to decide, and honouring a second one set here would let the
		// vault and the users it joins against live in different schemas.
		vaultOpts := *cfg.E2EE
		vaultOpts.Schema = cfg.TableSchema
		if vaults, err = e2ee.NewVaults(vaultOpts); err != nil {
			return nil, err
		}
		secretShape = e2ee.ValidateAuthSecret
	}
	accounts, err := authn.NewAccounts(authn.AccountsOptions{
		Hasher:               hasher,
		Sessions:             sessions,
		Mailer:               cfg.Mailer,
		BaseURL:              cfg.BaseURL,
		CookieName:           cfg.CookieName,
		Schema:               cfg.TableSchema,
		SecretShape:          secretShape,
		AllowUnverifiedLogin: cfg.AllowUnverifiedLogin,
		Audit:                cfg.Audit,
	})
	if err != nil {
		return nil, err
	}
	roles, err := authz.NewRoles(cfg.TableSchema)
	if err != nil {
		return nil, err
	}

	a := &Auth{
		Sessions: sessions, Accounts: accounts, Roles: roles, Hasher: hasher, Vaults: vaults,
		db: cfg.DB, cfg: cfg,
		mwOpts: session.MiddlewareOptions{CookieName: cfg.CookieName, ClientIP: cfg.ClientIP},
	}
	if cfg.JWTIssuer != "" {
		if len(cfg.JWTKeys) == 0 {
			return nil, errors.New("kal: Config.JWTIssuer is set but Config.JWTKeys is empty")
		}
		if a.JWT, err = session.NewJWT(cfg.JWTIssuer, cfg.JWTKeys...); err != nil {
			return nil, err
		}
	} else if len(cfg.JWTKeys) > 0 {
		return nil, errors.New("kal: Config.JWTKeys is set but Config.JWTIssuer is empty — a token nobody can attribute to an issuer is not verifiable")
	}
	return a, nil
}

// Middleware @notice The net/http middleware that resolves the session cookie into a
// [Principal], carries the cookie jar, and enforces the cross-site transport guard.
//
// Pass it to luima's Config.HTTPMiddleware (luima ≥ 0.2.0), or mount it in any net/http stack.
//
// @return func(http.Handler) http.Handler outermost-first middleware
func (a *Auth) Middleware() func(http.Handler) http.Handler {
	base := a.Sessions.Middleware(a.db, a.mwOpts)
	return func(next http.Handler) http.Handler {
		// Reversed, so index 0 ends up outermost: each iteration wraps what the previous one
		// produced, and the last thing wrapped is the first thing entered.
		for i := len(a.cfg.ExtraMiddleware) - 1; i >= 0; i-- {
			next = a.cfg.ExtraMiddleware[i](next)
		}
		if a.cfg.BypassRole != "" {
			inner := next
			next = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				inner.ServeHTTP(w, r.WithContext(authz.WithBypassRole(r.Context(), a.cfg.BypassRole)))
			})
		}
		return base(next)
	}
}

// DefaultSensitiveFields @notice The fields Config.SensitiveFields defaults to, as a fresh copy.
//
// @dev Config.SensitiveFields replaces this list rather than extending it, so a deployment adding
// its own names had to restate kal's or silently lose the aliasing guard on login. Returning a copy
// keeps a caller's append from writing through into kal's own defaults.
//
// @return []string a copy of kal's default sensitive-field list
func DefaultSensitiveFields() []string {
	return append([]string(nil), defaultSensitiveFields...)
}

// Configure @notice Applies kal's gqlgen extensions: the anti-batching guard, conditional
// introspection, and suggestion suppression.
//
// Pass it to luima's Config.Configure (luima ≥ 0.2.0).
//
// @dev SetDisableSuggestion is here rather than optional because gqlparser's "Did you mean …?"
// text passes straight through luima's presenter by design, so a caller guessing a field name
// still learns the real one with introspection off.
//
// @return func(*handler.Server) applied immediately before the handler is mounted
func (a *Auth) Configure() func(*handler.Server) {
	g := guard{
		sensitive:  map[string]bool{},
		maxAliases: a.cfg.MaxAliases,
		maxDepth:   a.cfg.MaxDepth,
	}
	fields := a.cfg.SensitiveFields
	if fields == nil {
		fields = defaultSensitiveFields
	}
	for _, f := range fields {
		g.sensitive[f] = true
	}
	if g.maxAliases == 0 {
		g.maxAliases = DefaultMaxAliases
	}
	if g.maxAliases < 0 {
		g.maxAliases = int(^uint(0) >> 1)
	}
	if g.maxDepth == 0 {
		g.maxDepth = DefaultMaxDepth
	}
	if g.maxDepth < 0 {
		g.maxDepth = int(^uint(0) >> 1)
	}

	allow := a.cfg.AllowIntrospection
	if allow == nil {
		allow = func(context.Context) bool { return false }
	}
	return func(srv *handler.Server) {
		srv.Use(g)
		srv.Use(conditionalIntrospection{allow: allow})
		srv.SetDisableSuggestion(true)
	}
}

// Directive @notice The @auth implementation for your generated DirectiveRoot.
//
//	c.Directives.Auth = auth.Directive()
//
// Paste [authz.DirectiveSDL] into your schema for the matching declaration.
func (a *Auth) Directive() func(context.Context, any, graphql.Resolver, AuthLevel, []string, *bool, []string) (any, error) {
	opts := authz.DirectiveOptions{
		MFAWindow:  a.cfg.MFAWindow,
		BypassRole: a.cfg.BypassRole,
		Proofs:     a.cfg.Proofs,
	}
	return authz.Directive(opts)
}

// Migrate @notice Applies every embedded migration in order.
//
// @dev A convenience, not a migration framework: it runs the .sql files and nothing else — no
// version table, no down migrations, no locking. Applications with their own tooling should
// feed it [migrations.FS] instead. Each file is idempotent only in the sense that a second run
// fails loudly on the existing tables rather than corrupting them.
//
// The DDL runs on the connection's search_path and this method ignores Config.TableSchema, which
// is correct for one application and a footgun for a fan-out loop. Use [Auth.MigrateSchema] for
// the multi-schema case; gotcha 80 is what happens otherwise.
//
// @param ctx the context for the statements
// @return error the first failure, naming the file
func (a *Auth) Migrate(ctx context.Context) error { return migrate(ctx, a.db) }

// MigrateSchema @notice Applies every embedded migration into the named schema, creating it if
// it does not exist.
//
// @dev [Auth.Migrate] runs the DDL on the connection's search_path, which is correct for a single
// application and a footgun for a fan-out loop: the caller must keep search_path and
// Config.TableSchema in agreement across N iterations, and a mismatch provisions one tenant's
// auth tables into another tenant's schema with no error at all. Taking the name here makes the
// two agree by construction. Still not a migration framework — no version table, no down
// migrations, no locking.
//
// @param ctx    the context for the statements
// @param schema the Postgres schema to create and migrate into; must match ^[a-z_][a-z0-9_]*$
// @return error the first failure, naming the file or the schema
func (a *Auth) MigrateSchema(ctx context.Context, schema string) error {
	return migrateSchema(ctx, a.db, schema)
}

// WithRLS @notice Runs fn in a transaction whose Postgres session variables carry the caller,
// plus whatever Config.RLSSettings resolves for this request.
// See [authz.WithRLS] for the four ways an RLS deployment breaks silently.
func (a *Auth) WithRLS(ctx context.Context, fn func(orm.DB) error) error {
	if a.cfg.RLSSettings == nil {
		return authz.WithRLS(ctx, a.db, fn)
	}
	return authz.WithRLSSettings(ctx, a.db, a.cfg.RLSSettings(ctx), fn)
}

// The re-exported surface. Types are aliases, so kal.Principal *is* authz.Principal and a value
// of either satisfies both spellings; functions are wrappers, because Go has no alias for a
// function.

// Principal @notice The authenticated caller. See [authz.Principal].
type Principal = authz.Principal

// AuthLevel @notice The @auth directive's requires argument. See [authz.AuthLevel].
type AuthLevel = authz.AuthLevel

// Error @notice A client-visible auth error with a stable code. See [kalerr.Error].
type Error = kalerr.Error

// Mailer @notice Delivers kal's transactional messages. See [authn.Mailer].
type Mailer = authn.Mailer

// Message @notice What to send. See [authn.Message].
type Message = authn.Message

// LogMailer @notice A development Mailer that logs messages. See [authn.LogMailer].
type LogMailer = authn.LogMailer

// Params @notice Argon2id cost parameters. See [authn.Params].
type Params = authn.Params

// Event @notice One security-relevant thing kal did. See [authz.Event].
type Event = authz.Event

// Audit @notice Called for every security-relevant event. See [authz.Audit].
type Audit = authz.Audit

// Hasher @notice Password hashing with the Argon2 work bounded. See [authn.Hasher].
type Hasher = authn.Hasher

// SessionInfo @notice One live session, as shown to its owner. See [session.Info].
type SessionInfo = session.Info

// VaultParams @notice One account's client-side KDF parameters. See [e2ee.Params].
//
// @dev Not kal.Params: that name is [authn.Params], the server's Argon2id cost, and the two must
// never be confused for each other — they answer to different limits and feeding one from the
// other is how a deployment ends up with vaults nobody can open. Same renaming as SessionInfo.
type VaultParams = e2ee.Params

// VaultOptions @notice Configuration for the vault service. See [e2ee.Options].
type VaultOptions = e2ee.Options

// Vault @notice One user's wrapped root key, opaque to kal. See [e2ee.Vault].
type Vault = e2ee.Vault

// Vaults @notice The vault service. See [e2ee.Vaults].
type Vaults = e2ee.Vaults

// The client KDF names, re-exported so a consumer need not import e2ee to switch on one.
const (
	KDFArgon2id = e2ee.KDFArgon2id
	KDFPBKDF2   = e2ee.KDFPBKDF2
)

// The AuthLevel values, re-exported so a consumer need not import authz for a switch.
const (
	LevelAnonymous     = authz.LevelAnonymous
	LevelAuthenticated = authz.LevelAuthenticated
)

// From @notice Returns the caller, and whether there is one. See [authz.From].
func From(ctx context.Context) (*Principal, bool) { return authz.From(ctx) }

// Require @notice Returns the caller, or a typed UNAUTHENTICATED error. See [authz.Require].
func Require(ctx context.Context) (*Principal, error) { return authz.Require(ctx) }

// HasRole @notice Whether the caller holds the named role. See [authz.HasRole].
func HasRole(ctx context.Context, role string) bool { return authz.HasRole(ctx, role) }

// Scope @notice The caller's ownership predicate, for luima's crud options. See [authz.Scope].
func Scope(ctx context.Context, column string) func(*orm.Query) *orm.Query {
	return authz.Scope(ctx, column)
}

// WithRLSSettings @notice WithRLS, plus consumer settings on the same transaction. See
// [authz.WithRLSSettings].
//
// @dev The direct form, for a caller with its own pool or one resolving settings at the call site
// rather than through Config.RLSSettings.
func WithRLSSettings(ctx context.Context, db *pg.DB, extra map[string]string,
	fn func(orm.DB) error) error {
	return authz.WithRLSSettings(ctx, db, extra, fn)
}

// AssertAuthCoverage @notice Fails if any field is reachable without an @auth annotation. Call
// it from a test. See [authz.AssertAuthCoverage].
func AssertAuthCoverage(schema graphql.ExecutableSchema, exempt ...string) error {
	return authz.AssertAuthCoverage(schema, exempt...)
}

// AssertDirectivesWired @notice Fails if any directive implementation is nil. See
// [authz.AssertDirectivesWired].
func AssertDirectivesWired(directiveRoot any) error {
	return authz.AssertDirectivesWired(directiveRoot)
}

// PresentError @notice luima's presenter plus an extensions.code for kal's errors. Set it as
// luima's Config.ErrorPresenter. See [kalerr.PresentError].
func PresentError(ctx context.Context, err error) *gqlerror.Error {
	return kalerr.PresentError(ctx, err)
}

// ValidatePassword @notice Applies the password policy. See [authn.ValidatePassword].
func ValidatePassword(password string) error { return authn.ValidatePassword(password) }

// NewHasher @notice Builds a Hasher to share across instances. See [authn.NewHasher].
//
// @dev Exported here because [Config.Hasher] is unusable otherwise: a consumer running one
// instance per tenant schema would have to import authn to build the one value that makes the
// Argon2 bound process-wide rather than per instance.
//
// @param p             cost parameters; zero fields take the OWASP defaults
// @param maxConcurrent the in-flight hash ceiling; ≤ 0 means GOMAXPROCS
// @return *Hasher      safe for concurrent use, and for sharing between [New] calls
// @return error        only a CSPRNG failure
func NewHasher(p Params, maxConcurrent int64) (*Hasher, error) {
	return authn.NewHasher(p, maxConcurrent)
}

// ValidateAuthSecret @notice Applies the client-derived secret's shape. See
// [e2ee.ValidateAuthSecret].
func ValidateAuthSecret(s string) error { return e2ee.ValidateAuthSecret(s) }

// NewRecoveryCode @notice Mints a vault recovery code, shown once. See [e2ee.NewRecoveryCode].
func NewRecoveryCode() (string, error) { return e2ee.NewRecoveryCode() }

// NewVaults @notice Builds the vault service directly. See [e2ee.NewVaults].
//
// @dev [New] does this for you from Config.E2EE; this is for a consumer wiring the packages
// separately.
func NewVaults(opts VaultOptions) (*Vaults, error) { return e2ee.NewVaults(opts) }
