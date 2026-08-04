# kal

Authentication and authorization for [gqlgen](https://gqlgen.com) applications on Postgres, as an
embedded library rather than a service. Built to sit alongside [luima](https://github.com/ulas96/luima).

> **Sessions in your database. Identity in the request context. Authorization in the WHERE clause.**

Three positions, each one taken against how the rest of the Go ecosystem does it.

**Sessions in your database.** Opaque server-side sessions, so revoking one is an `UPDATE`, "log out
everywhere" is one statement, and a user can list their own devices — all things that are
structurally unimplementable with stateless-only tokens. Kratos, SuperTokens and Zitadel are separate
services with separate databases, which costs you the `JOIN`, the shared transaction, and a second
backup and migration story. And because the session cookie is the long-lived credential, kal ships
**no refresh token at all**: nothing to rotate, no reuse-detection family, no two-tab race. That
entire subsystem — the largest single chunk of every JWT-first auth library — does not exist here.

**Identity in the request context.** The middleware is `net/http`, mounted inside luima's Fiber
adaptor, so a resolver reads a typed `*kal.Principal` from its own `ctx`. Anonymous is not an error
and the middleware never returns 401: one GraphQL endpoint serves public and private fields in the
same document, so the graph decides.

**Authorization in the WHERE clause.** Every authorization library in Go answers "may Alice read
document 7". None answers "which documents may Alice read" without N checks or a thousand-item ID
list. `kal.Scope` composes the caller's ownership predicate into the statement, which answers both
and applies to a `DELETE` without a read-then-check round trip that has a TOCTOU window.

## Install

```sh
go get github.com/ulas96/kal
```

Requires **luima ≥ 0.2.0** for the `HTTPMiddleware`, `Configure` and scoped-`crud` seams. Postgres 13
or newer (`gen_random_uuid()` is built in from 13).

## Wiring

```go
auth, err := kal.New(kal.Config{
    DB:      db,                          // *pg.DB
    BaseURL: "https://app.example.com",   // where emailed links point
    Mailer:  myMailer,                    // one Send method; kal ships no SMTP client
})
if err != nil {
    log.Fatal(err)
}

c := generated.Config{Resolvers: &graph.Resolver{DB: db, Auth: auth}}
c.Directives.Auth = auth.Directive()

app := luima.New(luima.Config{
    Schema:         generated.NewExecutableSchema(c),
    HTTPMiddleware: []func(http.Handler) http.Handler{auth.Middleware()},
    Configure:      auth.Configure(),
    ErrorPresenter: kal.PresentError,
})
```

Apply the schema with your own migration tool — the SQL is plain files behind an `embed.FS`
(`migrations.FS`), or `auth.Migrate(ctx)` runs them in order if you have no tooling yet.

Paste `authz.DirectiveSDL` into your `.graphqls`, and bind the enum in `gqlgen.yml`:

```yaml
models:
  AuthLevel:
    model: github.com/ulas96/kal/authz.AuthLevel
```

A login resolver is then three lines, because the cookie travels through the context:

```go
func (r *mutationResolver) Login(ctx context.Context, email, password string) (*model.User, error) {
    p, err := r.Auth.Accounts.Login(ctx, r.DB, email, password)
    if err != nil {
        return nil, err   // one INVALID_CREDENTIALS for every way it fails
    }
    return r.userByID(ctx, p.UserID)
}
```

## The three authorization layers

Ship all three. Each catches what the one above it misses.

**1 · The `@auth` directive** — coarse and declarative. One composed directive, never a stack,
because gqlgen chains directives inside-out and `@auth @hasRole(ADMIN)` runs `hasRole` first, which
is the opposite of how everyone reads it.

```graphql
type Query {
  health: String            @auth(requires: ANONYMOUS)
  me: User                  @auth
  auditLog: [Entry!]        @auth(roles: ["admin"])
  billingEmail: String      @auth(mfa: true)
}
```

The implementation reads only the context and never queries — a directive on a field of a list type
runs once per row, so a check that costs a query is an N+1 that appears only under load.

**2 · `Scope`** — the real enforcement.

```go
func (r *mutationResolver) DeleteDoc(ctx context.Context, id string) (bool, error) {
    return luima.Delete(ctx, r.DB, &model.Doc{ID: id}, kal.Scope(ctx, "owner_id"))
}
```

A row that exists but is not yours matches nothing, so the delete reports that nothing happened.
"Not yours" and "does not exist" become indistinguishable, which is the correct answer to give an
unauthorized caller. An anonymous caller gets a predicate matching nothing — never an open query.

Need something kal does not model? `Scope` returns a plain `func(*orm.Query) *orm.Query`, so call
OpenFGA inside your own closure and return `q.Where("id = any(?)", pg.Array(ids))`. There is no
`Authorizer` interface to implement.

**3 · Postgres RLS** — optional, and the point of it is that it survives a forgotten check in the two
above.

```go
err := auth.WithRLS(ctx, func(tx orm.DB) error { /* … */ })
```

Read `authz.WithRLS`'s doc comment before writing a policy. Four things there have each silently
broken a production deployment, and [`docs/gotchas.md`](docs/gotchas.md) lists them.

## The coverage test

The single highest-value thing in this library, and it is forty lines:

```go
func TestAuthCoverage(t *testing.T) {
    schema := generated.NewExecutableSchema(generated.Config{Resolvers: &graph.Resolver{}})
    if err := kal.AssertAuthCoverage(schema, "Query.health", "Mutation.login"); err != nil {
        t.Fatal(err)
    }
    if err := kal.AssertDirectivesWired(generated.DirectiveRoot{Auth: auth.Directive()}); err != nil {
        t.Fatal(err)
    }
}
```

The failure mode of resolver-level authorization is a *forgotten* check, and a forgotten check is
invisible: it compiles, it passes review, and it returns data. Walking the schema is the only way to
see the absence of something. It reports every miss at once, and it is a test rather than a startup
check so that adding a public field means a red test you annotate away — not a server that refuses to
boot on a Friday.

## Transport rules

kal's middleware requires every request to carry a `Content-Type` outside
`{text/plain, application/x-www-form-urlencoded, multipart/form-data}`, or an `X-Kal-Operation` /
`X-Requested-With` header. Those content types plus a header-free GET are exactly the CORS *simple
request* set — what a browser sends cross-origin with cookies and no preflight. Requiring anything
outside it forces a preflight the attacker's origin cannot pass. No token, no state.

> **Never register `transport.UrlEncodedForm`, `transport.MultipartForm` or `transport.GRAPHQL` while
> cookie authentication is on.** All three are POST with CORS-simple content types and no
> operation-type restriction, so a cross-origin form can execute mutations with ambient cookies.

luima sets no `Access-Control-Allow-Origin` anywhere, so configure `cors.New` with an explicit origin
list — never `*` with credentials.

## What is in the box

| package | what it holds |
|---|---|
| `kal` | `Config`, `New`, the guard extension, the re-export shim |
| `authn` | Argon2id, registration, login, backoff, verification, reset, invite |
| `authz` | `Principal`, `@auth`, `Scope`, `AssertAuthCoverage`, roles, RLS |
| `session` | tokens, the store, the cookie, the middleware, the JWT leg |
| `kalerr` | the error contract |
| `migrations` | the schema, as `.sql` behind an `embed.FS` |
| `tests` | every test, outside the packages it exercises |

The core adds **one** dependency beyond luima's graph: `golang-jwt/jwt/v5`, and only for the optional
JWT leg. Argon2 costs nothing new — `golang.org/x/crypto` is already there.

## Deliberately not here

WebAuthn/passkeys (a second authentication system's worth of surface; `auth_sessions.mfa_at` and
`@auth(mfa:)` are the seam if it is ever added), an admin UI, a scaffolding CLI, email templating
beyond a one-method `Mailer`, avatar storage, a policy DSL, SMS as a second factor, magic links as a
primary factor, and a pluggable `Store` interface — Postgres is the premise, so that interface would
have one implementation and would forbid the `JOIN` that is the entire point.

OAuth/OIDC and TOTP MFA are planned as separate opt-in packages, so their dependencies stay out of
the graph of anyone who does not use them.

## Development

```sh
make test      # go test ./...          — the TestDB* tests SKIP without a database
make test-db   # same, with .env loaded — they run
make check     # fmt + vet + lint + test-db + audit
make audit     # govulncheck + gosec
```

A green `go test ./...` proves less than it looks: the `TestDB*` tests skip without `DATABASE_URL`,
and a skip still reports `ok`. In this library that silence would cover session revocation, token
single-use and the unique index. Copy `.env.example` to `.env` and run `make test-db`; CI pins it
with a `postgres:16` service container and greps `--- PASS: TestDB` out of the `-v` output.

## Licence

MIT. See [LICENSE](LICENSE).
