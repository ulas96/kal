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

Requires **luima ≥ 0.2.0** for the `HTTPMiddleware`, `Configure` and scoped-`crud` seams — kal is
built and tested against `v0.2.1`. Postgres 13 or newer (`gen_random_uuid()` is built in from 13).

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
(`migrations.FS`), or `auth.Migrate(ctx)` runs them in order if you have no tooling yet. `Migrate`
runs the DDL on the connection's `search_path` and ignores `Config.TableSchema`; for one schema per
tenant use `auth.MigrateSchema(ctx, "tenant_a")`, which creates the schema and sets `search_path`
transaction-locally so the two cannot drift apart. If you generate code from `information_schema`,
`migrations.Tables()` is the list to exclude — several kal tables carry a `user_id` column, and a
generator following the usual owner-column convention will happily emit CRUD over `auth_user_roles`,
which is a mutation that grants its caller any role.

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
| `e2ee` | the client-side encryption vault: per-user KDF parameters and one wrapped key kal cannot open |
| `migrations` | the schema, as `.sql` behind an `embed.FS` |
| `tests` | every test, outside the packages it exercises |

### Operating seams

Optional `Config` fields for deployments that outgrow the defaults. Every one of them is a named
field rather than a mode, because the zero `Config` is the production posture and nothing here
relaxes a security property.

| field | what it is for |
|---|---|
| `Audit` | A `func(ctx, kal.Event)` called for the security-relevant things kal sees and a consumer structurally cannot: `login.ok`, `login.fail`, `backoff.open`, `password.rehash`, `mail.fail`, `session.lookup.fail`, `session.revoked`. Synchronous, so a hook that talks to the network must queue internally. Nil discards. Role grants and `e2ee` are not in the vocabulary yet. |
| `Hasher` | A pre-built `kal.NewHasher(params, max)` shared between instances. Without it every `New` builds its own Argon2 semaphore, so a process holding one instance per tenant schema holds N × the limit in flight at ~19 MiB each — the bound stops bounding at the scale where it matters. Setting it beside `Argon2` or `MaxConcurrentHashes` is an error, not a silently ignored cost parameter. |
| `RLSSettings` | `func(ctx) map[string]string` of extra `app.`-prefixed settings carried on `auth.WithRLS`'s transaction, for tenancy that is not a single owner column. `app.user_id` and `app.roles` are refused — they carry the caller. `authz.WithRLSSettings` is the direct form. |
| `Proofs` | `func(ctx, []string) error` — what `@auth(proves:)` resolves through, as a plain func so kal carries no dependency on a proof module. Nil denies every non-empty `proves` requirement: an installed schema whose proof module was never wired must refuse, not run unguarded. [`kal-zk`](https://github.com/ulas96/kal-zk) supplies one. |
| `ExtraMiddleware` | `[]func(http.Handler) http.Handler` mounted **inside** the session middleware, index 0 outermost. Inside, not around: anything here that reads the caller runs after the cookie has resolved into a `Principal`, and would see anonymous if it ran first. |
| `SensitiveFields` | Fields no document may select twice. It **replaces** kal's defaults rather than extending them — `DefaultSensitiveFields()` returns a fresh copy so you can `append` instead of restating the list. A module beside kal has mutations kal cannot know the names of; adding your own without appending silently drops the aliasing guard on `login`. |

A second factor is `auth.Sessions.RecordMFA(ctx, db, sessionID, userID)`: verify whatever factor you
ship, call it, and `@auth(mfa: true)` passes for `MFAWindow`. It does not rotate the session, and it
takes no timestamp — `now()` is the database clock.

### What it costs you to depend on kal

Beyond luima's graph, kal adds **two** direct requires — read `go.mod` for the pinned versions and
`go.sum` for the full transitive set:

| module | why | who pays |
|---|---|---|
| `github.com/golang-jwt/jwt/v5` | the optional JWT leg | everyone |
| `golang.org/x/sync` | the Argon2 semaphore that bounds concurrent hashing | everyone |

Argon2 costs nothing new — `golang.org/x/crypto` is already there.

**"Who pays: everyone" is literal, which is why this list is now short.** Until 0.5.0 it also held
`consensys/gnark` and `consensys/gnark-crypto`. They were *direct* requires, so they entered the
module graph of every consumer and were recorded in every consumer's `go.sum` — **116 packages and
four modules** — whether or not a single line of `zkauthn` was imported and whether or not
`Config.ZK` was ever set. Leaving it nil turned the feature off at runtime; it did not remove the
modules, and no build tag could, because build tags select which files compile and do not change
what `go.mod` requires.

0.5.0 moved `zkauthn` and `zkauthz` to [`github.com/ulas96/kal-zk`](https://github.com/ulas96/kal-zk),
which is the only thing that does remove them.
`go list -deps github.com/ulas96/kal | grep gnark` now returns nothing, and `go list -m all` reports
zero gnark modules where it used to report four. Measured rather than predicted: a program whose
entire body is `_ = kal.Config{}` links 398 packages into 8,438,898 bytes against 0.4.0 and 258
packages into 6,965,890 against 0.5.0 — 1.4 MiB and 140 packages every consumer used to carry to
link a feature it may never have called. (darwin/arm64, go1.26, no build flags.)

If you use proofs, add that module and read its README for the wiring; if you do not, upgrading
makes your `go.sum` shorter and costs you nothing.

## Deliberately not here

WebAuthn/passkeys (a second authentication system's worth of surface; verify the factor yourself and
call `Sessions.RecordMFA` to stamp `auth_sessions.mfa_at`, which is what `@auth(mfa:)` reads), an
admin UI, a scaffolding CLI, email templating
beyond a one-method `Mailer`, avatar storage, a policy DSL, SMS as a second factor, magic links as a
primary factor, and a pluggable `Store` interface — Postgres is the premise, so that interface would
have one implementation and would forbid the `JOIN` that is the entire point.

Zero-knowledge proofs are not here either, as of 0.5.0: `zkauthn` and `zkauthz` are
[`github.com/ulas96/kal-zk`](https://github.com/ulas96/kal-zk).

OAuth/OIDC and TOTP MFA are planned as **separate modules**, not merely separate packages, because a
separate package in this module would still put its dependencies in every consumer's graph. That is
not a prediction: it is what `zkauthn` did with `gnark` for three minor releases, and extracting it
is what the two `Config` seams above exist for. The next optional subsystem starts outside.

## Zero-knowledge proofs

Moved out in 0.5.0. `zkauthn` (Groth16/BN254 knowledge and membership proofs, the credential tree,
pseudonymous login) and `zkauthz` (proven claims behind `@auth(proves:)`) are
[`github.com/ulas96/kal-zk`](https://github.com/ulas96/kal-zk), which requires kal ≥ 0.5.0 and plugs
in through `Config.Proofs`, `Config.ExtraMiddleware` and `DefaultSensitiveFields()`. Its README
carries the wiring, the operating notes and the anonymity qualification.

kal keeps `migrations/0002_zk.sql` unchanged and its eight tables in `migrations.Tables()` —
production databases have applied it and their trackers hold a row for it. SQL text carries no Go
dependency, so keeping the file removes nothing from anyone's module graph.

## Operating the E2EE module

Browser-delivered end-to-end encryption does not protect against the server that serves the
JavaScript. An operator who wants the plaintext ships one line of JS to one user and has their
master key on the next page load, and no amount of care in this Go package changes that. Anyone
who tells you otherwise is selling something. A consumer who deploys this believing it defends
against their own server has deployed the wrong control, and the failure mode is that they *stop*
doing the thing that would have worked.

The honest claim is: **kal cannot read your data, and neither can anyone who reads your database.**
That claim is true, it is worth a lot, and it is the only one to make. A stolen dump, a stolen
backup, a compromised replica, a subpoenaed snapshot and a curious operator all yield ciphertext
plus a per-user Argon2id-wrapped key.

**What it costs.** Forgetting the password means losing the data — that is not a bug to be fixed
later, it is the property. Encrypted columns cannot be indexed, sorted, filtered or full-text
searched, and a blind index that restores equality lookup is an offline dictionary oracle on any
low-entropy field, which is most of the fields anyone wants to encrypt. Server-side features that
read user data — digest emails, admin support tooling, analytics, a report generator — stop
working, permanently. And kal can no longer enforce a password policy, because it no longer sees a
password. Each of these is a product decision wearing a technical costume, and each belongs in your
own README before a line is written.

**The client is yours.** kal ships `docs/e2ee-client.ts` and `docs/e2ee-client.md` as a reference
to copy, not a package to install — the format is pinned, so there is no version to keep in sync.
Every client that touches the password field must be updated in the same release as `Config.E2EE`.
`ValidateAuthSecret` turns a missed one into a login failure rather than a login that succeeds over
a vault that then never opens, which is the right failure, but it is still a failure.

**Encryption is not authorization.** A ciphertext row is still a row with an owner and still needs
`kal.Scope(ctx, "owner_id")`. The two controls are orthogonal and each fails open with respect to
the other.

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
