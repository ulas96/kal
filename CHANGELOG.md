# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the major version is `0`, the public API may change in a minor release. Every such change
will be listed here under **Changed** with the migration in one line.

## [0.1.0] - 2026-08-05

Initial development. Everything below is new.

### Added

- **`kal`** — root package re-exporting the five below, so the common case is one import.
  `kal.Principal` is a type alias for `authz.Principal`, not a copy, so the two spellings are
  interchangeable. Holds `Config`, `New`, the anti-batching guard extension and the conditional
  introspection mutator.
- **`kal/authn`** — Argon2id over `x/crypto` with `p` pinned to 1 and PHC encoding, so cost can be
  raised later without a password reset; registration, login, logout, password change; exponential
  per-account and per-IP backoff in Postgres; email verification, password reset and invitations
  over one emailed-token design; a one-method `Mailer`.
- **`kal/authz`** — `Principal` on the request context, the composed `@auth` directive,
  `AssertAuthCoverage`, `AssertDirectivesWired`, `Scope`, roles, and the `WithRLS` helper.
- **`kal/session`** — opaque Postgres sessions with idle and absolute expiry, the `__Host-` cookie,
  the `net/http` middleware with its cookie jar and cross-site transport guard, and the optional
  Ed25519 JWT leg with a JWKS handler.
- **`kal/kalerr`** — `Error` with a stable `Code`, and a presenter that wraps luima's rather than
  replacing it, so the redaction contract keeps running.
- **`kal/migrations`** — the schema as plain `.sql` behind an `embed.FS`. No migration framework.

### Notes

- Registration does **not** use `luima.Create`. That helper classifies SQLSTATE 23505 into a
  client-visible "already exists", which on a signup mutation is an account-enumeration oracle. kal
  inserts directly and treats a duplicate as success from the caller's point of view, branching only
  on which message is emailed.
- Session roles are read fresh on every lookup, in the same round trip, rather than frozen at login.
  Revoking a role therefore takes effect on the holder's next request at no extra cost.
- `AssertDirectivesWired` is a separate function from `AssertAuthCoverage` because a schema walk
  cannot reach the consumer's generated `DirectiveRoot`, which is a type in their module.
- `kalerr.Error` also satisfies `errors.As` for a `*luimaerr.CustomError` target, so a consumer who
  forgets to swap the error presenter still gets safe messages on the wire instead of "internal
  server error" for every auth failure — minus the `extensions.code`, which is the visible nudge.
- The `mfa` argument on `@auth` and the `auth_sessions.mfa_at` column ship, and `mfa: true` fails
  closed while no MFA module is installed. They are the seam a later module plugs into.

### Requirements

- **luima ≥ 0.2.0**, pinned to `v0.2.1`, for the `Config.HTTPMiddleware` and `Config.Configure`
  seams and for the query options on `crud.Get`, `crud.Update` and `crud.Delete` that `Scope`
  composes into. `TestDBLuimaIntegration` exercises all three through a real Fiber app: a login
  cookie surviving the fasthttp adaptor, a typed `Principal` and a deadline reaching a resolver,
  and the anti-batching guard registered through `Configure`.
- Postgres 13 or newer, for `gen_random_uuid()`.

### Not included, deliberately

OAuth/OIDC and TOTP MFA are planned as separate opt-in packages so their dependencies stay out of the
graph of anyone who does not use them. WebAuthn/passkeys, an admin UI, a scaffolding CLI, email
templating, avatar storage, a policy DSL, SMS as a second factor, magic links as a primary factor,
and a pluggable `Store` interface are out of scope — see the README and `SECURITY.md` for why each.

### Still to come

- An `examples/quickstart` nested module. Now unblocked — luima 0.2.1 is published and
  `TestDBLuimaIntegration` already wires the same three seams — but it needs a gqlgen codegen step
  and a nested module, which is a separate piece of work.
