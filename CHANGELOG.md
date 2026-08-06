# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the major version is `0`, the public API may change in a minor release. Every such change
will be listed here under **Changed** with the migration in one line.

## [0.2.0] - 2026-08-06

### Added

- Optional `zkauthn` and `zkauthz` packages: Groth16/BN254 knowledge and membership proofs,
  database-backed sparse Merkle credentials, pseudonymous sessions, and `@auth(proves:)`.

Design documents, not released surface:

- `docs/e2ee-handout.md` — the design for an optional `e2ee` package: client-hardened login password,
  one vault row per user, and a wire format kal cannot decrypt. Document only; nothing is built yet.
- `docs/security-audit-handout.md` — the procedure for an end-to-end security audit of the module:
  verdicts against the claimed controls, thirteen passes over the surface, and a report format.
  Document only; nothing is built yet.

### Security

Twenty findings from the zk module review are closed. The four that were exploitable:

- `ZK.Login` could never succeed — the resolving statement's outer join read `auth_users` from the
  snapshot taken before its own CTE inserted the pseudonym. Two statements now, and the resolve
  matches the derived `zk-<hex>@invalid` address, so a nullifier bound to a real password-holding
  account can no longer receive that account's session.
- Revoking the highest live leaf aborted on a duplicate root and rolled `revoked_at` back with it,
  leaving the credential able to prove membership. Republishing a returned-to root is now correct.
- Replacing a knowledge commitment required only a session cookie, so the second factor was
  defeated by the first. It now takes the current password, or recent MFA on an account without one.
- Proof verification ran inside the database transaction, converting CPU pressure on an
  unauthenticated endpoint into connection-pool exhaustion. It runs before the transaction opens;
  the single-use `UPDATE` remains the sole arbiter of challenge freshness.

Also: a recurring claim is no longer implicitly a login endpoint, an unknown claim name and a
retired root now cost a real pairing, a one-shot allowance is not burned when delivery fails, and
`proves: ["vote","vote"]` is no longer satisfied by one grant.

The 147-case register in `docs/vulnurability-test-cases.md` is disposed of explicitly: 51 cases
covered by a named test, 18 excused with reasons, 78 listed in a dated roadmap (§26) with the count
pinned in `tests/zk_case_manifest_test.go`. `SECURITY.md` gains 25 zk control rows, each naming a
test that exists and runs.

### Changed

- `authz.Directive` and the generated `DirectiveRoot.Auth` take a seventh parameter, `proves
  []string`. Regenerate gqlgen and add the parameter to the assignment in your resolver root.
- `authz.Scope` returns a false predicate for a principal with an empty `UserID`, where it
  previously returned an unfiltered query. An anonymous scope now matches no rows.
- `zkauthn.Options` requires a `Hasher`, and `zkauthn.EnrollKnowledge` takes a third parameter,
  `currentPassword string`. Pass `""` on first enrolment; replacing an existing commitment
  re-verifies the password, or recent MFA when the account has none, and revokes other sessions.

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
