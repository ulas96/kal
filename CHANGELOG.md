# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the major version is `0`, the public API may change in a minor release. Every such change
will be listed here under **Changed** with the migration in one line.

## [0.3.0] - 2026-08-08

### Added

- Optional `e2ee` package: one wrapped root key per user, the per-user client KDF parameters that
  produced it, and a pre-auth `Params` query that answers for every address whether or not it has
  an account. Enabled with `Config.E2EE`; `Auth.Vaults` is nil without it. Adds no dependency —
  `crypto/hmac` and `crypto/sha256` are the whole crypto surface, because a package that can
  decrypt is not doing client-side encryption. `TestE2EEImportGraph` pins that as an allowlist over
  the package's own imports.
- `migrations/0003_e2ee.sql`: `auth_e2ee_vaults`, one row per user. No core table is altered.
- `docs/e2ee-client.ts` and `docs/e2ee-client.md`: the pinned wire format and derivation, as a
  reference to copy rather than a package to install. `README.md` gains *Operating the E2EE
  module*, which states plainly that browser-delivered E2EE does not defend against the server that
  serves the JavaScript, and what enabling it costs — no search, no server-side features, and a
  forgotten password that loses the data.
- `kalerr.CodeConflict`, returned by `Vaults.Put` when a concurrent re-wrap got there first. The
  first code in the vocabulary that is not an authentication failure.
- `docs/gotchas.md` gains a *Client-side encryption* section, entries 64–78.
- `docs/e2ee-test-cases.md`: the security test register for `e2ee` — 120 cases in twelve groups and a
  36-row mutation matrix naming the case each mutation must turn red. Thirteen entries under
  `[UNSPECIFIED]` are findings against the design documents rather than against the code, the first
  being that `docs/e2ee-client.md` claims kal validates the blob's version and algorithm bytes when
  it validates only the length.
- The register implemented: `tests/e2ee_test.go` and `tests/e2ee_db_test.go` cite 119 of the 120
  cases, and `tests/e2ee_case_manifest_test.go` pins the reconciliation so the uncovered count can
  only fall by writing a test. The nine `[UNSPECIFIED]` cases assert today's behaviour and name the
  §17 finding they pin, so closing a finding breaks a test rather than passing silently. Three cases
  carry a disposition instead of full coverage: `E2EE-ISO-002` (mutation M-30 cannot live in the
  tree it mutates), `E2EE-DOC-005` (a review checklist, which the register says a code test would
  falsely pass) and `E2EE-SHM-001` (already compile-time in `tests/kal_test.go`).

### Changed

- `authn.AccountsOptions` gains `SecretShape func(string) error`. Nil keeps today's behaviour
  exactly — it defaults to `ValidatePassword`, and the four flows that check a submitted secret
  (`Register`, `ResetPassword`, `AcceptInvite`, `ChangePassword`) go through the field instead of
  calling the function directly. `kal.New` sets it to `e2ee.ValidateAuthSecret` when `Config.E2EE`
  is non-nil, which tightens the accepted secret from an 8–64 character password to 32 bytes of
  derived entropy. No migration for anyone not setting `Config.E2EE`.

  That check pins the encoded length at 43 characters before it decodes, because
  `encoding/base64` skips `\r` and `\n` wherever they appear and `Strict()` governs only padding and
  trailing bits. Without the length check a trailing newline from a shell heredoc and a `\r\n` from
  a Windows client both decode to the same 32 bytes, and one key reaches the password column in
  several forms — the account is hashed over whichever arrived first and the others cannot log in,
  over a vault that would have opened fine (gotcha 78).

  **Rollout.** Every client that touches the password field must be updated in the same release as
  `Config.E2EE` — a second frontend, a mobile app, a `curl` in a runbook, a test fixture. The shape
  check turns a missed one into a login failure rather than a login that succeeds over a vault that
  then never opens, which is the right failure, and it is still a failure. Plan for it.

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
