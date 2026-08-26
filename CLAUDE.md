# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```sh
make test      # go test ./...            — the TestDB* tests SKIP without a database
make test-db   # same, with .env exported — they run
make check     # gofmt + vet + lint + test-db + audit; run this before any PR
make audit     # govulncheck + gosec
make cover     # coverage profile + summary
```

One test, with the database:

```sh
set -a && . ./.env && set +a && go test -v -count=1 -run TestDBScope ./tests/
```

`make test` alone proves less than it looks: `TestDB*` skips without `DATABASE_URL`, and a skip still
reports `ok` — that silence covers session revocation, token single-use and the unique index. Copy
`.env.example` to `.env` (values **unquoted**) or `docker run -d -e POSTGRES_PASSWORD=postgres -p
5432:5432 postgres:16`. CI greps `--- PASS: TestDB` out of the `-v` output for this reason.

`make audit`'s govulncheck reports stdlib vulnerabilities against the *toolchain that built the code*,
so it fails on an out-of-date local Go even when kal is clean. Upgrade Go, don't suppress.

## Architecture

kal is an embedded library (not a service) giving a gqlgen-on-Postgres app authn/authz. It sits on
[luima](https://github.com/ulas96/luima) ≥ 0.2.1, which owns the Fiber/gqlgen server; kal plugs into
luima's `HTTPMiddleware`, `Configure` and `ErrorPresenter` seams. Read `README.md` for the wiring and
the three-layer authorization story (`@auth` directive → `Scope` → RLS).

| package | role |
|---|---|
| `kal` (root) | `Config`, `New`, the gqlgen guard extension, and a re-export shim |
| `authn` | Argon2id, registration, login, backoff, verification, reset, invite |
| `authz` | `Principal`, `@auth`, `Scope`, `AssertAuthCoverage`, roles, RLS |
| `session` | tokens, store, cookie, net/http middleware, optional JWT leg |
| `kalerr` | the error contract (`Error{Code,Message,Internal}`, `PresentError`) |
| `e2ee` | client-side encryption: per-user KDF params, one wrapped key kal cannot open |
| `migrations` | plain `.sql` behind an `embed.FS` |
| `tests` | every test, in one external `package tests` |

Flow: `session.Middleware` reads the cookie → `Sessions.Lookup` → puts a `*authz.Principal` and a
cookie jar on the request context. Resolvers read identity from `ctx` (`kal.From`/`Require`) and pass
`kal.Scope(ctx, "owner_id")` into luima's crud options so authorization lands in the `WHERE` clause.
Anonymous is never an error and the middleware never returns 401 — the graph decides.

## Invariants

**Re-export shim.** Root types are aliases and root functions are wrappers. A new exported symbol in a
sub-package is invisible from `kal.` until added to `kal.go` **by hand**; `tests/kal_test.go` asserts
the identity of both at compile time.

**All SQL lives in one `sql.go` per package**, rendered with a schema prefix. go-pg is in maintenance
mode, so keeping SQL greppable in one file per package is the migration plan. Error classification
goes through `luimaerr.SQLState`, never a type assertion — `pg.Error` is an interface, not pgx's
`*pgconn.PgError`.

**Tests live outside the packages they exercise.** `package tests` can only reach the exported
surface. If a security property can't be asserted from out there, a consumer can't rely on it either,
and the exported surface is what changes. A behaviour change needs a test that fails without it, and
for a security control the test asserts *the thing that goes wrong* (the row is still in the table),
not that a function returned false.

**The zero `Config` is the production posture.** This inverts luima, where the zero Config is the good
*development* config. There is no `Dev` bool and no environment flag that relaxes a security property;
anything a developer needs is an ordinary named field (`kal.LogMailer{}`, `AllowIntrospection`).

**`docs/gotchas.md` is a register of 61 silent failures** — transport, RLS, schema, gqlgen, errors,
crypto, client-side encryption. Entries 40–63 are absent on purpose: they went to
`github.com/ulas96/kal-zk` with `zkauthn`/`zkauthz` and keep those numbers there. Read the relevant
section before touching those areas; each entry is there because the failure produces no error, no
log line and a passing test suite. A new entry takes the next number after the highest; nothing is
ever renumbered and no gap is ever backfilled, because the numbers are cited from code comments and
from `tests/`.

**Update `CHANGELOG.md` under `## [Unreleased]`.**

## Doc comments

NatSpec tags inside ordinary godoc: open with the symbol name, then `@notice` (what), `@dev` (why it
is written this way), `@param` / `@return`. Comments explain **what breaks if the line is removed** —
`// #nosec G115 -- bounded to [8,64] just above`, not `// convert to uint32`. Do not write a comment
that describes what the next line does, or one that argues the change is correct. The existing files
are the register to aim for.
