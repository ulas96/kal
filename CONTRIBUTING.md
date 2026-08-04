# Contributing

## Before a pull request

```sh
make check   # gofmt + vet + lint + test-db + audit
```

`make test` alone is not enough. The `TestDB*` tests skip without `DATABASE_URL`, and a skipped test
still reports `ok` — in this library that silence covers session revocation, token single-use and the
unique index. Copy `.env.example` to `.env` (values unquoted) and use `make test-db`, or start one:

```sh
docker run -d --name kal-postgres -e POSTGRES_PASSWORD=postgres -p 5432:5432 postgres:16
```

`make audit` runs `govulncheck`, which reports standard-library vulnerabilities against **the
toolchain that built the code** — so it fails on an out-of-date local Go even when kal and its
dependencies are clean. That is the tool working correctly; upgrade Go rather than suppressing it.

## The rules

**A behaviour change needs a test that fails without it.** For a security control, the test should
read as *the thing that goes wrong* rather than as the implementation — `TestDBScope` asserts the row
is still in the table, not that a function returned false, because a delete that reports failure while
succeeding would pass the weaker version.

**New public API needs a runnable example or a test in `tests/`.** Every test lives in one
`package tests` outside the packages it exercises, so it can only reach the exported surface — the
same view a consumer has. If a security property cannot be asserted from out there, a consumer cannot
rely on it either, and the exported surface is what has to change.

**A new exported symbol in a sub-package is invisible from the root until it is added to `kal.go` by
hand.** Types are aliases, functions are wrappers; `tests/kal_test.go` asserts the identity of both at
compile time.

**All SQL lives in one `sql.go` per package.** go-pg is in maintenance mode by its own README, so
confining the SQL to one greppable file per package is the migration plan if a driver swap ever
becomes real. Note also that a driver swap changes the error-classification seam — `pg.Error` is an
*interface*, not pgx's `*pgconn.PgError` — which is why every 23505 check goes through
`luimaerr.SQLState` rather than a type assertion.

**Update `CHANGELOG.md` under `## [Unreleased]`.**

## Doc comments

NatSpec tags inside ordinary godoc comments: open with the symbol name, then `@notice` (what),
`@dev` (why it is written this way), `@param` / `@return`.

Comments explain **what breaks if the line is removed**. `// #nosec G115 -- bounded to [8,64] just
above` is a comment; `// convert to uint32` is noise. If code moves, its comment moves with it. The
existing files are the register to aim for — they are dense because most of what they record was
expensive to learn.

Two things not to do: do not write a comment that describes what the next line does, and do not write
one that argues the change is correct. Both are addressed to a reviewer rather than to the next
reader, and they become noise the moment the pull request merges.

## Style

`golangci-lint` enforces the rest, including `errorlint` — which catches the
`errors.As`-versus-type-assertion class that produced luima's finding E-01. In an error contract that
decides what a client may see, a type assertion that silently never matches is a redaction bypass,
not a style issue.
