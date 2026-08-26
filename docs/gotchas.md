# Gotchas

Things that fail silently. Each entry is here because the failure produces no error, no log line and
a passing test suite — which is the only kind of bug worth a register like this.

Entries **40–63 are not missing**: they went to
[`github.com/ulas96/kal-zk`](https://github.com/ulas96/kal-zk) with `zkauthn` and `zkauthz`, and they
keep those numbers there. Nothing in this register is ever renumbered, because the numbers are cited
from code comments and from `tests/`. 81 and 82 stayed — they are about `session` and `authz`.

## Transport

**1 · Never register `transport.UrlEncodedForm`, `transport.MultipartForm` or `transport.GRAPHQL`
while cookie authentication is on.** All three are POST with CORS-*simple* content types and no
operation-type restriction, so a cross-origin HTML form or `fetch` can execute mutations with ambient
cookies and no preflight. That is strictly worse than `transport.GET`, which at least refuses
mutations. If you genuinely need multipart uploads, you need Fiber v3's `csrf` middleware with
`TrustedOrigins` — and note that its v3 config renamed `KeyLookup` to `Extractor` and `Expiration` to
`IdleTimeout`, and that it **panics at startup** if the extractor reads the same cookie it sets.

**2 · `SameSite=Lax` is not sufficient on its own.** It permits the cookie on top-level cross-site
navigation with safe methods, and GraphQL-over-GET is a real thing (persisted queries, CDN caching).
It also applies to the whole registrable domain, so a compromised sibling subdomain defeats it. The
`__Host-` prefix closes that hole and kal's transport guard closes the other.

**3 · One layer owns each cookie name.** fasthttp's `Add` appends rather than replaces, so if
Fiber-side middleware sets a cookie with a name a resolver also sets, you emit two `Set-Cookie`
headers. Browsers take the last and the order is incidental. kal owns `__Host-kal_session`; keep
Fiber's session middleware away from it.

**4 · A deletion cookie must carry the same attributes as the cookie it deletes.** A browser will not
let a non-compliant cookie overwrite a `__Host-` one, so a bare `name=; Max-Age=0` is silently
ignored and the stale token rides along forever. `session.ClearCookie` does this correctly.

## Postgres and RLS

**5 · Table owners bypass RLS unless `ALTER TABLE … FORCE ROW LEVEL SECURITY`.** Most migration
setups connect as the table owner, which means RLS silently does nothing. This is the single most
common way an RLS deployment is quietly broken.

**6 · Superusers and `BYPASSRLS` roles bypass RLS even with `FORCE`.** Measured against Postgres 16:
a superuser sees every row through a policy that excludes them, with no error and no warning. If your
application connects as a superuser — and a default `postgres` user is one — RLS is decoration. kal's
own `TestDBRLS` switches to an unprivileged role and asserts that it did, because otherwise the test
would pass while proving nothing.

**7 · `SET LOCAL` outside a transaction is a no-op.** Postgres emits a warning and otherwise does
nothing, and with a connection pool the setting lands on one pooled connection while the query runs
on another. Everything must be inside `RunInTransaction`.

**8 · A plain session-scoped `SET` leaks to the next request that borrows the connection.** That is a
cross-tenant data leak that only manifests under concurrency. The `true` third argument to
`set_config` is what makes it transaction-local; it is not optional. It is also what keeps this
compatible with PgBouncer in *transaction* pooling mode, precisely because it dies at `COMMIT`.
Statement pooling breaks it entirely.

**9 · Never write a policy where a NULL or empty setting is permissive.**
`current_setting('app.user_id', true)` returns NULL when unset — the `true` is mandatory or it raises
— so `using (current_setting(...) is null or owner_id = ...)` fails open on every connection nobody
configured. Use `nullif(current_setting('app.user_id', true), '')::uuid`, since NULL never equals
anything.

**10 · Prefer a GUC over `SET ROLE`.** A client with any SQL-injection foothold can issue `RESET ROLE`
and escape back to the authenticator role. A GUC-based policy hands out no role-switching primitive.

**11 · `SET search_path` belongs in `OnConnect`, not in an `Exec`.** go-pg is a pool: a one-off `Exec`
configures one connection while later queries run on others.

**12 · `inet::text` drags the netmask along.** `ip::text` on an `inet` column yields `192.0.2.7/32`.
Use `host(ip)`.

**13 · `ON CONFLICT` must name a partial index by its predicate.** `on conflict (lower(email))` does
not match an index declared `where deleted_at is null`; Postgres rejects the statement rather than
silently ignoring the clause. The full form is
`on conflict (lower(email)) where deleted_at is null`.

**84 · A sibling query option can `OR` its way out of `Scope`.** `Scope` returns a
`func(*orm.Query) *orm.Query` that adds one `WHERE`, and luima's crud applies its options left to
right onto the same query. go-pg's `WhereOr` appends ` OR `, not ` AND `, and go-pg does not
parenthesise per option — so
`luima.List[Doc](ctx, db, kal.Scope(ctx, "owner_id"), func(q *orm.Query) *orm.Query { return
q.WhereOr("owner_id = ?", other) })` renders `where owner_id = $1 or owner_id = $2` and returns the
other tenant's rows. Ordering does not save it: the predicate is first and still escaped. Nothing
errors, and a test that only asserts "alice sees her row" still passes, because she does — alongside
everyone else's. The fix is a parenthesised group, which is what `Auth.List`, `Get`, `Update` and
`Delete` do (`owner_id = ? AND (caller clauses)`); reach for the raw `Scope` form only when the
options you pass hold no `WhereOr`, or group them yourself with `q.WhereGroup`.

## Schema

**14 · `unique (lower(email), deleted_at)` is backwards.** NULLs are distinct in a unique constraint,
so it permits unlimited *active* duplicates while forbidding the re-registration you actually want.
The partial index `on auth_users (lower(email)) where deleted_at is null` is the correct shape.

**15 · Do not use `citext`.** Its own documentation warns that its operators silently fall back to
case-sensitive comparison when the extension's schema is not on `search_path` — so `Admin@x.com` and
`admin@x.com` become two accounts with no error anywhere. An expression index on `lower(email)` has no
extension dependency (which also matters on RDS, Cloud SQL and Neon) and no `search_path` hazard.

**80 · `Auth.Migrate` ignores `Config.TableSchema`.** The migration files are deliberately
unqualified and the DDL runs on the connection's `search_path`, so `TableSchema: "tenant_a"` plus
`Migrate` on a default connection creates the tables in `public` and every query then looks for
them in `tenant_a`. That case fails loudly. The one that does not is a provisioning loop whose
`search_path` and `TableSchema` drift apart: one tenant's auth tables are created in another
tenant's schema, and nothing errors. `MigrateSchema` takes the name so the two cannot disagree.

## gqlgen

**16 · Denying a request inside an extension requires `graphql.OneShot`.** gqlgen's own source warns
twice: a short-circuit that returns an error without calling `next()` must be wrapped, or streaming
transports loop infinitely. An auth extension that denies is exactly that case, so the consequence is
a hot infinite loop, not a clean rejection.

**17 · Directives chain inside-out.** The generated code wraps `directive0` in `directive1` in
`directive2`, so the *last*-declared directive is the outermost and runs *first*. Written left to
right, `@auth @hasRole(role: ADMIN)` runs `hasRole` before `auth`. kal composes the checks into one
directive rather than documenting an ordering nobody remembers.

**18 · A nil directive implementation is a runtime error, not a compile error.** Forget to wire
`c.Directives.Auth` and every annotated field fails at request time with "directive auth is not
implemented". gqlgen validates none of this at startup — `kal.AssertDirectivesWired` is the check.

**19 · Denial on a non-null field nulls the *parent*.** A directive returning an error on a nullable
field yields `null` plus an error entry; on a non-null field it can blank an entire object. Prefer
nullable types for conditionally visible fields.

**20 · A schema argument becomes a trailing positional Go parameter in declaration order.** Non-null
gives a value type, nullable gives a pointer, and a default value does *not* make a nullable argument
non-pointer. Reordering arguments in the SDL silently changes the Go signature.

**21 · `ComplexityLimit` does not bound depth.** gqlgen's complexity is per selected field, so 400
levels of nesting through a cyclic schema costs about 400 and sails past a 1000 limit. kal's guard
walks the document.

**22 · Rate limiters count HTTP requests; GraphQL executes many operations per request.** Five
hundred aliased `login` selections in one document is one request. Fiber's `limiter` cannot see this
at all — the counting has to happen in an operation interceptor and in the resolver.

**23 · Introspection defaults to *off* in gqlgen's executor.** `extension.Introspection` exists to
turn it **on**, which luima does. luima 0.2.0 added `Config.DisableIntrospection` for the all-or-
nothing case; kal's `Configure` goes further and makes it a per-request predicate, so it can be
role-gated rather than switched by a deploy.

**24 · Introspection off is a smaller attack surface, not confidentiality.** gqlparser appends
"Did you mean …?" to validation errors, and luima's presenter passes validation errors through by
design — so a caller guessing `nam` still learns there is a `name`. `SetDisableSuggestion(true)` is
what closes it, and `Configure` sets it.

**82 · An empty directive argument list is not an absent one.** gqlgen emits a literal `nil` for a
directive argument the annotation omits, and a non-nil empty slice for one written as `[]`. An
all-of check over the empty set is vacuously true, so `@auth(proves: [])` reads as a restriction and
allows — and on `requires: ANONYMOUS` it is public. kal denies an explicit empty list before the
anonymous fast path; omitting the argument is how a field says it needs no proof.

## Errors

**25 · Never wrap a `*gqlerror.Error` — and know why the rule outlived its bug.** Through luima
0.1.0, `PresentError` matched the gqlerror branch with `errors.As`, which walks the whole chain, so
any error *wrapping* a gqlerror was returned to the client whole — message, path and extensions —
and redaction was effectively opt-out (luima finding E-01). **luima 0.2.0 fixed it** with a type
assertion on the top-level error, and `TestPresentError` pins the fixed behaviour from kal's side so
a regression is caught here rather than in production. Keep the habit anyway: wrapping a gqlerror
says something about the client's query that your own error text probably does not mean.

**26 · `CustomError.Error()` concatenates the internal cause.** Populating a `UserMessage` from any
`err.Error()` undoes redaction in a line that reads like careful error handling (finding E-04). A
client-visible message is always literal text.

**27 · `crud.Create` classifies 23505 into a client-visible "already exists".** On a signup-shaped
mutation that is an account-enumeration oracle: send an address, learn whether it is registered. It
is working as designed — which is why kal inserts into `auth_users` directly and never through
`crud.Create`. The same caution applies to the `label` parameter generally: it is returned verbatim,
so never build one from user input.

## Go and the crypto

**28 · Argon2 `Parallelism` must not be `runtime.NumCPU()`.** The popular wrapper defaults to it,
which makes the cost of hashing depend on which machine served the request — and because `p` is
encoded in the stored hash, verification keeps working and the bug survives review. kal pins `p=1`.

**29 · Argon2's memory parameter is a DoS primitive.** At `m=19456` every in-flight hash holds 19 MiB,
so a hundred concurrent login attempts is 1.9 GB and nothing else in the stack bounds it. kal's
semaphore does; size it against the pod memory limit, and remember the bound is per replica — and,
until you set `Config.Hasher`, per *instance* as well. Gotcha 79.

**79 · `MaxConcurrentHashes` bounds one `*Auth`, so N instances in one process is N times the
bound.** Each `New` builds its own `Hasher` with its own semaphore unless `Config.Hasher` is set,
and zero means GOMAXPROCS *each*. A process holding one instance per tenant schema holds
N·limit·19 MiB in flight: the parameter that stops concurrent logins from becoming a remote OOM
stops bounding anything at exactly the scale where it matters. The process ceiling is the sum, not
the max.

**81 · `mfa_at` is written on the database clock and read on the process clock.**
`Sessions.RecordMFA` stamps `now()` deliberately, so N replicas cannot disagree about when a factor
was satisfied; the `@auth(mfa:)` directive then compares it with `time.Since`, which is the clock of
whichever process is answering. The skew avoided on the write comes back on the read, and it fails
*open* by the skew when the process clock lags the database's — a 15-minute window is really
`window + skew`. Nothing errors, and the step-up looks like it works. Keep both on NTP; the two
clocks meet at `authz/directive.go` and nowhere else in kal.

**30 · Equalize timing with a real hash, not a sleep.** A sleep has a different distribution from a
hash, and an attacker averaging over samples sees the difference. Traefik shipped exactly this bug
(GHSA-g3hg-j4jv-cwfr).

**31 · `subtle.ConstantTimeCompare` returns early when the lengths differ.** Irrelevant for
fixed-length derived keys; anywhere secrets vary in length, hash both sides first.

**32 · golang-jwt v5 does not require `exp` by default.** Without `WithExpirationRequired()` a token
with no expiry validates forever.

**33 · golang-jwt joins its validation errors.** So `errors.Is(err, jwt.ErrTokenExpired)` can be true
on a token whose signature never verified, and the near-universal "expired, let me refresh" branch
then processes a forgery — this is CVE-2024-51744. Return exactly one flat error and check fatal
conditions before benign ones.

**34 · A JWT keyfunc receives the parsed but *unverified* token.** `alg` and `kid` are
attacker-controlled at that point. Fix the algorithm at construction, assert it inside the keyfunc,
and pass `WithValidMethods` as well.

**35 · Skipping `aud` validation is worse than it sounds.** Against a shared multi-tenant issuer, a
token minted for any other tenant authenticates against your API.

**36 · Never read-then-write an emailed token.** That shape leaves a window in which a
double-submitted link is consumed twice, and a double-clicked email link — or a mail client
prefetching URLs — hits it routinely. One `UPDATE … WHERE consumed_at IS NULL … RETURNING`.

**37 · A password-reset *request* must not mutate the account.** Anything it changes is a denial of
service anyone can trigger against any address.

**38 · The reset token is in a URL, so it leaks through `Referer`.** Any third-party asset on the
landing page receives it. Send `Referrer-Policy: no-referrer`, serve that page with no third-party
assets, and ideally exchange the token immediately and `history.replaceState` the URL out of history.

**39 · A skipped test still reports `ok`.** The `TestDB*` tests skip without `DATABASE_URL`, and in an
auth library that silence would cover session revocation, token single-use and the unique index. CI
greps `--- PASS: TestDB` out of the `-v` output for exactly this reason.

**83 · The email lookup key is lowercased twice, by two Unicode tables that version
independently.** Every address-keyed statement is `where lower(email) = ?`: Postgres lowers the
column with the collation's tables, Go lowers the parameter with its own
(`strings.ToLower(strings.TrimSpace(email))` in `authn`'s `Login`, `Register`,
`RequestPasswordReset` and `Invite`, and in `e2ee.Vaults`' `Params` and `Put`). A row is found
only where the two agree, and either side moves on its own schedule — a Go upgrade, or a
Postgres/ICU/glibc upgrade. Go 1.27 moved Go's side from Unicode 15 to 17, which gave 55 runes a
lowercase mapping they did not have before; no existing mapping changed.
Measured against Postgres 16.14 on `en_US.utf8` with the libc provider, that upgrade *aligns* five
letters Go previously left alone while Postgres folded them (U+A7CB `Ɤ`, U+A7CC `Ꟍ`, U+A7DA `Ꟛ`,
U+A7DC `Ƛ`, U+1C89 `Ᲊ`) and *newly diverges* three where Go now leads glibc (U+A7CE, U+A7D2,
U+A7D4). On a diverging address nothing errors: `Login` returns the deliberately
indistinguishable INVALID_CREDENTIALS, and `Vaults.Params` takes its `pg.ErrNoRows` branch and hands
back the *decoy* salt — the one path that must answer every address to avoid the enumeration oracle,
so it structurally cannot report a miss and the client derives a key that opens nothing. The unique
index is `on conflict (lower(email))`, so uniqueness is enforced under Postgres's table alone. If you
accept non-ASCII addresses, normalise once at the edge and store the normalised form, so the key is
a stored value rather than something re-derived from whichever toolchain and collation happen to be
running.

**85 · The `gofmt` gate is green on a file `gofmt` could not read.** `scoped.go` carries generic
methods, which the compiler, `go vet`, `go doc` and golangci-lint all accept and which gofmt in Go
1.27.0 rejects: `scoped.go:91:20: method must have no type parameters`. Those parse errors go to
*stderr* and gofmt lists nothing on stdout, so `make check`'s `test -z "$(gofmt -l .)"` and CI's
`unformatted=$(gofmt -l .)` both compare against an empty string and report the tree formatted, while
`gofmt -w` and `go fmt ./...` leave the file untouched and say nothing either. The gate is not wrong
about the other files — it never saw this one, and it will not see the next generic-method file
either. Read the *exit status* instead of the output when you touch one: `gofmt -l . >/dev/null`
exits 2 here. It is documented rather than fixed because routing stderr into the gate would fail the
run over code that compiles, tests and lints clean.

## Client-side encryption

**64 · The server that serves the JavaScript can serve JavaScript that exfiltrates the key.**
Browser E2EE defends against a database leak and an honest-but-curious operator. It does not defend
against the operator. A consumer who believes otherwise has skipped the control that would have
worked.

**65 · A raw password accepted where an auth secret was expected.** Login succeeds, the vault never
opens, and nothing anywhere errors or logs. One un-updated client does this to real users, which is
why `ValidateAuthSecret` is a shape check and not a hint.

**66 · Argon2's `parallelism` must be pinned on the client too.** kal pins `p=1` server-side for
cost predictability (gotcha 28); the client pins it because `p` changes the output. A browser that
picks `p` from the thread pool derives a different key on a laptop than on a phone, and the second
device reports a corrupt vault.

**67 · KDF parameters must be stored per user, not read from config at derive time.** Raise the
default memory cost and every existing vault becomes unopenable, with a working login and no error.

**68 · A random decoy salt for an unknown address is an enumeration oracle.** Call twice: the decoy
moves, the real salt does not. Both come from one HMAC over the pepper, so they are
indistinguishable by construction rather than by care.

**69 · Rate-limiting the params query through `auth_login_attempts` locks accounts out.** The table
is the login backoff; feeding it from an unauthenticated pre-auth endpoint lets anyone lock any
account by repeatedly asking for its salt. Rate-limit at the edge, not through the auth counter.

**70 · AES-GCM without AAD lets ciphertext move between rows.** Anyone who can write the column can
swap two of the user's own encrypted fields, and the client decrypts both. Resource, record id and
owner are bound into the AAD, and the reference client binds the wrapped data key the same way.

**71 · Nonce reuse under one key is a total GCM break, not a degradation.** A single vault key over
every record with a random 96-bit nonce reaches the birthday bound; a collision leaks both
plaintexts and the authentication key. Per-record DEKs.

**72 · An encrypted column cannot be indexed, sorted, filtered or searched.** A blind index restores
equality lookup and is an offline dictionary oracle on any low-entropy field, which is most of the
fields anyone wants to encrypt.

**73 · Encryption is not authorization.** A ciphertext row still needs `Scope`. The two controls
fail open with respect to each other, and "it's encrypted" reads like a reason to skip the `WHERE`
clause.

**74 · A vault whose password changed underneath it reads as a live vault.** Without the
`wrapped_for` fingerprint the client receives a key it cannot possibly open and fails somewhere far
from the cause. The write and the staleness read compute that fingerprint from one shared SQL
expression, because two copies that drift make every vault in the deployment read as stale forever.

**75 · WebCrypto has no Argon2id.** The native option is PBKDF2, which is GPU-cheap, so a client
written against "what the browser has" produces a weak wrapping key by default. `kdf` is a stored
per-user column so moving a user off it is a re-wrap on their next login, not a migration.

**76 · Enabling E2EE removes the server's ability to enforce a password policy.** It never sees a
password. Client-side strength checks are advisory against anyone who can call the API directly.

**77 · An unbounded vault blob is free storage for any authenticated caller.** `MaxBlob` is checked
before the insert.

**78 · `base64.Strict()` does not reject whitespace.** `encoding/base64` skips `\r` and `\n`
wherever they appear in the input, and `Strict()` governs padding and trailing bits only — so a
strict decode of a 32-byte auth secret accepts the trailing newline a shell heredoc adds, a `\r\n`
from a Windows client, and a newline in the middle. Each is a distinct string reaching the password
column and a distinct Argon2id hash over one key, so the account is hashed over whichever form
arrived first and the other one fails to log in, with a vault that would have opened fine.
`ValidateAuthSecret` pins the encoded length at 43 characters before it decodes.
