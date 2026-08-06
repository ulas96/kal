# Gotchas

Things that fail silently. Each entry is here because the failure produces no error, no log line and
a passing test suite — which is the only kind of bug worth a register like this.

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

## Schema

**14 · `unique (lower(email), deleted_at)` is backwards.** NULLs are distinct in a unique constraint,
so it permits unlimited *active* duplicates while forbidding the re-registration you actually want.
The partial index `on auth_users (lower(email)) where deleted_at is null` is the correct shape.

**15 · Do not use `citext`.** Its own documentation warns that its operators silently fall back to
case-sensitive comparison when the extension's schema is not on `search_path` — so `Admin@x.com` and
`admin@x.com` become two accounts with no error anywhere. An expression index on `lower(email)` has no
extension dependency (which also matters on RDS, Cloud SQL and Neon) and no `search_path` hazard.

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
semaphore does; size it against the pod memory limit, and remember the bound is per replica.

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

## Circuits

**40 · An under-constrained circuit proves a false statement.** Honest witnesses also satisfy an
under-constrained system, so tests must compare a plain-Go oracle with the circuit in both directions.

**41 · `Path[0]` is prover-supplied.** Merkle verification without binding it to the prover's
secret proves that some public leaf exists, not that the prover knows its secret.

**42 · A public input the circuit never reads is not bound to the proof.** Both ZK circuits spend
one explicit multiplication binding the challenge; removing it turns a proof into a replayable token.

**43 · Groth16 proofs are malleable.** Deduplicating proof bytes is not replay protection. A
server challenge must be a public input consumed by the circuit and atomically burned.

**44 · One hash domain for two purposes is a domain-crossing bug.** Knowledge commitments,
membership leaves, nullifiers and empty leaves use separate versioned domain elements.

**45 · Values at or above the field modulus wrap silently.** Secrets and audiences are 31 bytes,
attributes are range-checked to 64 bits, and all field encodings are canonical before gnark sees them.

**46 · Comparing an attribute that was never range-checked is not the policy comparison.** The
membership circuit bounds the attribute to 64 bits before checking its threshold.

**47 · `test.IsSolved` proves only that one witness satisfies the system.** The false-to-reject
half of a differential test is the part that catches a missing constraint.

## The gnark surface

**48 · `merkle.VerifyProof` calls its leaf-index parameter `leaf`.** The leaf value is `Path[0]`;
passing those two field elements in the opposite positions compiles and proves a different tree.

**49 · Reordering circuit fields changes the public-witness layout.** The declaration order is
part of the protocol and is pinned by the circuit identity, not merely by the constraint count.

**50 · `UnsafeReadFrom` skips curve and subgroup checks.** Proofs and keys use `ReadFrom`; verification
does not repair an unsafe deserialization performed earlier.

**51 · Native and in-circuit MiMC are separate implementations.** A cross-implementation test pins
their byte and field-element conventions before a mismatch makes every valid proof fail.

## The tree and the protocol

**52 · An empty leaf of zero is a credential target.** Empty leaves are a domain-separated MiMC
constant, so finding a credential equal to one requires a collision rather than a preimage for zero.

**53 · An in-memory tree is a different root per replica.** Sparse nodes and roots live in Postgres,
so restarts and multiple pods observe one tree.

**54 · Concurrent appends can publish a root no path verifies against.** A transaction-scoped
advisory lock is acquired before the first tree read and held through node and root publication.

**55 · A retired root that still verifies is a revoked credential that still authenticates.**
`RootGrace` is explicitly revocation latency and defaults to accepting only the current root.

**56 · A nullifier that is both a pseudonym and single-use is neither.** Recurring audiences keep
their nullifier as a stable account key; one-shot audiences burn it for exactly one action.

**57 · A nullifier checked by `SELECT` then `INSERT` is not single-use.** The primary key and one
atomic insert decide the winner under concurrency.

**58 · A public input copied from the request is attacker policy.** Roots are validated, challenges
are server rows, and audiences and thresholds come from the named claim row.

**59 · A proof not bound to an audience replays at another endpoint.** The nullifier circuit input
includes the policy-supplied audience.

## Proving keys and operations

**60 · A swapped verifying key is a universal bypass.** Key bytes are hashed and compared with a
consumer-pinned SHA-256 before parsing; no proving or verifying keys live in this repository.

**61 · Verification is unauthenticated CPU.** Proof length is checked before parsing and a short-
timeout semaphore bounds pairing work; challenge issuance also cleans up its 60-second rows.

**62 · Session IP and user-agent metadata undo a pseudonym with one join.** ZK login always calls
session issuance with a zero `Meta`; this is deliberately not configurable.

**63 · A fast "no commitment enrolled" path is an enrolment oracle.** Knowledge verification uses
one public error and performs a real dummy pairing check while holding the same semaphore slot.
