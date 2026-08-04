# Security

## Reporting a vulnerability

Open a private security advisory on the GitHub repository. Please do not open a public issue for
anything exploitable.

## What kal defends against, and how

Each control names the test that fails without it. They live in `tests/`, and the DB-backed ones need
`DATABASE_URL` — a skipped test still reports `ok`, which is why CI greps `--- PASS: TestDB`.

| control | the test that fails without it |
|---|---|
| Enumeration on registration | `TestDBRegister` — a new and an existing address produce identical results |
| Enumeration on reset | `TestDBPasswordReset` — same, and both send mail |
| Uniform login failure | `TestDBLogin` — four failure modes, compared byte for byte |
| Timing equalization | `TestPasswordHash` — the unknown-user path runs a real dummy verify |
| Session fixation | `TestDBSessions` — the pre-rotation token stops resolving |
| Revocation | `TestDBMiddleware` — revoked, then the next request is anonymous |
| Account disable | `TestDBSessions` — `deleted_at` drops live sessions at lookup |
| Revoke-all on reset | `TestDBPasswordReset` — every prior session dies |
| Reset does not mutate | `TestDBPasswordReset` — the old password still logs in after a request |
| Token single use | `TestDBTokenSingleUseUnderConcurrency` — 8 concurrent submissions, 1 success |
| Token purpose | `TestDBVerifyEmail` — a reset token cannot verify an email, and is not burned trying |
| Backoff before hashing | `TestDBLoginBackoff` — a throttled attempt returns in under 100 ms |
| Credential stuffing | `TestDBLoginBackoff` — the per-IP counter catches what per-account cannot |
| Argon2 bound | `TestPasswordBound` — a second hash is refused, not queued unboundedly |
| Pinned Argon2 parameters | `TestPasswordHash` — the encoded prefix, including `p=1` |
| Rehash on login | `TestDBRehashOnLogin` — a weaker stored hash is upgraded |
| Byte-exact passwords | `TestPasswordExactBytes` — NFC/NFD and whitespace are significant |
| Cookie attributes | `TestSessionCookieAttributes` — `__Host-`, `Secure`, `HttpOnly`, `SameSite=Lax`, no `Domain` |
| CSRF transport guard | `TestTransportGuard` — the whole CORS-simple matrix |
| `Scope` | `TestDBScope` — a scoped delete leaves another owner's row in place |
| Anonymous fails closed | `TestDBScope` — an anonymous scope matches nothing |
| RLS enforcement | `TestDBRLS` — under a role proven not to bypass RLS |
| GUC locality | `TestDBRLS` — the setting does not survive the transaction |
| Coverage | `TestAssertAuthCoverage` — an unannotated mutation is named |
| Directive wiring | `TestAssertDirectivesWired` — a nil implementation is named |
| Directive denial | `TestAuthDirective` — the resolver does not run when the check fails |
| Batching guard | `TestGuard` — two aliased logins rejected, including through a fragment |
| JWT algorithm confusion | `TestJWTForgery` — HS256 signed with the Ed25519 public key |
| JWT mandatory claims | `TestJWTMandatoryClaims` — missing `exp`, `aud`, `iss` all rejected |
| JWT error flattening | `TestJWTExpiry` — an expired forgery does not read as merely expired |
| Redaction | `TestPresentError` — no SQLSTATE, table or column name on the wire |

## What kal does not defend against — your responsibility

kal is a library inside your process. These are outside its reach, and skipping any of them undoes
much of the above.

**TLS.** Everything here assumes HTTPS. The session cookie is `Secure`, which means it is simply not
sent over plaintext — but the login request that creates it must not be either.

**CORS.** luima sets no `Access-Control-Allow-Origin` anywhere. Configure `cors.New` with an explicit
origin list. **Never `*` with credentials** — browsers reject that combination, and the workarounds
people reach for (reflecting the `Origin` header) are worse than no CORS at all.

**Edge rate limiting.** kal's backoff is per account and per IP, in Postgres, and it is the layer that
understands login semantics. It is not a substitute for a limiter at the edge that drops floods
before they reach your process — and note that Fiber's `limiter` counts HTTP requests, so it cannot
see the GraphQL batching attack at all.

**The database role.** If your application connects as a superuser or the table owner, RLS is
decoration (see gotchas 5 and 6). A privileged connection role makes the third authorization layer
inapplicable, silently.

**Transport registration.** Registering `UrlEncodedForm`, `MultipartForm` or `GRAPHQL` reopens CSRF
with ambient cookies. kal's guard cannot stop what the transport accepts before it runs.

**The reset landing page.** The token is in a URL and leaks through `Referer` to any third-party asset
on that page. Send `Referrer-Policy: no-referrer`, serve no third-party assets there, and exchange the
token immediately.

**Secrets.** Ed25519 signing keys, the database URL, and your mailer's credentials are yours to store
and rotate. kal supports two active JWT keys precisely so rotation is a deploy rather than an outage.

**Email delivery.** `Mailer` is one method with no default. If it silently drops messages, password
reset silently stops working — kal will log a send failure and nothing more.

## Deliberate design positions

Some of these look like omissions from the outside, so they are stated plainly.

**No hard account lockout.** Anyone who knows a victim's address could trip it, which makes lockout an
availability vulnerability wearing a security control's clothes (ASVS 6.1.1 says so explicitly). kal
uses capped exponential reject-until windows that self-recover.

**No development mode.** The zero `Config` is the production posture and there is no flag that relaxes
a security property. A `Dev bool` that skips a check reaches production, because that is what
environment flags do.

**No `Store` interface.** Postgres is the premise: the session lookup JOINs the users and roles
tables, which is exactly what an abstraction over "some backend" would forbid.

**No refresh tokens.** The session cookie is the long-lived credential, so there is nothing to rotate.
This deletes the reuse-detection subsystem entirely rather than implementing it carefully.

**The JWT TTL is capped in code, not config.** These tokens are not revocable, so the TTL *is* the
revocation window, and a config field inviting `24h` is one someone eventually sets.

**Password policy is a minimum and a maximum, nothing else.** No composition rules, no rotation, and
the password is verified exactly as received. That is ASVS 6.2 and NIST 800-63B, and every additional
rule measurably reduces password strength in practice.

## Supported versions

While the major version is `0`, only the latest minor release receives security fixes.
