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

### The ZK module

Only set `Config.ZK` if you have read the rest of this section. Each row names a test that exists and
runs; a row whose test you cannot point at is a control that is not there.

| control | the test that fails without it |
|---|---|
| Public-input binding | `TestZKCIR001PublicInputBinding` — a tampered root, audience, threshold, nullifier or challenge is refused against a real proof |
| Native/in-circuit hash agreement | `TestZKHSH001NativeAndCircuitMiMCAgreement` — two independent MiMC implementations agree, and disagree on a perturbed output |
| Circuit identity | `TestZKCircuitID` — the pinned constraint counts and R1CS hashes, so a key cannot outlive its circuit |
| Under- and over-constraining | `TestZKDifferential` — 2000 witnesses, circuit against a plain-Go oracle, in both directions |
| Challenge freshness | `TestDBZKChallengeReplay` — a proof is not a bearer token; the same one fails twice |
| Challenge survives a bad proof | `TestDBZKChallengeSurvivesFailedProof` — a failed verification does not burn the honest holder's challenge |
| One-shot single use | `TestDBZKNullifierSingleUse` — eight concurrent valid proofs, one allowance spent |
| One-shot not burned on delivery failure | `TestDBZKOneShotSurvivesUnmountedMiddleware` — no nullifier row for an action that never ran |
| Duplicate claim counting | `TestZKRequestClaimsCountsDuplicates` — one grant does not satisfy `proves: ["vote","vote"]` |
| Pseudonym confinement | `TestDBZKLoginRejectsBoundAccount` — a credential cannot mint a session on a real account, and leaves no session row trying |
| Bounded account growth | `TestDBZKLoginDoesNotGrowUsers` — five logins, one `auth_users` row |
| Recurring pseudonym stability | `TestDBZKPseudonymRecurs` — the same credential returns the same pseudonym |
| Enrolment step-up | `TestDBZKEnrolmentNeedsStepUp` — a wrong password leaves the stored commitment byte-identical |
| Factor replacement revokes sessions | `TestDBZKReenrolmentRevokesSessions` — a session held elsewhere stops resolving |
| Login eligibility is explicit | `TestDBZKLoginNeedsLoginClaim` — a recurring step-up claim mints no session |
| Server-side policy | `TestDBZKThresholdFromPolicy` — a request-supplied threshold does not override the claim row |
| Revocation removes membership | `TestDBZKRevokedCredential` — a revoked leaf no longer proves against the current root |
| Revocation is not rolled back | `TestDBZKRevokeRepublishesRoot` — revoking the highest live leaf still sets `revoked_at` |
| Tree write serialization | `TestDBZKConcurrentEnroll` — concurrent issuance publishes a root every path verifies against |
| Verification holds no transaction | `TestDBZKVerifyHoldsNoTransaction` — a bad proof is refused without a transaction ever being opened |
| Session-bound claims | `TestDBZKE2E002KnowledgeFillsMFASeam` — elevation belongs to the session, not the user, and does not survive re-login |
| No cross-satisfaction between claims | `TestDBZKE2E003MembershipSatisfiesProvesAndOnlyThat` — proving `is_member` does not grant `age_over_18` |
| Pseudonymous sessions carry no attribution | `TestDBZKE2E001LoginYieldsScopedSession` — no `ip`, no `user_agent`, from a request that supplied both |
| Replica agreement | `TestDBZKE2E005TwoReplicasAgree` — two instances, one database, symmetric behaviour |
| Anonymity at the database | `TestDBZKE2E006AnonymousAtTheDatabase` — twelve members, no column or join narrows below twelve |

### What the ZK module's anonymity claim actually means

**The anonymity set is the number of non-revoked leaves in the credential tree, and nothing larger.**
A proof says "some member of this tree satisfies this policy". With twelve live credentials that is
one-in-twelve. With one live credential it is one-in-one and the proof identifies its holder exactly
— correctly, and uselessly. A young deployment has a small anonymity set and there is no
configuration that changes this; only issuing more credentials does.

**The operator is the verifier, and they are not different parties.** kal runs verification inside
your process, on your database. Nothing here constrains an operator who wants to lie: they can return
`true` for a proof that did not verify, log what they like, or add a column tomorrow that joins a
nullifier to a member. Groth16 gives the *member* assurance against a *third party* reading the
database later; it gives nobody assurance against the party running the code. (Also worth stating
plainly: these are Groth16 circuits with a per-circuit trusted setup, not PLONK with a universal
one. Whoever ran `Setup` could forge proofs for that circuit if they kept the toxic waste. If that
matters to your threat model, the ceremony is the thing to scrutinise, not the verifier.)

**The prover is a client you package.** kal ships verifying keys and circuits, not a prover bundle.
Whatever JavaScript, WASM or native client you ship computes proofs *and holds the member's secret*.
A compromised prover is a compromised credential, and no server-side control in this file reaches it.

**Enrolment-to-first-use timing correlates.** `auth_zk_credentials.created_at` and
`auth_zk_nullifiers.first_seen_at` are both timestamps in the operator's own database. A member who
is issued a credential and immediately uses it links the two rows by nothing more than clock
proximity. The narrower the issuance window, the sharper the correlation; issuing in batches and
expecting delayed first use is the mitigation, and it is operational, not cryptographic.

**`issued_to` is a deliberate disclosure.** `auth_zk_credentials.issued_to` records which account
received which leaf, which means the operator can revoke a specific member's credential — and means
the credential is not anonymous *at issuance*. Only its *use* is anonymous: nothing links `issued_to`
to the nullifier a proof presents. Dropping the column would buy anonymity at issuance and would take
`RevokeCredentialsForUser` with it. kal keeps revocation. If your threat model prefers the other
trade, do not set `issued_to`, and accept that revocation becomes per-leaf and manual.

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
