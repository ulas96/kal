# Security test cases — `e2ee`

A test register for kal's client-side encryption module. Every case below is an **obligation on the
implementation**, not a report on it. No test here was written and no test here was run.

Scope is the Go side: the `e2ee` package, the `SecretShape` seam into `authn`, the `kal.Config`
wiring, `migrations/0003_e2ee.sql`, and the re-export shim. `docs/e2ee-client.ts` is out of scope —
it has no test harness, no CI step and no type check, and giving it one is a separate piece of work.

---

## 0 · How to read this document

### 0.1 Source of truth

`docs/e2ee-handout.md` is the specification and `docs/e2ee-client.md` is the wire contract. Where the
handout marks a decision **load-bearing**, the case here is CRITICAL by construction: the handout has
already asserted that a security property depends on it. Where it marks a decision **chosen**, the
case tests that the choice was implemented consistently, not that it was the right choice.

Where this register asserts something the handout does *not* settle, or asserts something the docs
claim and the code does not do, the case is tagged **[UNSPECIFIED]** and repeated in §17. Those are
findings against the design documents, not against a test.

### 0.2 The schema of a case

Seven fields, every time.

| field | what it holds |
|---|---|
| **Aim** | The security property, stated as a property and not as a function call. |
| **Point of failure** | Where the defect lives if the control is absent, and what it costs. |
| **Procedure** | What the test does. Enough to write it from, not code. |
| **Pass** | The observation that constitutes success, stated as *the thing that goes wrong not happening* — the row still in the table, the count still zero, the bytes still A's. Never "the function returned an error". |
| **Fail** | The observation that constitutes a finding. |
| **Avoidance** | Two things, both mandatory. **(a) The negative variant** that must run alongside, because the positive one alone is satisfiable by a broken system. **(b) The false-pass trap** — the shape of this test that goes green vacuously. A test that can only pass is a comment with a stack trace. |
| **Trace** | Handout §, gotcha number, and the source line the property lives on. |

Terseness on a GOOD-TO-HAVE case is terseness, not exemption. **Avoidance is never omitted.**

### 0.3 Severity

| tier | definition | gate |
|---|---|---|
| **CRITICAL** | Absence is a bypass, an enumeration oracle, or **silent data loss** — a working login over an unopenable vault. Reachable by a party this design claims to defend against. | Blocks the release. |
| **ESSENTIAL** | Absence is a real weakness under a plausible operational condition: concurrency, two replicas, a partial failure, a config change, an un-updated client. | Blocks the release. |
| **GOOD-TO-HAVE** | Regression fences, boundary checks, hygiene, and assertions that a documented non-goal is in fact documented. | Does not gate. |

Silent data loss sits at CRITICAL and not below. Everything this module protects fails the same way —
login works, nothing errors, nothing logs, and the vault never opens again. There is no operator alert
for it and no support answer to it, which is why it is graded next to a bypass rather than under one.

### 0.4 The register at a glance

120 cases in twelve groups: **42 CRITICAL, 52 ESSENTIAL, 17 GOOD-TO-HAVE**, plus 9 tagged
`[UNSPECIFIED]` that pin today's behaviour while §17 carries the decision. Twenty-three are discharged
by tests that exist today and 9 more partly — §16 is the ledger. §15's 36-row mutation matrix is the
deliverable that says whether any of it works.

### 0.5 What a green suite here does *not* mean

It does not mean the deployment is end-to-end encrypted against its own operator. From the handout,
in its own words, and repeated because softening it is the failure:

> Browser-delivered end-to-end encryption does not protect against the server that serves the
> JavaScript. An operator who wants the plaintext ships one line of JS to one user and has their
> master key on the next page load, and no amount of care in this Go package changes that. Anyone who
> tells you otherwise is selling something.
>
> The honest claim is: **kal cannot read your data, and neither can anyone who reads your database.**

Nothing in §3–§14 can reach that boundary. §14 tests only that it is written down where a deployment
will read it.

It also does not mean an encrypted table is authorized. Encryption and `Scope` are orthogonal controls
that fail open with respect to each other (gotcha 73), and "it's encrypted" reads like a reason to
skip the `WHERE` clause. That control is `authz`'s, and its cases live in `tests/scope_test.go`.

---

## 1 · Adversaries

Every case names exactly one. A case that cannot name its adversary is testing an implementation
detail, and belongs in a unit test somebody else maintains.

| | adversary | capability | what the cases must deny it |
|---|---|---|---|
| **T1** | **Unauthenticated network caller** | One HTTP request, repeated. `Vaults.Params` is necessarily pre-auth. | Learning whether an address has an account, or whether it has enrolled. Locking any account out by asking for its salt (gotcha 69). |
| **T2** | **Authenticated user** | A valid session, and the whole vault surface. | Reading, overwriting or deleting another user's row. Using an unbounded `bytea` column as free storage (gotcha 77). |
| **T3** | **Reader of a stolen database** | Every row, every column, the backup, the replica. This is the adversary the module exists for. | Any route to a plaintext or a vault key — including a second route via a stored recovery-code verifier. |
| **T4** | **Honest-but-curious operator** | T3, plus the code as written and the configuration. Does not deviate from its own code. | The same, plus anything a config field can be turned to at derive time (gotcha 67). |
| **T5** | **Mis-deploy / un-updated client** | No malice. A second frontend nobody remembered, a `curl` in a runbook, a raised default cost, a rotated pepper. | Silent data loss. Every T5 case has the same failure signature: it works, and the data is gone. |

**Explicitly not an adversary: the operator who serves the JavaScript.** Handout §1 establishes why,
and §14 tests that it is stated where a deployment will read it. A register that pretended otherwise
would be the exact failure gotcha 64 describes.

---

## 2 · Harness preconditions

Obligations on the test infrastructure. A case that depends on one of these and does not get it is a
case that reports green for the wrong reason.

**P-1 · A case that does not need Postgres must not be named `TestDB*`.** `TestDB*` skips without
`DATABASE_URL`, and a skip reports `ok`. `TestE2EEImportGraph`, `TestValidateAuthSecret` and the
recovery-code shape cases must run in a plain `make test`.

**P-2 · A case that does need Postgres must be named `TestDBE2EE*`.** CI greps `--- PASS: TestDB` out
of `-v` output and fails on `--- SKIP: TestDB` (`.github/workflows/ci.yml:76-80`). A DB case named
otherwise is invisible to the gate that exists to catch exactly this.

**P-3 · Concurrency cases use one barrier shape.** N goroutines constructed, all blocked on a single
channel close, released together. `TestDBE2EEPutConcurrency` (`tests/e2ee_db_test.go:219`) and
`TestDBTokenSingleUseUnderConcurrency` are the models. A `go func()` loop with no barrier tests the
scheduler and passes on a broken implementation roughly as often as not.

**P-4 · The fixture pepper is fixed, never random.** `newVaultFixture` uses
`bytes.Repeat([]byte{0x2b}, 32)` (`tests/e2ee_db_test.go:23`). Every salt case in §5 asserts on exact
bytes; a random pepper makes them unreproducible and the first flake gets them skipped. A case that
needs a *second* pepper constructs a second `Vaults` explicitly and says so.

**P-5 · Every case lives in `package tests`.** If a security property cannot be asserted from outside
the package, a consumer cannot rely on it, and the exported surface is what changes — not the test's
package clause. This is why §17's findings are findings and not internal assertions.

**P-6 · One fresh user per case.** `testDB(t)` rebuilds `kal_test` from every migration per test
(`tests/helpers_test.go:47`); there is no truncation step and no `t.Parallel()` anywhere in `tests/`.
Within a table-driven case, each subtest takes its own address — `TestDBE2EEPutRejects` is the model.

**P-7 · Reuse the existing fixtures rather than growing new ones.** `newVaultFixture`, `vaultCtx`,
`storedKey`, `vaultRows` (`tests/e2ee_db_test.go:19-63`), `newAuthnFixture`
(`tests/login_test.go:80`), `createPasswordUser` (`tests/login_test.go:152`), `tokenFromURL`
(`tests/tokens_test.go:18`). Cases below name the ones they need; three new helpers are called for
and are named where they first appear (`vaultRow`, `loginAttempts`, `putVaultDirect`).

**P-8 · A case that asserts a rejection asserts the row.** Every rejection case in §8 pairs its error
assertion with `vaultRows(...) == 0`, or — where a vault already exists — with `storedKey(...)`
unchanged. The error is the symptom; the row is the property.

---

## 3 · `E2EE-ISO` — the premise: kal cannot decrypt

The module's entire claim rests on this group. If kal can decrypt, kal is not doing client-side
encryption — it is doing server-side encryption with extra ceremony, sold under the same word.

### E2EE-ISO-001 · The package imports no AEAD and no password KDF · **CRITICAL** · T3, T4

**Aim** `e2ee`'s direct import list contains nothing that could decrypt a vault blob or derive a key
from a password.
**Point of failure** One helpful convenience method — `e2ee.Decrypt`, "just for the admin tool" —
converts a database-leak defence into a database-leak. Nothing about the API shape reveals it; the
signature reads like a feature.
**Procedure** `go list -f '{{join .Imports "\n"}}' github.com/ulas96/kal/e2ee`, compare every line
against `e2eeAllowedImports`.
**Pass** Every direct import is on the 14-entry allowlist.
**Fail** Any import not on it, whatever its justification in the diff.
**Avoidance** (a) Negative variant: temporarily add an entry to the allowlist for a package the code
does not import and confirm the test still passes — the test must gate on imports, not on list
length. (b) False-pass trap: a **denylist** over `go list -deps`. It cannot work and it will be
proposed: `e2ee` takes `orm.DB` in every signature, go-pg reaches `crypto/tls`, and `crypto/tls`
pulls `crypto/aes`, `crypto/cipher` and `crypto/hkdf` into the transitive closure of every package in
this module. `go list -deps ./authz` already prints all three. A test that fails on day one gets
deleted, and this is the one test that must not be.
**Trace** handout §0, §7 · `e2ee/e2ee.go:4-8` · covered today by `TestE2EEImportGraph`
(`tests/e2ee_test.go:48`).

### E2EE-ISO-002 · The allowlist catches crypto done on `e2ee`'s behalf · **CRITICAL** · T4

**Aim** The control survives the obvious workaround: a new `kal/internal/vaultcrypto` that `e2ee`
imports.
**Point of failure** A denylist of standard-library paths waves this through. The allowlist is
strictly stronger, and the case exists so that the strength is asserted rather than assumed.
**Procedure** Add a throwaway package under the module that imports `crypto/aes`, import it from
`e2ee`, run `TestE2EEImportGraph`. Revert.
**Pass** The test names the new package as not on the allowlist.
**Fail** Green.
**Avoidance** (a) Negative variant: the same throwaway package imported from `authz` instead must
*not* fail this test — the scope is `e2ee`'s direct imports, not the module's. (b) False-pass trap:
performing this by hand once and not recording it. This case belongs in §15's mutation matrix, where
it has to be re-run; as a one-off it decays to a memory.
**Trace** handout §0 · `tests/e2ee_test.go:22-23`.

### E2EE-ISO-003 · No exported symbol can return a plaintext or a key · **CRITICAL** · T3

**Aim** The surface offers no `Decrypt`, `Unwrap`, `Open`, or any method returning material derived
from a blob. `WrappedKey` and `RecoveryWrappedKey` go in and come out as the same opaque bytes.
**Point of failure** The import allowlist stops the crypto; it does not stop a method that takes a
password and forwards it somewhere. The surface is the second half of the same control.
**Procedure** Reflect over the exported surface of `e2ee` (and of `kal`'s re-exports): assert the
method set of `*Vaults` is exactly `Params`, `Get`, `Put`, `Discard`, and the package functions are
exactly `NewVaults`, `ValidateAuthSecret`, `NewRecoveryCode`.
**Pass** The sets match exactly, including no extras.
**Fail** Any additional exported method or function, which must be justified in the diff or removed.
**Avoidance** (a) Negative variant: assert the four expected methods are *present*, so a rename
cannot make the case pass by emptying the set. (b) False-pass trap: asserting "contains no method
named Decrypt". The next one is called `Reveal`. Assert the whole set.
**Trace** handout §4 · `e2ee/e2ee.go:150-162`.

### E2EE-ISO-004 · The root shim re-exports nothing that widens the surface · **ESSENTIAL** · T4

**Aim** `kal.` exposes the same four-method surface and no convenience wrapper of its own.
**Point of failure** The shim is hand-written (`kal.go`), so a symbol can be added there that has no
counterpart in `e2ee` and no import-graph test over it.
**Procedure** Assert `kal.Vaults` is an alias of `*e2ee.Vaults` and that the three re-exported
functions are the only e2ee-derived package functions in `kal.go`.
**Pass** Alias identity holds in both directions; no fourth function.
**Fail** A `kal.`-only helper that touches vault bytes.
**Avoidance** (a) Negative variant: the identity assertion must be compile-time, both directions —
`var _ e2ee.Vault = kal.Vault{}` and the reverse — so a *copy* of the struct fails. (b) False-pass
trap: asserting only that `kal.Vault` exists.
**Trace** CLAUDE.md re-export invariant · `kal.go:501-520, 574-585` · partly covered by
`tests/kal_test.go:139-158`.

---

## 4 · `E2EE-CFG` — `NewVaults` and the configuration that cannot be wrong

### E2EE-CFG-001 · An absent pepper is a hard error, not a generated default · **CRITICAL** · T5

**Aim** `NewVaults(Options{})` returns an error and a nil `*Vaults`.
**Point of failure** A generated-when-missing pepper differs per replica and per restart. Every salt
in the deployment moves under the user's feet: logins work, and every wrapped key becomes garbage.
Behind a load balancer it is worse — the vault opens on one pod and not the next.
**Procedure** `NewVaults(e2ee.Options{})`; then `NewVaults(e2ee.Options{Pepper: nil})`.
**Pass** Non-nil error and a nil `*Vaults` in both.
**Fail** A usable `*Vaults`.
**Avoidance** (a) Negative variant: a 32-byte pepper must succeed in the same case, or a
`return nil, err` at the top of the function passes. (b) False-pass trap: asserting `err != nil`
without asserting the returned `*Vaults` is nil — a constructor that returns both is worse than one
that returns neither, because the caller that ignores the error gets a working object with a
random pepper.
**Trace** handout §3 · `e2ee/e2ee.go:170-172`.

### E2EE-CFG-002 · The pepper floor is exactly 32 bytes · **CRITICAL** · T1

**Aim** 31 bytes is rejected; 32 is accepted.
**Point of failure** A short pepper is a brute-forceable HMAC key, and the property it holds up is
decoy indistinguishability: an attacker who can recover the pepper can compute `salt(email)` offline
and compare it to what `Params` returns, which turns §5's whole construction back into the
enumeration oracle it replaces.
**Procedure** Table: 0, 1, 16, 31, 32, 33, 64 bytes.
**Pass** Rejected below 32, accepted at and above it.
**Fail** Any acceptance below 32.
**Avoidance** (a) Negative variant: 33 and 64 must be accepted — a `len != 32` check is wrong in the
other direction and would pass a test that only probes 31. (b) False-pass trap: probing 0 only. Zero
is caught by any nil check; 31 is the boundary that distinguishes a real bound from a nil guard.
**Trace** handout §3 · `e2ee/e2ee.go:57, 170`.

### E2EE-CFG-003 · The pepper error is not a `*kalerr.Error` · **[UNSPECIFIED]** · GOOD-TO-HAVE

**Aim** Record what the constructor actually returns, so a later case does not assert the wrong
thing.
**Point of failure** `NewVaults` returns a bare `errors.New` for the pepper and a
`*kalerr.Error{Code: CodeInvalidInput}` for the schema, three lines apart. A test written from the
handout ("matching `session` and `authz` rather than `authn`'s bare `errors.New`", handout §4) asserts
`CodeInvalidInput` and fails.
**Procedure** `errors.As(err, &ae)` on both branches.
**Pass** The case documents the divergence and asserts today's behaviour.
**Fail** n/a — this is a finding, see §17.10.
**Avoidance** (a) Negative variant: assert the schema branch *does* carry `CodeInvalidInput`, so the
case pins the inconsistency rather than a blanket "no codes here". (b) False-pass trap: asserting
`err != nil` for both and calling the group covered.
**Trace** `e2ee/e2ee.go:171` vs `e2ee/e2ee.go:189-190` · handout §4.

### E2EE-CFG-004 · The pepper is retained by reference · **[UNSPECIFIED]** · ESSENTIAL · T5

**Aim** State what happens when the caller mutates the slice it passed.
**Point of failure** `v.pepper = opts.Pepper` with no copy. A consumer that reuses a scratch buffer,
or zeroes its config after construction, silently moves every future salt — and only for vaults
written *after* the mutation, so the deployment splits into two cohorts with no error anywhere.
**Procedure** Build `Vaults` from a slice; record `Params(addr).Salt`; mutate the caller's slice in
place; read `Params(addr)` again for an address with no row.
**Pass** Whatever the behaviour is, it is asserted. The register's position: the constructor should
copy, and until it does this case pins the hazard.
**Fail** The behaviour changes without the case changing.
**Avoidance** (a) Negative variant: an *enrolled* address must return the stored salt regardless, so
the case does not accidentally assert that mutation is harmless. (b) False-pass trap: mutating a
slice header rather than its backing array — `pepper = otherSlice` proves nothing.
**Trace** `e2ee/e2ee.go:174` · §17.11.

### E2EE-CFG-005 · The schema qualifier is validated, not quoted-and-hoped · **CRITICAL** · T4

**Aim** A schema name outside `^[a-z_][a-z0-9_]*$` is rejected with `CodeInvalidInput`, before any
statement is rendered.
**Point of failure** The prefix is `fmt.Sprintf`'d into every statement in `sql.go`. It is the one
string in this package that reaches SQL without a placeholder.
**Procedure** Table: `"kal_test"` (accept), `""` (accept, unqualified), `"public; drop table
auth_users --"`, `"Kal"`, `"1kal"`, `"kal-test"`, `"kal.test"`, `` "kal\"" ``, a 200-character name.
**Pass** `CodeInvalidInput` for every rejection, and for the accepted ones the rendered statements
run.
**Fail** Any construction that succeeds with a name outside the class.
**Avoidance** (a) Negative variant: `"kal_test"` and `""` must both succeed, or a constructor that
rejects everything passes. (b) False-pass trap: asserting only that `NewVaults` errored, without
confirming that the *accepted* names produce statements that actually execute against a schema —
a regex that is right and a `types.AppendIdent` that is wrong is still broken.
**Trace** handout §4 · `e2ee/e2ee.go:62, 186-193`.

### E2EE-CFG-006 · `MaxBlob` zero and negative both mean 8192 · **ESSENTIAL** · T2

**Aim** `MaxBlob: 0` and `MaxBlob: -1` both produce the 8192 ceiling, not an unbounded one.
**Point of failure** A `< 0` guard instead of `<= 0` leaves `MaxBlob: 0` meaning "no limit", and the
zero `Options` is the one every consumer starts from. An authenticated caller then has a free storage
bucket.
**Procedure** Build with 0 and with -1; `Put` 8192 bytes (accept) and 8193 (reject) against each.
**Pass** 8193 rejected with `CodeInvalidInput` and `vaultRows == 0` in both configurations.
**Fail** 8193 accepted under either.
**Avoidance** (a) Negative variant: 8192 must be accepted, or the case passes against a ceiling of
zero. (b) False-pass trap: testing only `MaxBlob: 0`. The negative is the arm that catches `< 0`.
**Trace** handout §5 · gotcha 77 · `e2ee/e2ee.go:58, 183-185`.

### E2EE-CFG-007 · A custom `MaxBlob` binds at its exact boundary · **ESSENTIAL** · T2

**Aim** `MaxBlob: 64` accepts 64 bytes and rejects 65.
**Point of failure** An off-by-one that only shows at a boundary nobody exercises, because the default
8192 is far from any test blob.
**Procedure** Build with `MaxBlob: 64`; `Put` 63, 64, 65 bytes.
**Pass** 63 and 64 accepted, 65 rejected, no row after the rejection.
**Fail** 65 accepted, or 64 rejected.
**Avoidance** (a) Negative variant: run the same three lengths in `RecoveryWrappedKey` — the code
checks both against the same ceiling in one condition, and a case that only moves `WrappedKey` would
not notice if it did not. (b) False-pass trap: using the default 8192 for this case. A boundary test
at the default value tells you nothing about whether the field is read.
**Trace** `e2ee/e2ee.go:317`.

### E2EE-CFG-008 · `Default` fills only the zero fields · **ESSENTIAL** · T4

**Aim** `Options.Default{Memory: 262144}` produces defaults of argon2id / 262144 / 3 — the caller's
memory, the package's KDF and iterations.
**Point of failure** A `withDefaults` that replaces the whole struct silently discards a deployment's
deliberate cost choice, and the first symptom is a phone that takes eleven seconds to log in.
**Procedure** Construct with each field set individually; read `Params` for an unknown address.
**Pass** Each set field survives; each unset one takes argon2id / 65536 / 3.
**Fail** Any set field replaced.
**Avoidance** (a) Negative variant: the fully-zero `Default` must produce exactly argon2id / 65536 /
3, so the case pins the documented default and not merely "something non-zero". (b) False-pass trap:
asserting `Memory != 0`.
**Trace** handout §4 · `e2ee/e2ee.go:82-94, 178`.

### E2EE-CFG-009 · `Floor` fills only the zero fields, and a raised floor binds · **ESSENTIAL** · T4

**Aim** `Floor{Memory: 131072}` rejects a `Put` at 65536 that the default floor would accept.
**Point of failure** A floor that is configured and not consulted reads as a control in code review
and is not one. It is also the field a deployment reaches for after an incident, so a dead one is
discovered at the worst moment.
**Procedure** Two `Vaults`, default floor and raised floor, same fixture user. `Put` at 65536 against
each.
**Pass** Accepted under the default floor, `CodeInvalidInput` and `vaultRows == 0` under the raised
one.
**Fail** Accepted under both.
**Avoidance** (a) Negative variant: `Put` at 131072 must be accepted under the raised floor, or a
floor that rejects everything passes. (b) False-pass trap: testing the floor only through `Memory`.
`Iterations` is a separate comparison in the same condition — see E2EE-POL-011.
**Trace** handout §4 · `e2ee/e2ee.go:179, 327`.

### E2EE-CFG-010 · `Floor.KDF` and `Floor.Parallelism` are never compared · **[UNSPECIFIED]** · ESSENTIAL · T4

**Aim** Record that two of `Floor`'s five fields are dead.
**Point of failure** `check` compares `Memory` and `Iterations` only. A deployment that sets
`Floor: Params{KDF: KDFArgon2id}` believing it has banned PBKDF2 has banned nothing, and PBKDF2 is
GPU-cheap (gotcha 75). `Parallelism` on both `Floor` and `Default` is overwritten to 1 by
`withDefaults` before anything could read it.
**Procedure** Build with `Floor{KDF: KDFArgon2id}`; `Put` with `Params{KDF: KDFPBKDF2, Memory: 65536,
Iterations: 3}`.
**Pass** The case asserts today's behaviour — accepted — and §17.2 carries the finding.
**Fail** The behaviour changes without this case changing.
**Avoidance** (a) Negative variant: an unknown KDF (`"scrypt"`) must still be rejected, so the case
does not read as "the KDF is unchecked". (b) False-pass trap: writing this as a passing test of a
*working* KDF floor. It does not work; the case exists to say so.
**Trace** `e2ee/e2ee.go:92, 324-329` · §17.2, §17.3.

### E2EE-CFG-011 · Two `Vaults` from one `Options` do not share mutable state · **GOOD-TO-HAVE** · T5

**Aim** Constructing twice from the same `Options` value yields two independent services.
**Point of failure** `Options` is taken by value, but `Pepper` is a slice and `sql` is rendered per
call. A future field that is a map or a pointer would alias silently across every consumer.
**Procedure** Build A and B from one `Options`; change B's schema at construction; assert A's
statements still target the original.
**Pass** Independent.
**Fail** Either affects the other.
**Avoidance** (a) Negative variant: assert both produce the *same* salt for the same address — they
share a pepper by design, and the case must not read as "these should differ". (b) False-pass trap:
comparing pointers instead of behaviour.
**Trace** `e2ee/e2ee.go:169-196`.

---

## 5 · `E2EE-SLT` — the salt

One HMAC closes three problems that are usually solved separately and badly. Every case in this group
is about the fact that **the same function mints the real salt and the decoy**, and that neither ever
moves.

### E2EE-SLT-001 · Every address gets exactly 16 bytes · **ESSENTIAL** · T1

**Aim** `Params(...).Salt` is 16 bytes for an unknown address, a known unenrolled one, and an enrolled
one.
**Point of failure** A truncation changed from `[:16]` to the full digest changes the Argon2id input
for every client, and the only symptom is that existing vaults stop opening.
**Procedure** Three addresses in the three states; `len(Salt)` on each.
**Pass** 16 in all three.
**Fail** Anything else, including 32.
**Avoidance** (a) Negative variant: the *stored* salt read back after a `Put` must also be 16 — the
insert path writes `v.salt(...)` and a change there would not show in the decoy arm. (b) False-pass
trap: `len(Salt) > 0`. Covered today only for the unknown-address arm
(`tests/e2ee_db_test.go:81`).
**Trace** `e2ee/e2ee.go:56, 208`.

### E2EE-SLT-002 · The decoy does not move between two calls · **CRITICAL** · T1

**Aim** An address with no vault answers the same 16 bytes every time it is asked.
**Point of failure** The usual fix for enumeration is a random decoy, and the usual fix is the bug: a
decoy generated fresh per call changes between two calls and a real salt does not. Call twice, diff,
and the user table is enumerable by anyone.
**Procedure** `Params(unknown)` twice; compare bytes.
**Pass** Byte-identical.
**Fail** Any difference.
**Avoidance** (a) Negative variant: two *different* addresses must differ, or a constant salt passes.
(b) False-pass trap: asserting only `len == 16`, which passes against exactly the random-decoy bug
this case exists for.
**Trace** handout §3 · gotcha 68 · `e2ee/e2ee.go:198-209` · covered by
`TestDBE2EEEnumeration` (`tests/e2ee_db_test.go:84-90`).

### E2EE-SLT-003 · The decoy for an address *is* the salt that address later gets · **CRITICAL** · T1

**Aim** The salt returned before enrolment and the salt stored at first `Put` are the same bytes.
**Point of failure** This is the property the whole construction is for, and nothing asserts it today.
Two code paths compute it — `Params`'s no-row branch and `Put`'s insert — and they happen to call the
same function. If they ever diverge, the decoy becomes distinguishable from a real salt by enrolling
and comparing, **and** every client that derived before enrolment derives a key that no longer opens
its own vault. Both failures at once, neither with an error.
**Procedure** `Params(addr)` for a fresh account with no vault; record the salt. `Put` a vault for that
user. `Params(addr)` again; compare.
**Pass** Byte-identical across the enrolment boundary.
**Fail** Any difference.
**Avoidance** (a) Negative variant: assert the same across a *second* `Put` too (the re-wrap path,
E2EE-SLT-008), so the case covers both the insert and the update. (b) False-pass trap: reading the
"before" salt from the same `Vaults` instance and never touching the table — the case must go through
`Params`, so it exercises the no-row branch and the stored-row branch, not `v.salt` twice.
**Trace** handout §3 · gotcha 68 · `e2ee/e2ee.go:234` and `e2ee/e2ee.go:299`.

### E2EE-SLT-004 · Two addresses derive different salts · **ESSENTIAL** · T3

**Aim** The derivation is per-address.
**Point of failure** A shared salt across a deployment makes one Argon2id table cover every user, which
is the entire reason salts exist.
**Procedure** Two unknown addresses; compare.
**Pass** Different.
**Fail** Equal.
**Avoidance** (a) Negative variant: the same address twice must be equal (E2EE-SLT-002), or the case
is satisfied by a random salt. (b) False-pass trap: two addresses that differ only in case — those
*must* be equal, see E2EE-SLT-005. Pick genuinely different addresses.
**Trace** `e2ee/e2ee.go:205` · covered by `tests/e2ee_db_test.go:102`.

### E2EE-SLT-005 · The address is normalised on both the read and the write path · **CRITICAL** · T5

**Aim** `Params("  NOBODY@Example.Test  ")` and `Params("nobody@example.test")` return the same salt,
**and** a `Put` by a principal whose `Email` carries different case stores that same salt.
**Point of failure** `Params` normalises its argument (`e2ee.go:227`); `Put` normalises `p.Email`
(`e2ee.go:299`). Two normalisations, in two functions, that must agree forever. Drop either and one
user typing their address with a capital letter derives a key that does not open the vault their
other device wrote. The read path is covered today; **the write path is not.**
**Procedure** Create a user whose stored email carries mixed case. `Params(lowercase)` → record.
`Put` through a `vaultCtx` carrying the mixed-case address. `Params(lowercase)` again → compare.
**Pass** Identical across all three, and equal to `Params(mixed case)`.
**Fail** Any difference between the read-path salt and the stored one.
**Avoidance** (a) Negative variant: `Params("nobody@example.test ")` (trailing space only) and
`Params("NOBODY@EXAMPLE.TEST")` must both match, so the case covers trim and lowercase separately —
one function might do only one. (b) False-pass trap: using a fixture that lowercases the email before
it ever reaches the principal. `createPasswordUser` inserts what it is given; the case must construct
`vaultCtx` with the mixed-case string deliberately.
**Trace** gotcha 66's cousin · `e2ee/e2ee.go:227, 299` · read path covered by
`tests/e2ee_db_test.go:108-114`.

### E2EE-SLT-006 · The salt depends on the pepper · **CRITICAL** · T1

**Aim** Two `Vaults` with different peppers return different salts for the same unknown address.
**Point of failure** If the pepper is accepted and not actually mixed in, `salt(email)` is computable
offline by anyone — the derivation is public, this file is public — and the decoy is distinguishable
from a real salt without ever touching the server. The pepper is the only thing standing between a
public derivation and an enumeration oracle.
**Procedure** Two `Vaults`, peppers `0x2b × 32` and `0x3c × 32`, same schema. `Params(unknown)` on
each.
**Pass** Different bytes.
**Fail** Equal.
**Avoidance** (a) Negative variant: the same pepper twice must produce equal bytes, or the case is
satisfied by randomness. (b) False-pass trap: using two peppers of *different lengths*, which changes
the HMAC key block padding and would differ even under a construction that ignored the pepper's
content. Use two 32-byte peppers.
**Trace** handout §3 · `e2ee/e2ee.go:206`.

### E2EE-SLT-007 · The derivation is domain-separated · **GOOD-TO-HAVE** · T3

**Aim** The HMAC input is `"kal.e2ee.salt|" + email`, not the bare email.
**Point of failure** The pepper is deployment-wide. Any other use of it — a future one — over the same
input would produce the same bytes for two different purposes.
**Procedure** Compute `HMAC-SHA256(pepper, email)[:16]` in the test and assert `Params(...).Salt`
does **not** equal it; then compute it with the domain prefix and assert it does.
**Pass** Matches the domain-separated value only.
**Fail** Matches the bare-email value.
**Avoidance** (a) Negative variant: the positive arm is mandatory — asserting only "not the bare
email" passes against any change at all, including a broken one. (b) False-pass trap: this case
duplicates the implementation in the test. That is acceptable here and only here, because the
constant is a wire contract a second client must reproduce; note it as such so nobody "simplifies"
it into calling `v.salt`.
**Trace** `e2ee/e2ee.go:55, 207` · `docs/e2ee-client.md:27`.

### E2EE-SLT-008 · The stored salt survives a re-wrap · **CRITICAL** · T5

**Aim** A second `Put` does not rotate the salt, even when it carries new cost parameters.
**Point of failure** `salt` is deliberately absent from the `on conflict do update set` list. Add it
back — it looks like an oversight — and every re-wrap moves the salt while the client is still
deriving from the old one. Every existing wrapped key in the deployment becomes garbage on the user's
next password change.
**Procedure** `Put`; read `Params`; `Put` again with `Memory: 131072, Iterations: 4, KeyVersion: 1`;
read `Params`.
**Pass** Salt byte-identical; `Memory` and `Iterations` **changed**.
**Fail** Salt moved.
**Avoidance** (a) Negative variant: the cost parameters must move. A `do update set` that omitted all
five columns would pass the salt assertion and break the pbkdf2-to-argon2id migration path (gotcha
75). (b) False-pass trap: reading the salt from `Get` rather than `Params` in one arm and `Params` in
the other — they read different statements; use one.
**Trace** handout §3 · `e2ee/sql.go:63-66` · covered by `TestDBE2EESaltNeverRotates`
(`tests/e2ee_db_test.go:351`).

### E2EE-SLT-009 · The stored salt survives an email change · **ESSENTIAL** · T5

**Aim** After a user's address changes, `Params(newAddress)` returns the salt minted under the old
one.
**Point of failure** The stored salt is looked up by `lower(u.email)`, so it follows the account, not
the address — which is correct, and is exactly why the case matters: the salt read back is now one
that `salt(newAddress)` would never produce. A future "recompute if it looks wrong" repair job would
destroy every affected vault.
**Procedure** Enrol at address A; update `auth_users.email` directly to B; `Params(B)`.
**Pass** The salt from A, unchanged.
**Fail** A salt derived from B.
**Avoidance** (a) Negative variant: `Params(A)` after the change must fall through to the decoy branch
and return `salt(A)` — a *different* value from the stored one — so the case captures both halves of
the asymmetry rather than asserting "the salt never changes" too broadly. (b) False-pass trap:
changing the email through a path that also rewrites the vault row. Do it with a direct `update`.
**Trace** handout §3 · `e2ee/sql.go:40`.

### E2EE-SLT-010 · A client-supplied salt is never stored · **CRITICAL** · T2

**Aim** `Put` with `Params.Salt` set to attacker-chosen bytes stores kal's derived salt instead.
**Point of failure** A client-chosen salt breaks decoy indistinguishability outright: enrol with a
salt of `0x00 × 16` and every subsequent `Params` for that address is trivially distinguishable from a
decoy. The parameter list in `putVaultSQL` never binds `vault.Params.Salt`, and the doc comment says
so — a case is what keeps it that way.
**Procedure** `Put` with `Params{KDF: KDFArgon2id, Memory: 65536, Iterations: 3, Salt: bytes.Repeat(
[]byte{0xff}, 16)}`; read the `salt` column directly.
**Pass** The column holds `HMAC(pepper, domain+email)[:16]`, not `0xff × 16`.
**Fail** The client's bytes in the column.
**Avoidance** (a) Negative variant: a salt of the *wrong length* (say 4 bytes) must also be ignored
rather than rejected or stored — the field is ignored, not validated, and the case should say which.
(b) False-pass trap: asserting the returned `Params` from a later `Get` rather than the column.
`Get` reads the column, so this is nearly equivalent — but "nearly" is how the `salt` column and the
`Get` projection drift apart. Read the column.
**Trace** handout §4 · `e2ee/e2ee.go:136-138, 299`.

---

## 6 · `E2EE-PRM` — the pre-auth parameter query

`Params` is the only unauthenticated method in the package, and it necessarily answers about accounts
the caller has not authenticated to. Every case here is against T1.

### E2EE-PRM-001 · `Params` requires no principal · **ESSENTIAL** · T5

**Aim** `Params(context.Background(), db, addr)` succeeds.
**Point of failure** Adding `authz.Require` here looks like tightening and is a deadlock: the client
needs the salt *before* it can produce the auth secret it would authenticate with. It also breaks
registration, where the account does not exist yet.
**Procedure** Call with a bare context, and with a context carrying an anonymous principal.
**Pass** Full `Params` and a nil error in both.
**Fail** `UNAUTHENTICATED`.
**Avoidance** (a) Negative variant: `Get`, `Put` and `Discard` on the same bare context must all
return `UNAUTHENTICATED` (§7), so the case reads as "this one method is deliberately open", not as
"authentication is not wired". (b) False-pass trap: calling with the fixture's authenticated context
out of habit.
**Trace** handout §3 · `e2ee/e2ee.go:211-226`.

### E2EE-PRM-002 · An unknown address gets a complete answer, never an error · **CRITICAL** · T1

**Aim** No `pg.ErrNoRows`, no zero `Params`, no nil salt for an address with no account.
**Point of failure** Any distinguishable response is an account-enumeration oracle on a pre-auth
endpoint. An error, an empty salt, a zero KDF string, or a different field set — all four are the
same finding.
**Procedure** `Params` for an address that does not exist; assert every field is populated.
**Pass** `KDF == "argon2id"`, `len(Salt) == 16`, `Memory == 65536`, `Iterations == 3`,
`Parallelism == 1`, nil error.
**Fail** An error, or any zero field.
**Avoidance** (a) Negative variant: pair it with E2EE-PRM-003 in the same case — a full answer that
does not *match* a real account's is still an oracle. (b) False-pass trap: asserting `err == nil`
only. The response body is the oracle, not the error.
**Trace** handout §3 · gotcha 68 · `e2ee/e2ee.go:232-236`.

### E2EE-PRM-003 · A known-but-unenrolled address answers identically to an unknown one · **CRITICAL** · T1

**Aim** The two are indistinguishable in every field except the salt, which differs because the
addresses differ.
**Point of failure** An account that exists but has no vault takes the same no-row branch as an
address with no account — because the statement joins `auth_users` and would find nothing either way.
If that ever changes to a left join, "registered but not enrolled" becomes visible.
**Procedure** `Params(unknown)`; create a user; `Params(known)`; compare `KDF`, `Memory`,
`Iterations`, `Parallelism`.
**Pass** All four equal.
**Fail** Any difference.
**Avoidance** (a) Negative variant: the salts must differ (E2EE-SLT-004), or the case is satisfied by
a constant response. (b) False-pass trap: creating the user and *also* enrolling them, which tests a
different branch entirely.
**Trace** gotcha 68 · `e2ee/sql.go:36-40` · covered by `tests/e2ee_db_test.go:92-104`.

### E2EE-PRM-004 · A stored row beats `Options.Default` · **CRITICAL** · T4

**Aim** An enrolled user's `Params` come from their row, never from configuration.
**Point of failure** This is gotcha 67, and it is the quietest catastrophe in the module. Read the
params from config at derive time and the first `Default` change makes every existing vault
unopenable — with a working login, a valid session, and no error anywhere in the system.
**Procedure** Enrol with `Memory: 131072, Iterations: 4`; read `Params`.
**Pass** 131072 / 4, not the configured default 65536 / 3.
**Fail** The default.
**Avoidance** (a) Negative variant: the *unenrolled* address in the same case must return the
default, so the case distinguishes "reads the row" from "ignores config entirely". (b) False-pass
trap: enrolling with values equal to the default. Choose values that differ in both fields.
**Trace** handout §4 · gotcha 67 · `e2ee/e2ee.go:240`.

### E2EE-PRM-005 · Raising `Options.Default` does not move an enrolled user's parameters · **CRITICAL** · T4

**Aim** The direct test of gotcha 67: a second `Vaults` with a higher default returns the *stored*
values for a user enrolled under the first.
**Point of failure** E2EE-PRM-004 proves the row is read once. This proves it survives the config
change that is the actual failure scenario — an operator raising the cost after an audit, which is
the recommended thing to do and must be safe.
**Procedure** `Vaults` A with default 65536/3; enrol a user with zero `Params` (so they take the
default). Build `Vaults` B with `Default{Memory: 262144, Iterations: 6}` and the same pepper and
schema. `Params` through B.
**Pass** 65536 / 3 — what the row holds.
**Fail** 262144 / 6.
**Avoidance** (a) Negative variant: an *unknown* address through B must return 262144 / 6, so the
case proves B's config is live and the row simply wins. Without that arm, a `Vaults` that ignored
`Default` entirely would pass. (b) False-pass trap: reusing instance A to read. The whole point is a
second instance with different configuration.
**Trace** gotcha 67 · `e2ee/e2ee.go:226-241`.

### E2EE-PRM-006 · `Params` records nothing in `auth_login_attempts` · **CRITICAL** · T1

**Aim** A thousand calls to `Params` for one address leave the login backoff untouched, and a
subsequent `Login` with the correct password succeeds.
**Point of failure** Gotcha 69, and it is the one denial-of-service in this module that an
unauthenticated attacker can drive with no cost. Rate-limiting a pre-auth endpoint through the login
counter lets anyone lock any account out by repeatedly asking for its salt. Nothing in the code does
this today; the case exists because it is the obvious "fix" a reviewer will propose the first time
someone points at an unauthenticated endpoint.
**Procedure** Create a password user. Call `Params` for their address N times, where N is comfortably
above the backoff threshold. Count rows in `auth_login_attempts` for that email (new helper
`loginAttempts(t, db, email) int`). Then `Login` with the correct password.
**Pass** Zero attempt rows, and the login returns a principal — not `RATE_LIMITED`.
**Fail** Any attempt row, or a rate-limited login.
**Avoidance** (a) Negative variant: N failed `Login` calls in the same case must *raise* the count and
eventually rate-limit, or the case passes against a backoff that is broken in the other direction and
is asserting nothing. (b) False-pass trap: choosing N below the threshold. Read the threshold from the
fixture's `Accounts` configuration and exceed it.
**Trace** handout §3 · gotcha 69 · `e2ee/e2ee.go:219-221`.

### E2EE-PRM-007 · A soft-deleted account reads as an unknown address · **ESSENTIAL** · T1

**Aim** Setting `deleted_at` makes `Params` return the decoy, not the stored row.
**Point of failure** `paramsByEmailSQL` gates `u.deleted_at is null` deliberately, so a disabled
account is indistinguishable from an absent one. Drop the gate and a deleted user's stored parameters
keep answering, which tells an attacker the account existed.
**Procedure** Enrol a user with non-default parameters; `update auth_users set deleted_at = now()`;
`Params`.
**Pass** The decoy: default KDF and cost, and `salt(email)` — **not** the stored salt.
**Fail** The stored row.
**Avoidance** (a) Negative variant: before the soft delete, the same call must return the stored
values, or the case passes against a statement that never finds anything. (b) False-pass trap:
asserting only the cost parameters. The salt is the field that distinguishes a stored answer from a
decoy, and enrolment gives the user a salt equal to their decoy (E2EE-SLT-003) — so this case must
enrol with parameters that differ *and* assert the KDF/cost fields, or compare against a second
address. Say which in the test comment.
**Trace** `e2ee/sql.go:35, 40`.

### E2EE-PRM-008 · An unverified account answers like a verified one · **ESSENTIAL** · T1

**Aim** `email_verified` does not change the response.
**Point of failure** A verification-gated `Params` is an oracle for "this address registered and has
not confirmed yet", which is more information than the login path gives out.
**Procedure** Two users, one verified and one not, both enrolled with identical parameters; compare
every field except the salt.
**Pass** Identical.
**Fail** Any difference.
**Avoidance** (a) Negative variant: assert both are non-decoy — i.e. both return their stored values —
so the case does not pass by both falling through to the same default. (b) False-pass trap: creating
both users through `createPasswordUser`, which sets `email_verified = true`. Insert the unverified one
directly.
**Trace** `e2ee/sql.go:36-40`.

### E2EE-PRM-009 · `Params` always reports `Parallelism == 1` · **ESSENTIAL** · T5

**Aim** Every response — decoy and stored — carries `Parallelism: 1`.
**Point of failure** Gotcha 66. Argon2's `p` changes the output. A client that reads `parallelism`
from the response and gets 0, or 2, derives a different key than the device that wrote the vault, and
the second device reports a corrupt vault. Three separate mechanisms pin this (`withDefaults`, the SQL
literal, the check constraint) and none of them is the one a client reads — the client reads this
response.
**Procedure** Decoy address, enrolled user, and an enrolled user whose `Put` carried
`Params{Parallelism: 4}`.
**Pass** 1 in all three.
**Fail** 0 or anything else in any.
**Avoidance** (a) Negative variant: the third arm is the negative — a client that *asks* for 4 must
still be told 1. Without it the case only proves the default is 1. (b) False-pass trap: asserting
`Parallelism != 0`.
**Trace** handout §4 · gotcha 66 · `e2ee/e2ee.go:73-78, 92` · `e2ee/sql.go:77` ·
`migrations/0003_e2ee.sql:26`.

### E2EE-PRM-010 · Two accounts whose addresses differ only in case · **[UNSPECIFIED]** · ESSENTIAL · T1

**Aim** Establish what `Params` does when `lower(u.email)` matches two rows.
**Point of failure** `QueryOneContext` over a statement returning two rows is a driver error, surfaced
from an unauthenticated endpoint. Whether `auth_users` permits such a pair is a `0001_core.sql`
question this register does not answer; if it does, the pre-auth surface has a reachable 500 and a
distinguishable response.
**Procedure** Attempt to insert `User@example.test` and `user@example.test`. If the schema rejects it,
the case records that and passes. If it does not, call `Params` and record the outcome.
**Pass** Either a unique constraint prevents the pair, or the case documents the driver error and
§17.7 carries the finding.
**Fail** Silent selection of an arbitrary one of the two rows.
**Avoidance** (a) Negative variant: assert the single-row case still works in the same test, so a
constraint discovered mid-case does not leave the group untested. (b) False-pass trap: assuming the
unique index is case-insensitive without checking `0001_core.sql`.
**Trace** `e2ee/e2ee.go:229` · §17.7.

### E2EE-PRM-011 · `Params` writes nothing at all · **ESSENTIAL** · T1

**Aim** The pre-auth endpoint is read-only: no vault row, no attempt row, no user row, no
`updated_at` touched.
**Point of failure** A `Params` that lazily materialises a vault row for an unknown address gives T1
unauthenticated row creation, and — worse — makes "does a row exist" true for every address anyone has
ever asked about, destroying the distinction the decoy exists to hide.
**Procedure** Snapshot the row counts of `auth_e2ee_vaults`, `auth_users` and `auth_login_attempts`;
call `Params` for 20 unknown addresses; re-count.
**Pass** All three counts unchanged.
**Fail** Any increase.
**Avoidance** (a) Negative variant: a `Put` in the same case must increase the vault count, or the
case passes against a database that is not being written to at all. (b) False-pass trap: counting only
`auth_e2ee_vaults`.
**Trace** `e2ee/e2ee.go:226-241`.

### E2EE-PRM-012 · The response is stable under repetition and concurrency · **GOOD-TO-HAVE** · T1

**Aim** 50 concurrent `Params` calls for one unknown address return 50 identical responses.
**Point of failure** Any per-call state — a cache with a race, a lazily seeded value — reintroduces
the moving decoy that E2EE-SLT-002 rules out, but only under load, where no sequential test looks.
**Procedure** P-3's barrier shape, 50 goroutines, one address.
**Pass** All 50 byte-identical.
**Fail** Any divergence.
**Avoidance** (a) Negative variant: run the same 50 against an *enrolled* address, which reads the
row rather than the HMAC — both paths must be stable. (b) False-pass trap: comparing each response to
the first sequentially after the fact without a barrier, which serialises the calls and tests
nothing.
**Trace** `e2ee/e2ee.go:205-209`.

---

## 7 · `E2EE-VLT` — `Get`, `Put`, `Discard`

The authenticated surface. Identity comes from the context principal and never from a parameter —
there is no `userID string` argument anywhere in this package, because an id parameter on a vault
method is an IDOR waiting for one resolver to pass the wrong variable.

### E2EE-VLT-001 · `Get` on an unauthenticated context returns `UNAUTHENTICATED` and reads nothing · **CRITICAL** · T1

**Aim** A bare `context.Background()` cannot read any vault.
**Point of failure** `authz.Require` is the only thing between an unauthenticated caller and a wrapped
key. Nothing tests it today for any of the three methods.
**Procedure** Enrol user A. `Get(context.Background(), db)`.
**Pass** `*kalerr.Error` with `CodeUnauthenticated`, a nil `*Vault`, and A's row still intact.
**Fail** A non-nil `*Vault`, or a nil error.
**Avoidance** (a) Negative variant: the same `Get` through `vaultCtx(aID, ...)` must return A's vault
in the same case, or a method that always errors passes. (b) False-pass trap: asserting `err != nil`
without asserting the `*Vault` is nil. A method that returns both hands the key to a caller that
ignores errors — which is the caller this control exists for.
**Trace** handout §4 · `e2ee/e2ee.go:252-255`.

### E2EE-VLT-002 · `Put` on an unauthenticated context writes no row · **CRITICAL** · T1

**Aim** Unauthenticated `Put` is rejected before `check` and before any statement runs.
**Point of failure** An unauthenticated write is both a storage bucket and — because `Put` derives the
salt from `p.Email` — a nil-pointer dereference away from a panic on a pre-auth path.
**Procedure** `Put(context.Background(), db, validVault)`; count rows across the whole table.
**Pass** `CodeUnauthenticated`, and `select count(*) from auth_e2ee_vaults` is zero.
**Fail** Any row, or a panic.
**Avoidance** (a) Negative variant: the authenticated `Put` in the same case must create a row. (b)
False-pass trap: counting rows for a specific `user_id`. There is no user id in this scenario — count
the table.
**Trace** `e2ee/e2ee.go:289-292`.

### E2EE-VLT-003 · `Discard` on an unauthenticated context deletes nothing · **CRITICAL** · T1

**Aim** Unauthenticated `Discard` cannot destroy a vault.
**Point of failure** `Discard` is the one irreversible operation in the module. An unauthenticated
one that reached the statement with an empty `user_id` would be a delete with no matching row today —
and a delete with no `where` clause after one refactor.
**Procedure** Enrol A. `Discard(context.Background(), db)`. Count all rows.
**Pass** `CodeUnauthenticated`, and A's row still present with the same bytes.
**Fail** Any deletion.
**Avoidance** (a) Negative variant: A's own `Discard` must delete A's row (E2EE-VLT-010). (b)
False-pass trap: asserting the count only. Assert the bytes — a delete-and-reinsert would preserve the
count.
**Trace** `e2ee/e2ee.go:341-344`.

### E2EE-VLT-004 · An anonymous principal is not a principal · **ESSENTIAL** · T1

**Aim** A context carrying an anonymous `*authz.Principal` (the shape the middleware installs for a
request with no cookie) is rejected by all three methods.
**Point of failure** The middleware never returns 401 — anonymous is not an error, the graph decides.
So the anonymous principal is a real, routinely-present context value, and `authz.Require` is what
distinguishes it from an authenticated one. A method that checked only `ctx.Value(...) != nil` would
pass every other case in this group.
**Procedure** Build the anonymous context the way `authz` does; call `Get`, `Put`, `Discard`.
**Pass** `CodeUnauthenticated` from all three, no row created or removed.
**Fail** Any success.
**Avoidance** (a) Negative variant: an authenticated principal through the same construction path must
succeed — otherwise the case is testing that the constructor is broken. (b) False-pass trap:
constructing the anonymous context by hand in a way `authz` never produces. Use the exported helper,
and if there is not one, that is a finding about the surface (P-5).
**Trace** README's "anonymous is never an error" · `e2ee/e2ee.go:252, 289, 341`.

### E2EE-VLT-005 · `Get` returns `(nil, nil)` for a user who never enrolled · **ESSENTIAL** · T2

**Aim** Absence is not an error, the same way `session.Lookup` treats an unknown token.
**Point of failure** Returning an error here pushes every consumer into `errors.Is(err,
pg.ErrNoRows)` at the resolver, which leaks a driver type through the API and gets mistranslated into
a 500 on the enrolment path every new user takes.
**Procedure** Create a user; `Get` without enrolling.
**Pass** Nil `*Vault`, nil error.
**Fail** A non-nil error, or a zero-valued non-nil `*Vault` — the second is worse, because the caller
then hands a client an empty wrapped key.
**Avoidance** (a) Negative variant: after `Put`, the same call must return a non-nil `*Vault`. (b)
False-pass trap: checking `err == nil` and not the `*Vault`. Covered incidentally today by
`TestDBE2EEVaultScope` (`tests/e2ee_db_test.go:135-141`) for B, not deliberately for the enrolment
path.
**Trace** handout §4 · `e2ee/e2ee.go:262-264`.

### E2EE-VLT-006 · `Get` round-trips the stored parameters · **ESSENTIAL** · T5

**Aim** `Vault.Params` on a `Get` carries the same `KDF`, `Salt`, `Memory`, `Iterations` and
`Parallelism` that `Params(email)` returns for that user.
**Point of failure** Two statements project the same five columns in the same order
(`paramsByEmailSQL` and `vaultByUserSQL`), and both scan positionally with no struct tags — field
order in the SQL is the entire contract. Swap two columns in one and the client derives with the wrong
memory cost. Nothing reads `Vault.Params` in any test today.
**Procedure** Enrol with `Memory: 131072, Iterations: 4`; compare `Get(...).Params` field by field
against `Params(email)`.
**Pass** All five equal.
**Fail** Any mismatch, especially a swapped `Memory`/`Iterations`, which is the failure a positional
scan produces.
**Avoidance** (a) Negative variant: use values that are distinguishable from each other and from the
defaults — `Memory: 131072, Iterations: 4` is fine; `Memory: 3, Iterations: 3` would hide a swap. (b)
False-pass trap: comparing `Get(...).Params` against the struct that was passed to `Put`. `Salt` is
ignored on write and `Parallelism` is forced, so that comparison fails for the right reasons and gets
"fixed" by weakening it. Compare against `Params(email)`.
**Trace** `e2ee/e2ee.go:257-261` · `e2ee/sql.go:37, 51`.

### E2EE-VLT-007 · B cannot read A's vault · **CRITICAL** · T2

**Aim** With A enrolled, B's `Get` returns nil.
**Point of failure** The scoping is `where v.user_id = ?` bound from `p.UserID`. There is no other
control — no RLS on this table, no `Scope` call — so this statement is the whole boundary.
**Procedure** A enrols; B `Get`s.
**Pass** Nil `*Vault`, nil error.
**Fail** A's bytes in B's hands.
**Avoidance** (a) Negative variant: A's own `Get` must return A's vault, or an always-nil `Get`
passes. (b) False-pass trap: giving B a principal with A's email but B's id, or vice versa. Build both
principals fully and correctly — the case is about the id binding, and a half-built principal makes
the result meaningless.
**Trace** handout §4 · `e2ee/sql.go:54` · covered by `TestDBE2EEVaultScope`
(`tests/e2ee_db_test.go:135-141`).

### E2EE-VLT-008 · B's `Put` does not touch A's row · **CRITICAL** · T2

**Aim** After B enrols, A's `wrapped_key` is byte-identical to what A wrote.
**Point of failure** Asserted on the row, not on B's return value: a `Put` that reported success while
writing to the wrong `user_id` passes any version of this that only checks B's error.
**Procedure** A enrols with a known blob; B `Put`s; read A's `wrapped_key` column directly.
**Pass** A's original bytes.
**Fail** B's bytes, or absence.
**Avoidance** (a) Negative variant: B's own row must exist afterwards with B's bytes, or a `Put` that
silently does nothing passes. (b) False-pass trap: reading A's vault through `Get` with A's context —
that reads the same statement B would have corrupted. Read the column.
**Trace** `e2ee/sql.go:79` · covered by `tests/e2ee_db_test.go:145-153`.

### E2EE-VLT-009 · B's `Discard` does not delete A's row · **CRITICAL** · T2

**Aim** A's row survives B's `Discard`.
**Point of failure** `deleteVaultSQL` is one line with one predicate. A `Discard` that reported
success while deleting the wrong row is unrecoverable and silent — there is nothing to compare
against afterwards.
**Procedure** A enrols; B `Discard`s (B has no vault); read A's row.
**Pass** Present, unchanged; B's `Discard` returns nil.
**Fail** A's row gone.
**Avoidance** (a) Negative variant: A's own `Discard` must remove A's row (E2EE-VLT-010). Without it,
a `Discard` that deletes nothing at all passes. (b) False-pass trap: asserting only that B's call
returned an error — it correctly returns nil, and a case written to expect an error would be "fixed"
by making `Discard` fail on a missing row, which is the wrong behaviour.
**Trace** `e2ee/sql.go:92-93` · covered by `tests/e2ee_db_test.go:142-144`.

### E2EE-VLT-010 · `Discard` actually deletes the caller's vault · **ESSENTIAL** · T2

**Aim** After the owner's `Discard`, `Get` returns nil and the row count for that user is zero.
**Point of failure** Nothing asserts this today. `TestDBE2EEVaultScope` only proves B's `Discard` did
not hit A — which a `Discard` that is a complete no-op also satisfies. A no-op `Discard` leaves the
user who asked to destroy their vault believing it is gone.
**Procedure** Enrol; `Discard`; `Get`; `vaultRows`.
**Pass** Nil `*Vault`, `vaultRows == 0`.
**Fail** The row survives.
**Avoidance** (a) Negative variant: a second `Discard` must also return nil — idempotence is the
documented behaviour and a case that expects an error on the second call pins the wrong contract. (b)
False-pass trap: this case is the negative variant that E2EE-VLT-009 needs. Write them adjacent so
neither can be deleted alone.
**Trace** handout §4 · `e2ee/e2ee.go:340-347`.

### E2EE-VLT-011 · A sequential `Put` at a stale `KeyVersion` is `CONFLICT` and changes nothing · **CRITICAL** · T5

**Aim** With a vault at version 2, `Put` carrying `KeyVersion: 1` returns `CodeConflict` and leaves
the stored key untouched.
**Point of failure** Only the concurrent race is tested today. The sequential case is the one every
real client hits: two tabs, one stale read, a re-wrap submitted from the older one. If the CAS is
absent the loser silently overwrites a key the winner has already shown its user — and that user's
next login fails against a vault key they were told was theirs.
**Procedure** `Put` (v1); `Put` with `KeyVersion: 1` (v2); `Put` again with `KeyVersion: 1` carrying
different bytes.
**Pass** Third call returns `*kalerr.Error` with `CodeConflict`; `storedKey` still holds the second
call's bytes.
**Fail** Success, or the third call's bytes in the table.
**Avoidance** (a) Negative variant: a `Put` at the *correct* version must succeed in the same case, or
a `Put` that always conflicts passes. (b) False-pass trap: asserting the error and not the bytes.
A CAS that returns `CONFLICT` *after* writing is exactly the bug, and it is reachable — the conflict
is derived from `pg.ErrNoRows` on a `returning` clause, so an implementation that split the statement
would produce it.
**Trace** handout §4 · gotcha 36 · `e2ee/sql.go:89` · `e2ee/e2ee.go:302-305`.

### E2EE-VLT-012 · `key_version` increments by exactly one per successful `Put` · **ESSENTIAL** · T5

**Aim** After N successful re-wraps, `Get(...).KeyVersion == N`.
**Point of failure** The version is the client's only handle on the CAS. If it jumps, or does not
move, a correct client is locked out of ever writing again — every subsequent `Put` conflicts, with
`CONFLICT` as the only diagnostic, and the user cannot re-wrap after a password change.
**Procedure** `Put` (insert), then three more at the version each previous `Get` reported.
**Pass** 1, 2, 3, 4 — and each `Put` succeeds.
**Fail** A gap, a repeat, or a conflict on a correctly-versioned write.
**Avoidance** (a) Negative variant: assert the *first* `Put` produces version 1, not 0 — the column
defaults to 1 and the update adds 1, so an off-by-one here would make every client's first re-wrap
conflict. (b) False-pass trap: reading the version from the value `Put` returns. It returns nothing —
see §17.5. Read it through `Get`.
**Trace** `e2ee/sql.go:87, 90` · `migrations/0003_e2ee.sql:31`.

### E2EE-VLT-013 · Concurrent `Put`s at one version: exactly one wins · **CRITICAL** · T5

**Aim** Eight goroutines re-wrapping from the same read produce one nil error and seven `CONFLICT`s.
**Point of failure** A read-then-write implementation passes every sequential case and fails this one,
and its failure mode is that a user is shown a key that was silently overwritten a moment later. Two
devices re-wrapping after the same password change is the ordinary case, not a theoretical one.
**Procedure** P-3's barrier, eight goroutines, all at `before.KeyVersion`.
**Pass** Exactly one nil error; every other a `*kalerr.Error` with `CodeConflict`.
**Fail** Two successes, or zero.
**Avoidance** (a) Negative variant: assert a winner *exists*. Zero successes is as broken as two, and
it is the failure mode of an over-tight CAS — the vault then holds a key no device has. (b)
False-pass trap: `go func()` with no barrier. It serialises in practice and passes against a
read-then-write.
**Trace** handout §4 · gotcha 36 · covered by `TestDBE2EEPutConcurrency`
(`tests/e2ee_db_test.go:219`).

### E2EE-VLT-014 · The table holds the winner's key, not a loser's · **CRITICAL** · T5

**Aim** After the race, `storedKey` equals the bytes of the attempt that was told it succeeded.
**Point of failure** The pairing is the property. "One success" and "the winner's bytes are stored"
are two different assertions, and a system that reports one winner while storing another's bytes has
told a user their key is safe and stored somebody else's.
**Procedure** As E2EE-VLT-013, with per-goroutine distinguishable blobs.
**Pass** `storedKey == keys[winner]`.
**Fail** Any other attempt's bytes.
**Avoidance** (a) Negative variant: the losers' blobs must be *absent* — with eight distinct values,
assert the stored one matches exactly one index and that index is the winner. (b) False-pass trap:
using the same blob in every goroutine, which makes the assertion vacuous.
**Trace** covered by `tests/e2ee_db_test.go:271-273`.

### E2EE-VLT-015 · A first `Put` ignores `KeyVersion` · **[UNSPECIFIED]** · ESSENTIAL · T5

**Aim** Record that `Put` with `KeyVersion: 57` against a user with no row succeeds and produces
version 1.
**Point of failure** `Vault.KeyVersion`'s doc says "Zero means no row yet", and the `where
auth_e2ee_vaults.key_version = ?` predicate lives in the `on conflict do update` clause — so it is
evaluated only when a row already exists. On the insert path the parameter is bound and never
consulted. A client that sends a stale non-zero version at enrolment gets a success it should not
have, and the mismatch surfaces on its *next* write.
**Procedure** Fresh user; `Put` with `KeyVersion: 57`; `Get`.
**Pass** The case asserts today's behaviour — success, version 1 — and §17.4 carries the finding.
**Fail** The behaviour changes without this case changing.
**Avoidance** (a) Negative variant: the same `KeyVersion: 57` against an *existing* row must
`CONFLICT`, so the case pins where the predicate does and does not apply. (b) False-pass trap:
writing this as a test that expects a rejection, which would fail and be "fixed" by deleting it.
**Trace** `e2ee/sql.go:80-89` · `e2ee/e2ee.go:140-141` · §17.4.

### E2EE-VLT-016 · `Put` for an absent or soft-deleted user reports `CONFLICT` · **[UNSPECIFIED]** · ESSENTIAL · T5

**Aim** Record that the insert's `where u.id = ? and u.deleted_at is null` produces zero rows, which
becomes `pg.ErrNoRows`, which becomes "the vault changed since it was read; re-read it and try
again".
**Point of failure** The message is wrong for the situation, and a client that follows it re-reads,
finds nothing, retries, and loops. The condition is not a conflict — it is a deleted account.
**Procedure** Enrol a user; soft-delete them; `Put` again with the correct version. Separately, a
principal carrying a `UserID` that does not exist.
**Pass** The case asserts `CodeConflict` in both, records the message, and §17.6 carries the finding.
**Fail** A panic, or a driver error surfacing raw.
**Avoidance** (a) Negative variant: the same `Put` before the soft delete must succeed, so the case
isolates `deleted_at` as the cause rather than the version. (b) False-pass trap: asserting only the
code. Assert the message text too — the finding is about the message.
**Trace** `e2ee/sql.go:79` · `e2ee/e2ee.go:302-305` · §17.6.

### E2EE-VLT-017 · `Get` for a soft-deleted user still returns the vault · **[UNSPECIFIED]** · ESSENTIAL · T2

**Aim** Record the asymmetry: `paramsByEmailSQL` gates `deleted_at`, `vaultByUserSQL` does not.
**Point of failure** A soft-deleted account whose session has not been revoked can still read its
wrapped key. Whether that is right depends on what soft delete means in the deployment — and the code
says nothing either way, which is the finding.
**Procedure** Enrol; soft-delete; `Get` with the same principal.
**Pass** The case asserts today's behaviour and §17.8 carries the finding.
**Fail** Undocumented change.
**Avoidance** (a) Negative variant: `Params` for the same address in the same case must return the
decoy, which is what makes the asymmetry visible rather than a bare observation. (b) False-pass trap:
assuming session revocation makes this unreachable. It is a property of the statement; assert the
statement.
**Trace** `e2ee/sql.go:40` vs `e2ee/sql.go:54` · §17.8.

### E2EE-VLT-018 · A principal with an empty email derives a shared salt · **[UNSPECIFIED]** · ESSENTIAL · T5

**Aim** Record that `Put` from a principal whose `Email` is empty stores
`HMAC(pepper, "kal.e2ee.salt|")` — one salt shared by every such user, and one that no `Params(email)`
call can ever return.
**Point of failure** `Put` takes the address from the principal, and a principal built by a code path
that does not populate `Email` produces a vault nobody can open, because the client asked `Params` for
a different salt. A JWT-only session, or a resolver constructing a principal by hand, reaches this.
**Procedure** `vaultCtx(userID, "")`; `Put`; read the `salt` column; compare against a second user
enrolled the same way.
**Pass** The case asserts today's behaviour — the two salts are equal — and §17.9 carries the finding.
**Fail** Undocumented change.
**Avoidance** (a) Negative variant: the same two users enrolled *with* addresses must get different
salts, which is what makes the collision a finding rather than a coincidence. (b) False-pass trap:
asserting only that the `Put` succeeded.
**Trace** `e2ee/e2ee.go:299` · §17.9.

---

## 8 · `E2EE-POL` — `check`, the policy that cannot live in the schema

Four rules, applied in a fixed order, before any statement runs. **P-8 applies to every case here:
assert the row, not just the error.**

### E2EE-POL-001 · An empty wrapped key is rejected and writes nothing · **ESSENTIAL** · T2

**Aim** `Vault{RecoveryWrappedKey: x}` with no `WrappedKey` is `CodeInvalidInput` and leaves no row.
**Point of failure** A row with a null `wrapped_key` reads as an enrolled vault to `Get` — the column
is nullable, and `Get` returns a non-nil `*Vault` with nil bytes. The client then imports a zero-length
key.
**Procedure** `Put` with `WrappedKey: nil`; then `WrappedKey: []byte{}`.
**Pass** `CodeInvalidInput` and `vaultRows == 0` for both.
**Fail** Either accepted.
**Avoidance** (a) Negative variant: a one-byte `WrappedKey` must be accepted — the rule is emptiness,
not a minimum size, and a case that only probes nil would not catch a `len < 32` guard added later
that breaks a legitimate short blob. (b) False-pass trap: `nil` only. `[]byte{}` is the arm that
distinguishes a nil check from a length check.
**Trace** `e2ee/e2ee.go:312-314` · covered by `TestDBE2EEPutRejects/no wrapped key at all`.

### E2EE-POL-002 · An over-ceiling wrapped key is rejected and writes nothing · **ESSENTIAL** · T2

**Aim** 8193 bytes under the default ceiling is `CodeInvalidInput`, no row.
**Point of failure** Gotcha 77: an authenticated caller with an unbounded `bytea` column has a free
storage bucket, replicated and backed up at the operator's expense.
**Procedure** `Put` with `WrappedKey` of 8193 bytes.
**Pass** `CodeInvalidInput`, `vaultRows == 0`.
**Fail** Accepted.
**Avoidance** (a) Negative variant: 8192 accepted (E2EE-POL-004). (b) False-pass trap: an over-size
blob that is *also* missing its recovery wrapping — `check` returns on the first failure, so the case
would be asserting the wrong rule. Every rejection case in this group must be otherwise valid.
**Trace** gotcha 77 · `e2ee/e2ee.go:317` · covered by `TestDBE2EEPutRejects/blob over MaxBlob`.

### E2EE-POL-003 · The ceiling applies to the recovery wrapping too · **ESSENTIAL** · T2

**Aim** An over-size `RecoveryWrappedKey` with a valid `WrappedKey` is rejected.
**Point of failure** Both blobs share one condition (`||`). Nothing tests the second operand today, so
a refactor that split the check and dropped one arm would leave half the storage bucket open — and the
recovery blob is the one with no size expectation in any client, so it is the easier half to abuse.
**Procedure** `WrappedKey` of 64 bytes, `RecoveryWrappedKey` of 8193.
**Pass** `CodeInvalidInput`, `vaultRows == 0`.
**Fail** Accepted.
**Avoidance** (a) Negative variant: swap the two sizes and confirm the other arm still rejects, so one
case cannot pass for the other's reason. (b) False-pass trap: making both blobs over-size, which
cannot distinguish the operands.
**Trace** `e2ee/e2ee.go:317`.

### E2EE-POL-004 · Exactly at the ceiling is accepted · **GOOD-TO-HAVE** · T5

**Aim** 8192 bytes succeeds and the bytes round-trip intact.
**Point of failure** A `>=` where a `>` belongs rejects a blob a correct client produced, and the user
cannot enrol at all — with `INVALID_INPUT` and no explanation of which input.
**Procedure** `Put` 8192 bytes; `Get`; compare.
**Pass** Accepted, and `Get` returns the identical 8192 bytes.
**Fail** Rejected, or truncated.
**Avoidance** (a) Negative variant: 8193 rejected in the same case. (b) False-pass trap: asserting
acceptance without reading the bytes back — a `bytea` round-trip through a positional scan is exactly
where a truncation would hide.
**Trace** `e2ee/e2ee.go:317`.

### E2EE-POL-005 · A missing recovery wrapping is rejected by default · **ESSENTIAL** · T5

**Aim** With the zero `Options`, a `Vault` with no `RecoveryWrappedKey` is `CodeInvalidInput`.
**Point of failure** Without a recovery wrapping, a forgotten password is unrecoverable data loss, and
the support queue that produces cannot be answered by anyone — including the operator. The field is
named for the opt-out (`AllowNoRecovery`) so that `false` is the safe posture; the case pins that the
default is in fact the safe one.
**Procedure** `Put` with `RecoveryWrappedKey` nil, then `[]byte{}`.
**Pass** `CodeInvalidInput`, `vaultRows == 0`, both.
**Fail** Either accepted.
**Avoidance** (a) Negative variant: E2EE-POL-006 — with the opt-out on, the same `Vault` must be
accepted, or the case passes against a rule that ignores the option. (b) False-pass trap: `nil` only.
**Trace** handout §11 · `e2ee/e2ee.go:320-322` · covered by
`TestDBE2EEPutRejects/no recovery wrapping`.

### E2EE-POL-006 · `AllowNoRecovery: true` accepts a vault with no recovery wrapping · **ESSENTIAL** · T5

**Aim** The opt-out works, and `Get` reports the empty recovery wrapping honestly.
**Point of failure** A dead opt-out means a deployment that deliberately chose no recovery cannot
enrol anyone, and the field reads as configuration that does nothing. It is also the arm that proves
E2EE-POL-005 tests the *rule* and not an unrelated failure.
**Procedure** Second `Vaults` with `AllowNoRecovery: true`; `Put` with no recovery wrapping; `Get`.
**Pass** Accepted; the row exists; `Get(...).RecoveryWrappedKey` is empty.
**Fail** Rejected, or a non-empty recovery wrapping appearing from somewhere.
**Avoidance** (a) Negative variant: the same `Put` through the default-configured `Vaults` must still
be rejected. (b) False-pass trap: setting `AllowNoRecovery` and also supplying a recovery wrapping.
**Trace** `e2ee/e2ee.go:124-129, 320`.

### E2EE-POL-007 · An unknown KDF is rejected and writes nothing · **ESSENTIAL** · T5

**Aim** `KDF: "scrypt"` is `CodeInvalidInput`.
**Point of failure** The `kdf` column is `text` with no check constraint. An unrecognised value is
stored, returned to every future client, and none of them knows how to derive with it — a vault that
cannot be opened by any conforming implementation.
**Procedure** Table: `"scrypt"`, `"bcrypt"`, `"Argon2id"` (wrong case), `"argon2i"`, `"argon2id "`
(trailing space).
**Pass** `CodeInvalidInput` and `vaultRows == 0` for every one.
**Fail** Any accepted.
**Avoidance** (a) Negative variant: `"argon2id"` and `"pbkdf2"` must be accepted in the same case. (b)
False-pass trap: testing only `"scrypt"`. The near-misses — wrong case, trailing space — are the ones
a real client sends, and they are what distinguishes an exact comparison from a fuzzy one.
**Trace** `e2ee/e2ee.go:324-326` · partly covered by `TestDBE2EEPutRejects/an unknown client KDF`.

### E2EE-POL-008 · `KDFPBKDF2` is accepted and stored · **ESSENTIAL** · T5

**Aim** A PBKDF2 vault can be written and read back with `kdf = "pbkdf2"`.
**Point of failure** Gotcha 75: WebCrypto has no Argon2id, so a client written against "what the
browser has" produces PBKDF2. The constant exists to keep those users openable, and `kdf`/`memory`/
`iterations` are in the `do update set` list precisely so moving them to Argon2id later is a re-wrap on
their next login rather than a migration. If `KDFPBKDF2` were rejected, that whole path is dead and
nobody would find out until a Safari user tried to enrol.
**Procedure** `Put` with `KDF: KDFPBKDF2`; `Params`; then re-wrap with `KDF: KDFArgon2id` and
`KeyVersion: 1`; `Params` again.
**Pass** First read reports `"pbkdf2"`; the re-wrap succeeds and the second read reports `"argon2id"`
with the same salt.
**Fail** The first `Put` rejected, or the `kdf` column not updating on re-wrap.
**Avoidance** (a) Negative variant: the salt must not move across the KDF change (E2EE-SLT-008) — a
KDF migration that also rotated the salt would destroy the very vaults it was meant to rescue. (b)
False-pass trap: asserting the `Put` succeeded without reading the column back. `kdf` is in the update
set; whether it is *bound* correctly is the thing.
**Trace** handout §6 · gotcha 75 · `e2ee/e2ee.go:43-45` · `e2ee/sql.go:81`.

### E2EE-POL-009 · An empty `KDF` is filled, not rejected · **GOOD-TO-HAVE** · T5

**Aim** `Params{}` on a `Put` produces `kdf = "argon2id"` in the row.
**Point of failure** `withDefaults` runs before the allowlist comparison, so `""` becomes `"argon2id"`
and passes. That is intentional — a client that omits parameters gets the deployment's defaults — but
it means the allowlist never sees an empty string, and a reader of `check` alone would conclude
otherwise.
**Procedure** `Put` with a zero `Params`; read the `kdf`, `memory`, `iterations` columns.
**Pass** `argon2id` / 65536 / 3.
**Fail** An empty `kdf`, or a rejection.
**Avoidance** (a) Negative variant: a non-empty unknown KDF must still be rejected (E2EE-POL-007), so
the case does not read as "the KDF is never checked". (b) False-pass trap: asserting the return value
of `Put` only.
**Trace** `e2ee/e2ee.go:83-85, 323-326`.

### E2EE-POL-010 · `Memory` below the floor is rejected and writes nothing · **ESSENTIAL** · T4

**Aim** `Memory: 1024` with valid iterations is `CodeInvalidInput`, no row.
**Point of failure** The floor is the only thing stopping a compromised or lazy client from enrolling
its user under parameters that make an offline attack on the stolen database cheap — which is the one
adversary this module exists for.
**Procedure** `Params{KDF: KDFArgon2id, Memory: 1024, Iterations: 3}`.
**Pass** `CodeInvalidInput`, `vaultRows == 0`.
**Fail** Accepted.
**Avoidance** (a) Negative variant: `Memory: 19456` (exactly the floor) accepted — E2EE-POL-012. (b)
False-pass trap: lowering `Memory` and `Iterations` together, which is what
`TestDBE2EEParamsFloor` does today. It cannot tell which comparison fired, so a floor that checks only
one of the two passes it.
**Trace** handout §4 · `e2ee/e2ee.go:327` · partly covered by `TestDBE2EEParamsFloor`.

### E2EE-POL-011 · `Iterations` below the floor is rejected independently · **ESSENTIAL** · T4

**Aim** `Iterations: 1` with `Memory` well above the floor is rejected.
**Point of failure** The two comparisons are one `||` condition. Drop the second operand and a client
can enrol at 64 MiB with a single pass, which is a real cost reduction, and nothing in the response
differs.
**Procedure** `Params{KDF: KDFArgon2id, Memory: 65536, Iterations: 1}`.
**Pass** `CodeInvalidInput`, `vaultRows == 0`.
**Fail** Accepted.
**Avoidance** (a) Negative variant: E2EE-POL-010, the mirror case with the other field. Together they
pin both operands; separately neither does. (b) False-pass trap: `Iterations: 0`, which
`withDefaults` fills to 3 before the comparison and therefore *passes* the floor. Use 1.
**Trace** `e2ee/e2ee.go:327`.

### E2EE-POL-012 · Exactly at the floor is accepted · **GOOD-TO-HAVE** · T4

**Aim** `Memory: 19456, Iterations: 2` succeeds.
**Point of failure** A `<=` where a `<` belongs rejects OWASP's own recommendation, which is the value
a careful client will send.
**Procedure** `Put` at exactly the documented floor.
**Pass** Accepted; the row holds 19456 / 2.
**Fail** Rejected.
**Avoidance** (a) Negative variant: one unit below each must be rejected. (b) False-pass trap: using
the *default* (65536 / 3) and calling it a floor test.
**Trace** `e2ee/e2ee.go:179`.

### E2EE-POL-013 · A rejected `Put` never damages an existing vault · **CRITICAL** · T2

**Aim** With a good vault already stored, every rejection in this group leaves the stored bytes,
parameters and version exactly as they were.
**Point of failure** Every rejection case today runs against a **fresh user with no row**, so they all
assert `vaultRows == 0` — which is satisfied by a `check` that runs after the write as easily as
before it. The failure this misses is the damaging one: a user with a working vault submits a bad
re-wrap and loses the good key. `check` does run first, and this case is what says so.
**Procedure** Enrol a valid vault; record `storedKey`, `Params` and `KeyVersion`. Then run each
rejection from E2EE-POL-001, -002, -003, -005, -007, -010, -011 against the *same* user at the correct
`KeyVersion`. Re-read after each.
**Pass** `CodeInvalidInput` every time; the stored key, parameters and version unchanged throughout.
**Fail** Any change to any of the three — especially a bumped `key_version`, which would lock the
client out of its next legitimate write.
**Avoidance** (a) Negative variant: a *valid* `Put` at the same version must succeed at the end and
bump the version to prove the row was writable all along. Without it, a `Put` that is broken for this
user passes. (b) False-pass trap: reusing `vaultRows == 0`. There is a row; count is the wrong
instrument. Compare bytes.
**Trace** `e2ee/e2ee.go:293-296` · P-8.

### E2EE-POL-014 · `Memory` has a floor and no ceiling · **[UNSPECIFIED]** · GOOD-TO-HAVE · T2

**Aim** Record that `Memory: 3_000_000_000` passes `check` and fails at the driver, because `Memory`
is `uint32` in Go over an `int4` column.
**Point of failure** The error surfaces as a driver error, not `CodeInvalidInput`, so a consumer's
error mapping turns a client's bad input into a 500. A client that stores an absurd memory cost that
*does* fit in `int4` — 2 GiB — makes its own users unable to log in on a phone, permanently, and kal
accepted it.
**Procedure** `Put` with `Memory: 3_000_000_000`, then with `Memory: 2_000_000` (fits, absurd).
**Pass** The case asserts today's behaviour for both and §17.12 carries the finding.
**Fail** A panic.
**Avoidance** (a) Negative variant: a sane value must succeed, so the case is about the ceiling and not
about `Put` being broken. (b) False-pass trap: asserting `err != nil` and stopping. Record *which*
error — the distinction between a driver error and `CodeInvalidInput` is the finding.
**Trace** `e2ee/e2ee.go:71, 327` · `migrations/0003_e2ee.sql:24` · §17.12.

---

## 9 · `E2EE-STL` — staleness, the fingerprint, and the drift that must not happen

`Vault.Stale` converts the worst failure in this design — a wrapped key handed to a client that has
no possible way to open it — into one typed boolean at the point of read.

### E2EE-STL-001 · A freshly written vault reads live · **ESSENTIAL** · T5

**Aim** `Get` immediately after `Put` reports `Stale: false`.
**Point of failure** The write and the read compute `sha256(coalesce(password_hash,''))` from one
shared constant. If they ever drift apart, **every vault in the deployment reads as stale forever** —
a working login, a key the client is told not to trust, and no error anywhere. This case is the
canary for that drift and it is cheap.
**Procedure** `Put`; `Get`.
**Pass** `Stale == false`.
**Fail** True.
**Avoidance** (a) Negative variant: E2EE-STL-002 in the same file — a flag that is always false is as
broken as one that is always true, and only the pair distinguishes them. (b) False-pass trap: reading
`Stale` from the `Vault` that was passed to `Put`. It is ignored on write; read it from `Get`.
**Trace** handout §4 · gotcha 74 · `e2ee/sql.go:21-29` · covered by
`TestDBE2EEStaleAfterReset` (`tests/e2ee_db_test.go:182-184`).

### E2EE-STL-002 · A password reset makes the vault stale · **CRITICAL** · T5

**Aim** After `RequestPasswordReset` → `ResetPassword`, `Get` reports `Stale: true` and the row still
exists.
**Point of failure** Without the flag the client receives a key derived from a password that no longer
exists, and fails somewhere far from the cause — a decrypt error in a resolver three screens away,
with no explanation. `authn` gets no hook and no callback for this; the join is the entire mechanism.
**Procedure** Enrol; full reset cycle through the mailer fixture and `tokenFromURL`; `Get`.
**Pass** `Stale == true`, `*Vault` non-nil.
**Fail** False, or the row gone.
**Avoidance** (a) Negative variant: assert `Stale == false` before the reset in the same test, or a
constant `true` passes. (b) False-pass trap: asserting that `password_hash` changed. It obviously did;
the property is the flag.
**Trace** handout §4 · gotcha 74 · covered by `TestDBE2EEStaleAfterReset`
(`tests/e2ee_db_test.go:163`).

### E2EE-STL-003 · `ChangePassword` makes the vault stale · **ESSENTIAL** · T5

**Aim** The other password-write path produces the same verdict.
**Point of failure** Only the reset path is tested. `ChangePassword` writes `password_hash` through a
different statement, and the staleness join does not care — which is the design's strength and
therefore worth one case, because a future `ChangePassword` that wrote through a path the join could
not see would be silent.
**Procedure** Enrol; `ChangePassword(current, next)` through the fixture; `Get`.
**Pass** `Stale == true`; the recovery wrapping intact.
**Fail** False.
**Avoidance** (a) Negative variant: a *failed* `ChangePassword` (wrong current password) must leave
`Stale == false`, so the case tracks the hash and not the call. (b) False-pass trap: running
`ChangePassword` under `Config.E2EE` semantics with a raw password, which is rejected by
`SecretShape` before the hash moves — see E2EE-SEC-012. Use a `Vaults` built directly, with an
`Accounts` whose `SecretShape` is nil.
**Trace** `authn/accounts.go:288` · gotcha 74.

### E2EE-STL-004 · A re-wrap after a reset clears the flag · **CRITICAL** · T5

**Aim** After the reset makes the vault stale, a `Put` at the current version restores
`Stale: false`.
**Point of failure** This closes the recovery loop, and nothing tests it. If `wrapped_for` is not
recomputed on the update path — it is in the `do update set` list, and it is the entry most likely to
be dropped in a refactor — the vault reads stale **forever** after one password reset. The user
re-wraps, is told the key is still untrustworthy, re-wraps again, and the loop never terminates.
**Procedure** Enrol; reset the password; confirm `Stale`; `Put` a new wrapping at the reported
`KeyVersion`; `Get`.
**Pass** `Stale == false`, and the new bytes are stored.
**Fail** Still stale.
**Avoidance** (a) Negative variant: a second reset must make it stale again, so the case proves the
fingerprint tracks the hash rather than being cleared once and left. (b) False-pass trap: re-wrapping
at the wrong `KeyVersion`, which returns `CONFLICT` — the case would then assert staleness on a vault
that was never rewritten and pass for the wrong reason. Read the version from `Get`.
**Trace** `e2ee/sql.go:86` · gotcha 74.

### E2EE-STL-005 · The recovery wrapping survives a reset · **CRITICAL** · T5

**Aim** `RecoveryWrappedKey` is byte-identical after a password reset.
**Point of failure** It is wrapped under the recovery code, not under the password, so it is the
**only** route back into a vault whose password was reset. The obvious implementation nulls both
columns together, and a user who resets their password would then have no route back at all — the
exact data loss the recovery code exists to prevent.
**Procedure** Enrol with a known recovery blob; reset; `Get`.
**Pass** Identical bytes.
**Fail** Nulled, changed, or the row deleted.
**Avoidance** (a) Negative variant: assert `WrappedKey` is *also* unchanged — kal does not null either,
and a case that only guards the recovery column would miss a reset that destroyed the password
wrapping. (b) False-pass trap: asserting non-nil. Compare the bytes.
**Trace** handout §11 · `e2ee/e2ee.go:381-383` · covered by `tests/e2ee_db_test.go:207-209`.

### E2EE-STL-006 · One user's password change does not stale another's vault · **ESSENTIAL** · T5

**Aim** A and B both enrolled; A resets; B reads `Stale: false`.
**Point of failure** The staleness expression joins `auth_users` on `v.user_id`. A join written
against the wrong column, or a fingerprint compared globally, would mark the whole deployment stale
the first time anyone changed a password — and every client would refuse a key that was perfectly
good.
**Procedure** Enrol A and B; reset A; `Get` as B.
**Pass** B `Stale == false`; A `Stale == true`.
**Fail** B stale.
**Avoidance** (a) Negative variant: A's own verdict in the same case, or a constant `false` passes.
(b) False-pass trap: enrolling B *after* A's reset, which would mask a join that ignores `user_id`.
Enrol both first.
**Trace** `e2ee/sql.go:48-54`.

### E2EE-STL-007 · A user with no password has a defined verdict · **ESSENTIAL** · T5

**Aim** For an account whose `password_hash` is null — an invited user who has not accepted — the
staleness verdict is deterministic and documented.
**Point of failure** `coalesce(password_hash, '')` means the fingerprint is `sha256('')`, so such a
user's vault reads live only if `wrapped_for` holds that exact digest. `IS DISTINCT FROM` is what
stops the comparison evaluating to NULL and scanning into a `bool` — which is the failure a plain `<>`
produces, and it is a scan error, not a wrong answer.
**Procedure** Create a user with a null `password_hash`; `Put`; `Get`. Then set a password directly;
`Get` again.
**Pass** First read `Stale: false` (both sides are `sha256('')`); second `Stale: true`. No scan error
in either.
**Fail** A driver error, or a NULL scanned into `Stale`.
**Avoidance** (a) Negative variant: the second read is the negative — without it, a `Stale` that is
always false passes. (b) False-pass trap: creating the user through `createPasswordUser`, which sets a
hash. Insert directly.
**Trace** `e2ee/sql.go:29, 50`.

### E2EE-STL-008 · The fingerprint is computed in SQL at write time · **ESSENTIAL** · T5

**Aim** A `Put` that races a password change stores the hash as it stands at the instant of the write,
never one read earlier in Go.
**Point of failure** Computing `wrapped_for` in Go requires reading `password_hash` first, which is a
read-then-write racing a concurrent password change: the vault is written against a hash that is
already gone, and it reads stale from the moment it is created.
**Procedure** P-3's barrier: one goroutine running `ChangePassword`, one running `Put`, released
together. Repeat 20 times on fresh users. After each, `Get`.
**Pass** Every iteration ends in one of two consistent states — the `Put` landed after the change and
reads live, or before it and reads stale. Never a vault that reads stale immediately after a `Put`
with no intervening password change.
**Fail** A vault that is stale at birth with no concurrent change, or a state neither ordering
explains.
**Avoidance** (a) Negative variant: the sequential ordering (change, then put) must reliably produce a
live vault, so the case has a known-good baseline. (b) False-pass trap: one iteration. The race window
is small; run enough iterations that a Go-side computation would be caught, and say in the comment
that a green run is evidence and not proof.
**Trace** `e2ee/sql.go:68-69, 77`.

### E2EE-STL-009 · `Stale` is ignored on write · **GOOD-TO-HAVE** · T2

**Aim** `Put` with `Stale: true` does not persist anything, and the next `Get` computes the verdict
from the fingerprint.
**Point of failure** If `Stale` ever became a stored column instead of a computed one, `authn` would
need a hook and an ordering requirement between two writes — the thing this design exists to avoid —
and a client could then mark its own vault fresh.
**Procedure** `Put` with `Stale: true`; `Get`.
**Pass** `Stale == false`.
**Fail** True.
**Avoidance** (a) Negative variant: `Put` with `Stale: false` after a password reset must still read
`true`. That is the arm that matters — a client clearing its own staleness flag is the security
failure; a client setting it is only noise. (b) False-pass trap: running only the harmless direction.
**Trace** `e2ee/e2ee.go:142-147`.

### E2EE-STL-010 · There is one fingerprint expression, not two · **CRITICAL** · T5

**Aim** The write and the staleness read derive from the same Go constant.
**Point of failure** Two copies that drift make every vault in the deployment read stale forever. The
symptom is indistinguishable from "everyone reset their password", which is not a hypothesis anyone
tests, and the fix is invisible from the outside.
**Procedure** Two arms. Behavioural: enrol, `Get`, assert live — that is E2EE-STL-001 and it fails
immediately on any drift. Structural: assert `putVaultSQL` and `vaultByUserSQL` both contain the
`wrappedForFingerprint` text, by reading `e2ee/sql.go` from the test and matching the substring in
both constants.
**Pass** Both arms.
**Fail** Either.
**Avoidance** (a) Negative variant: the structural arm must fail if the substring is *removed* from
one — verify by editing it under §15's mutation matrix, not by inspection. (b) False-pass trap: the
structural arm alone. Two identical strings that are both wrong pass it; E2EE-STL-001 is what catches
that, which is why the case carries both.
**Trace** `e2ee/sql.go:21-29` · gotcha 74 · §15 mutation M-08.

---

## 10 · `E2EE-SEC` — the auth secret and the `authn` seam

The shape check is the single most likely way to break a deployment of this feature, and one check
prevents all of it. §10 splits into the check itself (SEC-001..008) and the four places it fires —
plus the one place it deliberately does not.

### E2EE-SEC-001 · Plausible human passwords are rejected · **CRITICAL** · T5

**Aim** `"correct horse battery staple"`, `"P@ssw0rd!2026"`, `""` are all `CodeInvalidInput`.
**Point of failure** Gotcha 65 in one line: a client that sends the raw password logs in
successfully, and the account is now hashed over a value the vault key was not derived from. Login
works. The vault silently never opens. Nothing errors and nothing logs, and the user's data is gone.
**Procedure** Table of human-shaped inputs.
**Pass** `*kalerr.Error` with `CodeInvalidInput` for every one.
**Fail** Any acceptance.
**Avoidance** (a) Negative variant: a correctly-derived secret must be accepted, or a function that
rejects everything passes — and that function breaks every login in the deployment. (b) False-pass
trap: asserting `err != nil` without the code. The error class is what the consumer's error presenter
maps; a bare error becomes a 500 instead of a 400.
**Trace** handout §2 · gotcha 65 · `e2ee/e2ee.go:362-372` · covered by `TestValidateAuthSecret`.

### E2EE-SEC-002 · 42 and 44 characters are rejected · **CRITICAL** · T5

**Aim** One character short and one long both fail.
**Point of failure** 43 unpadded base64url characters is exactly 32 bytes. A length-tolerant decode
accepts a 33-byte or 31-byte secret, which is a different key and therefore silent data loss.
**Procedure** A valid secret truncated by one, and with one character appended.
**Pass** Both rejected.
**Fail** Either accepted.
**Avoidance** (a) Negative variant: the untouched 43-character value accepted. (b) False-pass trap:
truncating in a way that also breaks base64 alignment, so the case passes on the decode error rather
than the length. `RawURLEncoding` on 42 characters decodes cleanly to 31 bytes — that is the arm the
explicit `len(raw) != 32` check exists for, and the case must reach it.
**Trace** `e2ee/e2ee.go:368` · covered by `tests/e2ee_test.go:82-83`.

### E2EE-SEC-003 · The standard base64 alphabet is rejected · **ESSENTIAL** · T5

**Aim** `+` and `/` are not accepted in place of `-` and `_`.
**Point of failure** A client using `btoa` without the URL-safe substitution produces a secret with a
different byte string for the same key — accepted by a tolerant decoder, hashed, and the vault never
opens.
**Procedure** `"kal1." + strings.Repeat("+", 43)`, and a real secret with `-`/`_` swapped for `+`/`/`.
**Pass** Rejected.
**Fail** Accepted.
**Avoidance** (a) Negative variant: a secret that genuinely contains `-` and `_` must be accepted —
generate one deliberately rather than encoding zero bytes, which contains neither. (b) False-pass
trap: encoding `make([]byte, 32)`. It produces 43 `A`s, exercises no alphabet edge, and is what the
current test's "the real thing" arm uses.
**Trace** `e2ee/e2ee.go:367` · covered by `tests/e2ee_test.go:86`.

### E2EE-SEC-004 · Non-canonical trailing bits are rejected · **ESSENTIAL** · T5

**Aim** A secret whose final character carries non-zero low bits fails.
**Point of failure** 43 base64url characters carry 258 bits for a 256-bit value, so the last
character's two low bits must be zero. A character-class regex accepts these; a strict decode does
not. Two distinct strings would then map to the same 32 bytes, and the login path would accept a
secret the client never produced.
**Procedure** Take a valid secret, replace the last character with one differing only in its low bits.
**Pass** Rejected.
**Fail** Accepted.
**Avoidance** (a) Negative variant: the canonical form of the same 32 bytes must be accepted, which is
what makes this a canonicity test rather than a corruption test. (b) False-pass trap: replacing the
last character arbitrarily — most replacements also change the decoded bytes, and the case would pass
under a non-strict decoder. Pick the substitution deliberately (`...A` → `...B`).
**Trace** `e2ee/e2ee.go:357-358, 367` · covered by `tests/e2ee_test.go:89`.

### E2EE-SEC-005 · The version prefix is exact · **ESSENTIAL** · T5

**Aim** No prefix, `kal2.`, `KAL1.`, and a leading space are all rejected.
**Point of failure** The prefix versions the derivation so a future scheme is distinguishable on
sight rather than by a decode that happens to fail. A tolerant prefix match makes the version
meaningless the first time it is needed.
**Procedure** Table of prefix mutations against one valid body.
**Pass** All rejected; `kal1.` accepted.
**Fail** Any acceptance.
**Avoidance** (a) Negative variant: `kal1.` must be accepted. (b) False-pass trap: `strings.Contains`
in the test's own expectation. `CutPrefix` anchors at position zero; assert that a secret with a valid
prefix *embedded later* (`"x" + valid`) is rejected.
**Trace** `e2ee/e2ee.go:49-51, 363-366` · partly covered by `tests/e2ee_test.go:84-85`.

### E2EE-SEC-006 · Padded base64 is rejected · **ESSENTIAL** · T5

**Aim** `"kal1." + base64.URLEncoding.EncodeToString(32 bytes)` — the padded variant, 44 characters
with a trailing `=` — fails.
**Point of failure** `RawURLEncoding` and `URLEncoding` are one identifier apart in every language's
standard library, and a client that picks the padded one sends a secret that decodes to the right 32
bytes under a tolerant parser. Accept it and the same key has two wire forms; the account is hashed
over whichever arrived first, and the other client is locked out.
**Procedure** Encode 32 bytes with padding; prefix; validate.
**Pass** Rejected.
**Fail** Accepted.
**Avoidance** (a) Negative variant: the unpadded encoding of the identical bytes must be accepted, so
the case isolates the padding. (b) False-pass trap: assuming the 44-character case (E2EE-SEC-002)
covers this. It does — today, by length — but a future 48-byte secret would make length and padding
independent, and this case states the property that survives that change.
**Trace** `e2ee/e2ee.go:367` · `docs/e2ee-client.md:29`.

### E2EE-SEC-007 · Whitespace is not trimmed · **GOOD-TO-HAVE** · T5

**Aim** A leading or trailing space, tab or newline makes the secret invalid.
**Point of failure** A secret is not an email address. Trimming it would mean two different strings
hash to the same account credential, and a client that pastes with a trailing newline gets a
different-looking secret accepted — masking a bug that will bite the next client.
**Procedure** Valid secret with `" "`, `"\n"`, `"\t"` prepended and appended.
**Pass** All rejected.
**Fail** Any accepted.
**Avoidance** (a) Negative variant: the untrimmed valid secret accepted. (b) False-pass trap:
asserting this about `Params`'s email argument, which *is* trimmed deliberately (E2EE-SLT-005). The
two are opposite properties; state why in the comment.
**Trace** `e2ee/e2ee.go:363-369`.

### E2EE-SEC-008 · A secret from the documented derivation is accepted · **ESSENTIAL** · T5

**Aim** A value built exactly as `docs/e2ee-client.md` specifies — `"kal1." + b64url(32 bytes)` —
validates.
**Point of failure** The shape check and the reference client are one contract in two files. If the
check tightened without the doc changing, every conforming client breaks at once with
`INVALID_INPUT` and no route forward.
**Procedure** Generate 32 random bytes; encode with `RawURLEncoding`; prefix; validate. Repeat 100
times so the alphabet is exercised.
**Pass** All 100 accepted.
**Fail** Any rejection.
**Avoidance** (a) Negative variant: mutate one byte of the *encoding* (not the key) in each iteration
and confirm rejection where the mutation breaks canonicity. (b) False-pass trap: one iteration over
`make([]byte, 32)` — see E2EE-SEC-003(b). Random bytes are what covers `-` and `_`.
**Trace** `docs/e2ee-client.md:29` · `e2ee/e2ee.go:362`.

### E2EE-SEC-009 · `Register` under E2EE rejects a raw password and creates no user · **CRITICAL** · T5

**Aim** With `Config.E2EE` set, `Register(email, "a real password")` returns `CodeInvalidInput` and
`auth_users` gains no row.
**Point of failure** This is the first gate a mis-updated client hits. If the check runs after the
insert — or if the row is created and only the hash rejected — the address is now taken, the user
cannot register again, and support has an account nobody can log into.
**Procedure** Build `kal.New` with `E2EE` set; `Register` with a raw password; count `auth_users`
rows for that address; then `Register` with a valid auth secret.
**Pass** `CodeInvalidInput`, zero user rows, and the second call succeeds.
**Fail** Any row, or the second call failing with "already registered".
**Avoidance** (a) Negative variant: the second `Register` is the negative — without it, a `Register`
that always fails passes. (b) False-pass trap: asserting only the error code, which is what
`TestConfigValidation` does today (`tests/kal_test.go:267-317`). The row is the property; the error is
the symptom.
**Trace** handout §4 · gotcha 65 · `authn/tokens.go:61` · `kal.go:264-288`.

### E2EE-SEC-010 · `ResetPassword` under E2EE rejects a raw password and consumes no token · **CRITICAL** · T5

**Aim** A reset submitted with a raw password fails, the stored hash is unchanged, and the reset token
is **still usable**.
**Point of failure** The shape check is the first statement in `ResetPassword`, before `consume`. If
it moved after — an ordering nothing outside this case pins — a client that sent a raw password would
burn the user's one-shot token, leave the password unchanged, and leave the user with no way to
retry: the token is gone, the password is the old one they have forgotten, and the vault is
untouched but unreachable.
**Procedure** Enrol; request a reset; `ResetPassword(token, "a raw password")`; assert the failure;
then `ResetPassword(token, validAuthSecret)` with the same token.
**Pass** First call `CodeInvalidInput`, hash unchanged, vault `Stale == false`; second call succeeds
with the same token.
**Fail** The second call reporting an invalid or consumed token.
**Avoidance** (a) Negative variant: the successful second call is the negative — it proves the token
was never consumed rather than merely that the first call failed. (b) False-pass trap: requesting a
fresh token before the second call, which is exactly what hides the finding.
**Trace** gotcha 65 · `authn/tokens.go:171`.

### E2EE-SEC-011 · `AcceptInvite` under E2EE rejects a raw password and leaves the invite unconsumed · **CRITICAL** · T5

**Aim** The same property on the invite path.
**Point of failure** An invite is single-use and often the only one a person will get. Burning it on
a shape rejection means re-inviting through an admin, and under E2EE the invited user has no vault
yet — so the failure is recoverable only by a human.
**Procedure** Invite; `AcceptInvite(token, rawPassword)`; assert failure and that the user is still
unaccepted; `AcceptInvite(token, validAuthSecret)`.
**Pass** First rejected with no state change; second succeeds on the same token.
**Fail** The invite consumed by the first call.
**Avoidance** (a) Negative variant: the successful second call. (b) False-pass trap: asserting on the
returned error only, without checking the invite row.
**Trace** gotcha 65 · `authn/tokens.go:265`.

### E2EE-SEC-012 · `ChangePassword` shape-checks `next` and not `current` · **ESSENTIAL** · T5

**Aim** State both halves: `next` must be a valid auth secret, and `current` is passed to the verifier
unexamined.
**Point of failure** `next` unchecked is silent data loss on the most common vault-affecting
operation. `current` checked would be worse in a different way — an account enrolled before `E2EE`
was switched on still holds a password-derived hash, and shape-checking `current` locks that user out
permanently with `INVALID_INPUT`, with no migration path and no way for them to reach the very
operation that would fix it.
**Procedure** Under `E2EE`: `ChangePassword(currentAuthSecret, "a raw password")` → rejected, hash
unchanged, vault not stale. Then `ChangePassword("whatever shape", newAuthSecret)` → reaches the
verifier and fails as `INVALID_CREDENTIALS`, **not** `INVALID_INPUT`.
**Pass** Both, with the two error codes distinct.
**Fail** `current` producing `INVALID_INPUT`, or `next` producing anything else.
**Avoidance** (a) Negative variant: the correct `current` with a valid `next` must succeed and stale
the vault (E2EE-STL-003). (b) False-pass trap: asserting `err != nil` for the `current` arm. The two
codes are the entire finding — an implementation that rejects both looks identical under a bare
non-nil check.
**Trace** `authn/accounts.go:288-296` · handout §4.

### E2EE-SEC-013 · `Login` does not shape-check, and that is the property · **ESSENTIAL** · T5

**Aim** `Login` accepts any string and returns `INVALID_CREDENTIALS` — never `INVALID_INPUT` —
whatever shape arrives.
**Point of failure** Both directions are real. If `Login` shape-checked, every account that
registered before `E2EE` was enabled would be locked out at the login screen with `INVALID_INPUT`,
and the reset path would not save them (E2EE-SEC-010 requires an auth secret too). If it silently
*accepted* a raw password against a raw-password hash — which it does, correctly — the write-side
checks are what prevent such an account from existing in the first place. The control is on the write
path only, and this case is what says so out loud, so nobody "hardens" it.
**Procedure** Under `E2EE`: `Login(addr, "a raw password")` against an account registered with an auth
secret; and `Login(addr, validButWrongAuthSecret)`.
**Pass** `INVALID_CREDENTIALS` in both. No `INVALID_INPUT` anywhere on the login path.
**Fail** `INVALID_INPUT`.
**Avoidance** (a) Negative variant: the correct auth secret must produce a principal in the same case,
or a `Login` that rejects everything passes. (b) False-pass trap: reading this case as an argument
that `Login` should be tightened. Write the reason into the test comment; a case whose *purpose* is to
document a deliberate absence gets deleted by the next person unless the comment carries the argument.
**Trace** `authn/accounts.go:194-215` · gotcha 65 · §17.13.

### E2EE-SEC-014 · With `Config.E2EE` nil, `ValidatePassword` applies unchanged · **ESSENTIAL** · T5

**Aim** The zero posture is today's posture exactly: `SecretShape` defaults to `ValidatePassword`,
`Auth.Vaults` is nil, and a 5-character password is still rejected on its own terms.
**Point of failure** If `SecretShape` defaulted to nil-and-skipped rather than to `ValidatePassword`,
enabling nothing would silently remove the password policy from every existing deployment.
**Procedure** `kal.New` with a minimal config; assert `Auth.Vaults == nil`; `Register` with a
5-character password (`INVALID_INPUT`) and with a good one (succeeds).
**Pass** All three.
**Fail** A short password accepted, or `Vaults` non-nil.
**Avoidance** (a) Negative variant: the same short password under `E2EE` must fail for a *different*
reason — the shape check, not the length policy. Both fail, so assert the message or the branch. (b)
False-pass trap: asserting only that `Register` errored. Covered partly by `TestConfigValidation`
(`tests/kal_test.go:267-317`).
**Trace** CLAUDE.md zero-Config invariant · `authn/accounts.go:114` · `kal.go:264-278`.

### E2EE-SEC-015 · Enabling E2EE removes the password policy, on purpose · **GOOD-TO-HAVE** · T5

**Aim** Under `E2EE`, a valid auth secret derived from a one-character password is accepted, and no
strength check fires.
**Point of failure** Gotcha 76: the server never sees a password, so client-side strength checks are
advisory against anyone who can call the API directly. A deployment that believes otherwise has one
fewer control than it thinks. The case exists so the consequence is asserted rather than assumed.
**Procedure** Derive a valid-shaped auth secret; `Register`; succeed. Confirm no length policy runs.
**Pass** Accepted.
**Fail** Rejected — which would mean a password policy is being applied to a value that is not a
password.
**Avoidance** (a) Negative variant: a raw one-character *password* must still be rejected (by shape),
so the case does not read as "everything is accepted". (b) False-pass trap: presenting this as a
security control. It is a documented loss; §14 tests that it is documented.
**Trace** gotcha 76 · handout §4.

---

## 11 · `E2EE-RCV` — the recovery code

Thirty-two bytes from `crypto/rand`, shown once, and **kal stores no hash of it**. The wrapped key is
the verifier. Nothing anywhere can check a recovery code except an attempt to unwrap with it.

### E2EE-RCV-001 · A code is 32 bytes of unpadded base64url · **ESSENTIAL** · T3

**Aim** Every code decodes strictly to exactly 32 bytes.
**Point of failure** A short code is brute-forceable against a stolen database — and unlike a
password there is no rate limit in front of it, because the verifier is the wrapped blob and the
attacker has it.
**Procedure** 32 draws; `base64.RawURLEncoding.Strict().DecodeString`; length.
**Pass** All 32 decode to 32 bytes.
**Fail** Any shorter, or a decode error.
**Avoidance** (a) Negative variant: assert the encoding is *strict*-decodable, not merely decodable —
a padded or standard-alphabet code would break a client that decodes strictly. (b) False-pass trap:
`len(code) > 0`.
**Trace** handout §5 · `e2ee/e2ee.go:386-389` · covered by `TestE2EERecoveryCodeShape`.

### E2EE-RCV-002 · Codes never repeat · **CRITICAL** · T3

**Aim** No two draws collide.
**Point of failure** A code drawn from `math/rand`, or from a seeded generator, is predictable — and
it is the only route back into a vault whose password was reset. Two users with the same code means
one can open the other's vault, given the blob.
**Procedure** 1024 draws into a set (raise the current 32; the cost is negligible and the signal is
better).
**Pass** 1024 distinct.
**Fail** Any repeat.
**Avoidance** (a) Negative variant: a coarse distribution check — assert the concatenated bytes are
not constant and that byte values are spread — so a generator returning a fixed value under a
different code path is caught. Uniqueness alone passes for a counter. (b) False-pass trap: too few
draws. 32 draws of 32 bytes cannot distinguish `crypto/rand` from a counter.
**Trace** `session/token.go:24` · covered weakly by `tests/e2ee_test.go:114`.

### E2EE-RCV-003 · No hash or copy of the code reaches any table · **CRITICAL** · T3

**Aim** After minting a code and enrolling a vault wrapped under it, **no row anywhere** contains the
code or a hash of it.
**Point of failure** `NewRecoveryCode` calls `session.NewToken`, which returns `(code, hash, err)`,
and discards the hash. Storing it "so we can tell the user whether their code is right" is a natural
and fatal convenience: it gives a stolen database a second, verifiable route into every vault, which
is precisely the property the design forgoes. Nothing tests this, and the failing version is a
one-line change in a package that already computes the hash.
**Procedure** Mint a code; enrol a vault whose `RecoveryWrappedKey` is derived from it. Then scan
**every** `bytea` and `text` column of `auth_e2ee_vaults`, `auth_users` and `auth_sessions` for the
code string and for `session.HashToken(code)`.
**Pass** No match anywhere.
**Fail** Any match.
**Avoidance** (a) Negative variant: search for a value that *is* stored — the wrapped blob itself —
and confirm the scan finds it. Without that arm, a scan that is silently looking in the wrong place
passes. (b) False-pass trap: checking only `auth_e2ee_vaults`. Enumerate the tables from
`information_schema` so a new table added later is covered by construction.
**Trace** handout §5 · `e2ee/e2ee.go:374-389`.

### E2EE-RCV-004 · Minting a code requires no principal and writes nothing · **GOOD-TO-HAVE** · T1

**Aim** `NewRecoveryCode()` takes no context, touches no database, and returns only on a CSPRNG
failure.
**Point of failure** A version that recorded issuance would reintroduce E2EE-RCV-003's stored
verifier by the back door — "we only store when it was issued" becomes "and its hash, for support".
**Procedure** Snapshot all table counts; mint 100 codes; re-count.
**Pass** Unchanged.
**Fail** Any write.
**Avoidance** (a) Negative variant: a `Put` in the same case must move a count. (b) False-pass trap:
counting one table.
**Trace** `e2ee/e2ee.go:386-389`.

### E2EE-RCV-005 · The recovery wrapping is the only route back after a reset · **CRITICAL** · T5

**Aim** After a password reset, `Get` returns a stale vault whose `RecoveryWrappedKey` is intact, and
a `Put` re-wrapping from it succeeds.
**Point of failure** The whole recovery story is three properties that are each tested elsewhere and
never tested as a sequence: the code survives the reset (STL-005), the vault is marked stale
(STL-002), and a re-wrap clears it (STL-004). A break anywhere in the chain leaves the user with a
vault they can see and cannot open, and the failure only appears end-to-end.
**Procedure** The full path: enrol with a recovery wrapping → reset the password → `Get` (stale, blob
intact) → `Put` a new wrapping at the reported version → `Get` (live).
**Pass** Every step, in order.
**Fail** Any step.
**Avoidance** (a) Negative variant: a user who enrolled with no recovery wrapping (under
`AllowNoRecovery`) reaches the same reset with **no** route back — assert that state explicitly, so
the case documents what the opt-out costs. (b) False-pass trap: asserting the intermediate steps
individually and never running them as one sequence. The sequence is the case.
**Trace** handout §11 · `e2ee/e2ee.go:381-383`.

### E2EE-RCV-006 · A recovery code is not a session token · **GOOD-TO-HAVE** · T2

**Aim** A recovery code presented as a session cookie authenticates nobody.
**Point of failure** The two share a shape and a generator (`session.NewToken`). If a code were ever
inserted into `auth_sessions` — by a helpful "let them in after recovery" path — it would become a
bearer credential with no expiry and no revocation.
**Procedure** Mint a code; present it as a session cookie through the middleware.
**Pass** Anonymous principal; no session row matches.
**Fail** Authentication.
**Avoidance** (a) Negative variant: a genuine session token through the same path must authenticate.
(b) False-pass trap: asserting the middleware returned no error — it never does; anonymous is not an
error. Assert the principal.
**Trace** `e2ee/e2ee.go:387` · `session/token.go`.

---

## 12 · `E2EE-SCH` — the schema

One table, one check constraint, one foreign key. Everything else is Go's job — a floor expected to
rise over time should not be a migration.

### E2EE-SCH-001 · `check (parallelism = 1)` rejects at the database · **ESSENTIAL** · T5

**Aim** A direct `insert ... parallelism = 2` fails with a check violation.
**Point of failure** Gotcha 66. Three mechanisms pin `p = 1` — `withDefaults`, the SQL literal, and
this constraint — and the constraint is the only one that survives a bug in the other two. Nothing
tests it. A migration that dropped it would be invisible.
**Procedure** New helper `putVaultDirect(t, db, userID, parallelism)`: a raw insert bypassing `Put`.
Insert with 2, then 0, then 1.
**Pass** Errors for 2 and 0; success for 1.
**Fail** Any acceptance of a value other than 1.
**Avoidance** (a) Negative variant: 1 must succeed, or a broken insert statement passes. (b)
False-pass trap: going through `Put`, which hard-codes the literal `1` and can never reach the
constraint. The case must write raw SQL, and the comment must say why.
**Trace** gotcha 66 · `migrations/0003_e2ee.sql:26`.

### E2EE-SCH-002 · No `Put` can ever produce `parallelism ≠ 1` · **CRITICAL** · T5

**Aim** Whatever `Params.Parallelism` a client sends — 0, 2, 4, 255 — the stored column is 1.
**Point of failure** The client-facing half of gotcha 66. A browser that picks `p` from the thread
pool derives a different key on a laptop than on a phone, and the second device reports a corrupt
vault. `withDefaults` pins it, the SQL literal pins it, and the update set omits it entirely — three
independent reasons, none of them tested.
**Procedure** Table over `Parallelism` values; `Put` each; read the column; then re-wrap with a
different value and read again (the update path, which omits the column).
**Pass** 1 in every case, insert and update.
**Fail** Anything else.
**Avoidance** (a) Negative variant: assert `Params(email).Parallelism` and `Get(...).Params.Parallelism`
also report 1 (E2EE-PRM-009) — the column being right is useless if the projection is wrong, and it is
the projection the client reads. (b) False-pass trap: testing only the insert. The update path is a
different statement with different columns.
**Trace** gotcha 66 · `e2ee/e2ee.go:92` · `e2ee/sql.go:77, 80-89`.

### E2EE-SCH-003 · One vault row per user · **ESSENTIAL** · T2

**Aim** The primary key on `user_id` makes a second row impossible.
**Point of failure** Two rows for one user means `Get`'s `QueryOne` errors and the user's vault is
unreachable — a denial of service on their own data, triggered by whichever write path lost the
uniqueness.
**Procedure** `putVaultDirect` twice for one user without `on conflict`.
**Pass** The second fails on the primary key.
**Fail** Two rows.
**Avoidance** (a) Negative variant: `Put` twice through the normal path must succeed (the upsert), so
the case distinguishes the constraint from the code that works around it. (b) False-pass trap: using
`Put` for both, which never reaches the constraint.
**Trace** `migrations/0003_e2ee.sql:20`.

### E2EE-SCH-004 · Deleting a user removes the vault · **ESSENTIAL** · T3

**Aim** `on delete cascade` takes the wrapped key with the account.
**Point of failure** An orphaned vault row is ciphertext material outliving its owner in a database
whose whole threat model is "someone reads it". A hard delete that leaves it behind also leaves the
`user_id` dangling, which breaks every join in `sql.go`.
**Procedure** Enrol; `delete from auth_users where id = ?`; count vault rows.
**Pass** Zero.
**Fail** The row survives.
**Avoidance** (a) Negative variant: a *soft* delete must leave the row (E2EE-VLT-017) — the two
deletes have opposite semantics and a case that conflated them would pin the wrong one. (b)
False-pass trap: soft-deleting and expecting a cascade.
**Trace** `migrations/0003_e2ee.sql:20`.

### E2EE-SCH-005 · The parameter columns are `not null` · **GOOD-TO-HAVE** · T5

**Aim** `kdf`, `salt`, `memory`, `iterations`, `parallelism` reject null.
**Point of failure** A null in any of the five scans into a Go zero value on the way to the client,
which derives with `memory = 0` and produces a key nothing can reproduce.
**Procedure** `putVaultDirect` with each column null in turn.
**Pass** Five constraint violations.
**Fail** Any accepted.
**Avoidance** (a) Negative variant: the three blob columns *are* nullable by design — assert one
inserts as null successfully, so the case pins the boundary rather than "everything is not null". (b)
False-pass trap: relying on Go never sending null. The case is about the schema.
**Trace** `migrations/0003_e2ee.sql:21-26`.

### E2EE-SCH-006 · A pre-enrolment row is not a vault · **GOOD-TO-HAVE** · T2

**Aim** A row whose `wrapped_key` is null makes `Get` return something a client cannot mistake for an
enrolled vault.
**Point of failure** `wrapped_key` is nullable ("null until enrolment", per the migration), but
`Put` refuses an empty key — so the state is unreachable through the API and reachable through SQL.
`Get` returns a non-nil `*Vault` with a nil `WrappedKey`, and a client that checks `vault != nil`
imports a zero-length key.
**Procedure** `putVaultDirect` with a null `wrapped_key`; `Get`.
**Pass** The case asserts today's behaviour and states which side is responsible for the check.
**Fail** Undocumented change.
**Avoidance** (a) Negative variant: through `Put`, an empty key is rejected (E2EE-POL-001), so the
state cannot arise from the API. (b) False-pass trap: concluding the nullable column is a bug. It is
the enrolment-in-progress state the migration documents; the case records the gap between that and
what `Get` returns.
**Trace** `migrations/0003_e2ee.sql:28` · `e2ee/e2ee.go:312`.

### E2EE-SCH-007 · The migration applies in order and only adds · **GOOD-TO-HAVE** · T5

**Aim** `0003_e2ee.sql` creates one table and alters no core table.
**Point of failure** An `alter table auth_users` in a module migration couples the optional feature to
the core schema, and a deployment that never enables `E2EE` carries the change anyway.
**Procedure** Assert the file's text contains no `alter table`, and that applying every migration in
order against a clean schema yields `auth_e2ee_vaults` with the expected columns (cross-reference
`tests/migrations_test.go` rather than duplicating it).
**Pass** Both.
**Fail** Either.
**Avoidance** (a) Negative variant: assert the table *is* created, so a text-only check cannot pass
against an empty file. (b) False-pass trap: duplicating `migrations_test.go`'s coverage. Extend it if
it already runs every file; add only what is e2ee-specific.
**Trace** handout §5 · `migrations/0003_e2ee.sql`.

### E2EE-SCH-008 · No index exists that would make a ciphertext column searchable · **GOOD-TO-HAVE** · T4

**Aim** `auth_e2ee_vaults` carries no index beyond the primary key.
**Point of failure** Gotcha 72: a blind index restores equality lookup and is an offline dictionary
oracle on any low-entropy field. Nothing here needs one, and one added "for performance" would be the
first step toward the thing the module exists to prevent.
**Procedure** Query `pg_indexes` for the table.
**Pass** One entry, the primary key.
**Fail** Any additional index, which must be justified in the diff.
**Avoidance** (a) Negative variant: assert the primary key *is* present. (b) False-pass trap: reading
the migration text instead of the live catalogue — an index created elsewhere would not appear.
**Trace** gotcha 72 · `migrations/0003_e2ee.sql`.

---

## 13 · `E2EE-SHM` — the re-export shim and the `Config` seam

A new exported symbol in `e2ee` is invisible from `kal.` until it is added to `kal.go` by hand, and
the compiler will not say so.

### E2EE-SHM-001 · Alias identity holds in both directions · **ESSENTIAL** · T5

**Aim** `kal.VaultParams`, `kal.VaultOptions`, `kal.Vault` and `kal.Vaults` are aliases of the `e2ee`
types, not copies.
**Point of failure** A hand-written *copy* of a struct compiles, satisfies a one-directional
assertion, and diverges the first time a field is added to one and not the other — producing a
consumer that sets `kal.Vault.RecoveryWrappedKey` and a package that never reads it.
**Procedure** Compile-time assertions in both directions for each of the four.
**Pass** Compiles.
**Fail** Does not.
**Avoidance** (a) Negative variant: both directions, always. `var _ kal.Vault = e2ee.Vault{}` alone
passes for a struct with a superset of fields. (b) False-pass trap: a runtime `reflect.TypeOf`
comparison, which is weaker and can be skipped.
**Trace** CLAUDE.md re-export invariant · `kal.go:501-520` · covered by `tests/kal_test.go:139-158`.

### E2EE-SHM-002 · The re-exported functions are the package's own · **ESSENTIAL** · T5

**Aim** `kal.ValidateAuthSecret`, `kal.NewRecoveryCode` and `kal.NewVaults` behave identically to
`e2ee`'s.
**Point of failure** A wrapper that adds a "convenience" — trimming the secret, defaulting the pepper
— is a security change in a file whose job is forwarding, and no test in `e2ee`'s own group would see
it.
**Procedure** Run E2EE-SEC-001's table through both entry points and compare outcomes; call
`kal.NewVaults(VaultOptions{})` and assert the same error as `e2ee.NewVaults`.
**Pass** Identical.
**Fail** Any divergence.
**Avoidance** (a) Negative variant: assert both accept the valid case too. (b) False-pass trap:
asserting only that `kal.X` exists. `TestE2EEReExportedConstants` (`tests/kal_test.go:240`) covers the
constants' values; the functions need the same treatment.
**Trace** `kal.go:574-585`.

### E2EE-SHM-003 · The KDF constants carry the exact wire values · **ESSENTIAL** · T5

**Aim** `"argon2id"` and `"pbkdf2"`, lowercase, no variation.
**Point of failure** These are wire values a second client compares against. A rename that keeps the
Go identifier and changes the string breaks every client silently — the vault stores an unrecognised
`kdf` and nothing errors until a derive.
**Procedure** Literal string comparison at both `kal.` and `e2ee.`.
**Pass** Exact.
**Fail** Any difference.
**Avoidance** (a) Negative variant: assert the two differ from each other. (b) False-pass trap:
comparing `kal.KDFArgon2id == e2ee.KDFArgon2id`, which is true for any pair of equal wrong values.
Compare against the literals.
**Trace** `e2ee/e2ee.go:42, 45` · covered by `tests/kal_test.go:240`.

### E2EE-SHM-004 · `Config.E2EE` nil leaves `authn` untouched · **ESSENTIAL** · T5

**Aim** `Auth.Vaults` is nil and `SecretShape` defaults to `ValidatePassword`.
**Point of failure** The zero `Config` is the production posture. If wiring E2EE changed anything for
a deployment that did not ask for it, the invariant is broken in the direction that matters.
**Procedure** `kal.New` minimal; assert `Auth.Vaults == nil`; `Register` short password rejected.
**Pass** Both.
**Fail** Either.
**Avoidance** (a) Negative variant: E2EE-SHM-005. (b) False-pass trap: asserting `Vaults == nil` only.
Covered partly by `tests/kal_test.go:267-317`.
**Trace** CLAUDE.md zero-Config invariant · `kal.go:264-278`.

### E2EE-SHM-005 · `Config.E2EE` non-nil wires both halves · **CRITICAL** · T5

**Aim** Setting it produces a non-nil `Auth.Vaults` **and** a `SecretShape` that rejects a raw
password.
**Point of failure** Two things are wired in one `if`. Wire the vault and not the shape check and
every client that was not updated logs in successfully over a vault it cannot open — gotcha 65, with
the config that was supposed to prevent it switched on.
**Procedure** `kal.New` with `E2EE`; assert `Auth.Vaults != nil`; `Register` with a raw password →
`INVALID_INPUT`.
**Pass** Both.
**Fail** Either — especially the second with the first passing, which is the silent half.
**Avoidance** (a) Negative variant: `Register` with a valid auth secret must succeed. (b) False-pass
trap: asserting `Vaults != nil` and stopping, which is half the wiring.
**Trace** `kal.go:264-278` · covered partly by `tests/kal_test.go:267-317`.

### E2EE-SHM-006 · `Config.TableSchema` overrides `Options.Schema` silently · **ESSENTIAL** · T5

**Aim** Record that `kal.New` copies `*cfg.E2EE` and overwrites `Schema` with `cfg.TableSchema`, so a
schema set on `E2EE` is discarded.
**Point of failure** A consumer that sets `E2EE.Schema` and not `Config.TableSchema` gets statements
against the default schema with no warning — every vault operation silently targets the wrong tables,
which under a shared database is another tenant's.
**Procedure** `kal.New` with `TableSchema: "kal_test"` and `E2EE.Schema: "somewhere_else"`; enrol;
assert the row landed in `kal_test`.
**Pass** `kal_test`.
**Fail** Elsewhere, or an error.
**Avoidance** (a) Negative variant: assert the caller's `*cfg.E2EE` is **not** mutated — `kal.New`
takes a copy (`vaultOpts := *cfg.E2EE`), and a version that wrote through the pointer would change a
struct the consumer still holds. (b) False-pass trap: setting both to the same value.
**Trace** `kal.go:266-268`.

---

## 14 · `E2EE-DOC` — the refusals, where a deployment will read them

Gotcha 64 is not testable as behaviour. It is testable as text, and text is the only control there is
for it. These cases read files.

### E2EE-DOC-001 · The refusal is in the README, the package doc and the client doc · **CRITICAL** · T4

**Aim** All three carry the statement that browser-delivered E2EE does not defend against the server
that serves the JavaScript — in those words, not softened.
**Point of failure** Gotcha 64. A consumer who deploys this believing it defends against their own
server has deployed the wrong control, and the failure mode is that they **stop** doing the thing that
would have worked. There is no code change that fixes that; the paragraph is the whole mitigation.
**Procedure** Read `README.md`, `e2ee/e2ee.go`'s package comment and `docs/e2ee-client.md`. **Normalise
whitespace first** — strip `// ` prefixes, collapse every run of whitespace to one space — then match
three clauses: `"does not protect against the server that serves the JavaScript"`, `"Anyone who tells
you otherwise is selling something"`, `"kal cannot read your data"`.
**Pass** All three clauses in all three files.
**Fail** Missing or softened in any.
**Avoidance** (a) Negative variant: match on the *positive* claim too ("kal cannot read your data, and
neither can anyone who reads your database") — a document that carries only the refusal and not the
honest claim reads as a reason not to use the feature, which is its own failure. (b) **False-fail
trap, which is the live hazard here:** all three files hard-wrap at 100 columns, so every clause above
is split across a line break *today* — a naive `strings.Contains` over the raw bytes fails on all
three and the case gets deleted as broken within a week. Normalise, or the control does not survive
its first run. The ordinary false-pass trap also applies: matching a single common word. Say in the
comment that rewording these paragraphs is a deliberate decision, not a test failure to be silenced.
**Trace** gotcha 64 · handout §1 · `e2ee/e2ee.go:10-14` · `docs/e2ee-client.md:9-17`.

### E2EE-DOC-002 · The costs are stated before a deployment discovers them · **ESSENTIAL** · T4

**Aim** The README states, in order: a forgotten password loses the data; encrypted columns cannot be
indexed, sorted, filtered or searched; server-side features that read user data stop working
permanently; the server can no longer enforce a password policy.
**Point of failure** Each is a product decision wearing a technical costume. A team agrees to them in
the abstract and objects to them in the specific, and the specific arrives after the migration.
**Procedure** Substring match for each of the four in `README.md`.
**Pass** All four.
**Fail** Any missing.
**Avoidance** (a) Negative variant: the same four must appear in `docs/e2ee-client.md`, which is the
file a frontend author reads and the README is not. (b) False-pass trap: matching against the handout,
which no consumer reads.
**Trace** handout §1 · gotchas 72, 76.

### E2EE-DOC-003 · Gotchas 64–77 exist and are not renumbered · **ESSENTIAL** · T5

**Aim** Fourteen entries, numbered 64 through 77, with no gaps and no duplicates.
**Point of failure** The numbers are cited from code comments and from `tests/`. Renumbering silently
redirects every citation, and the register in `docs/gotchas.md` is the one place the silent failures
are written down.
**Procedure** Parse `^\*\*[0-9]+ ·` from `docs/gotchas.md`; assert the sequence is dense from 1 to 77
and that 64–77 fall under the client-side encryption heading.
**Pass** Dense, unique, correctly sectioned.
**Fail** A gap, a duplicate, or an entry moved.
**Avoidance** (a) Negative variant: assert the *count* separately from the density, so an entry
appended as 78 is visible as growth rather than failing the case. New entries take the next number;
that is allowed and this case must not forbid it. (b) False-pass trap: hard-coding 77 as a maximum.
Assert density up to whatever the maximum is.
**Trace** CLAUDE.md gotchas invariant · `docs/gotchas.md:274-328`.

### E2EE-DOC-004 · Every gotcha number cited from `e2ee` resolves · **GOOD-TO-HAVE** · T5

**Aim** Each `(gotcha N)` in `e2ee/*.go` and in the e2ee tests points at an entry that exists and is
about what the comment claims.
**Point of failure** A citation that drifts turns the register into decoration. The existing comments
cite 36, 66, 67, 68, 69, 74, 77 and 65 — one wrong number and the reader who follows it learns the
wrong lesson at the moment they are about to change the line.
**Procedure** Extract every `gotcha \d+` from `e2ee/` and `tests/e2ee*_test.go`; assert each exists in
`docs/gotchas.md`.
**Pass** All resolve.
**Fail** Any dangling.
**Avoidance** (a) Negative variant: assert the extraction found a non-zero number of citations, or an
empty match set passes trivially. (b) False-pass trap: checking existence and not subject. Existence
is what a test can do; a human reads the pairing once, at review.
**Trace** `e2ee/e2ee.go:67, 77, 146, 204, 221, 273, 316, 355`.

### E2EE-DOC-005 · The client doc does not claim controls the code lacks · **ESSENTIAL** · T4

**Aim** Every "kal validates X" sentence in `docs/e2ee-client.md` corresponds to a check in
`e2ee/e2ee.go`.
**Point of failure** `docs/e2ee-client.md:88` says kal validates the version byte, the algorithm byte
and the length. It validates the length. A second-client author reading that sentence writes no
version check of their own — reasonably, because the doc says the server does it — and a `0x02` blob
reaches a client that has no idea what it is holding.
**Procedure** Enumerate the validation claims in the doc; for each, name the line in `e2ee.go` that
performs it or record it as a finding.
**Pass** Every claim has a line, or is in §17.1.
**Fail** An unrecorded claim.
**Avoidance** (a) Negative variant: assert the claims that *are* true resolve — the length check, the
`kal1.` shape, the pinned `parallelism` — so the case is a mapping and not a complaint. (b)
False-pass trap: writing this as a code test. It is a review obligation with a checklist; say so, and
put the checklist in the file.
**Trace** `docs/e2ee-client.md:88-89` · `e2ee/e2ee.go:311-331` · §17.1.

### E2EE-DOC-006 · The rollout requirement is in the CHANGELOG · **GOOD-TO-HAVE** · T5

**Aim** The `[Unreleased]` entry states that every client touching the password field must be updated
in the same release as `Config.E2EE`.
**Point of failure** The shape check turns a missed client into a login failure rather than silent
data loss, which is the right failure — and it is still a failure, arriving on release day for a
frontend nobody remembered. The CHANGELOG is where an upgrading consumer looks.
**Procedure** Substring match in `CHANGELOG.md`.
**Pass** Present.
**Fail** Missing.
**Avoidance** (a) Negative variant: `docs/e2ee-client.md` §Rollout must carry it too. (b) False-pass
trap: matching "E2EE" alone.
**Trace** `docs/e2ee-client.md:145-150`.

---

## 15 · The mutation matrix

**This is the audit deliverable. The cases are how you get one.**

Every row is a one-line change to the implementation and the case that must go red because of it. A
suite that survives this matrix unchanged is not a suite — it is a set of assertions that happen to be
true about a system nobody has perturbed.

Run it by applying each mutation, running `make test-db`, recording which cases failed, and reverting.
A mutation with **no** red case is a hole, and the hole is named in the last column.

| # | mutation | file | must go red | if nothing fails |
|---|---|---|---|---|
| M-01 | Delete `p.Parallelism = 1` from `withDefaults` | `e2ee/e2ee.go:92` | E2EE-SCH-002, E2EE-PRM-009 | gotcha 66 is untested; a client can pick `p` and lose its own vault |
| M-02 | Drop `.Strict()` from the auth-secret decode | `e2ee/e2ee.go:367` | E2EE-SEC-004 | two wire forms for one key |
| M-03 | Drop the `len(raw) != authSecretBytes` clause | `e2ee/e2ee.go:368` | E2EE-SEC-002 | a 31-byte secret is accepted |
| M-04 | Change `authSecretPrefix` to `"kal"` (no dot) | `e2ee/e2ee.go:51` | E2EE-SEC-005 | the version prefix is decorative |
| M-05 | Remove `strings.ToLower(strings.TrimSpace(email))` from `Params` | `e2ee/e2ee.go:227` | E2EE-SLT-005 | one capital letter is a different vault |
| M-06 | Remove the same normalisation from `Put` | `e2ee/e2ee.go:299` | E2EE-SLT-005 | the write path and the read path disagree — **the failure with no symptom** |
| M-07 | Change `mac.Sum(nil)[:saltLen]` to `mac.Sum(nil)` | `e2ee/e2ee.go:208` | E2EE-SLT-001 | every existing vault stops opening on the next release |
| M-08 | Inline `wrappedForFingerprint` into both statements, then change one | `e2ee/sql.go:50, 77` | E2EE-STL-001, E2EE-STL-010 | every vault in the deployment reads stale forever |
| M-09 | Replace `is distinct from` with `<>` | `e2ee/sql.go:50` | E2EE-STL-007 | a null hash scans a NULL into a `bool` |
| M-10 | Add `salt = excluded.salt` to the update set | `e2ee/sql.go:80-89` | E2EE-SLT-008 | every wrapped key becomes garbage on the next re-wrap |
| M-11 | Delete `where auth_e2ee_vaults.key_version = ?` | `e2ee/sql.go:89` | E2EE-VLT-011, E2EE-VLT-013 | the loser of a race silently overwrites the winner |
| M-12 | Delete `wrapped_for = excluded.wrapped_for` from the update set | `e2ee/sql.go:86` | E2EE-STL-004 | a reset vault is stale forever and re-wrapping never helps |
| M-13 | Remove `and u.deleted_at is null` from `paramsByEmailSQL` | `e2ee/sql.go:40` | E2EE-PRM-007 | a disabled account is distinguishable pre-auth |
| M-14 | Change `where v.user_id = ?` to `where 1 = 1` in `vaultByUserSQL` | `e2ee/sql.go:54` | E2EE-VLT-007 | any user reads any vault |
| M-15 | Change `deleteVaultSQL` to `delete from ...auth_e2ee_vaults` | `e2ee/sql.go:93` | E2EE-VLT-009 | one `Discard` destroys every vault |
| M-16 | Replace `authz.Require(ctx)` in `Get` with a nil-tolerant lookup | `e2ee/e2ee.go:252` | E2EE-VLT-001 | unauthenticated vault reads |
| M-17 | Same in `Put` | `e2ee/e2ee.go:289` | E2EE-VLT-002 | unauthenticated writes, and a nil deref on `p.Email` |
| M-18 | Same in `Discard` | `e2ee/e2ee.go:341` | E2EE-VLT-003 | unauthenticated deletion |
| M-19 | Move `v.check(vault)` to after the statement in `Put` | `e2ee/e2ee.go:293` | E2EE-POL-013 | a rejected write destroys a good vault |
| M-20 | Delete the `len(...) > v.maxBlob` condition | `e2ee/e2ee.go:317` | E2EE-POL-002, E2EE-POL-003 | free storage for any authenticated caller |
| M-21 | Delete the second operand of that condition (`RecoveryWrappedKey`) | `e2ee/e2ee.go:317` | E2EE-POL-003 | half the ceiling |
| M-22 | Change `params.Memory < v.floor.Memory \|\| ...` to the `Memory` half only | `e2ee/e2ee.go:327` | E2EE-POL-011 | single-pass Argon2id accepted |
| M-23 | Delete the `!v.allowNoRecovery` condition | `e2ee/e2ee.go:320` | E2EE-POL-005 | a forgotten password is unrecoverable and nobody was warned |
| M-24 | Change `maxBlob <= 0` to `maxBlob < 0` | `e2ee/e2ee.go:183` | E2EE-CFG-006 | the zero `Options` means unbounded |
| M-25 | Change `len(opts.Pepper) < minPepperLen` to `== nil` | `e2ee/e2ee.go:170` | E2EE-CFG-002 | a 1-byte pepper |
| M-26 | Generate a random pepper when absent instead of erroring | `e2ee/e2ee.go:170-172` | E2EE-CFG-001 | every replica derives a different salt |
| M-27 | Make the decoy branch return `crypto/rand` bytes | `e2ee/e2ee.go:234` | E2EE-SLT-002, E2EE-SLT-003 | the enumeration oracle the design exists to close |
| M-28 | Return `pg.ErrNoRows` from `Params` for an unknown address | `e2ee/e2ee.go:232` | E2EE-PRM-002 | the same oracle, more obviously |
| M-29 | Store the hash from `session.NewToken` in a new column | `e2ee/e2ee.go:387` | E2EE-RCV-003 | a stolen database contains a verifiable second route into every vault |
| M-30 | Add `crypto/aes` to `e2eeAllowedImports` and import it | `tests/e2ee_test.go:24` | E2EE-ISO-002 | the premise is unenforced |
| M-31 | Drop `SecretShape` from `Register` | `authn/tokens.go:61` | E2EE-SEC-009 | gotcha 65 on the registration path |
| M-32 | Drop it from `ResetPassword` | `authn/tokens.go:171` | E2EE-SEC-010 | a reset re-hashes over a raw password and the vault dies |
| M-33 | Drop it from `ChangePassword` | `authn/accounts.go:293` | E2EE-SEC-012 | same, on the path a user takes voluntarily |
| M-34 | **Add** a `SecretShape` call to `Login` | `authn/accounts.go:194` | E2EE-SEC-013 | every pre-E2EE account is locked out with no route back |
| M-35 | Set `secretShape` to a no-op when nil instead of `ValidatePassword` | `authn/accounts.go:114` | E2EE-SEC-014 | enabling nothing removes the password policy |
| M-36 | Drop `check (parallelism = 1)` from the migration | `migrations/0003_e2ee.sql:26` | E2EE-SCH-001 | the last line of defence for gotcha 66 |

**M-06, M-08, M-19 and M-34 are the four to run first.** Each is a change a reasonable reviewer would
approve, each produces no error and no log line, and each is the kind of thing this register exists
for. If any of them survives a full `make test-db`, stop and write that case before writing any other.

---

## 16 · Coverage ledger

### What the ten existing tests discharge

| test | file:line | cases discharged |
|---|---|---|
| `TestE2EEImportGraph` | `tests/e2ee_test.go:48` | E2EE-ISO-001 |
| `TestValidateAuthSecret` | `tests/e2ee_test.go:70` | E2EE-SEC-001, -002, -003, -004; E2EE-SEC-005 partly (no embedded-prefix arm) |
| `TestE2EERecoveryCodeShape` | `tests/e2ee_test.go:114` | E2EE-RCV-001; E2EE-RCV-002 partly (32 draws, no distribution arm) |
| `TestDBE2EEEnumeration` | `tests/e2ee_db_test.go:73` | E2EE-SLT-002, -004; E2EE-PRM-003; E2EE-SLT-001 partly (decoy arm only); E2EE-SLT-005 partly (read path only) |
| `TestDBE2EEVaultScope` | `tests/e2ee_db_test.go:122` | E2EE-VLT-007, -008, -009; E2EE-VLT-005 incidentally |
| `TestDBE2EEStaleAfterReset` | `tests/e2ee_db_test.go:163` | E2EE-STL-001, -002, -005 |
| `TestDBE2EEPutConcurrency` | `tests/e2ee_db_test.go:219` | E2EE-VLT-013, -014 |
| `TestDBE2EEParamsFloor` | `tests/e2ee_db_test.go:277` | E2EE-POL-010 partly (moves both fields at once — see POL-010(b)) |
| `TestDBE2EEPutRejects` | `tests/e2ee_db_test.go:297` | E2EE-POL-001, -002, -005, -007 partly (one KDF value, no near-misses) |
| `TestDBE2EESaltNeverRotates` | `tests/e2ee_db_test.go:351` | E2EE-SLT-008 |
| `tests/kal_test.go:139-158, 240, 267-317` | | E2EE-SHM-001, -003; E2EE-SHM-004, -005 partly (error code, not the row) |

Ten `e2ee` test functions plus the assertions already in `tests/kal_test.go`, covering **23 of the
120 cases fully and 9 partly**.

### The gaps, ranked

**CRITICAL and untested — write these first.**

| case | what is unasserted today |
|---|---|
| E2EE-SLT-003 | The decoy for an address is the salt that address later gets. The premise of §5, and nothing checks it across the enrolment boundary. |
| E2EE-SLT-005 (write path) | `Put` normalises `p.Email`. Only the read path is covered, so M-06 survives. |
| E2EE-SLT-006 | The salt depends on the pepper at all. |
| E2EE-SLT-010 | A client-supplied `Params.Salt` is not stored. |
| E2EE-PRM-006 | `Params` does not feed the login backoff (gotcha 69). |
| E2EE-VLT-001/-002/-003 | `UNAUTHENTICATED` on all three methods. **No test calls any vault method with a bare context.** |
| E2EE-VLT-011 | A sequential stale-version `Put` conflicts and changes nothing. |
| E2EE-POL-013 | A rejected `Put` does not damage an existing vault. Every rejection test today runs on a user with no row. |
| E2EE-STL-004 | A re-wrap after a reset clears the staleness flag — the recovery loop terminates. |
| E2EE-SEC-009 (row) | `Register` under E2EE creates no user row, not merely an error. |
| E2EE-SEC-010, -011 | `ResetPassword` and `AcceptInvite` under E2EE, and that the token survives the rejection. |
| E2EE-SEC-012, -013 | `ChangePassword` checks `next` not `current`; `Login` checks nothing, deliberately. |
| E2EE-SCH-002 | No `Put` can produce `parallelism ≠ 1` (gotcha 66). |
| E2EE-RCV-003 | No hash of a recovery code reaches any table. |
| E2EE-DOC-001 | The refusal is present in all three documents (gotcha 64). |

**ESSENTIAL and untested.** E2EE-ISO-003, -004; E2EE-CFG-001 through -009 (the constructor has no
direct test — the pepper path is reached only through `kal.New`); E2EE-PRM-001, -004, -005, -007,
-008, -009, -011; E2EE-VLT-004, -006, -010, -012; E2EE-POL-003, -006, -008, -011; E2EE-STL-003, -006,
-007, -008; E2EE-SEC-006, -014, -015; E2EE-RCV-002 (distribution), -005; E2EE-SCH-001, -003, -004;
E2EE-SHM-002, -006; E2EE-DOC-002, -003.

**Gotchas with no test at all: 66, 69, 72, 73, 75.** 66 and 69 are covered by E2EE-SCH-002 /
E2EE-PRM-006 above. 72 and 73 are `authz`'s and the consumer's, and appear here only as E2EE-SCH-008
and §0.5. 75 is E2EE-POL-008.

### On counting

This ledger is a snapshot dated **2026-08-07**. It goes stale the moment a test lands, and a stale
ledger that claims a case is discharged is worse than no ledger — it makes an absent control read
green, which is the exact failure mode `docs/gotchas.md` catalogues. Two options, both acceptable:
re-derive it by hand at each release, or pin it in code the way `tests/zk_case_manifest_test.go` pins
the zk register, so the count can only fall by writing a test. **Do not use `t.Skip` for an unwritten
case.** A skip reports `ok`, and CI's `--- SKIP: TestDB` guard exists because that lesson was already
learned once here.

---

## 17 · `[UNSPECIFIED]` — findings against the design documents

Thirteen places where the docs and the code disagree, or where the code has a behaviour no document
settles. Each is already a case above; this section is so they are countable. None is a test failure —
they are decisions someone has to make, and until they are made the cases pin today's behaviour so a
change is visible.

**17.1 · The blob's version and algorithm bytes are not validated.** `docs/e2ee-client.md:88` and
handout §6 both say kal validates the version byte, the algorithm byte and the length. `check()`
inspects `len()` only (`e2ee/e2ee.go:311-331`); a `WrappedKey` of `[]byte{0x00}` is stored happily.
A second-client author reading that sentence reasonably writes no version check of their own. Either
the code grows a two-byte check — it is three lines and does not require knowing how to decrypt, which
is the stated limit — or both sentences change. *Cases: E2EE-DOC-005.*

**17.2 · `Options.Floor.KDF` is never compared.** It is populated with `KDFArgon2id` by
`withDefaults` (`e2ee/e2ee.go:179`) and read by nothing. A deployment that sets it believing it has
banned PBKDF2 has banned nothing, and PBKDF2 is GPU-cheap (gotcha 75). Either enforce it or remove
the field from `Floor`'s documented meaning. *Cases: E2EE-CFG-010.*

**17.3 · `Parallelism` on `Default` and `Floor` is dead.** `withDefaults` overwrites it
unconditionally (`e2ee/e2ee.go:92`) before anything could read it. Correct behaviour, misleading
surface: the field is settable and ignored. *Cases: E2EE-CFG-010, E2EE-PRM-009.*

**17.4 · The CAS does not apply to the first write.** `where auth_e2ee_vaults.key_version = ?` lives
inside `on conflict do update`, so on the insert path the parameter is bound and never consulted
(`e2ee/sql.go:80-89`). `Vault.KeyVersion` documents "Zero means no row yet"
(`e2ee/e2ee.go:140-141`); a `Put` with `KeyVersion: 57` against a fresh user succeeds and returns
version 1. *Cases: E2EE-VLT-015.*

**17.5 · `Put` returns no version.** It scans `returning key_version` into a local and discards it
(`e2ee/e2ee.go:297`). A client cannot chain two writes without a `Get` in between, which is one extra
round trip on the enrolment path and one more chance to race. *Cases: E2EE-VLT-012(b).*

**17.6 · An absent or soft-deleted user is reported as a conflict.** The insert's `where u.id = ? and
u.deleted_at is null` yields zero rows, which becomes `pg.ErrNoRows`, which becomes "the vault changed
since it was read; re-read it and try again" (`e2ee/e2ee.go:302-305`). A client that follows that
instruction loops. *Cases: E2EE-VLT-016.*

**17.7 · Two addresses differing only in case would break the pre-auth query.**
`paramsByEmailSQL` matches on `lower(u.email)` and runs through `QueryOneContext`. Whether
`auth_users` permits such a pair is a `0001_core.sql` question; if it does, `Params` has a reachable
driver error on an unauthenticated path. *Cases: E2EE-PRM-010.*

**17.8 · `vaultByUserSQL` has no `deleted_at` gate and `paramsByEmailSQL` does.** A soft-deleted user
with a live session still reads their wrapped key. Deliberate or not, it is undocumented and
asymmetric. *Cases: E2EE-VLT-017.*

**17.9 · A principal with an empty `Email` derives one shared salt.** `Put` takes the address from
`p.Email` (`e2ee/e2ee.go:299`), so a principal built without one produces
`HMAC(pepper, "kal.e2ee.salt|")` — identical for every such user, and one that no `Params(email)` call
returns. Reachable from a JWT-only session or a hand-built principal. *Cases: E2EE-VLT-018.*

**17.10 · The pepper error is not a `*kalerr.Error`.** `errors.New` at `e2ee/e2ee.go:171`, three
lines above a `*kalerr.Error{Code: CodeInvalidInput}` for the schema. Handout §4 asked for the second
style. *Cases: E2EE-CFG-003.*

**17.11 · The pepper is retained by reference.** `v.pepper = opts.Pepper` with no copy
(`e2ee/e2ee.go:174`). A consumer that reuses or zeroes the buffer moves every salt written afterwards,
splitting the deployment into two cohorts with no error. One `bytes.Clone` closes it.
*Cases: E2EE-CFG-004.*

**17.12 · `Memory` and `Iterations` have a floor and no ceiling.** `Memory` is `uint32` in Go over an
`int4` column, so a large value surfaces as a driver error rather than `CodeInvalidInput`; a merely
absurd value that fits makes the user's own devices unable to derive. *Cases: E2EE-POL-014.*

**17.13 · `Login`'s deliberate absence of a shape check is undocumented.** It is correct — an account
that registered before `E2EE` was enabled must still be able to log in, and the write-side checks are
what prevent such an account being created afterwards — but it is written down nowhere, which makes it
one release away from being "hardened" into a lockout. It belongs in `AccountsOptions.SecretShape`'s
doc comment, and probably as gotcha 78. *Cases: E2EE-SEC-013.*

---

## 18 · Deliberately not in this register

**The reference client.** `docs/e2ee-client.ts` has no test harness, no CI step and no type check.
Blob layout, AAD construction, the HKDF info strings, its non-strict `b64urlDecode`, and whether the
AAD is injective (`resource="a"`, `record="b|c"` and `resource="a|b"`, `record="c"` produce identical
bytes) are all real obligations and none of them is reachable from `package tests`. They need a Node
or Deno runner and a CI job, which is a separate piece of work.

**Cross-language test vectors.** Nothing today lets a second client be checked against the first, and
the doc promises "enough detail to write a second client that interoperates". The import allowlist
forbids AEAD inside `e2ee`, so a vector generator must live outside the package — `tests/` or a small
tool — and the strong direction is Go-produced blobs that the TS client decrypts, since `seal` draws
its IV internally with no injection point.

**`Scope`, RLS and `@auth`.** A ciphertext row is still a row with an owner (gotcha 73). Those
controls are `authz`'s and their cases live with it.

**The operator who serves the JavaScript.** Gotcha 64. Not a gap in the tests — the boundary of what
tests can reach. §14 is the only control there is.
