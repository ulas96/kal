# Vulnerability test cases — `zkauthn` / `zkauthz`

A security-audit test register derived **from `docs/zk-handout.md` by logic alone**. No implementation
was inspected, no test was written, no test was run. Every case below is an obligation on the
implementation, not a report on it.

---

## 0 · How to read this document

### 0.1 Source of truth

The handout is the specification. Where the handout marks a decision **load-bearing**, the
corresponding case here is CRITICAL by construction: the handout has already asserted that a security
property depends on it. Where the handout marks a decision **chosen**, the case tests that the choice
was implemented consistently, not that it was the right choice.

Where this register asserts something the handout does *not* settle, the case is tagged
**[UNSPECIFIED]** and repeated in §23. Those are audit findings against the design document itself,
not against code.

### 0.2 The schema of a case

Every case carries the same seven fields.

| field | what it holds |
|---|---|
| **Aim** | The security property being asserted, stated as a property and not as a function call. |
| **Point of failure** | Where the defect lives if the control is absent, and what an attacker gets. |
| **Procedure** | What the test does. Enough to write it from, not code. |
| **Pass** | The observation that constitutes success. Stated as *the thing that goes wrong not happening* — the row still in the table, the resolver not run — never as "the function returned false". |
| **Fail** | The observation that constitutes a finding. |
| **Avoidance** | Two things, both mandatory reading before writing the test. **(a) The negative variant** that must be run alongside, because the positive one alone is satisfiable by a broken system. **(b) The false-pass trap** — the shape of this test that passes vacuously. A test that can only go green is not a control, it is a comment with a stack trace. |
| **Trace** | Handout §, gotcha number, and the invariant in `CLAUDE.md` it protects. |

Terser fields on GOOD-TO-HAVE cases are terseness, not exemption. The **Avoidance** field is never
omitted.

### 0.3 Severity

| tier | definition | release gate |
|---|---|---|
| **CRITICAL** | Absence is an exploitable authentication or authorization bypass, a total loss of the anonymity being sold, or a proof of a false statement. Exploitable by a party the design claims to defend against. | Blocks the phase. |
| **ESSENTIAL** | Absence is a real weakness under a plausible operational condition — concurrency, two replicas, a misconfiguration, a partial failure — or the absence of a defence-in-depth control the design explicitly commits to. | Blocks the release. |
| **GOOD-TO-HAVE** | Regression fences, cost ceilings, hygiene, and assertions that a documented non-goal is in fact documented. Raises confidence in change over time. | Does not gate. |

### 0.4 The two disciplines this register is built on

Everything in §3 exists because of one fact from handout §2: **a constraint you forgot to write is a
root `Z` does not have, `t/Z` still divides, and the proof verifies.** There is no error, no log line,
and a suite of honest witnesses passes, because honest witnesses satisfy an under-constrained system
too. Two disciplines follow, and neither is optional.

**Differential testing (both directions).** For each circuit, a plain-Go reference predicate is the
oracle, and thousands of witnesses assert `goReference(w) == solves(w)`. The *false → reject*
direction catches under-constraining. The *true → accept* direction catches over-constraining. A
one-directional differential test is half a test and reads like a whole one.

**Mutation testing.** The handout states the acceptance criterion for the tests themselves: *"delete
line 8 of §4b and this test must fail; if it still passes, the test is wrong."* §19 generalises that
into a matrix of 38 mutations, each naming the case that must go red. A test suite that survives the
mutation matrix unchanged is not a suite, and this is the only mechanism in the document that can
tell the difference. **The mutation matrix is the audit deliverable.** The cases are how you get one.

### 0.5 What a green suite here does *not* mean

It does not mean the deployment is anonymous — see §22. It does not mean the operator is honest — the
operator is the verifier and can always return `true`. It does not mean the prover is trustworthy —
if the operator serves the JavaScript that holds the secret, every property below is a promise. These
are not gaps in the tests. They are the boundary of what tests can reach, and §22 tests only that
they are written down where a deployment will read them.

---

## 1 · Threat model, restated as test targets

Four parties, and every case below is against exactly one of them. A case that cannot name its
adversary is testing an implementation detail.

| # | adversary | capability | what the tests must deny it | groups |
|---|---|---|---|---|
| **T1** | **Malicious user, no credential** | Speaks the wire protocol. Can read any public value: leaf hashes, roots, published nullifiers, proofs seen anywhere. | Any session, any claim, any `mfa_at`. Specifically: proving membership by copying a public leaf value (gotcha 41). | CIR, INP, TRE, NUL, ENR |
| **T2** | **Malicious user, valid credential** | Everything T1 has, plus one secret and one leaf. | Proving a statement stronger than its own leaf supports; acting twice on a one-shot audience; acting as another pseudonym; replaying its own proof. | CIR, INP, CHL, NUL |
| **T3** | **Honest-but-curious operator** | The database, the logs, the code as written. Does not deviate from its own code. | Learning *which* member acted. Learning pseudonym ↔ IP ↔ time. Learning a member's attribute beyond the thresholds it was asked about. | SES, DOC |
| **T4** | **Unauthenticated network caller** | One HTTP request, repeated. | Free CPU, free rows, and an oracle on whether an account has enrolled. | DOS, ORC |
| **T5** | **Operational insider / mis-deploy** | Filesystem write on the server, or a mistaken mount. | Swapping the verifying key. Running the circuit against a key from another ceremony. Deterministic setup. | KEY |

**Explicitly not an adversary in this register:** a malicious operator (T3 without the "honest-but-
curious"), a compromised prover client, and a party that holds the toxic waste *and is not the
verifier*. Handout §1 and §12 establish why, §22 tests that it is stated where deployments read it.

---

## 2 · Harness preconditions

These are obligations on the test infrastructure. A case that depends on one of them and does not get
it is a case that reports green for the wrong reason.

**P-1 · The differential tests must not be named `TestDB*`.** Handout §10 is explicit and the reason
is CI: `TestDB*` skips without `DATABASE_URL`, and a skip reports `ok`. The single highest-value test
in the module must run in plain `make test`. A differential test that skips is a differential test
that never ran, and the output says `ok`.

**P-2 · Database-backed cases must be named `TestDBZK*`.** CI greps `--- PASS: TestDB` out of `-v`
output. A DB case named otherwise is invisible to the gate that exists to catch exactly this.

**P-3 · Every generator is seeded and the seed is printed on failure.** A random-witness failure that
cannot be reproduced is a flake ticket, and flake tickets get `t.Skip`ped. Print the seed; accept a
seed from an env var.

**P-4 · Concurrency cases use one barrier shape.** Handout §10 names it: copy
`TestDBTokenSingleUseUnderConcurrency` (`tests/tokens_test.go:296`). N goroutines constructed, all
blocked on one channel close, released together. A `go func()` loop with no barrier tests the
scheduler, and it passes on a broken implementation roughly as often as not.

**P-5 · Every test lives in `package tests`.** `CLAUDE.md`: if a security property cannot be asserted
from outside the package, a consumer cannot rely on it, and the exported surface is what changes —
not the test's package clause.

**P-6 · Fixtures never reuse a secret across cases.** A secret shared between two cases makes the
nullifier shared, and a one-shot burn in case A silently fails case B in whatever order the runner
picks. Per-case `crypto/rand`.

**P-7 · There is one honest-proof fixture per circuit, produced once.** Several CRITICAL cases verify
a *pre-existing* proof against a *modified* public witness. Re-proving inside those cases defeats
them — see ZK-CIR-001's Avoidance.

**P-8 · Two independent MiMC implementations must be reachable from the test.** The native one and
the in-circuit one, per ZK-HSH-001. If the test computes the expectation with the same code the
subject uses, it asserts that a function equals itself.

---

## 3 · Group CIR — Circuit soundness

The entire vulnerability class of this field. Every case here is against T1 or T2, and every failure
in this group is invisible: the circuit compiles, proves, verifies and authenticates the wrong party.

### ZK-CIR-001 · Public-input binding battery — **CRITICAL**

The single most important case in this document. It subsumes gotcha 42 for every input at once and is
the only case that can distinguish a public input that is *declared* from one that is *constrained*.

**Aim.** Every value the circuit declares public is materially bound to the proof, so a proof made for
one public vector does not verify against any other.

**Point of failure.** A public input that appears in no constraint has a zero coefficient in every
`A`, `B`, `C` polynomial, so it contributes nothing to the pairing check and the verifier's linear
combination is unaffected by its value. The proof verifies for *any* value of it. For `Challenge`
this is total replay: the first proof a member ever makes is a permanent bearer credential for that
pseudonym, held by every access log, reverse proxy, APM trace and crash report that ever saw the
request. For `Threshold` it is every claim in the schema satisfied at once.

The mechanism this case exists to catch that a reading of the source will not: **`c2 = Challenge *
Challenge` assigns to a wire nothing consumes.** Whether that survives the frontend's simplification
into an emitted R1CS constraint is a property of the compiler, not of the source line. The source
line can be present and correct and the constraint absent. Only a verification against a tampered
public witness observes the difference.

**Procedure.** Take the honest proof fixture (P-7) for each circuit. For each public field —
`Knowledge`: {`Commitment`, `Challenge`}; `Membership`: {`Root`, `Audience`, `Threshold`,
`Nullifier`, `Challenge`} — build a public witness identical to the honest one except that field is
replaced, in three variants: (i) another uniformly random field element, (ii) `0`, (iii) `r − 1`.
Call `groth16.Verify(proof, vk, tamperedPublicWitness)`. 3 × 7 = 21 verifications, plus the two
honest ones as the control.

**Pass.** Every one of the 21 returns a non-nil error. Both honest verifications return nil.

**Fail.** Any tampered verification returns nil. That input is unconstrained; treat as a total bypass
of whatever it names.

**Avoidance.**
(a) *Negative variant, mandatory:* the two honest verifications in the same test function. Without
them a harness that fails to construct any witness at all reports 21 green errors and a passing test.
(b) *False-pass trap:* **do not implement this with `test.IsSolved`.** `IsSolved` re-runs the solver
with the tampered value present in the assignment, so it reports "unsatisfied" for a reason that has
nothing to do with binding — the circuit legitimately fails to solve. It will report failure even for
an unconstrained input, and the test goes green while proving nothing. It must be `groth16.Verify`
against a proof produced *before* the tampering, from a fixture the case does not rebuild.
(c) *Second trap:* do not choose a tampered value that would make a different-but-true statement (a
lowered `Threshold`) and then reason about whether it "should" verify. It must not, regardless — the
proof commits to the original public vector. If it verifies, the input is unbound and the semantics
of the alternative statement are irrelevant.

**Trace.** §4a line 3 · §4b line 8 · §5 · gotchas 42, 43.

---

### ZK-CIR-002 · Differential, `Knowledge`, both directions — **CRITICAL**

**Aim.** The compiled `Knowledge` R1CS is satisfiable by exactly the witnesses the Go reference
predicate accepts — no more (under-constrained) and no fewer (over-constrained).

**Point of failure.** A missing `AssertIsEqual` between the computed hash and `Commitment` makes the
commitment decorative: any secret proves against any enrolled user. The proof verifies, the
differential test passes if it only ever supplies honest witnesses, and MFA becomes a formality that
returns `true`.

**Procedure.** ≥1000 witnesses from the generator of ZK-CIR-004a. For each, assert
`goReference(w) == (test.IsSolved(&c, &w, ecc.BN254.ScalarField()) == nil)`. Record and assert the
counts in both directions: the run must contain at least 100 witnesses the reference rejects and at
least 100 it accepts.

**Pass.** Zero disagreements, and both direction counts above their floor.

**Fail.** Any disagreement. A `false → solved` disagreement is under-constraining and is a soundness
break. A `true → unsolved` disagreement is over-constraining and is an availability break — honest
users rejected at a boundary.

**Avoidance.**
(a) *Negative variant:* the direction counts are the negative variant. A generator that emits only
valid witnesses produces 1000 agreements and a green test that has asserted nothing about the
rejecting direction. Assert the floor, do not hope for it.
(b) *False-pass trap:* the Go reference must be written **before** the circuit and must not be
derived from it. A reference written afterwards by reading `Define()` is a transcription of the
circuit, and a differential test between a circuit and its own transcription is a tautology that
costs 1000 iterations to compute. Handout §3 stage 1 puts the reference first for this reason and no
other.

**Trace.** §3 stages 1–2 · §4a · §10 · gotchas 40, 47.

---

### ZK-CIR-003 · Differential, `Membership`, both directions — **CRITICAL**

**Aim.** As ZK-CIR-002, for the eight-statement `Membership` circuit.

**Point of failure.** Eight statements, each of which can be dropped independently, and seven of the
eight drops produce a circuit that compiles, proves, verifies, and authenticates somebody who should
not be authenticated. §19 enumerates them.

**Procedure.** ≥1000 witnesses from ZK-CIR-004a's generator, same two-direction assertion and same
direction floors as ZK-CIR-002. The generator must span all eight statements — a witness family that
never varies `Index` cannot detect a dropped index constraint.

**Pass / Fail.** As ZK-CIR-002.

**Avoidance.**
(a) *Negative variant:* per-statement coverage counters. For each of the eight statements, assert the
run contained ≥20 witnesses whose *only* reason for rejection is that statement. A 1000-witness run
that rejects 400 times, all of them because the threshold failed, has tested one constraint 400 times
and seven constraints zero times, and it looks identical in the output to a run that tested all
eight.
(b) *False-pass trap:* as ZK-CIR-002 — reference before circuit, never derived from it.

**Trace.** §3 · §4b · §10 · gotcha 40.

---

### ZK-CIR-004 · The adversarial witness generator — **CRITICAL** *(harness obligation)*

Not a test. The precondition without which ZK-CIR-002 and ZK-CIR-003 are decorative. Uniform random
field elements almost never land on a boundary, and every under-constraining bug in this design lives
on a boundary.

**Aim.** The witness population reaches every case where the circuit's behaviour changes.

**Point of failure.** A uniform generator over `[0, r)` produces an `Attribute` in the 64-bit range
with probability ≈ 2⁻¹⁹⁰. It therefore never exercises the comparison, never exercises the range
check, and reports 1000 agreements on a circuit with neither.

**Required families.** Each must be an explicit branch of the generator with its own counter, and
each counter must be asserted non-zero:

| # | family | the constraint it is aimed at |
|---|---|---|
| 1 | `Threshold == Attribute` exactly | §4b line 5 boundary — off-by-one in either direction |
| 2 | `Threshold == Attribute ± 1` | the same, both sides |
| 3 | `Attribute == 2^64 − 1` | §4b line 1 upper bound, accept |
| 4 | `Attribute == 2^64` and `2^64 + 1` | §4b line 1 upper bound, reject |
| 5 | `Attribute == r − 1` (i.e. `−1`) | line 1 **ordering** — gotcha 46 |
| 6 | `Threshold == r − 1`, `Threshold == 0` | a threshold that was never bounded |
| 7 | `Index ≥ 2^32` | index domain, gotcha 48 |
| 8 | `Index` valid but not the index of `Path[0]`'s leaf | path/index consistency |
| 9 | `Path[0]` = a real leaf belonging to another member, prover's own secret unchanged | §4b line 3 — gotcha 41, the headline case |
| 10 | same `Secret`, different `Audience` | nullifier domain, unlinkability |
| 11 | same `Secret` and `Audience`, different `Challenge` | replay binding |
| 12 | `Challenge == 0`; `Secret == 0`; `Attribute == 0` | degenerate field elements |
| 13 | `Nullifier` set to another member's published nullifier | §4b line 7 |
| 14 | `Root` set to a previously published root, path unchanged | §4b line 4 |
| 15 | `Path` entries all `zeros[level]` (proof against an empty tree) | empty-tree soundness |

**Pass.** Every family's counter is non-zero in every run, asserted by the test.

**Fail.** Any counter zero. The suite silently stopped testing that constraint, and nothing in the
output says so.

**Avoidance.**
(a) *Negative variant:* families 3/4, 5, and 9 are themselves the negative variants of the whole
group — they are the witnesses an honest client cannot construct.
(b) *False-pass trap:* generating these by rejection-sampling from a uniform source. It will loop
forever on family 3 and quietly produce zero of them under a timeout. Construct each family directly.

**Trace.** §10 · gotchas 40, 41, 45, 46, 48.

---

### ZK-CIR-005 · `Path[0]` binds to the prover's own secret — **CRITICAL**

The handout calls this "the trap", and it produces a circuit that compiles, proves, verifies and
authenticates anybody.

**Aim.** Membership in the tree is proven as *knowledge of a secret whose commitment is a leaf*, not
as *the existence of a leaf*.

**Point of failure.** `merkle.VerifyProof` takes the leaf value in `Path[0]`, which is prover-supplied
witness. Called without `assert leaf == Path[0]`, the circuit proves only that some leaf is in the
tree. Leaf hashes are public — they are in `auth_zk_credentials.commitment` and derivable from any
published path. T1, holding **no secret at all**, copies any member's leaf value into `Path[0]`,
supplies a random `Secret` and `Attribute`, and authenticates. Total bypass, one `AssertIsEqual`, and
the omission is invisible in every other test.

**Procedure.** Two layers, both required.
1. *Circuit layer, no database.* Construct a witness where `Path[0]`, `Index` and `Path[1..32]` are a
   genuine, verifying path for member A's leaf, while `Secret` and `Attribute` are the tester's own
   random values unrelated to that leaf. Assert the Go reference rejects and `test.IsSolved` returns
   an error. Sweep with ≥100 such witnesses (family 9).
2. *Protocol layer, `TestDBZK*`.* Enrol member A. As an attacker who never enrolled, read A's
   commitment from `auth_zk_credentials`, build the path, prove, and submit a `Login`. Assert **no
   `auth_users` row was created, no `auth_zk_nullifiers` row was created, and no session cookie was
   issued** — the absence of the artefacts, not the presence of an error value.

**Pass.** Both layers reject. The tables are unchanged after layer 2.

**Fail.** Either layer produces a solved system or a session. Layer 1 solving is the finding; layer 2
is the demonstration.

**Avoidance.**
(a) *Negative variant, mandatory and easy to omit:* the *same* path with the *correct* secret must be
accepted, in the same test. Otherwise a circuit that rejects everything — a stray
`api.AssertIsEqual(0, 1)`, an over-constrained range check — passes this case perfectly.
(b) *False-pass trap:* building the attacker's witness with a `Path[0]` that is *not* a genuine leaf.
Then the Merkle verification fails and the test goes green on line 4, never touching line 3. The
attacker's path must be a real, verifying path. If you cannot make `merkle.VerifyProof` pass on its
own with this witness, you have not built the attack.
(c) *Third trap:* running only layer 1. Line 3 can be present in the circuit and the server can still
be broken if it verifies against a `Root` it took from the request (ZK-INP-004). Layer 2 is what ties
them.

**Trace.** §4b line 3 · gotchas 41, 48.

---

### ZK-CIR-006 · Range check precedes the comparison — **CRITICAL**

**Aim.** `Threshold <= Attribute` is a comparison over bounded integers, not over field elements.

**Point of failure.** Handout §2: *"an attribute that was never bounded can be `r − 1`, which is `−1`
read as a field element, and what 'less than' means there is not what the policy meant."* A member
whose leaf carries an unbounded `Attribute` chosen at enrolment — or, worse, a circuit whose range
check runs *after* the comparison and therefore constrains a value the comparison already consumed —
satisfies any threshold. Bit-decomposition comparators in gnark operate on the decomposition supplied
as auxiliary input; an undecomposed value is not what they compared.

**Procedure.** Witness families 5 and 6 from ZK-CIR-004, ≥100 each. `Attribute = r − 1` against
`Threshold = 18`; `Attribute = r − 1` against `Threshold = 0`; `Threshold = r − 1` against
`Attribute = 2^63`. Assert the Go reference rejects every one and `IsSolved` errors on every one.
Then: source-order assertion — the flattened list in the `@dev` block has the range check as
statement 1, and `Define()` mirrors it statement for statement.

**Pass.** All rejected. Boundary accepts (`Attribute = 2^64 − 1` with `Threshold = 2^64 − 1`)
succeed.

**Fail.** Any `r − 1` witness solves.

**Avoidance.**
(a) *Negative variant:* `Attribute = 2^64 − 1` must be **accepted**. A range check to the wrong width
— 63 bits, or 64 with an off-by-one — rejects the top of the legitimate domain and is caught by
nothing else in this register.
(b) *False-pass trap:* asserting only that `r − 1` is rejected. A circuit that rejects `r − 1`
because it happens to exceed the range check *after* an already-completed comparison still has the
ordering bug for other values; and a mutation that reorders the two statements without deleting
either will not be caught unless the mutation matrix (§19, M2) explicitly reorders them and this case
goes red. Run M2.

**Trace.** §2 "No `<`, no `%`" · §4b line 1 · gotcha 46.

---

### ZK-CIR-007 · The Merkle root is recomputed, not accepted — **CRITICAL**

**Aim.** `Root` as a public input is *constrained by* the path, not merely carried alongside it.

**Point of failure.** If the circuit computes a root from `Path` and `Index` but never asserts it
equals the public `Root` — a `VerifyProof` variant that returns the root rather than asserting it,
or a hand-rolled path walk missing its final `AssertIsEqual` — then `Root` is unconstrained and
ZK-CIR-001 catches it. But there is a second shape: the circuit asserts against a root it *also*
took from the witness. Then it proves "this path is consistent with itself", which every path is.

**Procedure.** (i) ZK-CIR-001's `Root` row must fail. (ii) Additionally, a witness whose `Path`
entries are internally consistent and whose recomputed root is genuine, submitted against a public
`Root` from a *different, real, previously published* root (family 14) — assert rejected. (iii) A
witness with an all-`zeros[level]` path (family 15) against the real root — assert rejected.

**Pass.** All three reject; the honest control accepts.

**Fail.** Any accept. (ii) accepting means `Root` is witness-derived; (iii) accepting means the empty
tree proves membership.

**Avoidance.**
(a) *Negative variant:* a genuine path against its own genuine root accepts.
(b) *False-pass trap:* using a *malformed* path for (ii). A path that does not verify against
anything fails for the wrong reason and tells you nothing about where `Root` came from. The path must
be perfect and only the root wrong.

**Trace.** §4b line 4 · §6 · gotcha 48.

---

### ZK-CIR-008 · The nullifier is constrained to the secret and audience — **CRITICAL**

**Aim.** `Nullifier` is `MiMC(DOM_NULLIFIER, Secret, Audience)` and nothing else, so the prover cannot
name a pseudonym it did not derive.

**Point of failure.** Drop `assert n == Nullifier` (§4b line 7) and the public `Nullifier` is
prover-chosen. On a **recurring** audience that is account takeover: T2 submits another member's
published nullifier and receives a session for *that member's pseudonymous account*, with a valid
proof of its own membership. On a **one-shot** audience it is unlimited action: T2 submits a fresh
random nullifier per attempt and the unique index never fires. Both with a correct membership proof,
a correct threshold, and a fresh challenge.

**Procedure.** (i) Circuit: witness with a correct secret, path and threshold, and `Nullifier` set to
an unrelated field element (family 13) — assert rejected; ≥100 variants. (ii) Circuit: same `Secret`,
two different `Audience` values must produce two different nullifiers, and the same `(Secret,
Audience)` must reproduce the same one — determinism and separation in one assertion set. (iii)
Protocol, `TestDBZK*`: member B proves membership honestly but submits member A's published nullifier
— assert **no session for A's `user_id`**, and A's `auth_zk_nullifiers` row unchanged.

**Pass.** (i) rejected, (ii) both properties hold, (iii) no session and no row mutation.

**Fail.** Any of the three.

**Avoidance.**
(a) *Negative variant:* the honestly-derived nullifier accepts, and (ii)'s determinism half — a
circuit that rejects every nullifier passes (i) and (iii) and breaks every login.
(b) *False-pass trap:* testing (ii) by computing the expected nullifier with the same code path the
circuit uses. Compute it natively, per ZK-HSH-002, and compare across the two implementations.

**Trace.** §4b lines 6–7 · §7 · gotchas 44, 56.

---

### ZK-CIR-009 · Domain separation between leaf, nullifier and empty leaf — **CRITICAL**

**Aim.** Three distinct purposes, three distinct domain tags, no value valid in two roles.

**Point of failure.** Handout §4b and gotcha 44: with a shared tag, a leaf commitment is a valid
nullifier and a **published nullifier can be replanted as a leaf**. The second is the dangerous
direction — nullifiers are public by construction, so a shared tag hands T1 a supply of values that
are simultaneously valid tree leaves. And with `zeros[0] = MiMC(DOM_EMPTY)` collapsed into the leaf
domain, every empty slot in a 4.3-billion-leaf tree is a credential whose preimage is findable rather
than a collision to be searched for.

**Procedure.** (i) Constants: assert `DOM_LEAF`, `DOM_NULLIFIER`, `DOM_EMPTY`, `DOM_KNOWLEDGE` (and
`DOM_AUDIENCE` if the deployment derives audiences) are pairwise distinct, all non-zero, and pinned
as constants a test reads rather than recomputes. (ii) Cross-role: for ≥100 random secrets, assert
`MiMC(DOM_LEAF, s, a) != MiMC(DOM_NULLIFIER, s, aud)` across a matrix of `a`/`aud` including
`a == aud`. (iii) Replant: take a published nullifier value, attempt to enrol it as a commitment —
assert the enrolment path rejects it, or that a `Membership` proof naming it as `Path[0]` fails
ZK-CIR-005's binding.

**Pass.** All distinct; the replant produces no leaf and no proof.

**Fail.** Any equality, or a successful replant.

**Avoidance.**
(a) *Negative variant:* assert the same tag with the same inputs *does* collide, in a scratch
computation. Otherwise (ii) passes trivially on a hash that is broken and returns random values.
(b) *False-pass trap:* comparing tags for inequality only. Tags that differ but are `0` and `1` are
distinct and still let an attacker steer a hash by controlling one input's low bits when arities
differ. Assert non-zero and assert the arity of each call site is fixed — a MiMC absorb of `(tag, s)`
and one of `(tag, s, aud)` must not be confusable by a caller that controls the number of inputs.

**Trace.** §4b · §6 · gotchas 44, 52.

---

### ZK-CIR-010 · `Index` is bit-constrained and within the tree — **ESSENTIAL**

**Aim.** The leaf index is a `MerkleDepth`-bit value, so one path corresponds to one position.

**Point of failure.** `merkle.VerifyProof`'s body reads `api.ToBinary(leaf, depth)` on the third
argument. `ToBinary` to 32 bits of a value ≥ 2^32 either errors at solve time or silently truncates,
depending on the gnark version and whether the value is a constant. A truncating decomposition means
two distinct `Index` values select the same sibling ordering — a second, unintended path to the same
leaf, which matters when the index is also used off-circuit to key `auth_zk_nodes`.

**Procedure.** Family 7: `Index = 2^32`, `2^32 + 1`, `r − 1`. Assert reference and circuit both
reject. Assert `Index = 2^32 − 1` with a genuine path accepts.

**Pass.** Out-of-domain rejected, top-of-domain accepted.

**Fail.** Any out-of-domain index solves, or the top of the domain is rejected.

**Avoidance.**
(a) *Negative variant:* `2^32 − 1` accepting is the negative variant and is the half that catches a
range check one bit too narrow.
(b) *False-pass trap:* asserting only that the *proof* fails. It may fail because the path does not
verify for a nonsense index, not because the index was constrained. Construct the case so that the
truncated index selects a path that *does* verify — if you cannot, state in the test comment that the
truncation is unreachable and why.

**Trace.** §4b line 4 · §6 · gotcha 48.

---

### ZK-CIR-011 · Witness field visibility — **CRITICAL**

**Aim.** `Secret`, `Attribute`, `Path` and `Index` are private; nothing else is.

**Point of failure.** A `gnark:",public"` tag on `Secret` does not break soundness — it breaks the
entire product. Every proof publishes the credential, the operator learns which member acted, and the
verifier's public witness contains a value that reconstructs the leaf. The circuit compiles, every
test in this register except this one passes, and the anonymity that is the reason the package exists
is gone with no error anywhere. The same tag on `Attribute` publishes the exact value the threshold
was supposed to hide.

**Procedure.** For each circuit, enumerate the public witness schema — `witness.New` on the circuit
type, then the public vector's length and field order — and assert it equals a pinned list: exactly
2 for `Knowledge`, exactly 5 for `Membership`, in the declared order. Assert the private witness
count likewise. Reflectively assert no field named `Secret`, `Attribute`, `Path` or `Index` appears in
the public schema.

**Pass.** Counts and names match the pin exactly.

**Fail.** Any extra public field, any missing one, any reordering.

**Avoidance.**
(a) *Negative variant:* the pin must be a literal in the test, not derived from the circuit type at
test time. A pin computed from the subject is a pin that moves with it.
(b) *False-pass trap:* asserting only the *count*. Swapping two public fields keeps the count and
changes the statement — gotcha 49. Assert names **and** order.

**Trace.** §4a, §4b public/private lists · gotcha 49.

---

### ZK-CIR-012 · Public witness layout is pinned against field reordering — **CRITICAL**

**Aim.** A reordering of the circuit struct's public fields is a red test, not a silent change of
statement.

**Point of failure.** Gotcha 49: gnark builds the witness vector from declaration order. Swap `Root`
and `Audience` and the code compiles, proves and verifies — against a statement with the two values
exchanged. The server hands the verifier `(Root, Audience, …)`, the circuit reads
`(Audience, Root, …)`, and a prover who controls neither still finds itself proving something the
policy did not ask for. Neither the compiler nor the verifier can see it. This is gotcha 20's failure
in a second location, which is why the handout flags both.

**Procedure.** For a fixed, hard-coded assignment of all public fields to distinct known constants,
serialize the public witness and assert the resulting bytes equal a pinned hex constant. One
constant per circuit, in the test file, with a comment naming the field order it encodes.

**Pass.** Bytes match.

**Fail.** Bytes differ — either the layout changed or a field was added. Both require a human.

**Avoidance.**
(a) *Negative variant:* a second assertion that the pinned bytes *change* when a field's value
changes. A pin over a serialization that ignores values would match forever.
(b) *False-pass trap:* pinning a hash of the witness *schema* rather than the serialized vector of
distinct values. Two fields of the same type are indistinguishable in a schema hash, and swapping
them is precisely the mutation this case exists for. Use distinct values — `1, 2, 3, 4, 5` is enough
and is readable in the failure diff.

**Trace.** §4b · gotchas 20, 49.

---

### ZK-CIR-013 · Over-constraining at every boundary — **ESSENTIAL**

**Aim.** Honest witnesses at the edge of the legitimate domain are accepted, so the circuit is not a
denial of service against correct users.

**Point of failure.** `test.IsSolved` shows a witness satisfies the system, never that no other one
does — gotcha 47 — and the inverse blind spot is that a suite of adversarial witnesses shows the
circuit rejects, never that it accepts anything. A range check to 63 bits, an off-by-one in the
comparator, a `Threshold < Attribute` where `<=` was meant: all reject honest users at a boundary,
all pass every soundness case in this group, and all surface in production as intermittent login
failure for a subset of accounts nobody can characterise.

**Procedure.** An explicit accept-list: `Attribute == Threshold`; `Attribute == Threshold + 1`;
`Attribute == 2^64 − 1` with `Threshold == 2^64 − 1`; `Attribute == 0` with `Threshold == 0`;
`Index == 0`; `Index == 2^32 − 1`; leftmost and rightmost leaves of the tree; `Challenge == 1`. Every
one must solve **and** produce a proof that verifies.

**Pass.** All accept.

**Fail.** Any reject.

**Avoidance.**
(a) *Negative variant:* `Attribute == Threshold − 1` must reject, in the same table. Otherwise a
circuit with no comparison at all passes this case perfectly.
(b) *False-pass trap:* asserting `IsSolved` only. Over-constraining that manifests at proving time
rather than solving time — an unsatisfiable hint, a bad `AssertIsLessOrEqual` witness — is invisible
to `IsSolved`. At least one boundary witness must go all the way through `Prove` and `Verify`.

**Trace.** §10 · gotcha 47.

---

### ZK-CIR-014 · `CheckCircuit` with valid and invalid assignments — **ESSENTIAL**

**Aim.** gnark's own circuit-level test harness runs over both classes of assignment, on the current
API.

**Point of failure.** `ProverSucceeded` / `ProverFailed` are deprecated in gnark v0.15. Deprecated
calls are the ones that get deleted in a dependency bump, and a test that stops compiling gets
commented out under time pressure far more often than it gets ported. Separately, `CheckCircuit`
exercises backends and curves that `IsSolved` does not, which is where a hint or a solver assumption
that holds in one backend and not another shows up.

**Procedure.** `test.NewAssert(tb)`, `Assert.CheckCircuit(circuit, WithValidAssignment(…),
WithInvalidAssignment(…))` for each circuit, with at least three of each class drawn from
ZK-CIR-004's families. Assert no deprecated symbol is referenced anywhere in the zk test files.

**Pass.** Green with both classes supplied.

**Fail.** Red, or the invalid class omitted.

**Avoidance.**
(a) *Negative variant:* the `WithInvalidAssignment` set is the negative variant, and it is the one a
first draft omits because `CheckCircuit` is green without it.
(b) *False-pass trap:* believing this replaces ZK-CIR-002/003. It does not — it runs a handful of
assignments, not a thousand, and it cannot reach the false→reject direction at scale. Both.

**Trace.** §10.

---

### ZK-CIR-015 · Constraint count pinned, with a ceiling — **GOOD-TO-HAVE**

**Aim.** Prover cost does not regress silently, and `Membership` stays under its stated ceiling.

**Point of failure.** Prover cost is superlinear in the constraint count (handout §2, QAP degree). A
refactor that adds a comparison inside a loop the compiler unrolls turns a 300ms proof into a
production timeout, and the only symptom is user reports.

**Procedure.** `ccs.GetNbConstraints() == nbConstraintsKnowledge` and `== nbConstraintsMembership`,
both pinned. Assert `nbConstraintsMembership < 20_000` — handout §4b: *"if the compiled circuit
exceeds ~20k constraints, something in §2 was ignored — stop and find it."* Assert
`nbConstraintsKnowledge < 1_000` (§4a: order 10²).

**Pass.** Exact match on both pins, both ceilings clear.

**Fail.** Either mismatch. Investigate before editing the constant — handout §3 stage 3: *"if the
measurement is more than ~2× the estimate, you flattened it wrong."*

**Avoidance.**
(a) *Negative variant:* the ceiling assertions are the negative variant. An exact pin alone is
satisfied by editing the constant, which is what everyone does; the ceiling is the number nobody can
edit without arguing with §4b.
(b) *False-pass trap:* treating this as a semantic control. The count is a **weak fingerprint** — a
refactor can change which statement is proven without changing how many gates prove it. ZK-KEY-004 is
the semantic control. Relying on the count for identity is the specific false confidence handout §3
stage 5 warns about.

**Trace.** §3 stage 3 · §4a, §4b budgets · §10.

---

### ZK-CIR-016 · The flattened form matches `Define()` — **GOOD-TO-HAVE**

**Aim.** The numbered flattened list in the `@dev` block is the circuit, so a reviewer can check the
circuit by reading.

**Point of failure.** Handout §3 stage 4: *"a circuit that does not read like its own flattened form
cannot be reviewed against it."* Once they diverge, the doc comment is a plausible, confident,
out-of-date description of a security-critical artifact, and every subsequent reviewer checks the
comment. This is not testable mechanically; it is a review gate.

**Procedure.** Review checklist item, recorded in the audit: each circuit's `@dev` block contains a
numbered list of statements of exactly the two shapes `x = y` and `x = y (op) z`; `Define()` executes
them in the same order with the same operands; the count of listed statements is consistent with the
pinned constraint count to within the documented factor.

**Pass.** A named reviewer signs it per circuit, per change.

**Fail.** Prose in place of the list, or an order mismatch.

**Avoidance.**
(a) *Negative variant:* none available mechanically — which is the finding. Record it as a manual
gate rather than pretending a test covers it.
(b) *False-pass trap:* accepting a `@dev` block that *describes* the circuit. Handout §3 stage 2:
*"Not prose describing the circuit — the actual list."*

**Trace.** §3 stages 2, 4 · `CLAUDE.md` doc-comment register.

---

### ZK-CIR-017 · Two leaves for one secret — **ESSENTIAL** [UNSPECIFIED]

**Aim.** The consequences of one secret appearing in two leaves are known and bounded.

**Point of failure.** `auth_zk_credentials.commitment` is `unique`, but the commitment is
`MiMC(DOM_LEAF, Secret, Attribute)` — so the same secret enrolled with two *different* attributes
produces two different commitments, passes the unique index, and yields a member who can choose at
proving time which attribute to prove. If an operator ever lowers someone's attribute by re-enrolling
rather than revoking, the old leaf is still in the tree and the higher claim still proves. The
nullifier is unaffected (it does not read `Attribute`), so the two leaves are one pseudonym and
nothing links them for the operator either.

**Procedure.** Enrol one secret at `Attribute = 21`. Enrol the same secret at `Attribute = 12`.
Assert the documented behaviour: either the second enrolment is refused, or both leaves exist and a
proof against `Threshold = 18` still succeeds. Whichever it is, assert it and record it.

**Pass.** The observed behaviour matches a decision written down in the package docs.

**Fail.** No decision exists. The handout does not settle this; see §23.

**Avoidance.**
(a) *Negative variant:* revoke the higher leaf and assert the `Threshold = 18` proof now fails, which
is the property an operator will assume it has.
(b) *False-pass trap:* asserting only that the unique index fired. It will not fire — the
commitments differ. A test that asserts a duplicate-key error passes on a different scenario than the
one described here.

**Trace.** §4b · §9 `auth_zk_credentials` · §12 recovery.

---

## 4 · Group HSH — Hash and primitive agreement

Two implementations of one function, in two packages, with different input types, and nothing checks
that they agree. When they do not, every proof rejects for a reason that looks like a circuit bug and
the debugging happens in the wrong file.

### ZK-HSH-001 · Native and in-circuit MiMC agree — **CRITICAL**

**Aim.** `gnark-crypto/ecc/bn254/fr/mimc` and `std/hash/mimc` compute the same function on the same
inputs.

**Point of failure.** `Enroll` computes the commitment natively; the circuit computes it in-circuit.
The native API takes `[]byte` in **32-byte canonical chunks**; the in-circuit API takes
`frontend.Variable`. A 31-byte secret must be padded to 32 somewhere, and which end it is padded on
is a decision nobody wrote down. Get it wrong and every stored commitment is the hash of a different
preimage than the circuit computes. Every proof rejects, uniformly, for every user, and the error
surface is `INVALID_PROOF` — the same code as "you are not a member". Handout §10 calls this out
precisely because the failure looks like a circuit bug and is not one.

**Procedure.** 1000 random 31-byte secrets. For each, compute `MiMC(DOM_KNOWLEDGE, s)` natively and
assert it equals the value the circuit computes for the same `s` — obtained by solving the circuit
with the native result as the public `Commitment` and asserting it solves. Assert in the failing
direction too: a native result perturbed by one bit must not solve.

**Pass.** 1000/1000 agree; every perturbed value fails.

**Fail.** Any disagreement, at any input length.

**Avoidance.**
(a) *Negative variant:* the perturbed-value half. Without it, a circuit whose `AssertIsEqual` was
dropped agrees with everything.
(b) *False-pass trap:* computing the "native" side with a helper the package also uses in `Enroll`
and that internally calls the circuit's own hash. Then the test asserts a function equals itself.
The two sides must reach the two library packages independently — harness precondition P-8.

**Trace.** §10 · gotcha 51.

---

### ZK-HSH-002 · Agreement at every arity used — **CRITICAL**

**Aim.** Agreement holds for each distinct absorb the design performs, not just the one-input case.

**Point of failure.** The design uses at least four shapes: `MiMC(DOM_KNOWLEDGE, Secret)`,
`MiMC(DOM_LEAF, Secret, Attribute)`, `MiMC(DOM_NULLIFIER, Secret, Audience)`, and `MiMC(zeros[i],
zeros[i])` for the tree. Padding and chunking behave differently per arity, and the tree's
zero-hashes are computed natively **only** — they are never recomputed in-circuit, so a divergence
there produces a tree whose empty slots the circuit cannot reproduce and whose sparse paths fail for
exactly the members enrolled next to an empty subtree. That is a subset of users, intermittently,
which is the worst possible failure signature.

**Procedure.** For each of the four shapes, 1000 random input tuples, native vs in-circuit, both
directions as ZK-HSH-001. For the tree shape additionally: recompute `zeros[0..32]` in a second,
independent implementation in the test (a literal loop over the native hash) and assert it equals the
package's precomputed table element by element.

**Pass.** All four shapes agree at all 1000 inputs; the 33 zero-hashes match the independent
recomputation.

**Fail.** Any disagreement in any shape.

**Avoidance.**
(a) *Negative variant:* assert `zeros[i] != zeros[j]` for `i != j` and `zeros[i] != 0` for all `i`. A
table of 33 zeroes matches a broken independent recomputation that is also 33 zeroes.
(b) *False-pass trap:* testing only the one-input shape and generalising. The chunking bug is
arity-specific and appears at the second input, not the first.

**Trace.** §4b lines 2, 6 · §6 · gotcha 51.

---

### ZK-HSH-003 · The 31-byte secret is always a canonical field element — **CRITICAL**

**Aim.** Every value the secret generator can produce is `< r`, so no reduction, split or rejection
sampling is needed and no bit is silently dropped.

**Point of failure.** Handout §0: `2^248 < r ≈ 2^253.6`, so every 31-byte value is canonical; 32
bytes is not — *"it wraps, silently, for one value in about thirty."* A wrapped secret produces a
commitment for the reduced value. The user holds the unreduced bytes. The client computes a different
preimage, or the same one, depending on which library reduces where. One user in thirty cannot log
in, permanently, and the failure is `INVALID_PROOF`.

**Procedure.** (i) Assert the generator reads exactly 31 bytes and that `len(secret) == 31` on the
returned value. (ii) Assert the maximum 31-byte value (`0xFF × 31`) interpreted as a field element is
`< r`, and that it round-trips through the native hash without reduction. (iii) Assert that a 32-byte
value at `r` and at `r + 1` — constructed deliberately — is **rejected** by the enrolment path rather
than reduced. (iv) Fuzz: 10000 generated secrets, assert every one `< r` and `!= 0`.

**Pass.** All four hold.

**Fail.** Any secret ≥ `r`, any silent reduction, any zero.

**Avoidance.**
(a) *Negative variant:* (iii) is the negative variant — a system that reduces rather than rejects
looks identical from (i), (ii) and (iv).
(b) *False-pass trap:* comparing against `2^248` instead of `r`. `< 2^248` is the property the design
*relies on*; `< r` is the property that matters, and a change from 31 to 32 bytes passes a `< r`
check 29 times out of 30 and fails a `< 2^248` check always. Assert **both**, and assert the length.

**Trace.** §0 "On the secret being 31 bytes" · §2 "Everything is a field element" · gotcha 45.

---

### ZK-HSH-004 · Secret generation is `crypto/rand` and is not silently short — **CRITICAL**

**Aim.** The credential is drawn from a CSPRNG, fully, with the error handled.

**Point of failure.** `math/rand` seeded from the clock gives an attacker who knows the enrolment
minute a search space of milliseconds. And `rand.Read` returning `(n < 31, nil)` — or an ignored
error — yields a secret whose tail is Go's zero value, which is a 31-byte value with 8 bits of
entropy that passes every canonicality check in ZK-HSH-003. Neither has a symptom.

**Procedure.** (i) Source-level: assert no `math/rand` import in `zkauthn`/`zkauthz`. (ii) Behavioural:
10000 generated secrets — assert all distinct, assert no byte position is constant across the
population, assert a per-byte chi-square within tolerance, assert no secret has a run of ≥8 zero
bytes. (iii) Inject a reader that returns `(15, nil)` and assert the enrolment path returns an error
rather than a short secret. (iv) Inject a reader that returns an error and assert the error is
propagated, not swallowed, and no partial credential row is written.

**Pass.** All four.

**Fail.** Any constant byte position, any short secret accepted, any swallowed error, any row written
on a failed draw.

**Avoidance.**
(a) *Negative variant:* (iii) and (iv) are the negative variants and are the only ones that catch the
common bug. A distribution test on a working CSPRNG proves nothing about the error path.
(b) *False-pass trap:* asserting distinctness only. 31 bytes of a broken generator are still distinct
if a counter is in there.

**Trace.** §0 · §4a "kal generates the secret" · `CLAUDE.md` — reuse `session.NewToken`'s shape.

---

### ZK-HSH-005 · The secret is returned exactly once and never stored — **CRITICAL**

**Aim.** `Enroll` stores the commitment, returns the secret once, and the secret is recoverable from
nowhere afterwards.

**Point of failure.** A secret persisted anywhere — an audit column, a debug log, an error's
`Internal` field, a returned struct that gets marshalled into a response cache — converts the whole
design into a password database with extra steps, and one that has no Argon2id in front of it. §4a's
entire refusal argument rests on the secret being machine-generated *and* not present in the
database; leaking it there restores the offline-attack posture the refusal exists to avoid, without
even needing the dictionary.

**Procedure.** (i) Schema: assert `auth_zk_commitments` and `auth_zk_credentials` have no column
capable of holding the secret — enumerate columns and assert the set matches §9 exactly. (ii)
Behavioural: run an enrolment, then dump every row of every `auth_zk_*` table plus `auth_users` and
`auth_sessions`, and assert the secret's bytes appear in none of them. (iii) Capture logs during
enrolment and assert the secret's bytes and its hex encoding appear in no log line. (iv) Assert a
second call to any read path returns no secret — there is no getter.

**Pass.** Secret bytes appear nowhere but the return value.

**Fail.** Any occurrence.

**Avoidance.**
(a) *Negative variant:* search the same dumps for the *commitment* and assert it **is** present.
Otherwise a test with a broken search function passes (ii) and (iii) trivially.
(b) *False-pass trap:* searching only for the exact byte slice. Search for the hex string and the
base64 encoding too — the leak is usually a formatted log line, not a raw write.

**Trace.** §4a · §9 · gotcha 29 lineage.

---

## 5 · Group INP — Public input provenance

Handout §5: *"`groth16.Verify` checks that the prover knows a witness for the public inputs you hand
it. It does not check that those are the public inputs your policy wanted."* This is the one group
where a correct circuit, a correct ceremony and a correct key still produce a total bypass, and where
every case in Group CIR passes while the system is wide open.

### ZK-INP-001 · `Threshold` comes from the policy row — **CRITICAL**

The headline bypass of the whole design.

**Aim.** The threshold a proof is verified against is the one in `auth_zk_claims` for the claim named
by the schema, and there is no path by which a request influences it.

**Point of failure.** Take `Threshold` from the request and a member whose attribute is `0` sends
`Threshold: 0`, proves `0 >= 0`, and satisfies `@auth(proves: ["age_over_18"])`. The proof verifies.
The circuit is correct. The differential test passes — the circuit is doing exactly what it was
asked. There is no error and no log line. Every claim in the deployment is satisfied by every member
simultaneously, and the only artifact is a successful request.

**Procedure.** Three layers.
1. *Compile-time.* Assert the request type has no threshold field and no `publicInputs []byte` field
   — handout §5: *"a struct with a `publicInputs []byte` field is a struct someone fills from the
   request body."* Reflect over `MembershipRequest`'s fields and assert the set is exactly
   `{Proof, Root, Nullifier, Challenge, Claim}`. Assert `Login`'s signature takes no threshold.
2. *Protocol, `TestDBZKThresholdFromPolicy`.* Seed `auth_zk_claims` with `age_over_18 → threshold
   18`. Enrol a member with `Attribute = 12`. Have the member produce an honest, fully valid proof
   for `Threshold = 0` and submit it naming claim `age_over_18`. Assert **the claim is not granted**
   and **the resolver behind `@auth(proves: ["age_over_18"])` did not run** — instrument the resolver
   with a counter and assert it is zero, per handout §10.
3. *Symmetric case.* Same member, `Attribute = 21`, honest proof for `Threshold = 18` — granted.

**Pass.** Layer 1 reflects the exact field set. Layer 2 grants nothing and the resolver counter is 0.
Layer 3 grants.

**Fail.** Any threshold reachable from the request; the claim granted in layer 2; the resolver counter
non-zero in layer 2.

**Avoidance.**
(a) *Negative variant:* layer 3. Without it, a `Proofs` func that returns an error unconditionally
passes layer 2 and denies every legitimate user.
(b) *False-pass trap, the important one:* asserting that the *request was rejected*. It may well be
rejected — for the wrong reason, because the proof was built for a public vector the server did not
construct and therefore fails the pairing check. That is the correct outcome and it is **not** what
this case is testing. The assertion is on the resolver counter and on the granted-claim set, so the
case still means something if the failure mode changes. A test that asserts on the error value alone
goes green on a system where `Threshold` is taken from the request and the proof happens to be
malformed.
(c) *Third trap:* seeding the claim row with threshold `0` for convenience. Then request-supplied and
policy-supplied agree and the case can never fail.

**Trace.** §5 table · §7 `@auth(proves:)` · gotcha 58.

---

### ZK-INP-002 · `Commitment` comes from the session's user — **CRITICAL**

**Aim.** `Knowledge.Verify` reads the commitment from `auth_zk_commitments` keyed by the user on the
request context's principal, never from the request.

**Point of failure.** Handout §5: *"Take `Commitment` from the request and any enrolled user
satisfies any other user's MFA with their own secret."* Attacker enrols their own secret,
authenticates as themselves at the password layer against a stolen first-factor credential for
victim, and completes step-up MFA with a commitment they supply and a secret they hold. `mfa_at` is
set on the attacker's session for the victim's account, and `@auth(mfa: true)` opens. The second
factor is now a first factor the attacker also owns.

**Procedure.** (i) Compile-time: `Knowledge.Verify` takes a proof and a challenge and nothing else
resembling a commitment; reflect over its parameters. (ii) Protocol: users A and B both enrolled. As
session-for-A, submit a proof honestly built against **B's** commitment. Assert
`auth_sessions.mfa_at` is still null for A's session **and** for B's, and that `@auth(mfa: true)`
still denies for A. (iii) Symmetric: A's own proof sets A's `mfa_at`.

**Pass.** (ii) leaves both `mfa_at` null. (iii) sets exactly one.

**Fail.** Any commitment reachable from the request; `mfa_at` set in (ii).

**Avoidance.**
(a) *Negative variant:* (iii). A `Verify` that always errors passes (ii).
(b) *False-pass trap:* asserting the returned error. Assert the **column** — `mfa_at` null — because
that is the thing that goes wrong, per `CONTRIBUTING.md`'s rule for security tests.

**Trace.** §5 table · §4a.

---

### ZK-INP-003 · `Audience` comes from the claims row — **CRITICAL**

**Aim.** The audience a nullifier is checked under is derived from the claim name in the schema, never
supplied.

**Point of failure.** A caller who supplies its own audience picks the domain in which its nullifier
lives. Two consequences, both bad. On a **one-shot** claim, the caller supplies a fresh audience per
attempt, derives a fresh nullifier, and the unique index never fires — the rate limit is gone with
every proof valid. On a **recurring** claim, the caller chooses an audience whose nullifier collides
with a row it wants — and handout §7 says exactly why the primary key is the nullifier alone:
*"keying on `(nullifier, audience)` is not stronger, it is a second chance for a caller who supplies
its own audience to claim a nullifier that is not theirs."*

**Procedure.** (i) Compile-time: no audience field on the request type; reflect. (ii) Protocol: seed
two claims with two audiences. Submit a proof honestly built for audience X while naming the claim
whose row says audience Y. Assert no session, no claim granted, and **no new `auth_zk_nullifiers`
row**. (iii) Assert the audience the server used equals the claims row's value — read it back from
the row written on a legitimate proof.

**Pass.** (ii) writes nothing; (iii) matches the policy row.

**Fail.** Any audience reachable from the request; a nullifier row written under a prover-named
audience.

**Avoidance.**
(a) *Negative variant:* a proof built for audience Y under claim Y succeeds and writes exactly one
row.
(b) *False-pass trap:* checking only that the request struct lacks the field. The audience can still
be reachable through `Claim` if the claim lookup falls back to interpreting an unknown claim name as
an audience, or if the claim string is used to derive the audience rather than to key a row. Assert
the lookup is a row read: an unknown claim must produce ZK-ORC-006's uniform failure, **not** a
derived audience.

**Trace.** §5 table · §7 two-audience-kinds · gotchas 58, 59.

---

### ZK-INP-004 · `Root` is validated, not supplied — **CRITICAL**

**Aim.** The root a proof verifies against is one the server published and has not retired beyond
`RootGrace`.

**Point of failure.** The client must name the root it built against — it cannot be looked up, since
the client chose it — so this is the one input the prover names and the server must therefore
*check*. Without the check, T1 builds its own tree containing a leaf for a secret it invented,
computes that tree's root, and proves membership of it. Every constraint in the circuit is satisfied.
`Path[0]` binds correctly to a secret the attacker genuinely knows. There is no forgery anywhere —
the attacker simply proved membership of a set it defined. This is the case where a perfect Group CIR
result is worth nothing.

**Procedure.** (i) Attacker-constructed root: build a one-leaf tree from a self-chosen secret, prove,
submit. Assert **no `auth_users` row, no nullifier row, no session**. (ii) Never-published root: a
uniformly random 32-byte value. Same assertions. (iii) Retired root with `RootGrace = 0`: enrol,
capture root R₁, enrol again producing R₂, prove against R₁, submit. Same assertions. (iv) Current
root: succeeds — the control.

**Pass.** (i)–(iii) leave every table unchanged; (iv) succeeds.

**Fail.** Any of (i)–(iii) yielding a session or a row.

**Avoidance.**
(a) *Negative variant:* (iv), and its absence is how a "reject everything" implementation passes.
(b) *False-pass trap:* using a root that is *also* structurally invalid — wrong length, non-canonical
— so the request fails a length check before the roots table is consulted. (i) must be a genuine,
well-formed BN254 field element that is a genuine root of a genuine tree. If the attack input is
malformed you have tested the parser.
(c) *Third trap:* checking the root against `auth_zk_roots` with no `retired_at` predicate and
calling (iii) covered. Run (iii) explicitly with `RootGrace = 0`.

**Trace.** §5 table · §6 `RootGrace` · gotcha 55.

---

### ZK-INP-005 · The prover names exactly three things — **ESSENTIAL**

**Aim.** The attack surface of the request is enumerated and pinned: the proof, the `Root` (validated),
and the `Nullifier`. Everything else is server-side.

**Point of failure.** New fields arrive one at a time, each with a local justification, and each is a
value the attacker chose. The register that says which values are attacker-controlled is the only
thing that makes the next review tractable.

**Procedure.** Reflect over `MembershipRequest` and over `Knowledge.Verify`'s parameters. Assert the
prover-controlled set is exactly `{Proof, Root, Nullifier, Challenge}` for `Membership` — with
`Challenge` a lookup key, not a value — and `{proof, challenge}` for `Knowledge`. Any field added
without updating this pin is a red test and a design review.

**Pass.** Exact match against the pinned list.

**Fail.** Any additional field.

**Avoidance.**
(a) *Negative variant:* assert `Claim` is present and is a *name*, not a value — a claim string that
carries a threshold (`"age>=18"`) reintroduces ZK-INP-001 through a parser. Handout §7: *"Claims are
opaque strings … no expression syntax, no parser."* Assert a claim containing `>`, `=`, `<` or a
digit-comparison shape is rejected before the lookup.
(b) *False-pass trap:* pinning field *names* only. A field renamed keeps the surface; a field whose
type widens from `string` to `map[string]any` does not. Pin names and types.

**Trace.** §5 · §7 `@auth(proves:)`.

---

### ZK-INP-006 · Structurally invalid inputs fail before anything expensive — **ESSENTIAL**

**Aim.** Malformed `Root`, `Nullifier`, `Challenge` and `Claim` are rejected on shape, uniformly, with
no allocation proportional to their size and no database round trip.

**Point of failure.** Every one of these is attacker-supplied and unbounded unless bounded. An
oversized `Claim` becomes a large query parameter; an oversized `Nullifier` becomes a large index
probe; a huge `Root` becomes a `bytea` comparison. Individually small, collectively a free
amplification against the database from an unauthenticated endpoint.

**Procedure.** For each field: empty, one byte short, one byte long, 1 MiB, and non-UTF-8 for
`Claim`. Assert the uniform `CodeInvalidProof` (or the uniform request-shape error, per ZK-ORC-001),
no panic, and — instrumented — zero queries issued for the oversized cases.

**Pass.** Uniform rejection, no panic, no query.

**Fail.** A panic, a distinct error, or a query issued on a 1 MiB input.

**Avoidance.**
(a) *Negative variant:* correctly-sized values of every field proceed to the next stage.
(b) *False-pass trap:* asserting no panic only. `recover()` in a middleware turns a panic into a 500
and the test sees a graceful failure. Assert the query count.

**Trace.** §5 · §9 DoS · gotcha 61.

---

## 6 · Group CHL — Challenge lifecycle

The challenge is what makes a proof a login rather than a bearer token. Group CIR proves the circuit
reads it; this group proves the server issues, binds and burns it.

### ZK-CHL-001 · A proof does not replay under its own challenge — **CRITICAL**

**Aim.** One challenge admits one successful verification, ever.

**Point of failure.** A Groth16 proof is a string of bytes that verifies forever, against anyone, with
no interaction and no expiry. If the challenge is not consumed, the first proof a member produces is
a permanent credential for that pseudonym, and it is held by every access log, reverse proxy, APM
trace, crash report, browser history entry and pasted support ticket that ever touched the request.
Handout §4b: *"Line 8 costs one constraint and is the difference between a login and a password
written on a postcard."*

**Procedure.** `TestDBZKChallengeReplay`. Issue challenge C. Produce proof P for C. Submit `(P, C)` —
succeeds. Submit the identical `(P, C)` bytes again. Assert **no second session row**, no second
`auth_zk_nullifiers` mutation, and — for `Knowledge` — that `mfa_at` was not advanced. Repeat for
both circuits.

**Pass.** Exactly one session exists after two submissions. `mfa_at` unchanged by the second.

**Fail.** Two sessions, or any state change on the second submission.

**Avoidance.**
(a) *Negative variant:* a **new** challenge C′ with a **new** proof P′ succeeds, in the same test.
Without it, an implementation that rejects every second request for any reason — a stuck semaphore, a
broken connection reuse — passes.
(b) *False-pass trap, specific to Groth16:* implementing replay defence as deduplication on proof
bytes and testing it with identical bytes. Gotcha 43: the `(A,B,C)` triple **re-randomises into a
different but valid proof**, so byte-dedup buys nothing and this test would pass anyway. ZK-CHL-002
is the case that closes it, and it must be run.

**Trace.** §4a line 3 · §4b line 8 · §5 · gotchas 42, 43.

---

### ZK-CHL-002 · A re-randomised proof does not replay — **CRITICAL**

The case that distinguishes a real control from byte-level deduplication.

**Aim.** Replay defence lives in the challenge burn and in the in-circuit challenge constraint, not in
the proof bytes.

**Point of failure.** Gotcha 43. An implementer who reads "reject a proof we have seen before"
implements a `seen_proofs` table, passes ZK-CHL-001, and ships a system where the attacker applies
the standard Groth16 re-randomisation and submits a byte-distinct, cryptographically valid proof of
the same statement. If the challenge row is not burned, it verifies.

**Procedure.** Produce proof P for challenge C. Submit — succeeds. Re-randomise P into P′ ≠ P (valid
under the same vk and public witness; verify locally that `groth16.Verify(P′, vk, w) == nil` before
submitting, or the case is untested). Submit `(P′, C)`. Assert no second session and no state change.
Then assert positively that `auth_zk_challenges.consumed_at` for C is non-null after the first
submission.

**Pass.** P′ rejected; `consumed_at` set by the first submission.

**Fail.** P′ accepted — the control is byte-dedup and the design's replay defence does not exist.

**Avoidance.**
(a) *Negative variant:* the local `groth16.Verify(P′, …) == nil` assertion **before** submitting. If
P′ is not a valid proof, the server rejecting it means nothing and the test is theatre. This
assertion is the whole case.
(b) *False-pass trap:* skipping this case because ZK-CHL-001 is green. ZK-CHL-001 is green on a
byte-dedup implementation. That is why both exist.

**Trace.** §4b line 8 · gotchas 42, 43.

---

### ZK-CHL-003 · The burn is atomic — **CRITICAL**

**Aim.** The challenge is consumed by the same statement that reads it.

**Point of failure.** Gotcha 36's rule, restated for a new table: *never read-then-write.* A `SELECT
… WHERE consumed_at IS NULL` followed by an `UPDATE` lets N concurrent submissions of the same proof
all pass the select. Under any real load — a retrying client, a double-clicked button, a mobile
network — this fires without an attacker, and it produces N sessions from one challenge.

**Procedure.** `TestDBZK*`, P-4's barrier shape. One challenge C, one proof P, 8 goroutines released
simultaneously, all submitting `(P, C)`. Assert **exactly one** succeeds and exactly one session row
exists. Assert the statement form: a single `UPDATE … WHERE consumed_at IS NULL … RETURNING`.

**Pass.** One success out of 8. One session row.

**Fail.** Two or more. Any count above one is the full finding — there is no "mostly atomic".

**Avoidance.**
(a) *Negative variant:* 8 goroutines with 8 *distinct* challenges and 8 distinct proofs produce 8
sessions. Without it, a global lock that serialises everything into failure passes.
(b) *False-pass trap:* running the 8 goroutines without a barrier. Go's scheduler will usually
serialise them on a single-CPU CI runner and the broken implementation passes most of the time,
producing an intermittent test that gets quarantined. Copy the barrier from
`tests/tokens_test.go:296`; do not invent a second one.

**Trace.** §4a `Verify` · §9 · gotchas 36, 57.

---

### ZK-CHL-004 · The challenge names a session, not a user — **CRITICAL**

**Aim.** `Knowledge` elevates the session that asked for step-up, and only that one.

**Point of failure.** `mfa_at` is a column on `auth_sessions`. A challenge row that identifies only
the user elevates whichever session happens to present the proof. Handout §4a: *"Two tabs, and the
one that asked for step-up is not the one that got it."* The attack, not just the annoyance: an
attacker holding a stolen session cookie for a victim waits for the victim to begin a legitimate MFA
step-up, and presents the victim's own proof — or simply races the victim's submission — from the
attacker's session. The victim's second factor elevates the attacker's session.

**Procedure.** User A with two sessions S1 and S2. S1 requests a challenge C. Produce a valid proof P
for C. Submit `(P, C)` **from S2**. Assert `mfa_at` is null on **both** S1 and S2 — the submission
must fail, not cross-elevate. Then submit from S1: assert `mfa_at` set on S1 and still null on S2.
Assert `auth_zk_challenges.session_id` is non-null for a `Knowledge` challenge.

**Pass.** Cross-session submission elevates nothing; same-session elevates exactly one row.

**Fail.** `mfa_at` set on either row by the cross-session submission.

**Avoidance.**
(a) *Negative variant:* the same-session half, which is what a "deny all step-up" implementation
fails.
(b) *False-pass trap:* asserting only that S2 was not elevated. If the implementation keys on the
user, it elevates *S1* on a submission from S2 — the wrong session, silently, and the attacker's goal
is achieved from the other direction in the racing variant. Assert **both** rows.

**Trace.** §4a "The challenge names a session, not a user" · §9 `auth_zk_challenges.session_id`.

---

### ZK-CHL-005 · Expiry is enforced — **ESSENTIAL**

**Aim.** A challenge older than its TTL is not consumable.

**Point of failure.** An unexpired challenge is a window in which a stolen proof is usable. The TTL is
60 seconds by handout §9; the failure of an unchecked `expires_at` is that the window is the lifetime
of the row, which — without ZK-CHL-006's cleanup — is forever.

**Procedure.** Issue C, advance the clock past 60s (injected clock, or write `expires_at` directly),
produce a valid P, submit. Assert no session, no `mfa_at`. Then: submit at T+59s — succeeds. Assert
the boundary is checked against `now()` in the same statement as the burn, not in application code.

**Pass.** Expired rejected, unexpired accepted, one statement.

**Fail.** Expired accepted, or the expiry checked in a read before the burn (reintroducing
ZK-CHL-003).

**Avoidance.**
(a) *Negative variant:* the T+59s acceptance. A TTL of zero passes the first half.
(b) *False-pass trap:* `time.Sleep(61 * time.Second)`. That is a minute of CI per run and it will be
shortened to 1s with a 1s TTL "for the test", which tests a configuration nobody ships. Inject the
clock or write the column.

**Trace.** §9 "A challenge is a row an unauthenticated caller creates".

---

### ZK-CHL-006 · Issuance deletes expired rows in the same statement — **ESSENTIAL**

**Aim.** The challenge table cannot be grown without bound by an unauthenticated caller.

**Point of failure.** Handout §9: *"or the endpoint is a free write amplifier and the table is the
thing that falls over first."* One HTTP request, one row, no authentication, no cleanup. The database
fills, and it fills on the table the login path reads, so the symptom is that logins get slow before
anything reports an error.

**Procedure.** Assert the issuing statement is a single `with del as (delete … where expires_at <
now()) insert …`. Behaviourally: insert 1000 rows with `expires_at` in the past, issue one challenge,
assert the row count afterwards is 1 (or bounded by the live set), in **one** round trip — assert the
query count is 1.

**Pass.** Row count collapses; one statement.

**Fail.** Rows accumulate, or cleanup is a second statement, or a background job (which is a
different failure: a job that stops has no symptom).

**Avoidance.**
(a) *Negative variant:* a live, unexpired challenge issued before the sweep is **still consumable**
after it. A cleanup that deletes the row it just wrote passes the count assertion and breaks login.
(b) *False-pass trap:* counting rows without asserting the statement count. Two statements pass the
count and lose atomicity.

**Trace.** §9.

---

### ZK-CHL-007 · Challenges are unpredictable — **ESSENTIAL**

**Aim.** A challenge cannot be guessed or precomputed by anyone who has not been issued it.

**Point of failure.** A predictable challenge — a counter, a timestamp, a truncated uuid v1 — lets an
attacker precompute a proof for a challenge that will be issued to a victim, or produce a proof
offline and submit it the instant that challenge appears. The freshness property is exactly the
unpredictability property; a sequential challenge is a constant with extra ceremony.

**Procedure.** Issue 10000 challenges. Assert: all distinct; ≥128 bits of length; no monotonic
relationship between issuance order and value (sort and assert the order is not the issuance order,
with a strong margin); per-byte distribution within tolerance; `crypto/rand` by source inspection;
never `0`.

**Pass.** All hold.

**Fail.** Any ordering correlation, any repeat, any short value.

**Avoidance.**
(a) *Negative variant:* assert two challenges issued in the same microsecond differ. A clock-derived
challenge passes a distinctness test on a slow loop and collides under load.
(b) *False-pass trap:* asserting distinctness alone — a counter is perfectly distinct.

**Trace.** §4a, §4b freshness · §9.

---

### ZK-CHL-008 · A `Membership` challenge needs no session; a `Knowledge` challenge requires one — **ESSENTIAL**

**Aim.** `auth_zk_challenges.session_id` is nullable for the login case and mandatory for the step-up
case, and the two are not confusable.

**Point of failure.** Handout §9 marks the column **nullable** because a `Membership` login has no
session yet. That nullability is also the hole: a `Knowledge` verification that accepts a challenge
row with a null `session_id` has no session to elevate and will either elevate the wrong one or
elevate by user — reintroducing ZK-CHL-004 through the schema rather than through the code.

**Procedure.** (i) Issue a `Membership` challenge unauthenticated; assert the row exists with null
`session_id` and that it is consumable by a `Membership` proof. (ii) Attempt to redeem a null-session
challenge with a `Knowledge` proof; assert rejected and no `mfa_at` set anywhere. (iii) Attempt to
redeem a session-bound challenge with a `Membership` proof; assert the behaviour is defined and
tested (reject, or accept and ignore the session — assert whichever, and record it).

**Pass.** (i) works, (ii) rejects, (iii) matches a written decision.

**Fail.** (ii) accepted, or (iii) undefined.

**Avoidance.**
(a) *Negative variant:* (i), which a "require session always" implementation fails by making
anonymous login impossible.
(b) *False-pass trap:* assuming the two challenge kinds are distinguishable because they are used
differently. If the table has no `kind` column, they are the same rows; the case is about whether the
consuming statement discriminates. Assert on the consuming statement's predicate. [UNSPECIFIED] — the
handout does not give the challenge table a kind discriminator; see §23.

**Trace.** §9 `auth_zk_challenges` · §4a.

---

### ZK-CHL-009 · A challenge is not transferable between users or sessions — **ESSENTIAL**

**Aim.** Possession of a challenge value confers nothing on a party it was not issued to.

**Point of failure.** Challenges travel in responses and are therefore in logs and caches. If a
`Membership` challenge issued to one client is consumable by another, an attacker who scrapes them
gains nothing directly — the proof still binds — but if the server *associates* the challenge with a
prospective identity anywhere, that association becomes the bypass.

**Procedure.** Issue challenge C to client 1. Client 2 (different secret, different member) produces a
valid proof for C and submits it. Assert the behaviour is defined: the proof should succeed on its own
merits — C is a nonce, not an authorisation — and the resulting session must belong to **client 2's**
pseudonym, never to client 1's. Assert the nullifier row written is client 2's.

**Pass.** The session belongs to the prover, not to the challenge's requester.

**Fail.** Any binding of the challenge to a prospective identity that the proof then inherits.

**Avoidance.**
(a) *Negative variant:* client 1's own proof for C also yields client 1's pseudonym.
(b) *False-pass trap:* reading this case as "challenges must be non-transferable" and adding a
binding. For `Membership` the challenge is deliberately identity-free — there is no identity yet. The
control is that it confers nothing, not that it is bound.

**Trace.** §4b · §7.

---

### ZK-CHL-010 · Challenge-table growth is bounded under sustained load — **GOOD-TO-HAVE**

**Aim.** The steady-state row count of `auth_zk_challenges` is a function of the TTL and the request
rate, not of uptime.

**Point of failure.** ZK-CHL-006 tests the mechanism; this tests the property. A cleanup predicate
that is subtly wrong — `expires_at < now() - interval '1 day'`, a timezone mismatch — passes
ZK-CHL-006 and grows the table anyway.

**Procedure.** Issue at a fixed rate for a duration exceeding several TTLs with an injected clock.
Assert the row count plateaus at approximately `rate × TTL` and does not trend upward.

**Pass.** Plateau observed.

**Fail.** Monotonic growth.

**Avoidance.** (a) Assert the plateau is non-zero — a cleanup that deletes everything plateaus at 0
and breaks login. (b) Do not run this on wall-clock time; it becomes the slowest test in the suite and
gets deleted.

**Trace.** §9 · gotcha 61.

---

## 7 · Group TRE — Tree integrity

Handout §13 gives this phase its own review *"because it has no cryptography in it and is the part
that fails silently under two replicas."* Every failure here is a data-structure failure that
presents as an authentication failure, or worse, as an authentication success.

### ZK-TRE-001 · Concurrent appends produce one consistent tree — **CRITICAL**

**Aim.** N simultaneous enrolments yield N leaves, one root per append, and every path verifies
against the final root.

**Point of failure.** Handout §6: both readers take `max(leaf_index)`, both take that index, both read
sibling hashes the other is about to change, and both publish a root — *"and the one that lands
second is a root that no path in the table verifies against."* The consequences split badly: one
member is silently overwritten (their credential exists in `auth_zk_credentials` and not in the tree,
so they can never log in, and `issued_to` says they are a member), while the published root is
consistent with neither. Under `RootGrace = 0` every proof in flight fails. Nothing errors.

**Procedure.** `TestDBZKConcurrentEnroll`, P-4 barrier. Start with a tree of K leaves. Release 2
goroutines, then repeat with 8, each enrolling a distinct member. Assert:
1. `auth_zk_credentials` gained exactly N rows with N distinct `leaf_index` values, contiguous from
   K.
2. `auth_zk_roots` gained exactly N rows.
3. For **every one** of the K+N members, the path read from `auth_zk_nodes` verifies against the
   **final** root — recomputed in the test with the native hash, independently of the package.
4. A `Membership` proof from the last-enrolled member and from the first-enrolled member both
   verify against the final root.

**Pass.** All four.

**Fail.** Any duplicate or missing `leaf_index`; any path that does not verify; fewer than N roots.

**Avoidance.**
(a) *Negative variant:* assertion 3 must include a member enrolled **before** the concurrent burst. A
race that corrupts only pre-existing siblings passes a check that only looks at the new leaves — and
that is the likely shape, since the new appends are the ones holding the lock and the old siblings
are what they overwrite.
(b) *False-pass trap:* verifying paths with the package's own verifier. If the package computes both
the path and the check, a consistently-wrong tree is self-consistent. Recompute the root in the test
from the leaf and the siblings, natively.
(c) *Third trap:* no barrier. See P-4.

**Trace.** §6 "The write must be serialized" · gotcha 54.

---

### ZK-TRE-002 · The advisory lock is taken before the first read — **CRITICAL**

**Aim.** `select pg_advisory_xact_lock(…)` is the **first statement** of the enrolment transaction.

**Point of failure.** Gotcha 54 names it precisely: *"Take the lock before the first read, not before
the write."* A lock acquired just before the `INSERT` is a lock acquired after `max(leaf_index)` was
read, and the read is where the race is. This is the single most likely way ZK-TRE-001 stays broken
after someone "adds the lock". The code reads as correct, the review passes, the test is
intermittent.

**Procedure.** (i) Statement-order assertion: capture the statements the enrolment transaction issues
(query hook or `pg_stat_activity` sampling) and assert `pg_advisory_xact_lock` is index 0. (ii)
Behavioural: instrument a delay between the index read and the write, then run ZK-TRE-001's 2-goroutine
case. With the lock in the right place the delay changes nothing; with it in the wrong place the delay
makes the corruption deterministic rather than rare.

**Pass.** (i) index 0; (ii) ZK-TRE-001 green even with the injected delay.

**Fail.** Lock anywhere but first, or corruption under the injected delay.

**Avoidance.**
(a) *Negative variant:* assert the lock is `_xact_` and therefore released at commit — a
`pg_advisory_lock` (session-scoped) never released deadlocks the pool on the second enrolment, which
looks like a hang, not a bug.
(b) *False-pass trap:* relying on (ii) alone without the injected delay. Without it the broken
implementation passes on most runs and the test is quarantined within a month.

**Trace.** §6 · gotchas 36, 54.

---

### ZK-TRE-003 · The advisory lock key is namespaced — **ESSENTIAL** [UNSPECIFIED]

**Aim.** The lock key does not collide with another subsystem's or another schema's.

**Point of failure.** Advisory locks are **per-database**, not per-schema. Two kal deployments sharing
one Postgres database in two schemas — a documented pattern, since all SQL is schema-prefixed — will
serialise on the same key, which is a liveness problem. Worse, a key colliding with an application's
own advisory lock produces a deadlock between two subsystems that have never heard of each other, at
a time nobody can reproduce.

**Procedure.** Assert the key is derived from a namespaced constant including the schema name (or is
the two-`int4` form with a kal-specific first word). Behaviourally: two schemas in one database, one
enrolment in each, concurrently — assert both complete and neither blocks beyond a short bound.

**Pass.** Independent progress; key includes the schema.

**Fail.** Cross-schema blocking, or a key that is a bare small integer.

**Avoidance.**
(a) *Negative variant:* two enrolments **in the same schema** must serialise. A key so unique it
differs per call serialises nothing and passes the independence test perfectly while failing
ZK-TRE-001.
(b) *False-pass trap:* testing with one schema. The collision is invisible there.

**Trace.** §6 · not settled by the handout; see §23.

---

### ZK-TRE-004 · The tree is in the database, not in memory — **CRITICAL**

**Aim.** Two processes see the same tree and publish compatible roots.

**Point of failure.** Gotcha 53: *"Two pods, two roots, no error: half the proofs in flight verify
against a root the other pod never published, and the failures look like user error."* A cache in
front of the node table has the same failure with a longer fuse. This is not detectable in a
single-process test suite, which is exactly why it ships.

**Procedure.** Two independent instances against one database — two `*ZK` values built from separate
constructors and separate connection pools, which is the in-process stand-in for two pods. Instance A
enrols member M. **Without any signal to instance B**, instance B reads the current root, builds M's
path, and verifies a proof from M. Assert it succeeds. Then B enrols member N and A verifies N.
Additionally: restart-equivalent — construct a third instance after the fact and assert it reproduces
the same root from the table alone.

**Pass.** Cross-instance verification succeeds in both directions; the fresh instance reproduces the
root.

**Fail.** Any instance holding a root the other does not, or a root that must be recomputed from a
leaf table rather than read.

**Avoidance.**
(a) *Negative variant:* assert instance B's root **changes** after A's enrolment. An implementation
that always reads the newest root and never caches passes trivially; one that caches passes the
positive direction if the cache happens to be cold.
(b) *False-pass trap:* sharing a connection pool between the two instances. Then they share a
transaction-visibility story they will not share in production. Separate pools.

**Trace.** §6 · gotcha 53.

---

### ZK-TRE-005 · Revocation clears the leaf and sets `revoked_at` in one transaction — **CRITICAL**

**Aim.** A revoked credential's leaf is `zeros[0]` and the flag is set, atomically.

**Point of failure.** Handout §6: *"In two transactions they disagree under concurrency, and the tree
is the one that authenticates: a credential flagged revoked whose leaf is still in the tree still
proves membership, and the flag is a comment."* The operational shape is worse than the concurrency
shape — the flag is what an operator reads to confirm the revocation worked, and it will say
`revoked_at = <timestamp>` while the member keeps logging in.

**Procedure.** (i) Happy path: enrol M, revoke M, assert in one read that `revoked_at` is non-null
**and** the leaf node at M's index equals `zeros[0]` **and** a new root was published. (ii)
Atomicity: inject a failure between the two writes (a hook, or a constraint violation on the second)
and assert **neither** landed — `revoked_at` null and the leaf unchanged — and no root published.
(iii) Assert `ZK-TRE-006` follows: M can no longer prove.

**Pass.** All three.

**Fail.** (ii) leaving a half-state in either direction. The dangerous half is `revoked_at` set with
the leaf intact.

**Avoidance.**
(a) *Negative variant:* a non-revoked member's leaf is untouched by the revocation of another. A
revocation that clears the wrong index passes (i) and (ii) and silently removes a bystander.
(b) *False-pass trap:* asserting `revoked_at` and calling it done. That is the exact comment-not-
constraint failure the case exists for. Assert the **node hash**.

**Trace.** §6 "Revocation is a leaf set back to `zeros[0]`" · gotcha 55.

---

### ZK-TRE-006 · A revoked credential does not authenticate — **CRITICAL**

**Aim.** After revocation, a proof from that credential against the current root yields nothing.

**Procedure.** `TestDBZKRevokedCredential`. Enrol M; confirm M can log in. Revoke M. Issue a fresh
challenge. Have M build a proof against the **current** root, using the current path — which now
resolves M's slot to `zeros[0]`, so M cannot construct a verifying path at all, and against the stale
path the root check fails. Submit both variants. Assert **no session row was created** and, if M had
a pseudonymous account from before, that no new session is attached to it.

**Pass.** Neither variant produces a session.

**Fail.** Either produces one.

**Avoidance.**
(a) *Negative variant:* a second, non-revoked member logs in successfully in the same test, after the
revocation. Without it, a revocation that corrupts the whole tree passes.
(b) *False-pass trap:* testing only the stale-path variant. It fails on the root check and tells you
nothing about whether the leaf was actually cleared. The current-path variant is the one that tests
§6.
(c) *Third trap:* asserting on an error code. Assert on the **absence of the session row** — the
existing sessions of a revoked member are a separate control (`auth_sessions.revoked_at`), and this
case must not accidentally pass because the login errored for an unrelated reason.

**Trace.** §6 · §7 · gotcha 55.

---

### ZK-TRE-007 · `RootGrace` defaults to 0 — **CRITICAL**

**Aim.** The zero `Config` accepts only the current root.

**Point of failure.** `CLAUDE.md`: *"The zero `Config` is the production posture."* A non-zero default
means every deployment that never heard of `RootGrace` has a revocation window it did not choose, and
handout §6 is explicit that this is *"the revocation-latency dial"*, not a cache. A default of "any
root ever published" means a removed member proves membership forever — with a valid proof, a correct
circuit, and a `revoked_at` timestamp in the table saying otherwise.

**Procedure.** (i) Construct a zero `Config` and assert `RootGrace == 0`, by value. (ii) Behavioural:
zero config, enrol A then B (producing R₁ then R₂), have A prove against R₁ — assert rejected. (iii)
Set `RootGrace` to admit one prior root, repeat — assert accepted. (iv) Assert there is no environment
variable, build tag or `Dev` bool that changes it.

**Pass.** All four.

**Fail.** Any non-zero default, or any environment-driven relaxation.

**Avoidance.**
(a) *Negative variant:* (iii). Without it, a `RootGrace` that is ignored entirely passes (i) and (ii).
(b) *False-pass trap:* asserting the struct field is `0` without asserting the *behaviour* at 0. A
field read as `if cfg.RootGrace == 0 { acceptAny() }` — an entirely plausible inversion, since 0 often
means "unset" in Go config — is the catastrophic reading, and it passes (i).

**Trace.** §6 `RootGrace` · `CLAUDE.md` zero-Config invariant · gotcha 55.

---

### ZK-TRE-008 · The grace window closes — **ESSENTIAL**

**Aim.** With `RootGrace > 0`, the accepted set is exactly the intended one and it shrinks as roots
are published.

**Point of failure.** A grace implemented as "any root in `auth_zk_roots` without `retired_at`" is not
a window, it is permanence with a manual step. A grace implemented as a count is a window whose size
depends on enrolment rate; as a duration, one whose size depends on wall clock. Whichever it is, the
member revoked inside the window still authenticates, and that is the documented cost — but only for
the window's length.

**Procedure.** `RootGrace` set to admit exactly one prior root. Publish R₁, R₂, R₃ by enrolling.
Assert: a proof against R₃ accepted; against R₂ accepted; against R₁ **rejected**. Then revoke M,
publish R₄, and assert M's proof against R₃ is accepted (the documented latency) and against R₄
impossible; publish R₅ and assert M's R₃ proof is now rejected.

**Pass.** The window is exactly the configured width and moves.

**Fail.** R₁ accepted, or M's proof still accepted after R₅.

**Avoidance.**
(a) *Negative variant:* the "accepted inside the window" half, which documents the latency as a
property rather than leaving it as a surprise.
(b) *False-pass trap:* describing this control as a cache in the doc comment. Handout §6: *"it must
not be described as a cache."* A reviewer who reads "cache" tunes it for performance.

**Trace.** §6 · gotcha 55.

---

### ZK-TRE-009 · Sparse zero-hashes resolve absent nodes — **ESSENTIAL**

**Aim.** A path through empty subtrees is correct, so members enrolled next to empty space can prove.

**Point of failure.** A 2^32-leaf tree exists only because an absent node *is* `zeros[level]`. Get the
level indexing off by one and paths are wrong for exactly the members whose siblings are empty — which
is nearly all of them in a small deployment, and a shrinking, unpredictable subset as the tree fills.
The failure migrates as enrolment proceeds.

**Procedure.** (i) A tree with one leaf at index 0: assert its path is `zeros[0..31]` above the leaf
and that it verifies against the published root. (ii) One leaf at index `2^32 − 1`. (iii) Two leaves
at indices 0 and `2^32 − 1`: assert both paths verify against one root. (iv) An empty tree: assert the
root equals `zeros[32]`. (v) Assert a missing `auth_zk_nodes` row at level L is answered by
`zeros[L]` and not by `0` or an error.

**Pass.** All five, with roots recomputed independently in the test.

**Fail.** Any path failing, or a missing row producing `0`.

**Avoidance.**
(a) *Negative variant:* (iv) plus the assertion that **no proof verifies against `zeros[32]`** —
family 15 of ZK-CIR-004. An empty tree with a valid-looking root is the worst case.
(b) *False-pass trap:* filling the tree densely in the fixture. Dense trees never exercise the sparse
path, and a real deployment at 12 members is entirely sparse.

**Trace.** §6 "Sparse, over 33 precomputed zero-hashes".

---

### ZK-TRE-010 · `zeros[0]` is domain-tagged, not `0` — **CRITICAL**

**Aim.** The empty-leaf constant has no findable preimage under the leaf domain.

**Point of failure.** Handout §6: an empty leaf of `0` is a leaf whose preimage is whatever
`(Secret, Attribute)` pair hashes to zero, *"and the tree cannot tell the difference between 'nobody
is here' and 'somebody is here whose commitment happens to be the empty value'."* With 4.3 billion
empty slots, one such pair authenticates everywhere in the tree, forever, immune to revocation
because revocation sets slots **to** that value. Its own domain tag makes finding the pair a MiMC
collision rather than a search.

**Procedure.** (i) Assert `zeros[0] == MiMC(DOM_EMPTY)` and `zeros[0] != 0`. (ii) Assert `DOM_EMPTY`
differs from `DOM_LEAF` (also covered by ZK-CIR-009). (iii) Behavioural: construct a witness whose
`Path[0]` is `zeros[0]` and whose `Secret`/`Attribute` are anything — assert the circuit rejects,
because line 3 binds `leaf == Path[0]` and no known preimage exists. (iv) Assert the revocation path
writes `zeros[0]`, not `0` — read the node row after ZK-TRE-005.

**Pass.** All four.

**Fail.** `zeros[0] == 0`, or a revoked slot holding `0`.

**Avoidance.**
(a) *Negative variant:* a genuine leaf at the same index verifies before revocation. Otherwise a tree
that rejects everything passes (iii).
(b) *False-pass trap:* asserting `zeros[0] != 0` only. The tag can be distinct and still equal
`DOM_LEAF`, which is gotcha 44's collision from the other direction.

**Trace.** §6 · gotchas 44, 52.

---

### ZK-TRE-011 · Append and revoke are atomic across all 33 writes — **ESSENTIAL**

**Aim.** A mutation writes the leaf, 32 node upserts and one root, or none of them.

**Point of failure.** A partial path write is a tree that is internally inconsistent at one level: the
leaf is present, the root is old, and the intermediate hashes disagree. Every proof for every member
whose path crosses the broken level fails, and the set of affected members is a subtree — a
contiguous, arbitrary-looking slice of the user base.

**Procedure.** Inject a failure at each of: after the leaf insert, after upsert 1, after upsert 16,
after upsert 32, before the root insert. For each, assert afterwards that (i) no new leaf row exists,
(ii) no node row changed, (iii) no new root exists, and (iv) an unrelated member's proof still
verifies against the unchanged root. Then assert a successful mutation writes exactly 32 node rows'
worth of upserts and exactly one root.

**Pass.** Every injection leaves the tree byte-identical to before.

**Fail.** Any residue.

**Avoidance.**
(a) *Negative variant:* the successful mutation's counts. Without them, a transaction that rolls back
unconditionally passes every injection.
(b) *False-pass trap:* injecting only at the last step. The dangerous residue is early — a leaf row
with no path — and it is the one an `INSERT`-first implementation produces.

**Trace.** §6 · gotcha 54.

---

### ZK-TRE-012 · A reused leaf index does not resurrect a credential — **ESSENTIAL** [UNSPECIFIED]

**Aim.** Whether indices are reused after revocation is a decision, and whichever it is, a revoked
commitment cannot return.

**Point of failure.** If `max(leaf_index)` is computed as a count rather than a maximum — or if a
revoked slot is treated as free — the next enrolment lands on a revoked index. Two consequences: the
revoked member's `auth_zk_credentials` row still holds `leaf_index` pointing at somebody else's leaf,
so a later revocation of the *new* member clears the wrong understanding of who was removed; and an
audit that reads `issued_to` by index attributes the leaf to the wrong person.

**Procedure.** Enrol A (index 0), B (index 1). Revoke A. Enrol C. Assert C's index is 2, not 0.
Revoke C, enrol D, assert index 3. Assert `auth_zk_credentials.leaf_index` remains unique across
revoked and live rows. Then: revoke B and re-enrol B's *same commitment* — assert either it is refused
(the `unique` index on `commitment` fires) or it lands on a new index and the old slot stays
`zeros[0]`.

**Pass.** Indices are monotonic; no revoked commitment returns to the tree.

**Fail.** Index reuse, or a revoked commitment landing back in the tree at any index.

**Avoidance.**
(a) *Negative variant:* assert D can actually prove at index 3 — a monotonic counter that outruns the
node table produces indices nothing verifies against.
(b) *False-pass trap:* testing with no revocations. Monotonicity is trivially true then.

**Trace.** §6 · §9 `auth_zk_credentials` · not settled by the handout; see §23.

---

### ZK-TRE-013 · `MerkleDepth` is a package constant — **ESSENTIAL**

**Aim.** Depth is fixed at compile time and unreachable from `Config`.

**Point of failure.** Handout §2: *"a configurable depth is a different circuit, a different R1CS, a
different setup and a different verifying key. Making it a field would let a consumer change it and
get a verifying key that silently no longer matches the circuit."* The symptom is universal proof
rejection after a config change nobody connects to it, or — if the vk is regenerated — a working
system whose stored tree is at the old depth and whose paths are one level short.

**Procedure.** Reflect over `Config` and assert no depth field. Assert `MerkleDepth` is a `const`
equal to 32. Assert `len(Path) == 33` in the circuit type. Assert no environment variable or build tag
influences it.

**Pass.** Constant, 32, `Path` of 33, no config surface.

**Fail.** Any settable depth.

**Avoidance.**
(a) *Negative variant:* assert the constant is actually *used* — a hard-coded 32 elsewhere in the path
walk while `MerkleDepth` sits unread is the same bug with a decoy.
(b) *False-pass trap:* checking only `Config`. A package-level `var` is settable from another package
in the same module and from a test, which is how it gets "temporarily" changed.

**Trace.** §0 · §2 "No loops" · §6.

---

### ZK-TRE-014 · Duplicate commitments are refused — **GOOD-TO-HAVE**

**Aim.** `auth_zk_credentials.commitment unique` is enforced and produces a classified error.

**Procedure.** Enrol a commitment; enrol it again; assert the second fails, that the classification
goes through `luimaerr.SQLState` and not a type assertion on `pg.Error`, and that no partial tree
mutation landed.

**Pass.** Refused, classified, tree unchanged.

**Fail.** A second leaf, or a `*pgconn.PgError` type assertion in the path (`CLAUDE.md`: `pg.Error` is
an interface, not pgx's concrete type — the assertion compiles and never matches).

**Avoidance.** (a) Assert a *different* commitment still enrols after the failure — a poisoned
transaction that refuses everything passes. (b) Do not assert on the error string; assert on the
SQLSTATE classification.

**Trace.** §9 · `CLAUDE.md` SQL invariant.

---

## 8 · Group NUL — Nullifier semantics

Handout §7 and gotcha 56: *"A nullifier that is both a pseudonym and single-use is neither."* Both
directions of that sentence are a shipped bug, and the design's own earlier draft had one of them.

### ZK-NUL-001 · A recurring nullifier logs in more than once — **CRITICAL**

The case the handout says would have caught its own earlier draft.

**Aim.** On a recurring audience the nullifier is a returning pseudonym: never consumed, always
resolving to the same account.

**Point of failure.** Burn it and the member logs in exactly once, ever. The account row created on
first sight is never read again. Every returning user is locked out permanently, with no recovery —
the secret *is* the credential and re-issuance produces a **different** nullifier and therefore a
different account, losing every row the first pseudonym owned. This is a data-loss bug wearing a
security control's clothing, and it will be discovered by users, not by the operator.

**Procedure.** `TestDBZKPseudonymRecurs`. Enrol M on a recurring claim. Log in — capture `user_id₁`
and session S1. Issue a fresh challenge, produce a fresh proof, log in again — capture `user_id₂` and
S2. Assert: `user_id₁ == user_id₂`; S1 ≠ S2 and **both are live**; exactly one `auth_users` row for
the pseudonym; exactly one `auth_zk_nullifiers` row; that row's `consumed_at` is **null** after both
logins; `first_seen_at` unchanged by the second.

**Pass.** All six.

**Fail.** `consumed_at` set; two accounts; the second login rejected.

**Avoidance.**
(a) *Negative variant:* a **third** login after a long gap, and one after S1 is revoked — the
pseudonym must survive session revocation. Two logins in a row can pass on an implementation that
caches the first result in memory.
(b) *False-pass trap:* asserting the second login "succeeded". Succeeding with a *new* `user_id` is
the failure this case is about, and it looks like success from the caller's side. Assert the
`user_id` equality and the row counts.

**Trace.** §7 "Two kinds of audience" · §10 · gotcha 56.

---

### ZK-NUL-002 · A one-shot nullifier permits exactly one action under concurrency — **CRITICAL**

**Aim.** On a one-shot audience the nullifier burns on first use and the unique index is the
enforcement.

**Point of failure.** Fail to burn and there is no limit at all — the anonymous rate limit, the
one-vote-per-member property, the whole reason the one-shot kind exists, is absent, and every proof is
valid so nothing looks wrong. Burn it non-atomically and 8 concurrent submissions all pass a `SELECT`
before any `INSERT` lands.

**Procedure.** `TestDBZKNullifierSingleUse`, P-4 barrier, 8 goroutines, one member, one one-shot
claim, 8 distinct challenges and 8 distinct valid proofs of the same statement. Assert: exactly
**one** row in `auth_zk_nullifiers` for that nullifier; exactly **one** action performed (assert the
action's own side effect — one vote row, one counter increment — not the HTTP status); the 7 failures
return the uniform `INVALID_PROOF`; `consumed_at` non-null.

**Pass.** 1 row, 1 action, 7 uniform failures.

**Fail.** Any count above 1. There is no partial credit.

**Avoidance.**
(a) *Negative variant:* 8 goroutines with 8 **different members** perform 8 actions. Without it, a
global mutex around the whole handler passes and serialises the deployment to one action at a time.
(b) *False-pass trap:* enforcing with `SELECT` then `INSERT` and testing without a barrier. Gotcha
57. The unique index must be the enforcement; assert it exists on `auth_zk_nullifiers.nullifier` and
that the code path relies on the insert conflict rather than a prior read.
(c) *Third trap:* asserting on the response and not on the side effect. Seven `INVALID_PROOF`
responses with two rows written is a pass by response and a total failure by state.

**Trace.** §7 · §10 · gotchas 36, 56, 57.

---

### ZK-NUL-003 · The primary key is the nullifier alone — **CRITICAL**

**Aim.** `auth_zk_nullifiers` is keyed on `nullifier`, not on `(nullifier, audience)`.

**Point of failure.** Handout §7 states the reasoning and it is subtle enough to be reverted by a
well-meaning reviewer: *"the audience is already inside the hash, so keying on `(nullifier, audience)`
is not stronger, it is a second chance for a caller who supplies its own audience to claim a
nullifier that is not theirs."* A composite key means the same nullifier value can hold two rows with
two different audiences — and if ZK-INP-003 ever regresses, that is the row a caller uses to attach
its proof to somebody else's pseudonym.

**Procedure.** (i) Schema assertion: the primary key of `auth_zk_nullifiers` is exactly
`(nullifier)`. (ii) Behavioural: insert a nullifier under audience X; attempt to insert the same
nullifier value under audience Y; assert it is refused by the constraint. (iii) Assert the refusal is
classified through `luimaerr.SQLState`.

**Pass.** Single-column PK; second insert refused.

**Fail.** A composite key, or two rows for one nullifier value.

**Avoidance.**
(a) *Negative variant:* two **different** nullifiers under the same audience both insert.
(b) *False-pass trap:* reading the PK from a migration file's text. Read it from the live catalog
after the migration runs — an added `alter table … add constraint` later in the file, or a second
migration, changes it.

**Trace.** §7 "The pseudonymous account" · §9.

---

### ZK-NUL-004 · Cross-audience unlinkability — **CRITICAL**

**Aim.** One secret under two audiences produces two nullifiers with no column linking them.

**Point of failure.** This is the property being sold. If two services can correlate, the pseudonym is
one pseudonym everywhere and the deployment has a global identifier that is merely opaque. The link
does not have to be cryptographic to exist — a `credential_id` column on `auth_zk_nullifiers`, a
shared `user_id` across audiences, an `issued_to` join, or an index that reveals insertion order can
all restore it.

**Procedure.** (i) Same secret, audiences X and Y: assert the two nullifiers differ and that neither
is derivable from the other without the secret. (ii) Schema: enumerate `auth_zk_nullifiers`' columns
and assert none of them, alone or joined, links the two rows — specifically no credential reference,
no leaf index, no commitment. (iii) Assert the two rows resolve to **different** `auth_users` rows
(different pseudonyms) unless the deployment deliberately shares one, and if it does, document that
as a linkage. (iv) Assert `first_seen_at` granularity does not itself link them — see ZK-DOC-004.

**Pass.** Distinct nullifiers, no linking column, distinct accounts.

**Fail.** Any column that joins the two rows.

**Avoidance.**
(a) *Negative variant:* the same secret under the **same** audience produces the **same** nullifier —
determinism, which is what makes the pseudonym return.
(b) *False-pass trap:* testing unlinkability only cryptographically. The cryptography is sound by
construction; the linkage arrives as a convenience column somebody added for an admin screen. This
case is a schema audit as much as a crypto one.

**Trace.** §7 · §1 "Against an honest-but-curious operator".

---

### ZK-NUL-005 · Recurring and one-shot rows have disjoint shapes — **ESSENTIAL**

**Aim.** A recurring row carries a `user_id` and never sets `consumed_at`; a one-shot row sets
`consumed_at` on insert and never gets a `user_id`.

**Point of failure.** A row that is both is a pseudonym that burned, or a burn that resolves to an
account — gotcha 56 in the data rather than in the code. And a one-shot row carrying a `user_id`
attaches an anonymous action to an account, which is the anonymity failing quietly in a column.

**Procedure.** After a recurring login: assert `user_id` non-null, `consumed_at` null. After a
one-shot action: assert `user_id` **null**, `consumed_at` non-null. Assert a `check` constraint (or
equivalent) enforces the disjunction, rather than leaving it to the code. Attempt to write each
forbidden shape directly and assert refusal.

**Pass.** Both shapes correct; both forbidden shapes refused by the database.

**Fail.** Either forbidden shape accepted, or the disjunction enforced only in Go.

**Avoidance.**
(a) *Negative variant:* both legal shapes must insert. A check constraint that is too strict blocks
one of the two kinds entirely.
(b) *False-pass trap:* enforcing in application code and testing through the application. Write the
forbidden shape with raw SQL — the constraint is the control, the code is a caller.

**Trace.** §7 · §9 `auth_zk_nullifiers` · gotcha 56.

---

### ZK-NUL-006 · The claim kind is constrained to two values — **ESSENTIAL**

**Aim.** `auth_zk_claims.kind` admits only `'recurring'` and `'one_shot'`.

**Point of failure.** A third value — a typo, `'Recurring'`, an empty string — falls through whatever
branch the code uses. If the code branches `if kind == "one_shot" { burn() }`, every unrecognised
value is silently recurring: a claim intended as one-vote-per-member becomes unlimited, with no error
and a policy row that reads correctly to a human skimming it.

**Procedure.** Attempt to insert `kind` values: `'Recurring'`, `'oneshot'`, `''`, `'one_shot '`
(trailing space), `null`. Assert every one is refused by the `check` constraint. Assert the Go code
handles exactly two cases and **fails closed** on anything else (defensive branch), even though the
constraint should make it unreachable.

**Pass.** All refused; the code's default branch denies.

**Fail.** Any accepted, or a Go `switch` with a permissive default.

**Avoidance.**
(a) *Negative variant:* both legal values insert.
(b) *False-pass trap:* relying on the constraint and leaving the Go default permissive. The constraint
protects the table; a claim row loaded from a pre-migration database, a fixture, or a future migration
gap reaches the Go code anyway. Handout §7's rule for `mfa` — *nil denies* — is the same failure
direction and the model to copy.

**Trace.** §7 · §9 `auth_zk_claims`.

---

### ZK-NUL-007 · An epoch in the audience gives per-epoch rate limiting — **GOOD-TO-HAVE**

**Aim.** `MiMC(DOM_AUDIENCE, deploymentID, "vote", epoch)` yields one action per member per epoch,
enforced by the database, with the server unable to say which member.

**Procedure.** Two epochs. Member M acts in epoch 1 — succeeds. M acts again in epoch 1 — refused. M
acts in epoch 2 — succeeds. Assert two distinct nullifier rows and that neither carries a `user_id`.
Assert the operator cannot join epoch-1's row to epoch-2's.

**Pass.** 1 action per epoch, 2 unlinked rows.

**Fail.** A second action inside an epoch, or a link across epochs.

**Avoidance.** (a) Assert a *different* member also acts once in epoch 1 — a per-epoch global limit is
a different, broken control that passes the single-member test. (b) Do not derive the epoch from the
request; it is server-side, or ZK-INP-003 regresses through the audience.

**Trace.** §7 "one-shot becomes anonymous rate limiting".

---

### ZK-NUL-008 · A proof does not cross deployments — **ESSENTIAL**

**Aim.** A proof valid at deployment A is not valid at deployment B.

**Point of failure.** Gotcha 59: *"A proof not bound to an audience is replayable at another endpoint
of the same deployment."* The stronger version is across deployments that share a ceremony — a vk
distributed to two installations, or a staging environment sharing production's keys. Without a
deployment identifier inside the audience, a proof harvested from staging authenticates in
production, and the trees need not even match if `Root` validation is the only difference.

**Procedure.** Two deployments, same vk, same circuit, different `deploymentID` in the audience
derivation, overlapping membership. Produce a valid proof at A. Submit it at B with a challenge issued
by B. Assert no session at B. Then: same test with `deploymentID` omitted from the derivation —
assert this case goes **red**, confirming it is testing the binding and not something else.

**Pass.** Rejected at B; the mutation makes it pass at B.

**Fail.** Accepted at B.

**Avoidance.**
(a) *Negative variant:* the mutation half. Without it this case is green on any two systems that
happen to have different trees, and it never tested the audience at all.
(b) *False-pass trap:* giving the two deployments different trees, so the proof fails on `Root`
validation. Give them identical trees, identical roots, identical members — then only the audience
distinguishes them.

**Trace.** §7 · gotcha 59.

---

### ZK-NUL-009 · A nullifier from one audience does not satisfy another claim — **ESSENTIAL**

**Aim.** Claims are scoped by audience end to end.

**Procedure.** Two claims, X and Y, two audiences. Member M proves under X. Submit the resulting
nullifier while naming claim Y (with a proof honestly built for X). Assert claim Y is not granted, the
resolver behind `@auth(proves: ["Y"])` did not run, and no row was written under Y's audience.

**Pass.** Nothing granted; resolver counter 0.

**Fail.** Y granted.

**Avoidance.** (a) M proving honestly under Y grants Y. (b) Do not assert on the error; assert the
resolver counter and the granted-claim set — the request may fail on the pairing check for reasons
that have nothing to do with claim scoping.

**Trace.** §7 · §5 · gotcha 58.

---

## 9 · Group PSD — The pseudonymous account

### ZK-PSD-001 · First sight creates one account; every later sight reuses it — **CRITICAL**

**Aim.** `Login` resolves a nullifier to an `auth_users` row, creating it exactly once.

**Point of failure.** Two accounts for one pseudonym splits a member's data in half at an arbitrary
moment. Their rows are scoped by `UserID`, so the second account sees none of the first's — the same
user experiences a silent, permanent data loss and a support ticket that reads "my stuff is gone". No
error, no log line.

**Procedure.** Log in three times with one recurring nullifier, across three fresh challenges and
three fresh proofs. Assert exactly one `auth_users` row whose email matches the pseudonym pattern, and
that all three sessions carry the same `user_id`.

**Pass.** One account, three sessions, one `user_id`.

**Fail.** More than one account.

**Avoidance.**
(a) *Negative variant:* two **different** nullifiers create two accounts.
(b) *False-pass trap:* running the three logins sequentially only. ZK-PSD-002 is the concurrent case
and it is where the bug is.

**Trace.** §7 "The pseudonymous account".

---

### ZK-PSD-002 · Concurrent first sight creates one account — **CRITICAL**

**Aim.** The unique index is what prevents two accounts, not a `SELECT` before the `INSERT`.

**Point of failure.** Gotcha 57's shape at a new table. Two concurrent first logins from the same
member — two tabs, a retried request, a double-tap — both `SELECT` and find nothing, both `INSERT`.
Without the partial unique index on `lower(email)` being the enforcement, both succeed.

**Procedure.** P-4 barrier, 8 goroutines, one nullifier, 8 distinct challenges and proofs. Assert
exactly one `auth_users` row and exactly one `auth_zk_nullifiers` row afterwards, and that all 8
sessions (or however many succeeded) carry the same `user_id`.

**Pass.** One account regardless of how many logins succeeded.

**Fail.** Two or more accounts.

**Avoidance.**
(a) *Negative variant:* at least one login must succeed. An implementation that fails all 8 on
conflict passes the count assertion and makes first login impossible under any concurrency.
(b) *False-pass trap:* asserting only the account count. If 7 of 8 fail with `INVALID_PROOF`, the
member's first login appears broken and the uniform error code hides why. Assert the success count is
8, or that the failures are retryable and documented.

**Trace.** §7 · gotcha 57.

---

### ZK-PSD-003 · The pseudonym's email is unroutable and unique — **CRITICAL**

**Aim.** `email = zk-<nullifier-hex>@invalid`, enforced unique by the existing partial index on
`lower(email)`.

**Point of failure.** Two failures. If the domain is not `.invalid` (RFC 2606 reserved, never
deliverable), the address may be registrable — and any flow that emails it, or that treats a verified
mailbox as proof of ownership, hands the account to whoever controls that mailbox. If the hex encoding
is not case-stable, `lower(email)` collapses two distinct nullifiers onto one account, merging two
members' data.

**Procedure.** (i) Assert the constructed address matches `^zk-[0-9a-f]{N}@invalid$` — lowercase hex,
fixed length. (ii) Assert two nullifiers differing only in the case of their hex rendering are
impossible (the encoder emits one case). (iii) Assert an attempt to register a normal account with
that exact address is refused by the existing partial unique index. (iv) Assert the domain is
literally `invalid`.

**Pass.** All four.

**Fail.** A mixed-case encoding, a routable domain, or a normal registration taking the address.

**Avoidance.**
(a) *Negative variant:* (iii)'s inverse — a pseudonym login **after** somebody has taken a
colliding address must not attach to that account. Assert the login fails rather than adopting the
existing row.
(b) *False-pass trap:* asserting the format string in the source. Assert the value in the database
row after a real login.

**Trace.** §7 · RFC 2606.

---

### ZK-PSD-004 · A pseudonym has no password and no verified mailbox — **CRITICAL**

**Aim.** `password_hash` is null and `email_verified` is false, so every flow requiring either denies.

**Point of failure.** Handout §7: *"Any flow requiring either denies, which is correct: a pseudonym
has no mailbox and no password."* The failure is the reverse: a null `password_hash` compared with a
supplied password by a comparison that treats null as empty, or an Argon2id verify against a
zero-value hash that errors and is then swallowed into a `true`. Then anybody logs into any pseudonym
account by name, and the name is derivable from a public nullifier.

**Procedure.** Create a pseudonym account by logging in. Then attempt, against that account:
password login with an empty password; with a random password; with the literal empty string as the
hash; password reset request; email verification request; invite acceptance; MFA enrolment via the
password path. Assert **every one denies** and, specifically, that no session is issued and no
`auth_tokens` row is created for the reset or verification attempts.

**Pass.** All deny, nothing written.

**Fail.** Any path issuing a session or writing a token row.

**Avoidance.**
(a) *Negative variant:* the same attempts against a normal account behave normally — otherwise a
globally broken auth path passes.
(b) *False-pass trap:* asserting the login "failed". A reset request that returns a uniform success
message (as it should, to avoid enumeration) has "failed" from the caller's view while writing a
token row. Assert the **rows**.
(c) *Third trap:* forgetting the token-issuing paths entirely. Reset and verification are the ones
that create a usable credential for an address the attacker may be able to reason about.

**Trace.** §7 · `authn` existing controls.

---

### ZK-PSD-005 · `Principal` gains no field and `Scope` needs no branch — **ESSENTIAL**

**Aim.** The pseudonym's `UserID` is a real uuid, so ownership scoping, RLS and role checks behave
normally with no zk-specific path.

**Point of failure.** A `Principal.IsPseudonym` bool is a branch, and every branch in an authorization
type is a place where one of the two sides was not updated. Handout §7 is explicit that the design
avoids this; a test pins it so the next feature does not add it quietly.

**Procedure.** Reflect over `authz.Principal` and assert its field set is unchanged from the
pre-zk baseline (pinned list). Assert `Scope`'s implementation has no zk-specific branch. Assert a
pseudonym principal's `UserID` parses as a uuid. Behaviourally: a pseudonym and a normal user both
scoped by the same `Scope` call return their own rows.

**Pass.** No new field, no branch, uuid parses, both scope identically.

**Fail.** A new field or a zk branch in `Scope`.

**Avoidance.**
(a) *Negative variant:* the pseudonym must actually get **its own** rows — a `Scope` that returns
nothing for pseudonyms passes a structural check and breaks the product.
(b) *False-pass trap:* pinning the field count. A renamed field keeps the count.

**Trace.** §7 · `authz/principal.go`.

---

### ZK-PSD-006 · Re-issuance produces a new pseudonym, and that is documented — **ESSENTIAL**

**Aim.** The consequence of revoke-and-reissue is stated: a new secret is a new nullifier is a new
account.

**Point of failure.** Handout §12: *"For `Membership` there is nothing to recover — the secret is the
credential — so the operator revokes the leaf and issues a new one."* What §12 does not say out loud
is that the reissued member arrives as a **different pseudonym** and loses every row the old one
owned. An operator performing a routine credential rotation destroys user data and finds out from the
user. This must be a test and a README paragraph, because it cannot be a fix — fixing it means linking
the two pseudonyms, which is the property being sold.

**Procedure.** Member M logs in, creates a row. Revoke M's credential; issue a new one. M logs in with
the new secret. Assert: a **different** `user_id`; the original row is still owned by the old
`user_id`; `Scope` for the new principal does not return it. Assert the README and `SECURITY.md`
state this.

**Pass.** New pseudonym, old data inaccessible, documented.

**Fail.** The behaviour is as described but undocumented — that is the finding.

**Avoidance.**
(a) *Negative variant:* the old secret no longer works (ZK-TRE-006), so the two accounts are not both
live.
(b) *False-pass trap:* treating this as a bug and linking the accounts via `issued_to`. That join is
exactly the operator-side link the design permits for revocation and must not become an
authentication path. If a deployment wants continuity it is an explicit, documented merge, not an
implicit one.

**Trace.** §12 "Recovery" · §1 `issued_to`.

---

## 10 · Group SES — Session issuance and privacy

Adversary T3 throughout. The cryptography can be intact and the anonymity gone, with nothing in the
schema marked wrong.

### ZK-SES-001 · A zk session carries no metadata — **CRITICAL**

**Aim.** `ZK.Login` calls `Sessions.Issue` with a zero `session.Meta`, so `auth_sessions.ip` and
`user_agent` are empty for zk sessions.

**Point of failure.** Gotcha 62 and handout §1: *"One `JOIN` and the operator holds pseudonym ↔ IP ↔
hour of day, which is most of an identity."* The path is `auth_zk_nullifiers.user_id → auth_users.id
→ auth_sessions.user_id`, and the session row carries the address the proof arrived from. Every
constraint in every circuit holds. The anonymity set collapses to one, and the only artifact is two
populated columns that look exactly like every other session row in the table.

**Procedure.** `TestDBZKLogin`. Perform a zk login through the full HTTP path with a request that
carries a real `X-Forwarded-For`/`RemoteAddr` and a real `User-Agent`. Read the resulting
`auth_sessions` row and assert `ip` and `user_agent` are **empty or null**. Then run the join —
`auth_zk_nullifiers` → `auth_users` → `auth_sessions` — and assert it yields no address for any zk
session.

**Pass.** Both columns empty; the join returns nothing identifying.

**Fail.** Either column populated.

**Avoidance.**
(a) *Negative variant:* a **password** login in the same test populates both columns. Without it, a
change that broke `session.Meta` for everything passes this case while removing a control the rest of
the product depends on.
(b) *False-pass trap:* running the login through a test helper that constructs the request without
headers. Then the columns are empty because there was nothing to write, and the test passes on an
implementation that faithfully copies whatever it is given. The request **must** carry an address and
a user agent.
(c) *Third trap:* asserting the `Meta` value passed to `Issue` rather than the row. Assert the row —
`Issue` may populate from the context independently.

**Trace.** §7 "The session carries no metadata" · §1 · gotcha 62.

---

### ZK-SES-002 · Metadata suppression is not configurable — **CRITICAL**

**Aim.** There is no field, flag or environment variable that turns session metadata back on for zk
logins.

**Point of failure.** Handout §7: *"Not a knob, because the pseudonym's entire value is that the
operator cannot join it to a person."* A knob is a knob somebody turns for a debugging session and
leaves on. And per `CLAUDE.md`, *"there is no `Dev` bool and no environment flag that relaxes a
security property"* — this is that invariant with a specific target.

**Procedure.** Reflect over `Config` and over the zk package's exported surface: assert no field whose
name or type could reintroduce metadata (`Meta`, `SessionMeta`, `RecordIP`, `AuditSessions`, a
`func(*http.Request) session.Meta` hook). Assert no environment variable is read anywhere in
`zkauthn`/`zkauthz`. Assert `ZK.Login`'s signature takes no `session.Meta`.

**Pass.** No such surface exists.

**Fail.** Any parameter, field or env read that could populate it.

**Avoidance.**
(a) *Negative variant:* assert the *non-zk* session paths still accept meta normally. A change that
removed `Meta` from `session.Issue` altogether passes this case and breaks the audit trail everywhere
else.
(b) *False-pass trap:* grepping for `Meta` only. A hook typed as `func(context.Context) any` and
documented as "for tracing" is the same hole with a different name. Reflect over the config's
function-typed fields specifically.

**Trace.** §7 · `CLAUDE.md` zero-Config invariant · gotcha 62.

---

### ZK-SES-003 · No zk artifact reaches a log — **ESSENTIAL**

**Aim.** Proofs, nullifiers, roots, challenges and secrets do not appear in log output.

**Point of failure.** A logged nullifier is a pseudonym in a system with a different retention policy
and a different access-control story than the database — usually a broader one. A logged proof is a
credential in the log if ZK-CHL-001 ever regresses. A logged challenge lets a log reader race a
victim's submission. And logs are the artifact most often shipped to a third party.

**Procedure.** Capture all log output across: challenge issuance, a successful login, a failed login,
a malformed request, a revoked-credential login, and an enrolment. Assert the nullifier hex, the proof
bytes, the challenge bytes, the secret bytes and the root hex appear in **no** line, in raw, hex or
base64 form. Assert error `Internal` fields, if logged, are likewise clean.

**Pass.** No occurrences.

**Fail.** Any occurrence, including in a debug-level line — debug level is on in staging, and staging
has real users often enough.

**Avoidance.**
(a) *Negative variant:* assert something **is** logged for a failed login — a bare `INVALID_PROOF`
with a request id. A system that logs nothing passes and is unoperable.
(b) *False-pass trap:* searching for the raw byte slice. Logs format; search for hex and base64.

**Trace.** §1 · §5 · gotcha 62's family.

---

### ZK-SES-004 · `mfa_at` is set only by a verified `Knowledge` proof — **CRITICAL**

**Aim.** The step-up column has exactly one writer.

**Point of failure.** `authz/directive.go:102` documents a seam that has never been filled;
`@auth(mfa: true)` currently always denies. The moment it starts meaning something, every other path
that can touch `auth_sessions` becomes a candidate writer. A session-refresh statement that
`UPDATE`s the row with a struct containing a zero-value `mfa_at` clears it (annoying); one that copies
a non-zero value forward across a re-authentication grants it (a bypass).

**Procedure.** (i) Enumerate every `UPDATE` against `auth_sessions` in the module and assert only the
`Knowledge` verification path assigns `mfa_at`. (ii) Behavioural: set `mfa_at` via a proof; then
exercise session refresh, session lookup, cookie rotation and revocation, and assert `mfa_at` is
neither cleared nor propagated to a different session. (iii) Assert a failed proof does not set it.
(iv) Assert `@auth(mfa: true)` denies before and allows after, with the resolver counter.

**Pass.** One writer; the value is stable across unrelated session operations; the directive flips.

**Fail.** Any second writer, or a value that survives into a session that did not prove.

**Avoidance.**
(a) *Negative variant:* (iv)'s "denies before" half, which is what a directive change that always
allows fails.
(b) *False-pass trap:* testing the directive with a single session. The propagation bug needs two
sessions for one user — see ZK-CHL-004.

**Trace.** §4a · `authz/directive.go:102`.

---

### ZK-SES-005 · A zk session is an ordinary session — **ESSENTIAL**

**Aim.** Revocation, expiry, cookie attributes and lookup work identically for a zk-issued session.

**Point of failure.** Handout §7's whole argument for the integration seam is *"revocation stays
`auth_sessions.revoked_at`; per-request cost is zero … `@auth` works unchanged."* If a zk session is
issued by a different code path, it can miss a control the normal path applies — most likely the
cookie flags, which are set at one call site and are easy to reimplement wrongly.

**Procedure.** Assert a zk session's cookie has the same `Secure`, `HttpOnly`, `SameSite`, `Path` and
name as a password session's — compare the two `http.Cookie` values field by field, excluding the
value. Assert `session.Revoke` on a zk session denies subsequent requests. Assert expiry applies.
Assert `SetCookie` and `NewToken`/`HashToken` are the reused functions, not reimplementations.

**Pass.** Identical attributes; revocation and expiry work.

**Fail.** Any attribute differing, or a second token implementation.

**Avoidance.**
(a) *Negative variant:* the session must actually authenticate a subsequent request. Identical flags
on a cookie nothing accepts is a pass with no product.
(b) *False-pass trap:* comparing cookie strings. Compare parsed attributes; ordering and formatting
differ harmlessly and will mask a real difference behind a diff nobody reads.

**Trace.** §7 · `CLAUDE.md` reuse invariant.

---

### ZK-SES-006 · Session fixation on the zk path — **ESSENTIAL**

**Aim.** A zk login issues a fresh session and does not elevate a pre-existing one.

**Point of failure.** If `Login` upgrades the session already on the request context rather than
issuing a new one, an attacker who plants a known session cookie in a victim's browser holds a live
session for the victim's pseudonym the moment the victim authenticates. This is the classic fixation
shape and the anonymous case makes it worse: the attacker gains a pseudonym that nothing links back
to them.

**Procedure.** Make a zk login request carrying a pre-existing session cookie for an unrelated
account. Assert: a **new** session row is created; the response sets a **new** cookie value; the
pre-existing session's `user_id` is unchanged and it is not attached to the pseudonym. Repeat with a
pre-existing *anonymous* request and with a forged cookie value.

**Pass.** New session every time; the old one untouched.

**Fail.** The incoming session id reused or elevated.

**Avoidance.**
(a) *Negative variant:* the new session works for a subsequent request.
(b) *False-pass trap:* asserting the cookie value changed. A rotated token on the same row is still
fixation if the row's `user_id` was rewritten. Assert the **row id**.

**Trace.** §7 · `session` existing controls.

---

### ZK-SES-007 · `issued_to` is the operator's map and nothing more — **ESSENTIAL**

**Aim.** `auth_zk_credentials.issued_to` links a leaf to a person for revocation, and is never
consulted during verification.

**Point of failure.** Handout §1: *"It does not weaken a proof — the proof reveals no leaf — but it
means the operator knows who is a member, only not who acted."* The failure is a verification path
that reads it: any join from a proof to `issued_to` reconstructs *which* member acted, which is the
one property the design sells against T3. It is also the natural thing to add when somebody wants
"which user is this proof from" in an admin view.

**Procedure.** (i) Assert the verification path issues no query touching `auth_zk_credentials.issued_to`
— instrument the query log for a full login and assert the column is absent. (ii) Assert the column
is nullable and that a null value does not break enrolment, proof or revocation-by-leaf-index. (iii)
Assert `SECURITY.md` documents the operator-side map.

**Pass.** No read on the hot path; null tolerated; documented.

**Fail.** Any join from a proof to a person.

**Avoidance.**
(a) *Negative variant:* revocation **by user** must work when `issued_to` is populated — that is the
column's entire purpose, and a change that removed it would pass (i) perfectly.
(b) *False-pass trap:* grepping for the column name. It can arrive through a `select *` into a struct
that a later log line renders. Instrument the queries and check the rendered output.

**Trace.** §1 · §9.

---

### ZK-SES-008 · The `Root` a client names does not fingerprint it — **GOOD-TO-HAVE**

An audit finding not raised by the handout.

**Aim.** The anonymity cost of client-chosen roots is measured and documented.

**Point of failure.** The client must say which root it built against (§5), so the root is a value the
prover discloses. Roots change on every enrolment and revocation. A proof against root R_k therefore
narrows the prover to members enrolled before R_k, and with `RootGrace > 0` a client that lags
discloses roughly *when* it last synced. In a deployment with a low enrolment rate and a member who
proves rarely, the root plus the timestamp can approach a unique identifier — the cryptography is
untouched and the anonymity set is smaller than the member count, which is the number `SECURITY.md`
promises.

**Procedure.** Analytical, recorded as a finding: for a deployment with enrolment rate λ and
`RootGrace` G, compute the expected anonymity set of a proof against a given root and compare it to
the non-revoked leaf count. Assert `SECURITY.md` states that the anonymity set is the intersection of
"non-revoked leaves" and "leaves present at the named root", not the former alone.

**Pass.** The document states the intersection.

**Fail.** The document claims the anonymity set is the non-revoked leaf count.

**Avoidance.**
(a) *Negative variant:* confirm the effect is real by checking that clients do **not** all name the
newest root — if the implementation forces the newest root, the effect collapses and that is worth
recording as the mitigation.
(b) *False-pass trap:* treating this as a bug to fix. Hiding the root is not possible without hiding
which tree was proven. It is a disclosure to document, and §22 is where it lives.

**Trace.** §1 anonymity set · §5 `Root` · §6 `RootGrace`.

---

### ZK-SES-009 · Threshold disclosure narrows the attribute — **GOOD-TO-HAVE**

**Aim.** The privacy cost of multiple thresholds on one attribute is documented.

**Point of failure.** `Threshold` is public and per-claim. A deployment with `age_over_18`,
`age_over_21` and `age_over_65` learns, for any member that proves all three or fails one, a bracket
rather than a bit. Handout §7 already establishes that all claims are thresholds on **one** quantity,
so the brackets compose. Nothing is broken; the deployment simply learns more than "is a member".

**Procedure.** Assert `SECURITY.md` states that each distinct threshold proven or refused discloses
one bit about the attribute, and that N claims over one attribute disclose up to N bits.

**Pass.** Documented.

**Fail.** Absent.

**Avoidance.** (a) Check that the claims table's own contents are not exposed to unauthenticated
callers (see ZK-ORC-006) — otherwise an attacker learns the bracket structure for free. (b) Do not
"fix" this by hiding thresholds from the schema; they are policy and must be reviewable.

**Trace.** §7 · §1 · §12.

---

## 11 · Group AUZ — The authorization seam

### ZK-AUZ-001 · `Scope` denies on an empty `UserID` — **CRITICAL**

**Aim.** `authz.Scope` returns a predicate matching nothing when the principal's `UserID` is empty.

**Point of failure.** Handout §7 spells out the current behaviour: `authz/scope.go:48` branches on
principal-absent → `q.Where("false")`, otherwise `q.Where("? = ?", pg.Ident(column), p.UserID)`. An
empty `UserID` therefore scopes on `owner_id = ''` — **a live match against any `text` owner column**,
and an invalid-input error against a `uuid` one. Neither is the "predicate matching nothing" the
function's own doc comment promises. On a `text` column this is a mass data exposure and a mass
deletion: every row whose owner column is the empty string, and in many schemas that is every row
created before a nullable column was backfilled.

`Principal.UserID` is *"never empty for an authenticated principal"* (`authz/principal.go:23`) — a
**comment, not a constraint**. The pseudonymous account means kal never constructs such a principal;
a consumer constructing one directly does.

**Procedure.** Per `CONTRIBUTING.md`, the test reads as the thing that goes wrong.
1. Seed a table with a `text` owner column containing rows owned by `''`, by `'a'`, and by a real
   uuid. Build a `Principal` with an empty `UserID`. Run a `DELETE` scoped by `Scope`. **Assert every
   row is still in the table** — count before, count after, and assert the `''`-owned row
   specifically is present.
2. Same with a `SELECT`: assert zero rows returned, not "the empty-owner rows".
3. Same against a `uuid` owner column: assert no error is surfaced to the caller that reveals the
   predicate, and no rows are affected.
4. Principal absent: unchanged behaviour, rows still present.
5. A real principal: exactly its own rows, and the other rows still present after a scoped delete.

**Pass.** 1–4 affect nothing; 5 affects exactly the principal's own rows.

**Fail.** Any row removed or returned in 1–3.

**Avoidance.**
(a) *Negative variant:* case 5 is mandatory. `q.Where("false")` unconditionally passes 1–4 and breaks
every scoped query in the product.
(b) *False-pass trap, the specific one:* testing only against a `uuid` column. There, the empty string
raises an invalid-input error, the delete fails, the rows survive, and the test is green — on an
implementation with no fix at all. The `text` column case is the one that fails, and it is the one a
first draft omits because uuid owner columns are what kal's own fixtures use.
(c) *Third trap:* asserting `Scope` "returned false". The rule is the row is still in the table.

**Trace.** §7 "Harden `Scope` anyway" · `authz/scope.go:48` · `authz/principal.go:23` ·
`CONTRIBUTING.md`.

---

### ZK-AUZ-002 · A nil `Proofs` implementation denies — **CRITICAL**

**Aim.** `DirectiveOptions.Proofs` unset means every `@auth(proves: …)` field denies.

**Point of failure.** Fail-open is the failure direction that produces no error. A `nil` func that is
skipped — `if opts.Proofs != nil { … }` with no `else` — makes every proof-gated field public, and
the schema still reads `@auth(proves: ["age_over_18"])` to anyone reviewing it. Handout §7: *"Nil
denies, exactly as `mfa` does today — same failure direction, same reasoning."* The `mfa` block at
`authz/directive.go:137` is the model.

**Procedure.** (i) Configure the directive with `Proofs: nil`. Query a field annotated
`@auth(proves: ["x"])` as a fully authenticated principal. Assert the field resolves to an error and
**the resolver did not run** — resolver counter zero. (ii) Repeat with a `Proofs` func that returns
nil (grants) and assert the resolver runs — the control. (iii) Assert `AssertDirectivesWired` reports
the nil `Proofs`, per handout §7: *"`AssertDirectivesWired` already names a nil implementation without
being taught to"* — verify that claim rather than assuming it.

**Pass.** (i) denies with counter 0; (ii) resolves; (iii) named.

**Fail.** (i) resolving, or `AssertDirectivesWired` silent.

**Avoidance.**
(a) *Negative variant:* (ii). Without it a directive that always denies passes.
(b) *False-pass trap:* asserting the GraphQL response contains an error. gqlgen returns partial data
with errors; a field can error *after* the resolver ran and did work. Assert the counter.

**Trace.** §7 · `authz/directive.go:137` · `AssertDirectivesWired`.

---

### ZK-AUZ-003 · `proves:` is the last schema argument and the last Go parameter — **CRITICAL**

**Aim.** The directive's Go signature matches its SDL declaration order.

**Point of failure.** Gotcha 20, restated by handout §7: *"a schema argument becomes a trailing
positional Go parameter in declaration order, so reordering silently changes the signature."* Insert
`proves` before `mfa` in the SDL and the generated call passes the claims list where the mfa bool was
expected and vice versa — types may even line up if both are optional pointers. The result is an
`mfa: true` field gated on a claims list and a `proves:` field gated on a boolean, both compiling,
both running, neither doing what the schema says.

**Procedure.** (i) Assert `DirectiveSDL` ends with `proves: [String!]` after every existing argument.
(ii) Assert the Go directive function's trailing parameters are, in order, the existing ones followed
by `[]string`. (iii) Behavioural: a field with `@auth(mfa: true, proves: ["x"])` and a field with
`@auth(proves: ["x"], mfa: true)` must behave **identically** — that is the assertion that catches a
positional mismatch, because SDL argument order at the *call site* is free while declaration order is
not. (iv) Assert a field with only `mfa: true` is unaffected by the addition.

**Pass.** All four.

**Fail.** Any behavioural difference between the two orderings in (iii).

**Avoidance.**
(a) *Negative variant:* (iv). A change that broke `mfa` entirely passes (i)–(iii).
(b) *False-pass trap:* testing declaration order by reading the SDL string. That is the input, not the
outcome. (iii) is the test; the rest is documentation.

**Trace.** §7 · gotcha 20.

---

### ZK-AUZ-004 · `AssertAuthCoverage` still demands annotation on zk-gated fields — **CRITICAL**

**Aim.** There is no separate `@zkAuth` directive, so proof-gated fields remain ordinary annotated
fields that the coverage assertion knows to require.

**Point of failure.** Handout §7: *"a separate `@zkAuth` directive would create fields the coverage
test does not know to demand, which is the exact failure that test exists to catch."* A second
directive creates a class of fields that satisfy nobody's coverage requirement, and the failure is a
field with **no** authorization at all that the coverage test reports as fine.

**Procedure.** (i) Assert the schema declares exactly one auth directive; assert no `@zkAuth` exists.
(ii) Add an unannotated field to a test schema and assert `AssertAuthCoverage` fails. (iii) Annotate
it `@auth(proves: ["x"])` and assert coverage passes. (iv) Assert coverage's exemption list did not
grow to accommodate zk fields.

**Pass.** All four.

**Fail.** A second directive, or coverage passing on an unannotated field.

**Avoidance.**
(a) *Negative variant:* (iii). A coverage assertion that always fails passes (ii).
(b) *False-pass trap:* checking (i) only. The directive can be single and coverage can still have been
taught an exemption — (iv) is the half that catches the workaround somebody added to make CI green.

**Trace.** §7 · `AssertAuthCoverage`.

---

### ZK-AUZ-005 · The proven-claim set is loaded once per request — **CRITICAL**

**Aim.** `zkauthz.Middleware` loads the set once; the `Proofs` func reads a context value and issues
zero queries.

**Point of failure.** Handout §7: *"The directive still must not query — it runs once per row on a
list field."* A directive that queries is an N+1 against the authorization path, on a list field, from
an unauthenticated-adjacent code path. At 1000 rows it is 1000 queries per request, which is a
self-inflicted denial of service that scales with the attacker's page size — and the attacker chooses
the page size. It is also a latency oracle: the query count is observable in response time and reveals
list length.

**Procedure.** Instrument the query log. Request a list field of 1000 rows annotated `@auth(proves:
["x"])`. Assert **exactly one** claim-set query for the whole request, and zero during directive
execution. Repeat with 10 000 rows and assert the count is unchanged. Assert the middleware is
composed **after** `session.Middleware` in luima's `HTTPMiddleware` slice — a claim set loaded before
the principal exists is loaded for nobody.

**Pass.** One query at 1000 rows and at 10 000; composition order correct.

**Fail.** Query count scaling with rows, or the middleware ordered first.

**Avoidance.**
(a) *Negative variant:* assert the claim set is actually **used** — a directive reading a context value
that is never populated denies everything and issues zero queries, passing this case perfectly.
Combine with ZK-AUZ-002(ii).
(b) *False-pass trap:* counting queries with a 1-row list. One row cannot distinguish one query from
one-per-row.

**Trace.** §7 · luima `HTTPMiddleware`.

---

### ZK-AUZ-006 · Claims do not leak across requests — **ESSENTIAL**

**Aim.** A claim proven in one request is available to that session's later requests via the database,
never to another request via shared state.

**Point of failure.** A package-level map keyed by anything, a `sync.Map` cache, or a context value
attached to a reused struct: any of them can serve one principal's claim set to another. Under
concurrency this is authorization by race, and it succeeds intermittently — the worst failure mode to
diagnose and the easiest to dismiss as a flake.

**Procedure.** Two principals, A with claim `x` proven and B with none, issuing interleaved concurrent
requests (P-4 barrier, 50 rounds). Assert B's `@auth(proves: ["x"])` field **never** resolves —
resolver counter for B's requests is zero across all rounds — and A's always does. Then assert there
is no package-level mutable state in `zkauthz` (reflect or review).

**Pass.** Counter for B is 0 over 50 rounds; A's is 50.

**Fail.** Any nonzero count for B.

**Avoidance.**
(a) *Negative variant:* A's counter must be 50. A middleware that populates nothing gives B zero and
passes.
(b) *False-pass trap:* running sequentially. The bug is a race; sequential requests never expose it.

**Trace.** §7.

---

### ZK-AUZ-007 · An unknown claim denies — **ESSENTIAL**

**Aim.** `@auth(proves: ["typo"])` with no matching `auth_zk_claims` row denies rather than allowing.

**Point of failure.** A claim name that does not resolve is a lookup miss, and a lookup miss is
`(nil, nil)` in a lot of Go. If the directive treats "no policy row" as "no policy to enforce", a typo
in the schema makes a field public. The schema still reads as protected — this is the failure that
survives code review indefinitely because the schema is the thing reviewers read.

**Procedure.** Annotate a field `@auth(proves: ["no_such_claim"])`. Query as a fully authenticated
principal with every other claim proven. Assert the field denies and the resolver counter is 0. Then
delete a claim row that a live annotation references and assert the field starts denying, not
allowing.

**Pass.** Both deny with counter 0.

**Fail.** Either resolves.

**Avoidance.**
(a) *Negative variant:* a claim that **does** exist resolves.
(b) *False-pass trap:* asserting a startup validation catches unknown claims. Startup validation is
good and is not this control — the claims table is data and can change after startup. Test the runtime
behaviour with the row deleted while the process is live.

**Trace.** §7 · `authz/directive.go` mfa model.

---

### ZK-AUZ-008 · An anonymous principal never satisfies `proves:` — **CRITICAL**

**Aim.** A request with no principal denies every proof-gated field.

**Point of failure.** Handout's architecture note: *"Anonymous is never an error and the middleware
never returns 401 — the graph decides."* So an anonymous request reaches the directive normally. If
the claim-set lookup for a nil principal returns an empty-but-non-error result and the directive's
check is `if !contains(claims, c) { deny }` guarded by an earlier `if principal == nil { return next }`
— a shape that exists in real code to let public fields through — every proof-gated field is public to
anonymous callers.

**Procedure.** Unauthenticated request against a field annotated `@auth(proves: ["x"])`. Assert deny
and counter 0. Repeat for a field with `@auth(proves: ["x"])` and no other argument, and for one with
`@auth(mfa: true, proves: ["x"])`. Repeat with a *revoked* session and with an expired one.

**Pass.** All deny, counter 0.

**Fail.** Any resolution.

**Avoidance.**
(a) *Negative variant:* an authenticated principal with the claim resolves.
(b) *False-pass trap:* testing only the fully-unauthenticated case. The revoked-session case takes a
different path — the principal may be constructed and then discarded — and it is the one that leaks.

**Trace.** §7 · architecture note in `CLAUDE.md`.

---

### ZK-AUZ-009 · An empty `proves:` list has a defined meaning — **ESSENTIAL** [UNSPECIFIED]

**Aim.** `@auth(proves: [])` behaves according to a written decision.

**Point of failure.** `[]` is what a code generator emits for an absent list in some paths, and
`contains-all-of-empty-set` is vacuously true. So `@auth(proves: [])` most naturally means "allow",
and the annotation reads as a restriction. If a schema-generation step ever emits `[]` instead of
omitting the argument, every such field becomes as permissive as `@auth` with no arguments.

**Procedure.** Query a field annotated `@auth(proves: [])`. Assert the behaviour matches the
documented decision — deny is the safe reading given the handout's fail-closed posture throughout.
Assert the same for a `null` list.

**Pass.** Behaviour matches a decision recorded in the directive's doc comment.

**Fail.** No decision exists; the handout does not settle it. See §23.

**Avoidance.**
(a) *Negative variant:* a field with **no** `proves:` argument must be unaffected — conflating "absent"
with "empty" is the actual bug and only the pair of cases separates them.
(b) *False-pass trap:* deciding it at test-writing time and not writing it down. The decision belongs
in the doc comment; the test pins it.

**Trace.** §7 · not settled by the handout; see §23.

---

### ZK-AUZ-010 · Claims bind to the session, and that property is stated — **ESSENTIAL**

**Aim.** Two claims satisfied by two different secrets on one session is the documented behaviour, not
an accident.

**Point of failure.** Handout §7: *"Two proofs under two audiences are unlinkable by construction …
so the server cannot tell they came from one secret, and records both against the session. One person
holding two credentials can therefore satisfy two claims with two different secrets."* A deployment
that assumes `proves: ["age_over_18", "is_employee"]` means one person is both will build policy on a
conjunction the system does not enforce. Handout §7 is explicit: *"State the property; do not build the
fix."*

**Procedure.** Two credentials held by two colluding members, or by one party holding both. Prove
claim X with credential 1 and claim Y with credential 2 on one session. Assert both claims are
granted — the documented behaviour. Assert `SECURITY.md` states that a multi-claim `proves:` list is a
conjunction over the **session**, not over a credential.

**Pass.** Both granted; documented.

**Fail.** The behaviour occurs and is undocumented.

**Avoidance.**
(a) *Negative variant:* a session with only claim X does not satisfy `proves: ["x", "y"]` — the
conjunction over the session must still hold.
(b) *False-pass trap:* treating this as a vulnerability and "fixing" it. The fix is one circuit
proving both statements, which is a second circuit and a second ceremony. The finding is a missing
paragraph, not missing code.

**Trace.** §7 · §12.

---

### ZK-AUZ-011 · A one-shot claim used as a session claim behaves predictably — **ESSENTIAL** [UNSPECIFIED]

**Aim.** The interaction between `kind = 'one_shot'` and `@auth(proves:)` is decided.

**Point of failure.** A one-shot nullifier burns on first use. If a `one_shot` claim can appear in
`@auth(proves:)`, the member satisfies that field exactly once per lifetime — and every subsequent
request denies with the uniform error, which reads as a broken credential. Conversely, if the claim
set is loaded per request from `auth_zk_nullifiers`, a burned one-shot row might satisfy the claim
forever, which is a one-shot that limits nothing after the first use.

**Procedure.** Configure a `one_shot` claim referenced by `@auth(proves:)`. Prove once; assert the
field resolves. Make a second request on the same session; assert the documented behaviour. Make a
request on a *new* session with the same credential; assert the documented behaviour. Record all
three.

**Pass.** All three match a written decision.

**Fail.** No decision exists. The handout describes one-shot as "one action per member per audience"
via `ZK.Login`-adjacent flows and does not say whether it is admissible in a directive. See §23.

**Avoidance.**
(a) *Negative variant:* the same test with a `recurring` claim, which must resolve on every request
and every session.
(b) *False-pass trap:* forbidding `one_shot` in `@auth(proves:)` silently in code. If it is forbidden,
it must be a startup validation error naming the claim, not an unexplained denial at 3am.

**Trace.** §7 · not settled by the handout; see §23.

---

### ZK-AUZ-012 · New mutations are in `defaultSensitiveFields` — **ESSENTIAL**

**Aim.** Every mutation the zk work adds is covered by the guard extension's sensitive-field list.

**Point of failure.** `guard.go:35`'s list is what suppresses argument logging and applies whatever
else the guard does for sensitive operations. A new mutation absent from it is a mutation whose
arguments — a proof, a nullifier, a challenge, potentially a secret on the enrolment response path —
are handled as ordinary. This is ZK-SES-003's leak arriving through a list nobody updated.

**Procedure.** Enumerate every mutation `zkauthn`/`zkauthz` adds. Assert each is present in
`defaultSensitiveFields`. Behaviourally: invoke each and assert no argument value appears in the
guard's output.

**Pass.** Complete coverage, no argument values emitted.

**Fail.** Any omission.

**Avoidance.**
(a) *Negative variant:* a non-sensitive mutation still logs normally, confirming the mechanism works.
(b) *False-pass trap:* asserting the list's length. Enumerate the mutations from the schema and check
membership per name, or the next mutation is uncovered and the count still matches something.

**Trace.** §7 "Also:" · `guard.go:35`.

---

### ZK-AUZ-013 · Claim names are opaque, with no expression syntax — **ESSENTIAL**

**Aim.** `@auth(proves: ["age_over_18"])`, never `["age>=18"]`. No parser exists.

**Point of failure.** Handout §7 and §2: a comparison operator in the schema is a policy language, and
every clause of a policy language costs constraints on every proof for every caller forever. But the
security failure is nearer: a parser in the authorization path takes attacker-adjacent input (a claim
name that could arrive from a dynamically-built schema or a persisted query) and turns it into a
threshold — which is ZK-INP-001 rebuilt as a feature.

**Procedure.** Assert the claim lookup is a keyed row read with no parsing. Assert a claim name
containing `>`, `<`, `=`, `>=`, or a digit suffix pattern is treated as an ordinary opaque name that
misses the table and therefore denies (ZK-AUZ-007), **not** as an expression. Assert no parser,
tokenizer or comparison-operator handling exists in `zkauthz`.

**Pass.** Opaque lookup; expression-shaped names deny.

**Fail.** Any interpretation of a claim name's structure.

**Avoidance.**
(a) *Negative variant:* a legitimate claim name containing an underscore and digits (`age_over_18`)
resolves normally — an over-strict validator that rejects digits breaks the documented naming
convention.
(b) *False-pass trap:* validating claim names with a regex and calling that the control. The control
is the absence of a parser; a regex that permits `age_over_18` also permits a future
`age_over_18_or_employee` that somebody then implements a parser for.

**Trace.** §7 · §2 third rule · §12.

---

## 12 · Group ENR — Enrolment and credential issuance

The handout specifies `Enroll`'s cryptography precisely and does not specify who may call it. That
gap is the most severe unspecified item in this register, so it leads.

### ZK-ENR-001 · Membership enrolment is not self-service — **CRITICAL** [UNSPECIFIED]

**Aim.** Only an authorized operator path can add a leaf to the tree.

**Point of failure.** Enrolment is the issuance of a credential that authenticates anonymously and
forever. If the enrolment endpoint is reachable by an unauthenticated caller — or by any authenticated
user — then T1 enrols itself, receives a secret, and is a member. Every constraint in every circuit
holds. `Root` validation passes because the server itself published the root. The anonymity of the
whole set is destroyed too: an attacker who enrols N times owns N of the M leaves and can partition
the anonymity set. There is no test in Groups CIR, INP, TRE or NUL that fires. This is the single
largest bypass reachable without touching any cryptography, and the handout does not name the guard.

**Procedure.** (i) Unauthenticated call to every enrolment entry point — assert denied, no leaf, no
root, no credential row. (ii) Authenticated as an ordinary user — assert denied. (iii) Authenticated
as a user holding the operator role — assert permitted. (iv) Assert the enrolment mutation is in
`defaultSensitiveFields`. (v) Assert the guard is a `@auth`-annotated field or an explicit role check,
not an unexported function that a consumer is trusted to wire correctly.

**Pass.** (i) and (ii) write nothing; (iii) succeeds.

**Fail.** Any leaf created by a non-operator. Also fail if the handout's design has no answer — record
as a design finding regardless of what the implementation chose. See §23.

**Avoidance.**
(a) *Negative variant:* (iii), or a system with enrolment disabled entirely passes (i) and (ii).
(b) *False-pass trap:* testing the Go method rather than the GraphQL/HTTP surface. The Go method may
be correctly unexported while the resolver that calls it is annotated `@auth` with no role. The reachable
surface is what an attacker has.
(c) *Third trap:* assuming "it's a library, the consumer wires it". The consumer wires `Scope` too, and
handout §7 still hardens `Scope`. Defence in depth applies here more, not less.

**Trace.** §4a `Enroll` · §9 `auth_zk_credentials` · **not settled by the handout** — §23.

---

### ZK-ENR-002 · `Knowledge` enrolment binds to the session's user — **CRITICAL**

**Aim.** `Enroll` writes `auth_zk_commitments` keyed by the principal on the context, never by a
caller-supplied user id.

**Point of failure.** A `userID` parameter on enrolment lets any authenticated user install their own
commitment as another user's second factor. They then satisfy that user's MFA at will. This is
ZK-INP-002's failure moved one step earlier, and it is invisible to ZK-INP-002 because the commitment
in the database is now genuinely the attacker's.

**Procedure.** (i) Reflect: `Enroll` takes `ctx` and `orm.DB` and no user identifier. (ii)
Behavioural: as user A, enrol; assert the row's `user_id` is A's. (iii) Attempt every available shape
of supplying B's id and assert none lands. (iv) Unauthenticated enrolment denies.

**Pass.** Row always keyed to the session's user; unauthenticated denies.

**Fail.** Any caller-influenced key.

**Avoidance.**
(a) *Negative variant:* A's own enrolment succeeds and A's subsequent proof sets A's `mfa_at`.
(b) *False-pass trap:* checking the signature only. The user can arrive via a struct field or a
context value the caller sets. Assert the written row under an attempted override.

**Trace.** §4a · §5 `Commitment` row · §9.

---

### ZK-ENR-003 · Re-enrolment replaces rather than accumulates — **CRITICAL**

**Aim.** `auth_zk_commitments` is keyed on `user_id`, so a second enrolment replaces the first and the
old secret stops working.

**Point of failure.** Handout §9: *"Keyed on the user, so re-enrolment replaces rather than
accumulating commitments that all still verify."* If it accumulates — a surrogate primary key, an
`insert` without `on conflict do update` against a non-unique column — then a user who re-enrols after
losing a device leaves the lost device's commitment live forever. The user believes they rotated; they
did not. There is no error and the UI says "enrolled".

**Procedure.** Enrol user A with secret S1; confirm a proof under S1 sets `mfa_at`. Re-enrol A with
secret S2. Assert: exactly **one** row in `auth_zk_commitments` for A; a proof under S2 succeeds; a
proof under **S1 fails and sets no `mfa_at`**. Assert the primary key is `user_id`.

**Pass.** One row; S2 works; S1 does not.

**Fail.** Two rows, or S1 still working.

**Avoidance.**
(a) *Negative variant:* S2 must work. A re-enrolment that deletes and fails to insert passes the
"S1 no longer works" half and locks the user out.
(b) *False-pass trap:* asserting the row count. A single row whose commitment was not updated means S1
works and S2 does not — the count is 1 and the system is broken in the opposite direction. Assert both
proofs.

**Trace.** §9 `auth_zk_commitments` · §12 recovery.

---

### ZK-ENR-004 · The attribute is set by the operator, never by the enrollee — **CRITICAL**

**Aim.** The `Attribute` committed into a leaf comes from the issuing operator's decision.

**Point of failure.** If the enrolling member supplies the attribute, every threshold in the
deployment is satisfiable by everyone — `age_over_18` becomes "the member claimed to be over 18",
which is a checkbox with a proof attached. ZK-INP-001 protects the threshold; this protects the other
side of the comparison, and nothing in Group INP covers it because the attribute is *private witness*
and correctly so.

**Procedure.** (i) Reflect the enrolment API: the attribute is a parameter of the operator-facing call
and is not reachable from a self-service path. (ii) Behavioural: enrol with `Attribute = 12`; assert
the returned secret cannot prove `Threshold = 18` (it cannot — the leaf binds it, per ZK-CIR-005 —
so assert the *leaf* stored equals `MiMC(DOM_LEAF, S, 12)` computed independently in the test). (iii)
Assert no path lets a caller re-issue their own leaf with a different attribute (see ZK-CIR-017).

**Pass.** Leaf matches the operator's attribute; no self-service path.

**Fail.** Any caller-supplied attribute reaching a leaf.

**Avoidance.**
(a) *Negative variant:* an operator enrolling `Attribute = 21` yields a leaf that proves
`Threshold = 18`.
(b) *False-pass trap:* verifying the attribute through a proof only. A proof shows the prover knows
*some* attribute clearing the threshold; recompute the leaf natively and compare to the stored
commitment, which is the only way to see what was actually committed.

**Trace.** §4b · §14 "What does `Attribute` mean?".

---

### ZK-ENR-005 · Enrolment failure leaves no partial credential — **ESSENTIAL**

**Aim.** A failure anywhere in enrolment leaves no leaf, no commitment, no root and no returned
secret.

**Point of failure.** A credential row without a tree leaf is a member who can never authenticate and
whom `issued_to` reports as enrolled. A tree leaf without a credential row is a leaf nobody can
revoke, because revocation names a person through `issued_to`. The second is permanent: an
unrevocable anonymous credential in the tree, and no record of who holds it.

**Procedure.** Inject failure after: the secret draw, the commitment computation, the credential
insert, the tree append, the root publish, the response write. For each, assert `auth_zk_credentials`,
`auth_zk_nodes` and `auth_zk_roots` are all unchanged, and that no secret was returned.

**Pass.** Every injection is a clean rollback.

**Fail.** Any residue, especially a leaf with no credential row.

**Avoidance.**
(a) *Negative variant:* the successful path writes exactly one credential row, one root, and the
expected node upserts.
(b) *False-pass trap:* injecting only database failures. The response-write failure is the one that
returns no secret to a member whose leaf is live — assert the operator can detect and revoke that
leaf.

**Trace.** §6 · §9.

---

### ZK-ENR-006 · Revocation names a person and revokes one leaf — **ESSENTIAL**

**Aim.** `issued_to` lets revocation name a user, and revoking one member does not affect another.

**Procedure.** Enrol A, B, C. Revoke by naming A's user. Assert A's leaf is `zeros[0]`, A cannot
prove, and B and C can. Revoke a user with no credential — assert a clean no-op, not an error that
rolls back an unrelated transaction. Revoke a credential whose `issued_to` is null — assert revocation
by leaf index still works.

**Pass.** Exactly one leaf cleared; the null case still revocable by index.

**Fail.** Any bystander leaf changed, or a null `issued_to` making a leaf unrevocable.

**Avoidance.** (a) B and C proving afterwards is the negative variant. (b) Do not test with a
single-member tree — the "wrong leaf cleared" bug is invisible there.

**Trace.** §1 `issued_to` · §6 · §9.

---

## 13 · Group KEY — Keys, ceremony and artifacts

Adversary T5. Handout §8's premise: *"a swapped verifying key is a universal bypass — every proof
verifies, including ones nobody made — and 'mount it read-only' is advice where a hash comparison is a
control."*

### ZK-KEY-001 · No proving or verifying key is in the repository — **CRITICAL**

**Aim.** The module ships no Groth16 keys, in any form.

**Point of failure.** Handout §0: *"A library that ships Groth16 keys has shipped a backdoor with a
licence file attached."* A committed proving key means the toxic waste holder is whoever ran the
ceremony that produced it — which for a shipped key is nobody the deployment trusts. A committed
verifying key is worse in a different way: every deployment that uses it shares a soundness domain
with every other, and a proof from one is a proof at all of them.

**Procedure.** Scan the working tree and the **full git history** — `git log --all --diff-filter=A
--name-only` — for files matching key patterns (`*.pk`, `*.vk`, `*.key`, `*.ph1`, `*.ptau`), for
embedded byte arrays above a size threshold, and for `embed.FS` directives outside `migrations`.
Assert `Setup` is not invoked at `init()`, at package load, or from any test that writes into the
repo. Assert `.gitignore` is **not** the control — a `.gitignore` entry is not evidence a key was
never committed, and the repo has already been bitten by `.gitignore` swallowing a real file
(`1ada86e`).

**Pass.** No key artifact anywhere in history; no generating side effect.

**Fail.** Any key blob, including one already deleted from HEAD — a deleted key is still distributed.

**Avoidance.**
(a) *Negative variant:* assert `Setup` **can** produce keys when called explicitly, into caller-supplied
writers. A build that cannot generate keys passes the scan and ships nothing usable.
(b) *False-pass trap:* scanning HEAD only. Git history is the distribution.

**Trace.** §0 "On the trusted setup" · §8.

---

### ZK-KEY-002 · The verifying key is hash-pinned before it is parsed — **CRITICAL**

**Aim.** `LoadVerifyingKey(r io.Reader, wantSHA256 []byte)` reads the bytes, hashes them, compares,
**and only then** parses.

**Point of failure.** Gotcha 60: swap the vk and every proof verifies, including ones nobody made. The
attack requires only a write to the path the vk is mounted from — a container image tag, a config-map
update, a shared volume, a build-step substitution. The symptom is an authentication system that says
yes to everything, and there is nothing in the logs distinguishing it from a working one. The ordering
matters as much as the check: parsing first means attacker-controlled bytes reach gnark's
deserialization — which is Group KEY's other case, ZK-KEY-006 — before any authenticity check.

**Procedure.** (i) Correct hash: loads. (ii) One bit flipped in the vk bytes, correct hash supplied:
assert an error naming a hash mismatch, and assert **no parse occurred** — instrument or use bytes
that are a valid hash mismatch *and* structurally valid, so a parse-first implementation succeeds and
this case catches it. (iii) A **valid vk from a different ceremony** with the pinned hash: assert
refused. (iv) Empty reader, truncated reader, reader returning an error mid-stream: uniform refusal,
no panic. (v) Assert the hash argument is mandatory — no overload, no nil-means-skip.

**Pass.** Only the pinned bytes load.

**Fail.** Any load of unpinned bytes; a nil hash accepted; a parse before the compare.

**Avoidance.**
(a) *Negative variant:* (i). A `LoadVerifyingKey` that always errors passes (ii)–(v).
(b) *False-pass trap, the important one:* using **corrupt** bytes for (ii). Corrupt bytes fail the
parse too, so a parse-first implementation still errors and the test is green while the ordering is
wrong. The bytes must be a *valid, parseable* verifying key that simply is not the pinned one — which
makes (iii) and (ii) the same shape and both necessary.
(c) *Third trap:* pinning the hash inside kal. Handout §8: *"The consumer pins the hash as a constant
in their own source, next to the call that loads it."* A hash kal ships is a hash kal can change in a
patch release.

**Trace.** §8 · gotcha 60.

---

### ZK-KEY-003 · `CircuitID` pins the statement, not the cost — **CRITICAL**

**Aim.** The hash of the compiled R1CS is a constant, checked at load, so a vk from a different circuit
is a named startup error.

**Point of failure.** Handout §3 stage 5 and §8: the constraint count *"is a weak fingerprint — a
refactor can change which statement is proven without changing how many gates prove it."* Swap two
arguments to a hash; drop one `AssertIsEqual` and add another. The count is identical, every
performance test is green, the differential test catches it **only if the generator reaches the
distinguishing witnesses**, and `CircuitID` catches it always. Without the check at load, the symptom
is *"a verification failure at 3am that reads like a client bug"*.

**Procedure.** (i) Assert `CircuitID` equals a pinned constant for each circuit. (ii) Load a vk
produced from a different circuit and assert a **named** error identifying the mismatch, at the point
the setup is read — not a verification failure later. (iii) Assert the check runs at load, not at
first verify: construct the system with the mismatched key and assert the constructor fails.

**Pass.** Pin matches; mismatched key is a construction error.

**Fail.** Pin drift, or a mismatched key deferring its error to runtime.

**Avoidance.**
(a) *Negative variant:* the matching key constructs successfully.
(b) *False-pass trap:* deriving `CircuitID` from the source file's hash, the constraint count, or the
circuit type's name. All three are stable across the argument-swap mutation this case exists for. It
must be the compiled R1CS.

**Trace.** §3 stage 5 · §8 · §10.

---

### ZK-KEY-004 · R1CS serialization is deterministic — **CRITICAL** *(precondition for ZK-KEY-003)*

**Aim.** `ccs.WriteTo` is byte-stable across compilations of the same source, so pinning its hash is
meaningful.

**Point of failure.** Handout §8 is explicit that this must be *confirmed before pinning*: *"Do not
pin a constant to a serialization you have not established is deterministic; the failure is a test
that goes red on an unrelated toolchain upgrade, and the fix everybody reaches for is deleting the
test."* Deleting ZK-KEY-003 removes the only semantic control on the circuit.

**Procedure.** Compile the same circuit twice in one test process; serialize both; assert byte
equality. Compile in two separate processes and compare. Compile with `GOFLAGS` and map-iteration
order perturbed (`-race`, repeated runs) and compare. If any comparison fails: **pin the hash of the
verifying key instead**, and record the substitution in the comment with the reason.

**Pass.** Byte-identical across all variants, or a documented substitution to the vk hash.

**Fail.** Non-determinism with the R1CS hash still pinned. That is a time bomb, not a control.

**Avoidance.**
(a) *Negative variant:* compile a **modified** circuit and assert the serialization differs. A
`WriteTo` that emits a constant passes determinism perfectly and fingerprints nothing.
(b) *False-pass trap:* two compilations in one process sharing a cached `ccs`. Force independent
compilation; the in-process cache is the likeliest reason this passes vacuously.

**Trace.** §8 "Confirm before pinning".

---

### ZK-KEY-005 · `ReadFrom`, never `UnsafeReadFrom` — **CRITICAL**

**Aim.** Every deserialization of attacker-supplied group elements performs the on-curve and subgroup
checks.

**Point of failure.** Gotcha 50: *"Groth16 verification depends on deserialization having done them.
On attacker-supplied bytes the unsafe variant is a small-subgroup attack with no error and a better
benchmark, which is exactly the profile of a change somebody makes on purpose."* A point in a small
subgroup makes the pairing equation degenerate in ways an attacker can steer, and the "better
benchmark" is why this arrives as a performance PR with a green test suite.

**Procedure.** (i) Source: assert `UnsafeReadFrom` appears nowhere in `zkauthn`/`zkauthz`, including
in benchmarks and test helpers — a helper that uses it teaches the next reader that it is fine. (ii)
Behavioural: construct a proof blob whose `A` component is a point **not on the curve**; submit;
assert a uniform rejection and no panic. (iii) Construct one whose `A` is on the curve but in a small
subgroup (not in the prime-order subgroup); submit; assert rejection. (iv) Assert both rejections are
indistinguishable from an ordinary invalid proof (ZK-ORC-001).

**Pass.** Both malformed points rejected, uniformly, without panic.

**Fail.** Either accepted, or a panic, or a distinguishable error.

**Avoidance.**
(a) *Negative variant:* a well-formed proof still verifies. A parser that rejects everything passes
(ii) and (iii).
(b) *False-pass trap, specific and likely:* skipping (iii) because (ii) is easier to construct. The
off-curve point is caught by almost any implementation; the small-subgroup point is the one
`UnsafeReadFrom` lets through, and it is the entire case. If you cannot construct it, the case is not
done — say so rather than marking it green.

**Trace.** §8 · gotcha 50.

---

### ZK-KEY-006 · `Setup` writes to two separate sinks — **ESSENTIAL**

**Aim.** `Setup(pkw, vkw io.Writer)` — the proving key and the verifying key cannot end up in one
file.

**Point of failure.** Handout §8: *"One writer means one file, and one file means the proving key ends
up mounted next to the server that has no use for it and the verifying key ends up in whatever bundle
the prover ships."* A proving key on the server is a several-megabyte artifact whose compromise lets
the holder prove anything — and it is sitting on the machine most exposed to the network, for no
reason.

**Procedure.** (i) Reflect the signature: two `io.Writer` parameters. (ii) Call with two distinct
buffers; assert both are non-empty, assert their sizes differ by orders of magnitude (pk ≫ vk), and
assert the vk buffer parses as a vk and the pk buffer does not. (iii) Assert passing the same writer
twice produces an artifact that fails to load as either — or is rejected outright.

**Pass.** Two distinct, correctly-typed artifacts.

**Fail.** A single combined artifact, or the two swappable.

**Avoidance.**
(a) *Negative variant:* the produced pk and vk actually work together end to end — prove with the pk,
verify with the vk.
(b) *False-pass trap:* asserting the signature only. A two-writer signature that writes the same bytes
to both is worse than one writer.

**Trace.** §8.

---

### ZK-KEY-007 · The ceremony is not deterministic — **CRITICAL**

An audit case the handout does not raise, and the one that would make §0's argument collapse.

**Aim.** Two runs of `Setup` on the same circuit produce different proving and verifying keys.

**Point of failure.** Groth16's security rests on the toxic waste being unknown. If `Setup` draws its
randomness from a seeded, fixed, or hashed-from-the-circuit source — a plausible "for reproducible
builds" change, or an injected `io.Reader` that a test fixture pins and a config later reuses — then
**anyone who can run the same setup recovers the toxic waste** and forges proofs for that circuit.
Handout §0's argument is that the operator holding the waste is harmless *because it is also the
verifier*. A deterministic setup hands the waste to every user, and the argument does not survive
that: forgery now buys an outsider exactly what it did not have.

**Procedure.** (i) Run `Setup` twice on the identical circuit; assert the pk bytes differ and the vk
bytes differ. (ii) Assert a proof made under ceremony 1's pk does **not** verify under ceremony 2's vk
— confirming the two are genuinely independent and not merely differently serialized. (iii) Assert no
parameter, field or environment variable supplies a seed or a randomness source to `Setup`. (iv)
Assert the randomness source is `crypto/rand`.

**Pass.** Different keys, non-interoperable, no seed surface.

**Fail.** Identical keys, or cross-ceremony verification succeeding, or any seed input.

**Avoidance.**
(a) *Negative variant:* (ii)'s positive half — ceremony 1's pk and ceremony 1's vk **do** interoperate.
Without it, a `Setup` returning garbage passes (i) and (ii).
(b) *False-pass trap:* asserting the byte difference alone. Two serializations of the same key can
differ in a header, a timestamp or a compression flag while encoding identical parameters. (ii) is the
assertion that means something.
(c) *Third trap:* accepting a determinism argument on grounds of reproducible builds. A reproducible
ceremony is not a build; it is a published private key.

**Trace.** §0 "On the trusted setup" · §12 PLONK condition.

---

### ZK-KEY-008 · The proving key is not required by the verifier — **ESSENTIAL**

**Aim.** The server-side verification path loads only the verifying key.

**Point of failure.** If the verifier's constructor requires or accepts the pk, deployments mount it,
and §8's separation is undone at the call site rather than at the signature. It also makes the
verifying server the highest-value target in the deployment for a reason unrelated to what it does.

**Procedure.** Construct the verification path with a vk and **no** pk. Assert it verifies proofs.
Assert no exported constructor requires a pk. Assert `make bench-zk`'s prove side is separable.

**Pass.** Verification works with the vk alone.

**Fail.** Any verifier path requiring a pk.

**Avoidance.** (a) Assert the prover path **does** require a pk. (b) Do not accept an optional pk
parameter documented as "for testing" — optional inputs get supplied.

**Trace.** §8 · §9.

---

### ZK-KEY-009 · Constraint counts and prove/verify cost are measured and pinned — **GOOD-TO-HAVE**

**Aim.** `make bench-zk` reports constraint count and prove/verify wall time, and the numbers are
recorded.

**Point of failure.** Prove time in the hundreds of milliseconds (§4b) is a product decision. A
regression to seconds is a support load; to minutes it is an outage. Without a recorded baseline
nobody can say when it changed.

**Procedure.** Assert `make bench-zk` exists, prints constraint count and prove/verify time for both
circuits, and that the phase's numbers are recorded in `CHANGELOG.md`. Assert ZK-CIR-015's pins.

**Pass.** Target exists, prints both, numbers recorded.

**Fail.** Absent, or reporting only one circuit.

**Avoidance.** (a) Assert the benchmark actually produces a valid proof — a benchmark of a failing
prove is fast and meaningless. (b) Do not gate CI on wall time; it will be flaky on shared runners.
Gate on the constraint count (ZK-CIR-015), report the time.

**Trace.** §13 Phase 1 · §4a, §4b budgets.

---

### ZK-KEY-010 · `make audit` findings are suppressed with reasons, not silence — **ESSENTIAL**

**Aim.** gosec findings introduced by gnark and gnark-crypto carry `#nosec` comments in kal's style.

**Point of failure.** `CLAUDE.md`'s doc-comment register: a comment says *what breaks if the line is
removed*, not that the code is fine. A blanket suppression, an exclusion in the Makefile, or a
`#nosec` with no reason turns the audit into a formality — and gnark carries assembly and `unsafe`,
which is exactly the code where a real finding would appear.

**Procedure.** Assert `make audit` runs clean. Assert every `#nosec` in the zk packages names a
concrete reason in the repo's register (`// #nosec G115 -- bounded to [8,64] just above`, not
`// convert to uint32`). Assert no gosec rule is globally disabled and no path is globally excluded.
Assert govulncheck is not suppressed — handout §13: *"Upgrade Go, don't suppress."*

**Pass.** Clean audit; every suppression reasoned and local.

**Fail.** A global exclusion, or a reasonless `#nosec`.

**Avoidance.** (a) Assert removing a `#nosec` makes the audit fail — otherwise it is a stale
suppression accumulating. (b) Do not accept "gnark is a dependency" as a reason; the reason must name
what breaks.

**Trace.** §13 Phase 0 · `CLAUDE.md` doc-comment register.

---

## 14 · Group DOS — Resource bounds

Handout §9: *"Proof verification is a DoS primitive in the same way Argon2's memory parameter is:
milliseconds of pairing arithmetic that an unauthenticated caller triggers with one HTTP request, and
nothing else in the stack bounds it."*

### ZK-DOS-001 · Verification concurrency is bounded — **CRITICAL**

**Aim.** A `semaphore.Weighted` sized against the pod's CPU bounds concurrent verifications, acquired
through the same short-timeout `acquire` that returns `CodeRateLimited`.

**Point of failure.** Unbounded, N concurrent unauthenticated requests each consume a CPU core for
milliseconds of pairing arithmetic. The pod saturates, health checks fail, the orchestrator restarts
it, the restart drops in-flight sessions, and the attacker's cost is N HTTP requests. Queueing instead
of refusing is the same failure with a longer queue: the request that eventually runs is answering a
client that timed out, and the memory holding it is the thing that falls over.

**Procedure.** `TestZKVerifyBound`. Set the bound to 1. Start one verification that blocks (an
instrumented hook, or a genuinely slow proof). Issue a second concurrently. Assert the second returns
**`CodeRateLimited`** promptly — within the configured acquire timeout, asserted as an upper bound on
elapsed time — and specifically **not** that it queued and eventually succeeded. Assert the first
completes normally. Repeat at a bound of 4 with 8 callers: assert exactly 4 proceed and 4 are refused.

**Pass.** Refusal, not queueing; the refusal is prompt; the permitted count equals the bound.

**Fail.** Queueing, an unbounded wait, or a different error code.

**Avoidance.**
(a) *Negative variant:* with the bound at 8 and 4 callers, all 4 succeed. A semaphore that always
refuses passes the refusal assertion and makes login impossible under any concurrency.
(b) *False-pass trap, the important one:* asserting only that the second call **failed**. It may have
failed by queueing until a context deadline elsewhere — which is the exact behaviour §9 is written to
prevent, and it produces the same error to the caller. Assert **elapsed time** against the acquire
timeout.
(c) *Third trap:* sizing the bound from `runtime.NumCPU()` and testing on a CI runner with a different
core count, making the test's expectations machine-dependent. Inject the bound.

**Trace.** §9 · `authn/password.go:115` · gotcha 61.

---

### ZK-DOS-002 · The dummy verify takes a semaphore slot — **CRITICAL**

**Aim.** The timing-equalization path in §5 is inside the bound, not around it.

**Point of failure.** Handout §9: *"The dummy verify takes a semaphore slot like any other, per §9."*
If it does not, an attacker discovers the cheapest way to consume CPU: hit the no-commitment path,
which by design performs a full pairing verification against a fixed dummy commitment and — being
outside the bound — is unbounded. The DoS control and the timing control cancel each other out, and
each looks correct in isolation.

**Procedure.** Bound set to 1. Hold the slot with a real verification. Concurrently issue a request
for a user with **no commitment enrolled** — the dummy-verify path. Assert it returns
`CodeRateLimited` promptly, exactly as a real verification would. Assert it does not bypass, and
assert it does not skip the dummy verify when the slot is unavailable (skipping would restore the
timing oracle under load — which is when an attacker would measure).

**Pass.** The dummy path is refused identically.

**Fail.** The dummy path proceeding, or silently skipping the verification.

**Avoidance.**
(a) *Negative variant:* with a free slot, the dummy path performs a real verification — assert the
elapsed time is within ZK-ORC-002's tolerance of a genuine one.
(b) *False-pass trap:* asserting the error code alone. Both bypass and correct-refusal can produce a
plausible error. Assert timing and slot occupancy.

**Trace.** §5 · §9 · gotchas 30, 63.

---

### ZK-DOS-003 · The proof blob is length-checked before deserialization — **CRITICAL**

**Aim.** A Groth16 proof over BN254 is a fixed number of bytes, so the check is an **equality**, and it
runs before gnark sees a byte.

**Point of failure.** Handout §9: *"Attacker-chosen bytes must not reach hand-written assembly on the
strength of a parser being careful."* gnark-crypto's deserialization is performance code with
assembly paths. An unbounded blob is also an unbounded allocation from an unauthenticated request —
the cheapest possible memory-exhaustion primitive, requiring no cryptography from the attacker at all.

**Procedure.** (i) Measure the exact proof length once; assert it is pinned as a constant. (ii) Submit
blobs of length `n−1`, `n+1`, `0`, `1`, `1 MiB` and `64 MiB`. Assert every one is rejected **before**
any deserialization — instrument gnark's entry point or assert allocation/elapsed bounds. (iii) Assert
the rejection is the uniform `CodeInvalidProof`. (iv) Assert no panic and no allocation proportional
to the input for the large cases.

**Pass.** Only length `n` proceeds; large blobs rejected with bounded work.

**Fail.** Any blob of the wrong length reaching the parser; an allocation proportional to input size.

**Avoidance.**
(a) *Negative variant:* a genuine, correct-length proof verifies. An equality check against the wrong
constant rejects everything and passes every assertion above.
(b) *False-pass trap:* implementing this as a `<=` bound because "a bound is safer than an equality".
A bound admits every shorter blob into the parser, which is the population an attacker actually
sends. §9 says equality and means it.
(c) *Third trap:* measuring the constant on a compressed encoding and shipping an uncompressed one, or
vice versa. Measure it on the encoding the wire format uses, and assert the wire format is pinned too.

**Trace.** §9 · §5 (`ReadFrom`, length-checked first) · gotcha 61.

---

### ZK-DOS-004 · The challenge endpoint is not a write amplifier — **ESSENTIAL**

Covered mechanically by ZK-CHL-006 and ZK-CHL-010; recorded here as the DoS-facing statement of the
same control.

**Aim.** One unauthenticated request creates at most one row, and the table's steady state is bounded.

**Procedure.** As ZK-CHL-006 (single-statement issue-and-sweep) and ZK-CHL-010 (plateau). Additionally:
assert the endpoint is itself rate-limited or that its cost is bounded — a row insert per request is
cheap but not free, and the table is on the login path.

**Pass.** Bounded steady state; bounded per-request cost.

**Fail.** Unbounded growth or an unbounded per-request write.

**Avoidance.** (a) Legitimate issuance must still work under the limit. (b) Do not rate-limit by IP
alone on the zk path — see ZK-DOS-006.

**Trace.** §9 · gotcha 61.

---

### ZK-DOS-005 · Server-side proving, if it exists, has its own smaller bound — **GOOD-TO-HAVE**

**Aim.** `groth16.Prove` is worse than `Verify` by two orders of magnitude and is bounded separately.

**Point of failure.** Handout §9. The position in §12/§14 is that kal ships a Go prover and the wire
format and stops — so this case is conditional. If kal ever proves on a request path, one request
consumes a core for hundreds of milliseconds and gigabytes of transient memory, and the `Verify`
semaphore's sizing is wrong for it by 100×.

**Procedure.** If no server-side prove exists: assert it — no exported path calls `groth16.Prove` from
a request handler. If it does: assert a separate, smaller semaphore, and assert its bound is not the
verify bound.

**Pass.** Either absent, or separately bounded.

**Fail.** Prove sharing the verify bound.

**Avoidance.** (a) The absence assertion must cover test helpers that a consumer might copy. (b) Do
not size a shared bound to the prove cost — that throttles verification to prove rates.

**Trace.** §9 · §12 · §14.

---

### ZK-DOS-006 · The bound's ceiling is documented as per-replica — **GOOD-TO-HAVE**

**Aim.** A `ponytail:` comment names the ceiling and the upgrade path, matching `authn.Hasher`'s.

**Point of failure.** A per-replica semaphore is not a deployment-wide limit. Twenty pods is twenty
times the bound, and an operator reading "verification is bounded" will size capacity against the
wrong number. The same note exists for `authn.Hasher` and the register is what makes the two
comparable.

**Procedure.** Assert the comment exists, names the per-replica ceiling, and names the upgrade
(a shared limiter) as a measurement-gated change rather than a TODO.

**Pass.** Present and specific.

**Fail.** Absent, or a bare "TODO: distributed rate limit".

**Avoidance.** (a) Assert the same note exists for `authn.Hasher`, so the two read as one register. (b)
Do not implement a distributed limiter to close this — it is a documentation obligation with a named
upgrade path.

**Trace.** §9 · `CLAUDE.md` doc-comment register.

---

## 15 · Group ORC — Error uniformity and oracles

Adversary T4. Handout §5: *"Distinguishing them tells an unauthenticated caller which roots are live
and — the one that matters — whether a given account has enrolled a second factor."*

### ZK-ORC-001 · One error code for every verification failure — **CRITICAL**

**Aim.** Malformed bytes, a non-verifying proof, an unknown root, a retired root, a consumed
challenge, an expired challenge and an unenrolled user all return one `kalerr.CodeInvalidProof`.

**Point of failure.** Each distinguishable failure is a query an attacker can ask. "Unknown root" vs
"retired root" enumerates the live root set, which reveals enrolment activity and timing. "No
commitment enrolled" is an MFA-enrolment oracle over the whole user base — the highest-value one,
because it tells an attacker which stolen passwords are worth using. This is `Login`'s single
`INVALID_CREDENTIALS` applied to the same problem for the same reason.

**Procedure.** Construct each of the seven failure classes. Assert every one returns the identical
`kalerr` code, the identical `Message`, and — through `PresentError` — an identical GraphQL error
payload, byte for byte after removing request-scoped identifiers. Assert identical HTTP status.
Assert the `Internal` field differs (that is where the detail belongs) and that `PresentError` never
surfaces it.

**Pass.** Seven identical external responses; seven distinct internals.

**Fail.** Any external difference, including a differing `extensions` map, a differing field path, or
a differing error count.

**Avoidance.**
(a) *Negative variant:* a **successful** verification is distinguishable — obviously, and the test must
confirm it, or an implementation that returns the same thing for everything passes and authenticates
nobody.
(b) *False-pass trap:* comparing error codes only. gqlgen's payload carries a path, an extensions map
and sometimes a locations array; a `nil` vs empty extensions map is a distinguishing bit. Compare the
serialized payload.
(c) *Third trap:* forgetting the malformed-bytes class, which often fails earlier in the stack — in
middleware, or in JSON decoding — and produces a completely different response shape. That is the
easiest oracle to find and the one most likely to be missed.

**Trace.** §5 "One failure, however it failed" · gotcha 63.

---

### ZK-ORC-002 · The enrolment path is timing-equalized — **CRITICAL**

**Aim.** A user with no commitment costs the same as one with a commitment, because the server
verifies against a fixed dummy commitment and throws the result away.

**Point of failure.** Handout §5: *"A user with no commitment otherwise returns before any pairing
arithmetic runs, which is a few milliseconds of difference and an enrolment oracle that a uniform
error code does not close."* A few milliseconds is enormous — pairing arithmetic against nothing is a
signal visible over the network with modest sampling. `authn`'s `VerifyDummy` (`password.go:207`) is
the model; this is gotcha 30's rule on a pairing instead of a hash.

**Procedure.** Sample ≥1000 request timings for each of: (a) an enrolled user with a wrong proof, (b)
an unenrolled user, (c) an enrolled user with a correct proof. Assert the distributions for (a) and
(b) are statistically indistinguishable — compare medians and a rank test, with a documented
tolerance; a difference on the order of a pairing check (milliseconds) must not be present. Assert the
dummy commitment is a **fixed** constant and is not derived from the request. Assert the dummy verify's
result is discarded and cannot influence control flow.

**Pass.** (a) and (b) indistinguishable at the stated tolerance.

**Fail.** A separation on the order of the pairing cost.

**Avoidance.**
(a) *Negative variant:* (c) should be distinguishable from (a) and (b) only by whatever the success
path legitimately costs — assert that the *failure* paths are the equal pair, not that all three are
equal, or an implementation that skips verification entirely passes.
(b) *False-pass trap:* running the timing test on a loaded CI runner and widening the tolerance until
it passes. State the tolerance as a fraction of the measured pairing cost — the signal you are looking
for is exactly one pairing — and if the environment cannot resolve it, mark the case
environment-limited rather than green.
(c) *Third trap:* short-circuiting the dummy verify when the semaphore is unavailable. See
ZK-DOS-002.

**Trace.** §5 · `authn/password.go:207` · gotchas 30, 63.

---

### ZK-ORC-003 · The internal detail never reaches the client — **ESSENTIAL**

**Aim.** `kalerr.Error{Code, Message, Internal}`'s `Internal` field is server-side only.

**Point of failure.** The error contract exists so detail can be kept for logs. A `PresentError` that
includes `Internal` — or an error wrapped with `%w` and then rendered by gqlgen's default presenter
because the custom one was not wired — publishes the exact distinctions ZK-ORC-001 exists to hide.
The failure is one missing wire-up, and the symptom is a helpful error message.

**Procedure.** For each of the seven failure classes, assert the rendered GraphQL payload contains
none of: the internal message, the SQLSTATE, a table name, a column name, a root value, a challenge
value, a stack frame or a file path. Assert `PresentError` is the presenter luima is configured with
(`ErrorPresenter` seam). Assert `AllowIntrospection` false does not change the answer.

**Pass.** No internal detail in any payload.

**Fail.** Any leak.

**Avoidance.**
(a) *Negative variant:* the internal detail **is** present in the log/`Internal` field — otherwise the
detail was simply dropped and operability is gone.
(b) *False-pass trap:* testing `PresentError` directly. Test through the server, or the default
presenter path stays untested and that is where the leak is.

**Trace.** §5 · `kalerr` contract · luima `ErrorPresenter`.

---

### ZK-ORC-004 · Unknown and retired roots are indistinguishable — **ESSENTIAL**

**Aim.** An attacker cannot enumerate the live root set.

**Point of failure.** Root history is enrolment and revocation history. Distinguishing "never
published" from "retired" lets an unauthenticated caller binary-search the deployment's membership
activity over time — how many members, when they joined, when someone was removed. None of that is
secret by cryptography; it is secret only by uniform errors.

**Procedure.** Submit proofs against: a random never-published root, a genuinely retired root, the
current root with a bad proof. Assert the three external responses are byte-identical (per ZK-ORC-001)
and that timings are indistinguishable — a root lookup that misses the index returns faster than one
that hits it and then checks `retired_at`.

**Pass.** Identical responses and indistinguishable timings.

**Fail.** Either differing.

**Avoidance.** (a) The current-root-good-proof case must succeed. (b) Do not fix a timing difference by
adding a sleep — equalize by performing the same work, as ZK-ORC-002 does.

**Trace.** §5 · §6.

---

### ZK-ORC-005 · Nullifier existence is not observable — **ESSENTIAL**

**Aim.** A caller cannot test whether a given nullifier has been seen or burned.

**Point of failure.** Nullifiers are public values. If submitting a proof against an already-burned
one-shot nullifier is distinguishable from submitting against an unburned one, an attacker can poll
the published nullifier space and learn **who has acted** in a one-shot audience — which is exactly
the anonymity property the one-shot kind is sold for. The proof requirement does not save this: the
attacker can pair a known nullifier with a garbage proof and read the timing.

**Procedure.** Submit an invalid proof naming (a) an existing burned nullifier, (b) an existing
unburned one, (c) a never-seen one. Assert identical responses and indistinguishable timings. Repeat
with a *valid* proof for (a) and (b) — assert the second submission's rejection is indistinguishable
from an ordinary invalid proof.

**Pass.** All indistinguishable.

**Fail.** Any distinction, especially a timing one from the unique-index probe.

**Avoidance.**
(a) *Negative variant:* the first valid submission must succeed.
(b) *False-pass trap:* checking only the response body. The index probe's timing is the leak, and it
is ordered so that the burned case does more work. Sample timings.

**Trace.** §7 · §5 · gotcha 63's family.

---

### ZK-ORC-006 · Claim existence is not observable — **ESSENTIAL**

**Aim.** An unknown claim name is indistinguishable from a known one with a failing proof.

**Point of failure.** The claims table is policy: names, thresholds and kinds. Enumerating it tells an
attacker the deployment's bracket structure (ZK-SES-009), which claims are one-shot, and therefore
where the valuable actions are. Introspection may already reveal claim names used in the schema —
which is a reason to check `AllowIntrospection`'s posture, not a reason to leak the rest.

**Procedure.** Submit with (a) an unknown claim name, (b) a known claim and a failing proof, (c) a
known claim and a malformed proof. Assert identical responses and indistinguishable timings. Assert
the claims table is not exposed by any query, and that with `AllowIntrospection` false the directive's
arguments do not enumerate claim names to an unauthenticated caller.

**Pass.** All indistinguishable; no table exposure.

**Fail.** Any distinction, or a query returning claim rows.

**Avoidance.** (a) A known claim with a valid proof succeeds. (b) Do not rely on introspection being
off — assert the behaviour with it on and off, since the zero `Config` has it off and developers turn
it on.

**Trace.** §5 · §7 · `Config.AllowIntrospection`.

---

### ZK-ORC-007 · Failure paths do not differ in observable side effects — **ESSENTIAL**

**Aim.** Uniformity extends to state, not just to responses.

**Point of failure.** Two failures returning the same error can still differ in what they wrote: one
burns the challenge, another does not; one increments a counter, another does not; one writes a log
line with a distinct shape. Any of those is observable — the challenge burn most directly, because the
attacker holds the challenge and can test whether it still works.

**Procedure.** For each of the seven failure classes, record the full state delta: challenge
`consumed_at`, nullifier rows, session rows, `mfa_at`, log line count and shape. Assert the deltas
are identical **or** that each difference is justified in writing. Specifically: assert the challenge
is burned in **every** case where it was successfully claimed, so a caller cannot retry a challenge
after a failed proof and learn from which failures allow a retry.

**Pass.** Deltas identical, or each difference documented.

**Fail.** An undocumented difference, especially a challenge that survives one failure class and not
another.

**Avoidance.**
(a) *Negative variant:* a malformed request that never reached the challenge lookup must **not** burn
a challenge — otherwise an attacker burns a victim's challenge with garbage bytes, which is a cheap
denial of service against a specific login attempt.
(b) *False-pass trap:* comparing only the tables. Log line shape is observable to anyone with log
access and is often the first oracle restored after (a) is fixed.

**Trace.** §5 · §9.

---

## 16 · Group SQL — Schema and migration

### ZK-SQL-001 · `0002_zk.sql` alters no core table — **CRITICAL**

**Aim.** The zk migration adds tables and touches nothing `0001_core.sql` created.

**Point of failure.** Handout §9 states it as a rule: *"Do not alter a core table."* An `alter table
auth_users` or `alter table auth_sessions` in an optional package's migration makes the core schema
depend on whether an optional feature was installed — so a deployment that never uses zk has a
different `auth_sessions` than one that does, and every subsequent core migration has two shapes to
handle. The security-relevant version: an added nullable column with a default that a core query
now reads.

**Procedure.** Parse `0002_zk.sql` and assert every statement is `create table`, `create index`,
`create unique index` or a `check` on an `auth_zk_*` object. Assert no `alter table` naming a core
table. Behaviourally: snapshot the core schema (columns, types, constraints, indexes) before and
after the migration; assert byte-identical.

**Pass.** Core schema unchanged.

**Fail.** Any core alteration, including an added index.

**Avoidance.**
(a) *Negative variant:* the zk tables **were** created — an empty migration passes the snapshot
comparison.
(b) *False-pass trap:* comparing table lists only. An added column, a widened type or a dropped
constraint keeps the list identical.

**Trace.** §9 · `migrations`.

---

### ZK-SQL-002 · The migration follows `0001_core.sql`'s conventions — **ESSENTIAL**

**Aim.** Unqualified table names, `gen_random_uuid()`, no extensions, Postgres ≥ 13.

**Point of failure.** A `create extension` in a library's migration requires superuser, which many
managed Postgres deployments do not grant — the migration fails at install time, which is loud. The
quiet failure is a **schema-qualified** table name: the migration writes into a hard-coded schema
while the package renders its SQL with a configurable prefix, so the code queries one schema and the
tables live in another. Every zk query returns "relation does not exist" — or, worse, finds a
same-named table from another tenant.

**Procedure.** Assert: no `create extension`; no schema-qualified identifier; `gen_random_uuid()` and
not `uuid_generate_v4()`; no syntax above Postgres 13. Run the migration on a clean PG 13 and on the
current version. Run it under a non-superuser role.

**Pass.** Applies cleanly on 13 and current, as a non-superuser.

**Fail.** Any extension requirement, any qualified name, any 14+ syntax.

**Avoidance.** (a) Assert the tables are then reachable through the package's schema-prefixed SQL —
a convention-clean migration that lands in the wrong schema passes every static check. (b) Do not test
on the newest Postgres only; the version floor is the constraint.

**Trace.** §9 · `migrations/0001_core.sql`.

---

### ZK-SQL-003 · The schema prefix is validated — **CRITICAL**

**Aim.** The schema name is checked against `identRe` and rendered with `types.AppendIdent`, once at
construction.

**Point of failure.** The schema prefix is interpolated into every statement in `sql.go`. If it is
not validated, it is SQL injection with a configuration-shaped delivery — and a library that accepts
a schema name from a consumer's config, which may itself come from an environment variable, has a
plausible path from an attacker-influenced value to arbitrary SQL. Rendering per-call rather than once
at construction also means the check can be skipped on one path and nobody notices.

**Procedure.** Construct with schema names: `public`, `kal_test`, `"; drop table auth_users; --`,
`pg_catalog`, one containing a quote, one containing a null byte, one 200 characters long, one empty.
Assert every invalid one is rejected **at construction**, not at first query. Assert the valid ones
render correctly and that the rendering happens once — instrument or assert the rendered strings are
built in the constructor.

**Pass.** Invalid names refused at construction; valid ones render once.

**Fail.** Any injection-shaped name accepted, or per-call rendering.

**Avoidance.**
(a) *Negative variant:* a legitimate schema name works end to end.
(b) *False-pass trap:* asserting the regex in isolation. The control is that every statement in
`sql.go` uses the rendered prefix — one statement that concatenates the raw name bypasses the check
entirely. Enumerate the statements.

**Trace.** §7 "Also:" · `authz/roles.go:14` · `CLAUDE.md` SQL invariant.

---

### ZK-SQL-004 · All zk SQL lives in one `sql.go` per package — **ESSENTIAL**

**Aim.** `zkauthn/sql.go` and `zkauthz/sql.go` hold every statement, greppable in one place.

**Point of failure.** `CLAUDE.md`: *"go-pg is in maintenance mode, so keeping SQL greppable in one
file per package is the migration plan."* SQL scattered across files is SQL that a migration off
go-pg will miss — and a missed statement is one that silently keeps using the old driver's semantics,
including its error classification, which is ZK-SQL-005.

**Procedure.** Grep the zk packages for SQL-shaped string literals and `orm.DB` method calls outside
`sql.go`. Assert none. Assert every exported method's queries are constructed from `sql.go`'s
rendered strings.

**Pass.** No SQL outside `sql.go`.

**Fail.** Any statement elsewhere, including in a test helper that the packages themselves use.

**Avoidance.** (a) Assert `sql.go` is non-empty and its statements are actually used. (b) Do not
exempt "trivial" queries — the advisory lock statement is one line and is the most important one in
the tree path.

**Trace.** `CLAUDE.md` SQL invariant · §6 · §9.

---

### ZK-SQL-005 · Errors are classified by SQLSTATE — **ESSENTIAL**

**Aim.** Classification goes through `luimaerr.SQLState`, never a type assertion.

**Point of failure.** `CLAUDE.md` states the trap precisely: *"`pg.Error` is an interface, not pgx's
`*pgconn.PgError`."* A type assertion to the concrete pgx type **compiles** and never matches, so
every classified branch falls to the default. A unique-violation on `auth_zk_nullifiers` — the control
enforcing one-shot single use — becomes an unclassified internal error instead of the expected
conflict, and whether that denies or retries depends on the default branch. ZK-NUL-002's 8-goroutine
test may still pass while the code path is wrong, because the insert genuinely failed.

**Procedure.** Grep for type assertions on database errors in the zk packages; assert none. Trigger
each classified condition — unique violation on the nullifier, on the commitment, foreign-key
violation on a cascade, check violation on `kind` — and assert each maps to the intended `kalerr`
code through `luimaerr.SQLState`.

**Pass.** Every condition classified correctly; no type assertions.

**Fail.** Any assertion on a concrete error type, or a condition falling to the default.

**Avoidance.**
(a) *Negative variant:* an unrelated error (a syntax error, a connection failure) must **not** be
classified as a conflict.
(b) *False-pass trap:* testing classification through a mock that returns a `*pgconn.PgError`
directly. The bug is that the real driver returns something else. Trigger the real condition against
a real database.

**Trace.** `CLAUDE.md` SQL invariant · §9.

---

### ZK-SQL-006 · Cascades are exactly as specified — **ESSENTIAL**

**Aim.** `on delete cascade` and `on delete set null` behave as §9 declares.

**Point of failure.** Two directions. `auth_zk_credentials.issued_to` is `on delete set null` — so
deleting a user leaves the **leaf in the tree**, unrevoked and now unattributable. That is the
intended trade (the credential outlives the account record) and it must be tested, because the natural
mistake is `cascade`, which deletes the credential row and leaves the tree node behind: an orphaned,
live, unrevocable leaf. Meanwhile `auth_zk_nullifiers.user_id` is `on delete cascade` — deleting a
user deletes the pseudonym link, so the member's next login creates a **new** account, silently.

**Procedure.** For each FK in §9's list, delete the parent and assert the child's fate matches the
declaration. Specifically: delete a user with a credential — assert `issued_to` is null, the
credential row survives, and **the leaf is still in the tree**; assert an operator can still revoke it
by leaf index (ZK-ENR-006). Delete a user with a nullifier — assert the nullifier row is gone and
document that the next login creates a new pseudonym.

**Pass.** Every cascade matches; the orphaned-leaf case is revocable.

**Fail.** Any mismatch, or a leaf that becomes unrevocable.

**Avoidance.**
(a) *Negative variant:* deleting an unrelated user affects nothing.
(b) *False-pass trap:* reading the DDL. Read the live catalog and exercise the delete — a later
migration or an ORM-generated constraint can differ from the file.

**Trace.** §9.

---

### ZK-SQL-007 · RLS still applies to zk-created rows — **ESSENTIAL**

**Aim.** The third layer of the authorization story is unaffected by the pseudonymous account.

**Point of failure.** `README.md`'s three-layer story is `@auth` → `Scope` → RLS. A pseudonym's
`UserID` is a real uuid precisely so RLS behaves normally (§7). If any zk path uses a connection with
RLS bypassed — a superuser role for the advisory lock, a separate pool for the tree writes — then rows
created or read on that connection escape the third layer, and the escape is invisible because the
first two layers still pass.

**Procedure.** Assert every zk query runs on the same RLS-subject connection/role as core queries.
Behaviourally: create a row as a pseudonym; assert RLS prevents another principal reading it directly.
Assert the tree-write path's connection is not privileged beyond what the advisory lock needs.

**Pass.** RLS applies uniformly; no privileged pool.

**Fail.** Any zk path on a bypassing role.

**Avoidance.** (a) Assert the pseudonym **can** read its own rows. (b) Do not accept "the tree tables
have no RLS policy" as coverage — the question is the role the connection uses, not the policy on the
zk tables.

**Trace.** §7 · `README.md` three-layer story · `authz`.

---

### ZK-SQL-008 · The migration is idempotent and ordered — **GOOD-TO-HAVE**

**Aim.** `0002_zk.sql` applies once, after `0001`, on a fresh database and on an existing one.

**Procedure.** Apply to a fresh database; apply to a database already at `0001` with data; apply twice
and assert the second is a no-op or a clean refusal. Assert it cannot apply before `0001` (the FKs to
`auth_users` and `auth_sessions` must fail).

**Pass.** All four.

**Fail.** A partial application, or an apply-before-`0001` that succeeds (meaning the FKs are missing).

**Avoidance.** (a) Assert the tables work after each successful path. (b) Do not add `if not exists`
everywhere to make the double-apply pass — that hides a genuine ordering bug and makes a partially
applied migration look complete.

**Trace.** §9 · `migrations`.

---

## 17 · Group INV — Repository invariants

These are not cryptography. They are the invariants in `CLAUDE.md` that make everything above
reviewable, and each has a failure mode with no error message.

### ZK-INV-001 · Every new exported symbol has a hand-written shim — **CRITICAL**

**Aim.** Root types are aliases and root functions are wrappers, for every symbol the zk work exports.

**Point of failure.** `CLAUDE.md`: *"A new exported symbol in a sub-package is invisible from `kal.`
until added to `kal.go` by hand."* The security consequence is specific: a consumer who cannot reach
`kal.MembershipRequest` from the root reaches into `zkauthn` directly, bypassing whatever the root
wrapper does — and the wrappers are where the semaphore acquisition, the uniform error mapping and the
context plumbing live. An invisible symbol is not a missing feature; it is a second, unguarded API.

**Procedure.** Enumerate every exported identifier in `zkauthn` and `zkauthz` (reflection or
`go/types`). Assert each has a corresponding alias or wrapper in `kal.go`. Assert `tests/kal_test.go`
carries a compile-time identity assertion for each — the pattern already exists for the core packages
and is the model.

**Pass.** Complete coverage in both `kal.go` and `tests/kal_test.go`.

**Fail.** Any exported symbol without both.

**Avoidance.**
(a) *Negative variant:* assert an alias actually resolves to the sub-package type — `var _ zkauthn.X =
kal.X{}` — rather than to a re-declared struct with the same fields. A copied type compiles, satisfies
a name check, and is a different type at every boundary.
(b) *False-pass trap:* enumerating by hand. The check must be generated from the package's actual
exported set, or the next symbol is missed and the test stays green.

**Trace.** `CLAUDE.md` re-export shim · §7 "Also:".

---

### ZK-INV-002 · The zero `Config` is the production posture — **CRITICAL**

**Aim.** No zk field relaxes a security property at its zero value, and no environment flag exists.

**Point of failure.** `CLAUDE.md`: *"This inverts luima, where the zero Config is the good development
config. There is no `Dev` bool and no environment flag that relaxes a security property."* The zk
surface adds several candidates: `RootGrace` (ZK-TRE-007), a verification bound, a challenge TTL, and
any "skip the vk hash check for local development" convenience. Each is a property whose safe value
must be the zero value, and the zero value is what every deployment that never read the docs runs.

**Procedure.** Construct a zero `Config` and assert, field by field: `RootGrace == 0` and behaving
strictly; the verification semaphore bounded (not zero-meaning-unlimited); the challenge TTL at its
short default (not zero-meaning-never-expires); the vk hash check mandatory; introspection off.
Reflect over every zk config field and assert its zero value is the strict one. Assert no
`os.Getenv` anywhere in `zkauthn`/`zkauthz`.

**Pass.** Every zero value is the strict value; no environment reads.

**Fail.** Any zero-means-permissive field, especially a zero TTL or a zero semaphore.

**Avoidance.**
(a) *Negative variant:* the strict defaults must permit a legitimate flow — a zero config that refuses
every login is not a posture.
(b) *False-pass trap, the one that matters here:* a numeric field where `0` is idiomatic Go for
"unset" and the code reads `if n == 0 { n = unlimited }`. Assert the **behaviour** at zero, not the
field's value. This is the same trap as ZK-TRE-007(b) and it will appear on every numeric field the
zk work adds.

**Trace.** `CLAUDE.md` zero-Config invariant · §6 · §9.

---

### ZK-INV-003 · Tests live outside the packages they exercise — **ESSENTIAL**

**Aim.** `package tests`, reaching only the exported surface.

**Point of failure.** `CLAUDE.md`: *"If a security property can't be asserted from out there, a
consumer can't rely on it either, and the exported surface is what changes."* An internal test that
reaches an unexported helper to construct a witness, or to bypass the semaphore, asserts a property
of code no consumer can invoke. The test is green and the shipped API is untested.

**Procedure.** Assert no `_test.go` file exists inside `zkauthn` or `zkauthz`. Assert every zk test is
in `package tests`. For each CRITICAL case in this register, assert it is expressible through the
exported surface — and where it is not, that the **exported surface changed**, not the test's package.

**Pass.** No internal tests; every critical property reachable from outside.

**Fail.** Any internal test file, or a critical property only assertable internally.

**Avoidance.**
(a) *Negative variant:* the properties must actually be asserted — an empty external test package
satisfies the structural check.
(b) *False-pass trap:* adding an `Export_` helper or a `//export_test.go` bridge. That is an internal
test wearing an external package clause, and it re-opens the exact gap the invariant closes.

**Trace.** `CLAUDE.md` test-location invariant · §10.

---

### ZK-INV-004 · Test naming matches CI's gates — **ESSENTIAL**

**Aim.** Differential tests run without a database; database tests are visible to CI's grep.

**Point of failure.** `CLAUDE.md`: *"`make test` alone proves less than it looks: `TestDB*` skips
without `DATABASE_URL`, and a skip still reports `ok`."* Two symmetric failures. A differential test
named `TestDBZKDifferential` skips in `make test` and reports `ok` — the single highest-value test in
the module never runs and the output says it passed. A database test named `TestZKSomething` runs
where a database exists and is invisible to CI's `--- PASS: TestDB` grep, so its absence from a run is
not detected.

**Procedure.** Enumerate zk test names. Assert every circuit-level test (differential, hash agreement,
constraint count, `CircuitID`, public-witness pin) is **not** prefixed `TestDB` and passes with
`DATABASE_URL` unset. Assert every database-backed case **is** prefixed `TestDBZK`. Run `make test`
with no database and assert the circuit cases actually executed — count assertions, not the `ok`.

**Pass.** Correct prefixes; circuit cases execute without a database.

**Fail.** Any misprefix, or a circuit case that skips.

**Avoidance.**
(a) *Negative variant:* run `make test-db` and assert the `TestDBZK*` cases produce `--- PASS` lines
the grep would find.
(b) *False-pass trap:* trusting `ok`. Assert on the executed-assertion count, which is the whole point
of this invariant existing.

**Trace.** `CLAUDE.md` commands section · §10.

---

### ZK-INV-005 · Gotchas 40–63 exist and precede the code — **ESSENTIAL**

**Aim.** `docs/gotchas.md` carries the three new sections, written in Phase 0.

**Point of failure.** Handout §13: *"entries 40–63 are the checklist for Phases 1–4, not their
write-up, and a register written afterwards records what you already got right."* A register written
after the fact is a description of the implementation, and it will omit precisely the failures the
implementation has — because the author did not encounter them. Its value as a checklist for the next
change is then zero.

**Procedure.** Assert `docs/gotchas.md` contains entries 40–63 under the three headings (`## Circuits`,
`## The gnark surface`, `## The tree and the protocol`, `## Proving keys and operations`). Assert each
entry describes a failure with **no error, no log line and a passing test suite** — matching the
register of 1–39. Assert via git history that they landed before the circuit code.

**Pass.** All 24 present, in register, before the code.

**Fail.** Missing entries, entries that describe a loud failure, or entries committed after the code
they describe.

**Avoidance.**
(a) *Negative variant:* cross-check each entry against this register's Trace column — an entry with no
corresponding test is a gotcha nothing catches, which §10's closing line names as the point: *"a
control whose test you cannot name is a control that is not there."*
(b) *False-pass trap:* counting entries. Read them; an entry that says "be careful with X" is not in
this register's voice and will not stop anything.

**Trace.** §11 · §13 Phase 0 · `CLAUDE.md`.

---

### ZK-INV-006 · `SECURITY.md`'s control table gains the zk rows — **ESSENTIAL**

**Aim.** Every control in this register appears in `SECURITY.md`'s `| control | the test that fails
without it |` table.

**Point of failure.** Handout §10: *"It also forces the property: a control whose test you cannot name
is a control that is not there."* The table is the mechanism that converts a claim into an obligation.
A control described in prose and absent from the table is a claim nobody has to keep.

**Procedure.** Assert the table contains at minimum the twelve rows handout §10 lists, plus a row for
every CRITICAL case in this register. Assert every named test exists and is currently green. Assert
no row names a test that skips (ZK-INV-004).

**Pass.** Complete, and every named test exists and runs.

**Fail.** A row naming a nonexistent or skipping test — worse than a missing row, because it reads as
covered.

**Avoidance.**
(a) *Negative variant:* delete a named test and assert the check fails, so the table is verified rather
than transcribed.
(b) *False-pass trap:* starting a second register. Handout §10: *"the zk work adds to it rather than
starting a second register."* Two tables mean one gets updated.

**Trace.** §10 · §13.

---

### ZK-INV-007 · `README.md`'s dependency claims are corrected — **ESSENTIAL**

**Aim.** The three statements gnark falsifies are rewritten.

**Point of failure.** Handout §0 names them: the *"adds one dependency beyond luima's graph"*
paragraph, the *What is in the box* table, and *"OAuth/OIDC and TOTP MFA are planned as separate
opt-in packages, so their dependencies stay out of the graph of anyone who does not use them."* zk is
the counterexample to the third, so leaving it standing *"leaves the README arguing against this
module."* This is a security-adjacent honesty failure: *"a README that overstates the dependency
posture of an auth library is the kind of thing this repo keeps a whole gotchas file about."*

**Procedure.** Assert all three statements are rewritten to reflect gnark, gnark-crypto and their
transitive set being in the module graph of every consumer. Assert the README states plainly that
build tags do not help — *"`//go:build` excludes a file from a compilation, not a module from `go.mod`
and `go.sum`."* Assert the actual module graph matches what the README claims: `go mod graph`
compared against the documented set.

**Pass.** All three corrected; the graph matches the claim.

**Fail.** Any surviving claim, or a graph larger than documented.

**Avoidance.**
(a) *Negative variant:* assert the README still documents the seams accurately — a rewrite that
deleted the dependency discussion entirely passes a "no false claim" check.
(b) *False-pass trap:* checking the prose without checking `go mod graph`. The claim is about the
graph; verify the graph.

**Trace.** §0 "On packaging" · §13 Phase 0.

---

### ZK-INV-008 · `CHANGELOG.md` carries an `[Unreleased]` entry per phase — **GOOD-TO-HAVE**

**Aim.** Each phase ends with a changelog entry.

**Procedure.** Assert `## [Unreleased]` exists and that each phase's merge added an entry naming the
security-relevant behaviour changes — new codes in `kalerr`, the `Scope` hardening, the directive
argument, the new config fields and their strict defaults.

**Pass.** Present per phase.

**Fail.** Absent, or entries that omit the behaviour changes a consumer must act on (`Scope`'s new
denial, `RootGrace`'s default).

**Avoidance.** (a) Assert the `Scope` change is listed — it changes behaviour for existing consumers
who construct principals directly, and it is the entry most likely to be omitted as "internal
hardening". (b) Do not accept "added zk support" as an entry.

**Trace.** `CLAUDE.md` · §13.

---

### ZK-INV-009 · `make check` is green at each phase boundary — **ESSENTIAL**

**Aim.** gofmt, vet, lint, `test-db` and audit all pass at every phase.

**Point of failure.** Handout §13: *"`make test` alone reports `ok` while proving nothing here, same
as everywhere else in this repo."* A phase merged on `make test` alone has run neither the database
cases nor the audit, and the database cases are where every concurrency control in Groups TRE, NUL and
PSD lives.

**Procedure.** At each phase boundary run `make check` and assert green. Assert the run included
`--- PASS: TestDB` lines for every `TestDBZK*` case. Assert `make audit`'s govulncheck ran against a
current toolchain — handout §13: an out-of-date local Go fails it even when kal is clean, and the fix
is upgrading Go.

**Pass.** Green, with the DB cases visibly passing.

**Fail.** Green with zero `--- PASS: TestDB` lines — that is a skipped suite reporting success.

**Avoidance.** (a) Assert a deliberately failing DB case actually fails the run, confirming the gate
works. (b) Do not suppress a govulncheck finding to make the gate green.

**Trace.** §13 · `CLAUDE.md` commands section.

---

## 18 · Group E2E — End to end

Each of these composes controls that pass individually and can still fail together.

### ZK-E2E-001 · A zk login yields a working, correctly-scoped session — **CRITICAL**

**Aim.** `TestDBZKLogin`, the composite case handout §10 specifies.

**Procedure.** Full HTTP path. Enrol a member. Request a challenge. Prove. Log in. Then:
1. The response sets a session cookie; a subsequent request with it resolves a `*authz.Principal`.
2. `kal.Scope(ctx, "owner_id")` for that principal returns **its own rows only** — asserted by seeding
   rows for three other users and confirming **those rows are still present** and unreturned, per
   `CONTRIBUTING.md`'s rule.
3. The `auth_sessions` row has **no `ip` and no `user_agent`**, from a request that carried both.
4. `auth_zk_nullifiers` has exactly one row, `consumed_at` null (recurring), `user_id` set.
5. `auth_users` has exactly one pseudonym row with the `zk-…@invalid` email.
6. The challenge row is consumed.

**Pass.** All six.

**Fail.** Any one. In particular, 3 failing means the cryptography worked and the product did not.

**Avoidance.**
(a) *Negative variant:* a second, unrelated principal's `Scope` returns *its* own rows, so step 2 is
not satisfied by a `Scope` that returns nothing.
(b) *False-pass trap:* driving this through Go method calls rather than HTTP. `session.Meta` is
populated from the request; skipping the transport skips the only place step 3 can fail.

**Trace.** §7 · §10 · gotcha 62.

---

### ZK-E2E-002 · `Knowledge` fills the `mfa` seam — **CRITICAL**

**Aim.** After a verified `Knowledge` proof, `@auth(mfa: true)` stops always-denying and starts
meaning something.

**Procedure.** Field annotated `@auth(mfa: true)`, resolver instrumented. (i) Authenticated, no proof:
assert denied, counter 0. (ii) Enrol, prove, resubmit: assert resolved, counter 1. (iii) A second
session for the same user: assert still denied, counter unchanged (ZK-CHL-004). (iv) After session
revocation and re-login: assert denied again — `mfa_at` belongs to the session, not the user.

**Pass.** All four.

**Fail.** (i) or (iii) resolving, or (iv) carrying the elevation forward.

**Avoidance.**
(a) *Negative variant:* (ii). Without it, the pre-existing always-deny behaviour passes (i), (iii) and
(iv) perfectly and nothing was built.
(b) *False-pass trap:* (iv) omitted. Elevation surviving a re-login is the shape that turns a second
factor into a one-time formality.

**Trace.** §4a · `authz/directive.go:102`.

---

### ZK-E2E-003 · `Membership` satisfies `@auth(proves:)` and only that — **CRITICAL**

**Aim.** The full path from proof to directive to resolver.

**Procedure.** Claims `age_over_18` (threshold 18) and `is_member` (threshold 0), both recurring.
Member with `Attribute = 21`. (i) Before any proof: both fields deny, counters 0. (ii) Prove
`is_member`: that field resolves; `age_over_18` still denies. (iii) Prove `age_over_18`: both resolve.
(iv) A member with `Attribute = 12` proves `is_member` only: `age_over_18` denies, and the
request-supplied `Threshold: 0` variant denies (ZK-INP-001). (v) Revoke the credential: on the next
session, both deny.

**Pass.** All five.

**Fail.** Any cross-satisfaction, or (iv) granting.

**Avoidance.**
(a) *Negative variant:* (ii) and (iii)'s positive halves.
(b) *False-pass trap:* using one claim. Cross-satisfaction is the failure and it needs two.

**Trace.** §5 · §7 · §10.

---

### ZK-E2E-004 · The full revocation story — **ESSENTIAL**

**Aim.** Revocation removes the credential, the tree membership and the ability to log in, and
existing sessions are handled per the documented decision.

**Procedure.** Member logs in (session S). Revoke the credential. Assert: (i) a new login fails; (ii)
the leaf is `zeros[0]`; (iii) a new root was published; (iv) S's fate matches the written decision —
either it survives until expiry (credential revocation ≠ session revocation) or it is revoked, and
whichever it is, it is documented. Assert `RootGrace = 0` closes the window immediately and
`RootGrace > 0` leaves the documented latency (ZK-TRE-008).

**Pass.** (i)–(iii) hold; (iv) matches a written decision.

**Fail.** A successful new login, or (iv) undecided. [UNSPECIFIED] — the handout does not say whether
credential revocation revokes live sessions; see §23.

**Avoidance.**
(a) *Negative variant:* another member logs in fine after the revocation.
(b) *False-pass trap:* assuming session revocation follows. `auth_sessions.revoked_at` is a separate
control and nothing in the handout couples them.

**Trace.** §6 · §7 · §12.

---

### ZK-E2E-005 · Two replicas agree — **ESSENTIAL**

**Aim.** The composite of ZK-TRE-004 and the login path.

**Procedure.** Two instances, one database, one verifying key. Enrol on A. Log in on B without any
coordination. Enrol on B; log in on A. Revoke on A; assert B refuses immediately at `RootGrace = 0`.
Assert both instances' `CircuitID` and vk hash match.

**Pass.** Symmetric behaviour throughout.

**Fail.** Any instance-dependent outcome.

**Avoidance.** (a) Assert both instances can independently serve the *same* member. (b) Separate
connection pools — see ZK-TRE-004(b).

**Trace.** §6 · §8 · gotcha 53.

---

### ZK-E2E-006 · The whole thing is anonymous at the database — **CRITICAL**

The composite privacy case: every individual control can pass and the join can still exist.

**Aim.** From the operator's own database, a proof cannot be attributed to a member.

**Procedure.** Enrol members M₁…M₁₂. Have M₇ log in and act. Then, as the operator with full database
access, attempt to determine which member acted, using only: `auth_zk_credentials` (including
`issued_to`), `auth_zk_nodes`, `auth_zk_roots`, `auth_zk_nullifiers`, `auth_users`, `auth_sessions`
and any log output. Assert the best achievable attribution is **one of twelve** — the non-revoked leaf
count — and enumerate every column examined so the analysis is repeatable.

**Pass.** No column or join narrows below the anonymity set.

**Fail.** Any narrowing. The likely culprits, in order: `auth_sessions.ip` (ZK-SES-001), a timestamp
correlation between the credential's `created_at` and the nullifier's `first_seen_at`
(ZK-DOC-004), a log line (ZK-SES-003), and a convenience column added since the last audit
(ZK-NUL-004).

**Avoidance.**
(a) *Negative variant:* confirm the operator **can** determine that *a member* acted, and can revoke
by user — the properties the design keeps. A system that reveals nothing at all has broken revocation.
(b) *False-pass trap, the significant one:* running this with a tree of 1 or 2 members. The anonymity
set is the count of non-revoked leaves, so at N=1 the attribution is exact and correct, and the test
"fails" for a reason that is not a defect. Use twelve, and state the count in the assertion.
(c) *Third trap:* examining only the zk tables. The join runs through `auth_users` and
`auth_sessions`, which is exactly gotcha 62.

**Trace.** §1 entire · §7 · gotcha 62.

---

## 19 · The mutation matrix

The acceptance criterion for the test suite itself. Apply each mutation to a scratch branch, run the
suite, and confirm the named case goes **red**. A mutation that leaves the suite green is a control
with no test, whatever `SECURITY.md` says. Run this at each phase boundary; it is the deliverable.

### Circuit mutations — `zkauthn`

| # | mutation | must go red |
|---|---|---|
| M1 | Delete §4b line 1 (`rangecheck Attribute`) | ZK-CIR-003, ZK-CIR-006 |
| M2 | **Move** §4b line 1 to after line 5 | ZK-CIR-006 |
| M3 | Narrow the range check to 63 bits | ZK-CIR-013 |
| M4 | Delete §4b line 3 (`leaf == Path[0]`) | ZK-CIR-005, ZK-CIR-003 |
| M5 | Delete §4b line 4 (`merkle.VerifyProof`) | ZK-CIR-007, ZK-CIR-001 (`Root`) |
| M6 | Delete §4b line 5 (threshold comparison) | ZK-CIR-003, ZK-CIR-001 (`Threshold`) |
| M7 | Flip line 5 to `Attribute <= Threshold` | ZK-CIR-003 (families 1–2) |
| M8 | Delete §4b line 7 (`n == Nullifier`) | ZK-CIR-008, ZK-CIR-001 (`Nullifier`) |
| M9 | **Delete §4b line 8** (`c2 = Challenge²`) | ZK-CIR-001 (`Challenge`), ZK-CHL-001 |
| M10 | Delete §4a line 2 (`h == Commitment`) | ZK-CIR-002, ZK-CIR-001 (`Commitment`) |
| M11 | Delete §4a line 3 (`c2 = Challenge²`) | ZK-CIR-001 (`Challenge`), ZK-CHL-001 |
| M12 | Use `DOM_LEAF` for the nullifier hash | ZK-CIR-009 |
| M13 | Set `zeros[0] = 0` | ZK-TRE-010, ZK-CIR-009 |
| M14 | Swap the operands of §4b line 2 (`Attribute, Secret`) | ZK-KEY-003 *(count unchanged — this is the case the count cannot catch)* |
| M15 | Pass `Path[0]` as `VerifyProof`'s third argument instead of `Index` | ZK-CIR-003, ZK-CIR-010 |
| M16 | Swap two public struct fields | ZK-CIR-012 |
| M17 | Tag `Secret` as public | ZK-CIR-011 |
| M18 | Change `MerkleDepth` to 31 | ZK-CIR-015, ZK-KEY-003 |

### Server-side mutations — verification and policy

| # | mutation | must go red |
|---|---|---|
| M19 | Read `Threshold` from the request | ZK-INP-001 |
| M20 | Read `Commitment` from the request | ZK-INP-002 |
| M21 | Read `Audience` from the request | ZK-INP-003 |
| M22 | Skip the `auth_zk_roots` validation | ZK-INP-004 |
| M23 | Ignore `retired_at` when validating the root | ZK-INP-004, ZK-TRE-008 |
| M24 | Split the challenge burn into `SELECT` then `UPDATE` | ZK-CHL-003 |
| M25 | Key the challenge on the user instead of the session | ZK-CHL-004 |
| M26 | Drop the challenge TTL check | ZK-CHL-005 |
| M27 | Replace the challenge burn with proof-byte deduplication | ZK-CHL-002 |
| M28 | Distinguish the seven failure classes by error code | ZK-ORC-001 |
| M29 | Remove the dummy verify | ZK-ORC-002 |
| M30 | Move the dummy verify outside the semaphore | ZK-DOS-002 |
| M31 | Remove the semaphore | ZK-DOS-001 |
| M32 | Change the proof length check from `==` to `<=` | ZK-DOS-003 |
| M33 | Use `UnsafeReadFrom` | ZK-KEY-005 |
| M34 | Remove the vk hash comparison | ZK-KEY-002 |
| M35 | Parse the vk before comparing its hash | ZK-KEY-002(b) |
| M36 | Seed `Setup`'s randomness | ZK-KEY-007 |

### Tree, nullifier and integration mutations

| # | mutation | must go red |
|---|---|---|
| M37 | Move `pg_advisory_xact_lock` to just before the leaf insert | ZK-TRE-002, ZK-TRE-001 |
| M38 | Remove the advisory lock | ZK-TRE-001 |
| M39 | Cache the tree in memory | ZK-TRE-004, ZK-E2E-005 |
| M40 | Split revocation into two transactions | ZK-TRE-005 |
| M41 | Default `RootGrace` to "any published root" | ZK-TRE-007 |
| M42 | Burn the nullifier on a recurring audience | ZK-NUL-001 |
| M43 | Skip the burn on a one-shot audience | ZK-NUL-002 |
| M44 | Enforce one-shot with `SELECT` then `INSERT` | ZK-NUL-002 |
| M45 | Key `auth_zk_nullifiers` on `(nullifier, audience)` | ZK-NUL-003 |
| M46 | Populate `session.Meta` on the zk login | ZK-SES-001, ZK-E2E-001, ZK-E2E-006 |
| M47 | Restore `Scope`'s fallthrough on an empty `UserID` | ZK-AUZ-001 |
| M48 | Make a nil `Proofs` implementation allow | ZK-AUZ-002 |
| M49 | Move `proves:` before `mfa:` in the SDL declaration | ZK-AUZ-003 |
| M50 | Query the claim set inside the directive | ZK-AUZ-005 |
| M51 | Treat an unknown claim as unconstrained | ZK-AUZ-007 |
| M52 | Cache the claim set in a package-level map | ZK-AUZ-006 |
| M53 | Add a `userID` parameter to `Enroll` | ZK-ENR-002 |
| M54 | Give `auth_zk_commitments` a surrogate primary key | ZK-ENR-003 |
| M55 | Change `issued_to` to `on delete cascade` | ZK-SQL-006 |

**Reading the matrix.** A mutation whose named case stays green is one of three things, in decreasing
order of likelihood: the test asserts on an error value rather than on state (the most common defect
in this whole register); the test's fixture cannot reach the mutated path; or the control does not
exist. Diagnose in that order.

**M9, M11, M14 and M46 are the four to run first.** M9 and M11 are the constraints the compiler may
eliminate. M14 is the one the constraint count provably cannot catch. M46 is the one where every
cryptographic control passes and the product's reason for existing is gone.

---

## 20 · Traceability — gotchas 40–63

Every gotcha the handout specifies must have at least one case that fails without the control. A
gotcha with no case is a documented failure nothing detects.

| gotcha | subject | cases |
|---|---|---|
| 40 | Under-constrained circuit proves a false statement | ZK-CIR-002, ZK-CIR-003, ZK-CIR-004 |
| 41 | `Path[0]` is prover-supplied | ZK-CIR-005 |
| 42 | An unread public input is not bound | ZK-CIR-001 |
| 43 | Groth16 proofs are malleable | ZK-CHL-002 |
| 44 | One hash, two purposes | ZK-CIR-009, ZK-TRE-010 |
| 45 | Values ≥ the modulus wrap silently | ZK-HSH-003, ZK-CIR-004 (family 5) |
| 46 | Comparison without a range check | ZK-CIR-006 |
| 47 | `IsSolved` proves satisfiability, not exclusivity | ZK-CIR-002/003 (both directions), ZK-CIR-013 |
| 48 | `VerifyProof`'s third parameter is the index | ZK-CIR-005, ZK-CIR-010, M15 |
| 49 | Struct field order is the witness layout | ZK-CIR-011, ZK-CIR-012 |
| 50 | `UnsafeReadFrom` skips curve and subgroup checks | ZK-KEY-005 |
| 51 | Native and in-circuit MiMC are two implementations | ZK-HSH-001, ZK-HSH-002 |
| 52 | An empty leaf of `0` is a credential | ZK-TRE-010 |
| 53 | A tree in memory is a root per replica | ZK-TRE-004, ZK-E2E-005 |
| 54 | Two concurrent appends publish an unverifiable root | ZK-TRE-001, ZK-TRE-002, ZK-TRE-011 |
| 55 | A retired root that verifies is a live revoked credential | ZK-TRE-006, ZK-TRE-007, ZK-TRE-008 |
| 56 | Pseudonym and single-use conflated | ZK-NUL-001, ZK-NUL-002, ZK-NUL-005 |
| 57 | `SELECT`-then-`INSERT` is not single-use | ZK-NUL-002, ZK-PSD-002, ZK-CHL-003 |
| 58 | A public input from the request is attacker-chosen | ZK-INP-001…004, ZK-NUL-009 |
| 59 | A proof not bound to an audience replays elsewhere | ZK-NUL-008, ZK-NUL-009 |
| 60 | A writable verifying key is a universal bypass | ZK-KEY-002, ZK-KEY-003 |
| 61 | Verification is unauthenticated CPU | ZK-DOS-001, ZK-DOS-003, ZK-DOS-004, ZK-CHL-006 |
| 62 | `session.Issue` writes `ip` and `user_agent` | ZK-SES-001, ZK-SES-002, ZK-E2E-001, ZK-E2E-006 |
| 63 | A distinguishable "no commitment" is an oracle | ZK-ORC-001, ZK-ORC-002, ZK-DOS-002 |

**Gotchas with no dedicated negative-side case, flagged:** none. **Cases with no gotcha behind them**
— i.e. this register's additions to the handout's own checklist: ZK-KEY-007 (deterministic ceremony),
ZK-ENR-001 (enrolment authorization), ZK-ENR-004 (operator-set attribute), ZK-SES-006 (session
fixation), ZK-SES-008 (root as fingerprint), ZK-SQL-003 (schema-prefix injection), ZK-SQL-007 (RLS on
zk paths), ZK-CIR-017 (two leaves, one secret). Each is a candidate gotcha entry.

---

## 21 · Traceability — handout sections

| § | subject | cases |
|---|---|---|
| §0 | Packaging, curve, setup, secret length, depth | ZK-HSH-003, ZK-KEY-001, ZK-KEY-007, ZK-TRE-013, ZK-INV-007 |
| §1 | What this buys and what it does not | ZK-SES-001, ZK-SES-007, ZK-E2E-006, ZK-DOC-001…006 |
| §2 | The four "no"s | ZK-CIR-006, ZK-CIR-013, ZK-CIR-015, ZK-TRE-013, ZK-AUZ-013 |
| §3 | The five-stage checklist | ZK-CIR-002, ZK-CIR-015, ZK-CIR-016, ZK-KEY-003 |
| §4a | `Knowledge` | ZK-CIR-002, ZK-INP-002, ZK-CHL-004, ZK-ENR-002, ZK-ENR-003, ZK-E2E-002 |
| §4b | `Membership` | ZK-CIR-003…013, ZK-CIR-017, ZK-NUL-004 |
| §5 | What the verifier must supply | ZK-INP-001…006, ZK-ORC-001, ZK-ORC-002 |
| §6 | The tree | ZK-TRE-001…014 |
| §7 | The integration seam | ZK-NUL-001…009, ZK-PSD-001…006, ZK-SES-001…007, ZK-AUZ-001…013 |
| §8 | Keys | ZK-KEY-001…008 |
| §9 | Schema and DoS | ZK-SQL-001…008, ZK-DOS-001…006, ZK-CHL-005, ZK-CHL-006 |
| §10 | Tests | Harness preconditions P-1…P-8; every case's Avoidance field |
| §11 | Gotchas 40–63 | §20, ZK-INV-005 |
| §12 | Deliberately not here | ZK-DOC-002, ZK-DOC-006, ZK-PSD-006, ZK-AUZ-010 |
| §13 | Phases | ZK-INV-005…009, §24 |
| §14 | Decide before Phase 1 | ZK-ENR-004, ZK-DOC-003, ZK-KEY-007, §23 |

---

## 22 · Out of scope — tested as documentation, not as controls

Handout §1 says these belong in `SECURITY.md` *"alongside 'What kal does not defend against — your
responsibility', in the same register."* Each case below asserts the text exists and says the right
thing. None asserts a control, because there is none to assert — that is the point, and a deployment
that has not read them *"will believe it bought more than it did."*

### ZK-DOC-001 · The anonymity set is the non-revoked leaf count — **ESSENTIAL**

**Aim.** `SECURITY.md` states that twelve members is one-in-twelve, and that the first proof after the
first enrolment is one-in-one.

**Point of failure.** *"The tree is the anonymity, and an empty tree has none."* A deployment with a
handful of members has built *"an expensive pseudonym system, which may still be what it wants, but it
should know which one it bought."* Selling this as anonymity without the sentence is the whole failure.

**Procedure.** Assert the paragraph exists, states the count relationship, names the one-in-one case,
and — per ZK-SES-008 — states the intersection with the named root rather than the raw leaf count.

**Pass.** Present, with the intersection qualification.

**Fail.** Absent, or claiming anonymity without a set-size qualifier.

**Avoidance.** (a) Cross-check against `README.md` — a correct `SECURITY.md` and an overselling README
is the same failure. (b) Do not add a runtime warning below a threshold; the anonymity set is a
deployment property, not a config error, and a warning that fires on every small deployment is a
warning that gets suppressed.

**Trace.** §1.

---

### ZK-DOC-002 · The operator is the verifier and can always lie — **ESSENTIAL**

**Aim.** `SECURITY.md` states that zero-knowledge protects users from each other and privacy from an
operator that follows its own code, and does not make a malicious operator honest.

**Point of failure.** This is §0's trusted-setup argument generalized and it is the load-bearing
sentence for the whole single-party ceremony decision. Omit it and a reader concludes the operator
cannot forge — which is false, and which matters the moment kal is deployed where the issuer and the
verifier are different parties. That deployment needs PLONK, and §12 names the condition.

**Procedure.** Assert the paragraph exists and that §12's PLONK condition is stated: *"§0's argument
holds because the operator running the setup is the verifier. Deploy kal where those are different
parties … and the argument fails."*

**Pass.** Both present.

**Fail.** Either absent — particularly the PLONK condition, which is what a future deployment needs to
recognise its own situation.

**Avoidance.** (a) Assert the ceremony instructions do not imply a third party can rely on the proofs.
(b) Do not soften it into "the operator is trusted"; the point is *which* trust and *why it is
acceptable here*.

**Trace.** §0 · §1 · §12.

---

### ZK-DOC-003 · The prover is the operator's JavaScript — **ESSENTIAL**

**Aim.** `SECURITY.md` and `README.md` state that meaningful anonymity requires a client the operator
did not ship, and that WASM packaging is the consumer's problem.

**Point of failure.** Handout §1: *"If the operator serves the code that holds the secret, it can serve
code that exfiltrates it, and every property above collapses to a promise."* §12 requires this be said
*"plainly in the README rather than half-shipped."* A deployment that ships a browser prover from its
own origin has an anonymity story with no floor, and nothing in the code can tell it so.

**Procedure.** Assert both documents state it. Assert §14's decision — kal ships the Go prover and the
wire format and stops — is recorded with its date and the reason.

**Pass.** Stated in both, with the decision recorded.

**Fail.** Absent, or a half-shipped WASM prover in the repo without the caveat.

**Avoidance.** (a) Assert the documented wire format is complete enough that a third-party prover is
actually buildable — otherwise the caveat is advice with no alternative. (b) Do not ship a
"reference" browser prover; §12 lists it as deliberately not here.

**Trace.** §1 · §12 · §14.

---

### ZK-DOC-004 · Timing links enrolment to first use — **ESSENTIAL**

**Aim.** The correlation is documented: a credential issued at T and first proved at T+ε is one
correlation, recorded in the operator's own logs.

**Point of failure.** `auth_zk_credentials.created_at` and `auth_zk_nullifiers.first_seen_at` are both
in the schema by design. In a low-traffic deployment they are a join. Nothing in the protocol prevents
it, and no control in this register closes it — ZK-E2E-006 will surface it as a narrowing and this
case is where the answer lives.

**Procedure.** Assert `SECURITY.md` states it. Additionally, assert as a **finding** whether the
timestamp granularity makes the correlation practical for the reference deployment shape, and record
the mitigation available to a deployment that cares (coarsen `first_seen_at`, or delay first use).

**Pass.** Documented, with the granularity finding recorded.

**Fail.** Absent.

**Avoidance.** (a) Do not "fix" it by dropping the timestamps — `first_seen_at` is operationally
necessary and `created_at` is how revocation is reasoned about. (b) Assert ZK-E2E-006's analysis
explicitly examined this join, so the two cases do not each assume the other covered it.

**Trace.** §1.

---

### ZK-DOC-005 · `issued_to` is the operator's leaf ↔ user map — **ESSENTIAL**

**Aim.** Documented that the operator knows who *is* a member, only not who *acted*, and that a
deployment refusing that sets the column null and loses per-member revocation.

**Procedure.** Assert `SECURITY.md` states both halves — the disclosure and the cost of removing it.
Assert ZK-SES-007's behaviour (null tolerated, revocation by index still works) matches what the
document promises.

**Pass.** Both halves documented and matching the behaviour.

**Fail.** The disclosure documented without the cost, or the cost stated without being true (i.e. a
null `issued_to` that breaks more than per-member revocation).

**Avoidance.** (a) Verify the claim rather than transcribing it — ZK-SES-007(ii) is that verification.
(b) Do not present it as optional if the implementation depends on it elsewhere.

**Trace.** §1 · §9.

---

### ZK-DOC-006 · Claims bind to the session, not the credential — **ESSENTIAL**

**Aim.** Documented that one person holding two credentials satisfies two claims with two different
secrets, and that binding them means a second circuit and a second ceremony.

**Procedure.** As ZK-AUZ-010. Assert the property is stated and the non-fix is explained, per handout
§7: *"State the property; do not build the fix."*

**Pass.** Stated with the reason.

**Fail.** Absent — a deployment will build a conjunction policy assuming a guarantee that is not there.

**Avoidance.** (a) Assert the conjunction over the *session* is still enforced (ZK-AUZ-010's negative
variant). (b) Do not describe it as a limitation to be lifted later; it is a design boundary with a
named cost.

**Trace.** §7 · §12.

---

## 23 · Findings against the handout itself

Nine questions this register had to answer to write a case, and which `docs/zk-handout.md` does not
settle. Each is a decision somebody will make by accident during implementation. They are ordered by
consequence.

**F-1 · Who may enrol a `Membership` credential?** — ZK-ENR-001. The handout specifies `Enroll`'s
cryptography exactly and never names the guard. Self-service enrolment is a total bypass that touches
no cryptography: the attacker enrols, gets a secret, is a member, and every constraint holds. It also
destroys the anonymity set — enrol N times and own N of M leaves. **This is the largest gap in the
document.** It needs a sentence in §4b or §9 naming the authorization, and a corresponding row in
`SECURITY.md`.

**F-2 · Does credential revocation revoke live sessions?** — ZK-E2E-004. §6 revokes a leaf; §7 says
*"revocation stays `auth_sessions.revoked_at`"* for sessions. Nothing couples them. An operator
revoking a compromised credential will reasonably expect the holder's live session to end, and it
will not. Decide and document; the safe default is that credential revocation cascades to that
pseudonym's sessions, but the pseudonym-to-session link runs through `auth_zk_nullifiers.user_id`,
which is exactly the join §7 is careful about.

**F-3 · Is `kind = 'one_shot'` admissible in `@auth(proves:)`?** — ZK-AUZ-011. §7 describes one-shot
as one action per member per audience and describes `@auth(proves:)` as a per-request claim check.
The two compose badly in both directions: either the field works once per member ever, or the burned
row satisfies the claim forever. A startup validation rejecting one-shot claims in `proves:` is the
cheapest resolution.

**F-4 · Does `@auth(proves: [])` allow or deny?** — ZK-AUZ-009. Vacuous truth over an empty set means
the natural implementation allows, and the annotation reads as a restriction. Fail-closed matches
every other decision in the document; say so in the directive's doc comment.

**F-5 · Are leaf indices reused after revocation?** — ZK-TRE-012. §6 revokes by setting a leaf to
`zeros[0]`, which makes the slot indistinguishable from never-used. Whether the next enrolment lands
there changes what `issued_to` means historically and whether `leaf_index` is a stable reference.
Monotonic is the simpler answer and costs nothing at depth 32.

**F-6 · What is the advisory lock key?** — ZK-TRE-003. Advisory locks are per-database, not
per-schema, and kal renders all its SQL with a configurable schema prefix — so two kal installations
in one database will contend on a bare key. Derive it from the schema name and say so.

**F-7 · May one secret hold two leaves with different attributes?** — ZK-CIR-017. The `unique`
constraint is on the commitment, and the commitment includes the attribute, so it does not prevent
this. The holder then chooses which attribute to prove, and an operator "lowering" someone's attribute
by re-enrolling achieves nothing. Either constrain uniqueness differently or document that an
attribute change is revoke-then-issue.

**F-8 · Is the challenge table's kind discriminated?** — ZK-CHL-008. §9 makes `session_id` nullable so
a `Membership` login can issue one, which means a `Knowledge` verification can be handed a
null-session row. §4a's whole point is that the challenge names a session. A `kind` column, or a
`not null` predicate in the `Knowledge` consuming statement, closes it.

**F-9 · Is `Setup`'s randomness source pinned to `crypto/rand`?** — ZK-KEY-007. §0 argues at length
that a single-party ceremony is acceptable *because the operator is the verifier*. That argument
requires the toxic waste to be unknown to **users**. A seeded or reproducible setup — the natural
result of a "reproducible builds" request — publishes it to everyone and the argument collapses
entirely. §0 should say the ceremony must not be reproducible, in as many words.

Three smaller ones, recorded without discussion: the wire encoding of `Proof` (compressed vs
uncompressed) must be pinned before ZK-DOS-003's length constant can be (§9 says measure it, not which
encoding); `Audience` derivation is described in §7 as `MiMC(DOM_AUDIENCE, deploymentID, "vote",
epoch)` but `deploymentID`'s provenance is unspecified, which is what ZK-NUL-008 depends on; and §5's
uniform-failure list has six entries while a seventh — malformed request shape — fails earlier in the
stack and is the easiest oracle to leave open (ZK-ORC-001(c)).

---

## 24 · Execution plan

Cases are ordered by the phase that makes them runnable. A phase does not end until its CRITICAL cases
are green **and** its slice of the mutation matrix has been run.

### Phase 0 — honesty and the build

| case | why here |
|---|---|
| ZK-KEY-001 | The repo must be provably key-free before any key exists to commit. |
| ZK-KEY-010 | gosec against gnark's assembly and `unsafe`, before the suppressions accumulate. |
| ZK-INV-005 | Gotchas 40–63 land **before** the circuits — §13 is explicit, and a register written afterwards records what you already got right. |
| ZK-INV-007 | The three `README.md` claims gnark falsifies. |
| ZK-INV-008 | `## [Unreleased]` exists at all. |

**Gate:** `make check` green. No circuit code in the diff.

### Phase 1 — `zkauthn.Knowledge`, with the key handling

| case | tier |
|---|---|
| ZK-CIR-001 (both circuits' machinery, `Knowledge` populated), ZK-CIR-002, ZK-CIR-011, ZK-CIR-012, ZK-CIR-014 | CRITICAL |
| ZK-HSH-001, ZK-HSH-002 (`Knowledge` arity), ZK-HSH-003, ZK-HSH-004, ZK-HSH-005 | CRITICAL |
| ZK-INP-002, ZK-INP-006 | CRITICAL / ESSENTIAL |
| ZK-CHL-001…009 | CRITICAL / ESSENTIAL |
| ZK-KEY-002…008 | CRITICAL / ESSENTIAL |
| ZK-DOS-001, ZK-DOS-002, ZK-DOS-003 | CRITICAL |
| ZK-ORC-001…007 | CRITICAL / ESSENTIAL |
| ZK-ENR-002, ZK-ENR-003 | CRITICAL |
| ZK-SES-004, ZK-E2E-002 | CRITICAL |
| ZK-CIR-015, ZK-KEY-009, ZK-INV-001…004 | supporting |

**Gate:** mutations M10, M11, M19*, M20, M24…M36 (\*M19 deferred where it needs `Membership`).
§8 ships **entire** here — split `Setup`, pinned vk, `CircuitID`, the determinism check — and §5's
uniform failure and dummy verify, because both are cheaper now than retrofitted across two circuits.

### Phase 2 — the tree, and nothing else

No circuit, no proof, no gnark in the diff. §13: *"This phase has no cryptography in it and is the
part that fails silently under two replicas."*

| case | tier |
|---|---|
| ZK-TRE-001…014 | CRITICAL / ESSENTIAL |
| ZK-HSH-002 (tree arity and the zero-hash table) | CRITICAL |
| ZK-SQL-001…008 | CRITICAL / ESSENTIAL |
| ZK-ENR-001, ZK-ENR-004, ZK-ENR-005, ZK-ENR-006 | CRITICAL / ESSENTIAL |
| ZK-E2E-005 | ESSENTIAL |

**Gate:** mutations M13, M37…M41, M53…M55. Resolve findings F-1, F-5 and F-6 before merge — all three
are decisions this phase's code makes irreversibly.

### Phase 3 — `zkauthn.Membership`, plus the `Scope` hardening

§13: *"Do not merge the circuit before the hardening."* ZK-AUZ-001 therefore lands **first** in this
phase, not last.

| case | tier |
|---|---|
| **ZK-AUZ-001** | CRITICAL — first |
| ZK-CIR-003…010, ZK-CIR-013, ZK-CIR-016, ZK-CIR-017 | CRITICAL / ESSENTIAL |
| ZK-CIR-001 (`Membership` rows), ZK-CIR-004 (all 15 families) | CRITICAL |
| ZK-INP-004, ZK-INP-005 | CRITICAL / ESSENTIAL |
| ZK-KEY-003 (second circuit), ZK-CIR-015 (second pin) | CRITICAL |

**Gate:** mutations M1…M9, M12, M14…M18, M22, M23, M47. Resolve F-7.

### Phase 4 — `Login`, the pseudonymous account, the two audience kinds, `zkauthz`

| case | tier |
|---|---|
| ZK-INP-001, ZK-INP-003 | CRITICAL |
| ZK-NUL-001…009 | CRITICAL / ESSENTIAL |
| ZK-PSD-001…006 | CRITICAL / ESSENTIAL |
| ZK-SES-001…003, ZK-SES-005…009 | CRITICAL / ESSENTIAL |
| ZK-AUZ-002…013 | CRITICAL / ESSENTIAL |
| ZK-E2E-001, ZK-E2E-003, ZK-E2E-004, ZK-E2E-006 | CRITICAL / ESSENTIAL |
| ZK-DOC-001…006 | ESSENTIAL |

**Gate:** mutations M19, M21, M42…M46, M48…M52. Resolve F-2, F-3, F-4, F-8. **The full mutation matrix
runs here**, all 55, because Phase 4 is the first point at which every named case exists.

### Standing gates, every phase

1. `make check` green — not `make test`, which reports `ok` on a skipped `TestDB*` suite.
2. The phase's mutation slice run, with every named case observed **red**.
3. `SECURITY.md`'s control table gains the phase's rows (ZK-INV-006).
4. `CHANGELOG.md` under `## [Unreleased]` (ZK-INV-008).
5. Every new exported symbol shimmed in `kal.go` with an identity assertion in `tests/kal_test.go`
   (ZK-INV-001).

---

## 25 · Register summary

| group | subject | cases | critical | essential | good-to-have |
|---|---|---:|---:|---:|---:|
| CIR | Circuit soundness | 17 | 11 | 4 | 2 |
| HSH | Hash and primitive agreement | 5 | 5 | 0 | 0 |
| INP | Public input provenance | 6 | 4 | 2 | 0 |
| CHL | Challenge lifecycle | 10 | 4 | 5 | 1 |
| TRE | Tree integrity | 14 | 7 | 6 | 1 |
| NUL | Nullifier semantics | 9 | 4 | 4 | 1 |
| PSD | Pseudonymous account | 6 | 4 | 2 | 0 |
| SES | Session and privacy | 9 | 3 | 4 | 2 |
| AUZ | Authorization seam | 13 | 6 | 7 | 0 |
| ENR | Enrolment and issuance | 6 | 4 | 2 | 0 |
| KEY | Keys, ceremony, artifacts | 10 | 6 | 3 | 1 |
| DOS | Resource bounds | 6 | 3 | 1 | 2 |
| ORC | Oracles and error uniformity | 7 | 2 | 5 | 0 |
| SQL | Schema and migration | 8 | 2 | 5 | 1 |
| INV | Repository invariants | 9 | 2 | 6 | 1 |
| E2E | End to end | 6 | 4 | 2 | 0 |
| DOC | Documented non-goals | 6 | 0 | 6 | 0 |
| **total** | | **147** | **71** | **64** | **12** |

Plus 8 harness preconditions (§2), 55 mutations (§19) and 9 design findings (§23).

**If only ten cases are ever written**, these, in this order — each is a total bypass or a total loss
of the property being sold, and each fails silently:

1. **ZK-CIR-001** — public-input binding battery. Nothing else can tell a declared input from a
   constrained one, and it is the only case that survives the compiler eliminating a dead constraint.
2. **ZK-CIR-005** — `Path[0]` binds to the prover's secret. Without it, membership needs no secret.
3. **ZK-INP-001** — the threshold comes from the policy row. Without it, every claim is satisfied by
   everyone, with a valid proof and a correct circuit.
4. **ZK-INP-004** — the root is validated. Without it, the attacker proves membership of a tree it
   built.
5. **ZK-ENR-001** — enrolment is not self-service. The largest bypass that touches no cryptography,
   and the handout does not specify the guard.
6. **ZK-AUZ-001** — `Scope` denies on an empty `UserID`. A live match against any `text` owner column.
7. **ZK-SES-001** — the zk session carries no metadata. One `JOIN` and the anonymity is gone with
   every constraint intact.
8. **ZK-CIR-003** — the `Membership` differential, both directions, with ZK-CIR-004's families.
9. **ZK-KEY-002** — the verifying key is hash-pinned before it is parsed. A universal bypass behind a
   file write.
10. **ZK-NUL-002** — one-shot single use under concurrency, enforced by the unique index.

And one rule that outranks all ten: **a test that asserts on an error value instead of on state is
not a test.** The row is still in the table. The resolver did not run. The session was not issued.
`mfa_at` is still null. That is what a security case asserts here, and it is the difference between a
register that catches the mutation matrix and one that reports `ok`.






---

## 26 · Roadmap — documented, not yet tested

**Dated 2026-08-06.** The register was derived from `docs/zk-handout.md` by logic alone: every case
is an obligation on the implementation, not a report on it. This section records which obligations
are met and which are outstanding, so the gap is a tracked number rather than an impression.

Of the 147 documented cases: **51 are covered by a named test**,
**18 are excused** as unreachable through the exported surface or analytical (the
`zkNonAutomatedCases` map in `tests/zk_case_manifest_test.go`, each with its reason), and
**78 remain below**. `TestZKINV003ExternalCaseCoverage` pins all three numbers and fails
if any case falls out of all of them, so this list cannot quietly grow or be deleted.

These are not excuses. Nothing here is unreachable — each is work that should be done, in roughly
this order.

### Critical

31 cases.

| case | obligation |
|---|---|
| `ZK-AUZ-004` | AssertAuthCoverage still demands annotation on zk-gated fields |
| `ZK-AUZ-005` | The proven-claim set is loaded once per request |
| `ZK-AUZ-008` | An anonymous principal never satisfies proves: |
| `ZK-CHL-002` | A re-randomised proof does not replay |
| `ZK-CHL-003` | The burn is atomic |
| `ZK-CIR-004` | The adversarial witness generator |
| `ZK-CIR-005` | Path[0] binds to the prover's own secret |
| `ZK-CIR-006` | Range check precedes the comparison |
| `ZK-CIR-007` | The Merkle root is recomputed, not accepted |
| `ZK-CIR-008` | The nullifier is constrained to the secret and audience |
| `ZK-CIR-009` | Domain separation between leaf, nullifier and empty leaf |
| `ZK-DOS-003` | The proof blob is length-checked before deserialization |
| `ZK-ENR-001` | Membership enrolment is not self-service |
| `ZK-ENR-002` | Knowledge enrolment binds to the session's user |
| `ZK-ENR-004` | The attribute is set by the operator, never by the enrollee |
| `ZK-HSH-005` | The secret is returned exactly once and never stored |
| `ZK-INP-002` | Commitment comes from the session's user |
| `ZK-KEY-001` | No proving or verifying key is in the repository |
| `ZK-KEY-005` | ReadFrom, never UnsafeReadFrom |
| `ZK-KEY-007` | The ceremony is not deterministic |
| `ZK-NUL-003` | The primary key is the nullifier alone |
| `ZK-NUL-004` | Cross-audience unlinkability |
| `ZK-ORC-001` | One error code for every verification failure |
| `ZK-ORC-002` | The enrolment path is timing-equalized |
| `ZK-PSD-002` | Concurrent first sight creates one account |
| `ZK-PSD-004` | A pseudonym has no password and no verified mailbox |
| `ZK-SES-002` | Metadata suppression is not configurable |
| `ZK-SQL-001` | 0002_zk.sql alters no core table |
| `ZK-SQL-003` | The schema prefix is validated |
| `ZK-TRE-002` | The advisory lock is taken before the first read |
| `ZK-TRE-010` | zeros[0] is domain-tagged, not 0 |

### Essential

40 cases.

| case | obligation |
|---|---|
| `ZK-AUZ-006` | Claims do not leak across requests |
| `ZK-AUZ-007` | An unknown claim denies |
| `ZK-AUZ-009` | An empty proves: list has a defined meaning |
| `ZK-AUZ-010` | Claims bind to the session, and that property is stated |
| `ZK-AUZ-011` | A one-shot claim used as a session claim behaves predictably |
| `ZK-AUZ-012` | New mutations are in defaultSensitiveFields |
| `ZK-AUZ-013` | Claim names are opaque, with no expression syntax |
| `ZK-CHL-005` | Expiry is enforced |
| `ZK-CHL-006` | Issuance deletes expired rows in the same statement |
| `ZK-CHL-007` | Challenges are unpredictable |
| `ZK-CHL-008` | A Membership challenge needs no session; a Knowledge challenge requires one |
| `ZK-CHL-009` | A challenge is not transferable between users or sessions |
| `ZK-CIR-010` | Index is bit-constrained and within the tree |
| `ZK-CIR-013` | Over-constraining at every boundary |
| `ZK-CIR-014` | CheckCircuit with valid and invalid assignments |
| `ZK-DOS-004` | The challenge endpoint is not a write amplifier |
| `ZK-ENR-006` | Revocation names a person and revokes one leaf |
| `ZK-INP-005` | The prover names exactly three things |
| `ZK-INP-006` | Structurally invalid inputs fail before anything expensive |
| `ZK-KEY-008` | The proving key is not required by the verifier |
| `ZK-NUL-005` | Recurring and one-shot rows have disjoint shapes |
| `ZK-NUL-006` | The claim kind is constrained to two values |
| `ZK-NUL-008` | A proof does not cross deployments |
| `ZK-NUL-009` | A nullifier from one audience does not satisfy another claim |
| `ZK-ORC-003` | The internal detail never reaches the client |
| `ZK-ORC-004` | Unknown and retired roots are indistinguishable |
| `ZK-ORC-005` | Nullifier existence is not observable |
| `ZK-ORC-006` | Claim existence is not observable |
| `ZK-ORC-007` | Failure paths do not differ in observable side effects |
| `ZK-PSD-005` | Principal gains no field and Scope needs no branch |
| `ZK-PSD-006` | Re-issuance produces a new pseudonym, and that is documented |
| `ZK-SES-003` | No zk artifact reaches a log |
| `ZK-SES-007` | issued_to is the operator's map and nothing more |
| `ZK-SQL-004` | All zk SQL lives in one sql.go per package |
| `ZK-SQL-005` | Errors are classified by SQLSTATE |
| `ZK-SQL-006` | Cascades are exactly as specified |
| `ZK-SQL-007` | RLS still applies to zk-created rows |
| `ZK-TRE-003` | The advisory lock key is namespaced |
| `ZK-TRE-008` | The grace window closes |
| `ZK-TRE-009` | Sparse zero-hashes resolve absent nodes |

### Good to have

7 cases.

| case | obligation |
|---|---|
| `ZK-DOS-005` | Server-side proving, if it exists, has its own smaller bound |
| `ZK-DOS-006` | The bound's ceiling is documented as per-replica |
| `ZK-INV-008` | CHANGELOG.md carries an [Unreleased] entry per phase |
| `ZK-KEY-009` | Constraint counts and prove/verify cost are measured and pinned |
| `ZK-NUL-007` | An epoch in the audience gives per-epoch rate limiting |
| `ZK-SES-009` | Threshold disclosure narrows the attribute |
| `ZK-SQL-008` | The migration is idempotent and ordered |

### How to close one

Write the test, give it a `// Covers: ZK-XXX-000` doc comment, delete its row from
`zkRoadmapCases`, and lower `zkRoadmapPinned` by one. The pinned constant is what makes progress
and regression both show up in a diff.
