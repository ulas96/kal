# The kal e2ee client

The wire format and the derivation, in enough detail to write a second client that interoperates
with the first. `docs/e2ee-client.ts` is the reference implementation — **copy it, do not install
it.** There is no npm package and no build step, so there is no version to keep in sync and no
skew matrix between a Go release train and a JavaScript one.

## What this protects against, and what it does not

Browser-delivered end-to-end encryption does not protect against the server that serves the
JavaScript. An operator who wants the plaintext ships one line of JS to one user and has their
master key on the next page load, and no amount of care in this Go package changes that. Anyone
who tells you otherwise is selling something.

The honest claim is: **kal cannot read your data, and neither can anyone who reads your
database.** That claim is true, it is worth a lot, and it is the only one to make.

What it costs, stated up front so nobody discovers it in production: forgetting the password means
losing the data — that is not a bug to be fixed later, it is the property. Encrypted columns cannot
be indexed, sorted, filtered or full-text searched. Server-side features that read user data —
digest emails, admin support tooling, analytics, a report generator — stop working, permanently.
And the server can no longer enforce a password policy, because it no longer sees a password.

## Derivation

```
params  = Vaults.Params(email)                                // pre-auth, leaks nothing
mk      = Argon2id(password, params.Salt, params)             // 32 bytes, never leaves
authSec = "kal1." + b64url(HKDF-SHA256(mk, "kal.e2ee.v1/auth"))
encKey  = HKDF-SHA256(mk, "kal.e2ee.v1/enc")                  // wraps the vault key
send authSec in the field where the password used to go
```

The server then runs its own Argon2id over `authSec` and stores that hash, exactly as it did for a
password. `authSec` and `encKey` are independent given `mk` because HKDF with distinct `info`
strings says so, and `mk` is not recoverable from `authSec` because HKDF is one-way — so the
server holds a hash of a value that is useless for decryption.

HKDF is invoked with an **empty salt** and the `info` strings above, verbatim, including the
`kal.e2ee.v1/` prefix. Two clients that disagree here derive two different keys and the second
device reports a corrupt vault.

**`parallelism` is pinned to 1.** Argon2's `p` changes the output, so a client that picks it from
the thread pool derives a different key on a laptop than on a phone. The column carries a
`check (parallelism = 1)` for the same reason.

**The KDF parameters are stored per user and read from `Vaults.Params`, never from your own
config.** Raise a default and every existing vault becomes unopenable, with a working login and no
error anywhere.

`Params` is a pre-auth call and answers for every address, enrolled or not — the salt for an
unknown address is derived from the same function that mints real ones, so the two are
indistinguishable and calling twice returns the same bytes. Do not rate-limit it through the login
backoff counter: that lets anyone lock any account out by repeatedly asking for its salt.

## Keys

| key | where it comes from | what it protects |
|---|---|---|
| `mk` | Argon2id over the password | nothing directly; split into the two below |
| `authSec` | `HKDF(mk, ".../auth")` | sent to the server in place of the password |
| `encKey` | `HKDF(mk, ".../enc")` | wraps the vault key |
| vault key | 32 random bytes in the browser | wraps every record's data key |
| recovery key | `HKDF(code, ".../recovery")` | a second wrapping of the same vault key |
| DEK | 32 random bytes, one per record | one record's ciphertext |

The vault key is random rather than `encKey` itself, so a password change re-wraps one small blob
instead of re-encrypting every record.

The recovery code is 32 bytes of CSPRNG returned exactly once by kal, base64url, the same shape as
a session token. It needs no stretching, so HKDF alone derives its key. kal stores **no hash of
it** — the wrapped key is the verifier. It survives a password reset, because it is wrapped under
the code and not under the password, which makes it the only route back into a vault whose
password was reset.

## Blob format

```
blob := 0x01 || alg || nonce(12) || ciphertext||tag        // alg 0x01 = AES-256-GCM
AAD  := "kal.e2ee.v1|" || resource || "|" || record_id || "|" || owner_id
```

The version byte is first and it is load-bearing. Replacing AES-GCM later, or moving off Argon2id,
is a per-record decision the format has to carry; a format with no version can never change, and
the migration for "we must change the cipher" is otherwise "ask every user to re-enter their
password".

kal validates the version byte, the algorithm byte and the length, and never parses further —
parsing further requires knowing how to decrypt.

**The AAD is load-bearing.** Without it a ciphertext is a portable object: anyone who can write the
column can move Alice's encrypted note into Bob's row, or her `salary` blob into her `bonus` field,
and the client decrypts it happily because the key is right. The reference client binds the wrapped
DEK with the same AAD as the record it belongs to — it is the same call with the same argument, and
it closes the matching swap on the wrapping.

The vault key's own wrapping uses `resource = "vault"`, an empty `record_id`, and the owner's id.

**Per-record data keys, not one vault key over everything.** A random 96-bit nonce under a single
key reaches the GCM birthday bound at ~2^32 messages, and a nonce collision under AES-GCM is not a
degradation — it is a total break of both messages and the authentication key. Encrypt each record
under its own random DEK, wrap the DEK under the vault key, and store both in your row.

## Worked example

```ts
import { derive, newVaultKey, wrapVaultKey, unwrapVaultKey, recoveryKey,
         encryptRecord, decryptRecord } from "./e2ee-client";

// 1 · Enrolment, right after registering or logging in for the first time.
const params = await api.vaultParams(email);          // Vaults.Params — pre-auth
const { authSecret, encKey } = await derive(password, params);
await api.login(email, authSecret);                   // authSecret, never the password

const code = await api.newRecoveryCode();             // returned exactly once — show it now
const vaultKey = newVaultKey();
await api.putVault({
  wrappedKey:         await wrapVaultKey(encKey, vaultKey, userId),
  recoveryWrappedKey: await wrapVaultKey(await recoveryKey(code), vaultKey, userId),
  keyVersion:         0,                              // 0 is "no row yet"
  params,
});

// 2 · Every later login.
const vault = await api.getVault();
if (vault.stale) {
  // The password moved since this key was wrapped. The current password cannot open it; ask for
  // the old one, or for the recovery code, then Put the re-wrapped blob at vault.keyVersion.
}
const key = await crypto.subtle.importKey(
  "raw", await unwrapVaultKey(encKey, vault.wrappedKey, userId), "AES-GCM", false,
  ["encrypt", "decrypt"]);

// 3 · One record.
const { ciphertext, wrappedDek } =
  await encryptRecord(key, new TextEncoder().encode("42000"), "invoices", invoiceId, userId);
// … store both columns in your own table, alongside the owner_id you already scope on …
const plain = await decryptRecord(key, ciphertext, wrappedDek, "invoices", invoiceId, userId);
```

**A ciphertext row is still a row with an owner.** Encryption is not authorization: an encrypted
table needs the same `kal.Scope(ctx, "owner_id")` as any other, and the two controls fail open with
respect to each other.

## Rollout

Every client that touches the password field must be updated in the same release as
`Config.E2EE` — a second frontend, a mobile app, a `curl` in a runbook, a test fixture. kal's shape
check on `authSec` turns a missed one into a login failure instead of silent data loss, which is
the right failure, but it is still a failure. Plan for it.
