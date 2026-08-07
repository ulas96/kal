// kal e2ee reference client — copy this file into your app. Do not install it.
//
// Browser-delivered end-to-end encryption does not protect against the server that serves the
// JavaScript. An operator who wants the plaintext ships one line of JS to one user and has their
// master key on the next page load, and no amount of care in this Go package changes that. Anyone
// who tells you otherwise is selling something.
//
// The honest claim is: kal cannot read your data, and neither can anyone who reads your database.
// That claim is true, it is worth a lot, and it is the only one to make.
//
// The wire format below is pinned. Two independent clients must agree on it byte for byte, so
// treat every constant in this file as part of the protocol rather than as an implementation
// detail. See docs/e2ee-client.md.
//
// Argon2id comes from hash-wasm, because WebCrypto has none. PBKDF2 is the native fallback and it
// is GPU-cheap; it is here only so that an account enrolled under `kdf: "pbkdf2"` can still open
// its vault and be re-wrapped to Argon2id on the next login.

import { argon2id } from "hash-wasm";

export type Params = {
  kdf: "argon2id" | "pbkdf2";
  salt: Uint8Array; // 16 bytes, from Vaults.Params — never generated here
  memory: number; // KiB
  iterations: number;
  parallelism: 1; // pinned: p changes the output, so a thread-pool-derived p is a different key
};

const VERSION = 0x01;
const ALG_AES_256_GCM = 0x01;
const NONCE_BYTES = 12;
const te = new TextEncoder();

/** The two independent values derived from one password. `master` never leaves this module. */
export async function derive(password: string, p: Params) {
  const master =
    p.kdf === "argon2id"
      ? await argon2id({
          password,
          salt: p.salt,
          parallelism: p.parallelism,
          iterations: p.iterations,
          memorySize: p.memory,
          hashLength: 32,
          outputType: "binary",
        })
      : await pbkdf2(password, p.salt, p.iterations);

  // Distinct info strings are what make these two independent given `master`, and HKDF is what
  // makes `master` unrecoverable from the auth secret the server stores a hash of.
  const auth = await hkdf(master, "kal.e2ee.v1/auth");
  const enc = await hkdf(master, "kal.e2ee.v1/enc");
  master.fill(0);
  return { authSecret: "kal1." + b64url(auth), encKey: await aesKey(enc) };
}

/** The vault key: random, wrapped under `encKey`, and never `encKey` itself — so a password change
 *  re-wraps one small blob instead of re-encrypting every record. */
export function newVaultKey(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

export async function wrapVaultKey(encKey: CryptoKey, vaultKey: Uint8Array, ownerId: string) {
  return seal(encKey, vaultKey, aad("vault", "", ownerId));
}

export async function unwrapVaultKey(encKey: CryptoKey, blob: Uint8Array, ownerId: string) {
  return open(encKey, blob, aad("vault", "", ownerId));
}

/** The recovery code is 32 bytes of CSPRNG, so it needs no stretching — HKDF alone. */
export async function recoveryKey(code: string) {
  return aesKey(await hkdf(b64urlDecode(code), "kal.e2ee.v1/recovery"));
}

/** Encrypts one record under its own data key. A single vault key over every record reaches the
 *  GCM birthday bound at ~2^32 messages, and a nonce collision there is a total break of both
 *  messages and the authentication key — not a degradation. */
export async function encryptRecord(
  vaultKey: CryptoKey,
  plaintext: Uint8Array,
  resource: string,
  recordId: string,
  ownerId: string,
) {
  const a = aad(resource, recordId, ownerId);
  const dek = crypto.getRandomValues(new Uint8Array(32));
  const ciphertext = await seal(await aesKey(dek), plaintext, a);
  const wrappedDek = await seal(vaultKey, dek, a);
  dek.fill(0);
  return { ciphertext, wrappedDek };
}

export async function decryptRecord(
  vaultKey: CryptoKey,
  ciphertext: Uint8Array,
  wrappedDek: Uint8Array,
  resource: string,
  recordId: string,
  ownerId: string,
) {
  const a = aad(resource, recordId, ownerId);
  const dek = await open(vaultKey, wrappedDek, a);
  return open(await aesKey(dek), ciphertext, a);
}

/** Binds a ciphertext to where it was written. Without this a blob is portable: anyone who can
 *  write the column can move Alice's note into Bob's row, or her `salary` blob into her `bonus`
 *  field, and the client decrypts it happily because the key is right. */
function aad(resource: string, recordId: string, ownerId: string) {
  return te.encode(`kal.e2ee.v1|${resource}|${recordId}|${ownerId}`);
}

async function seal(key: CryptoKey, plaintext: Uint8Array, additionalData: Uint8Array) {
  const iv = crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData }, key, plaintext),
  );
  const blob = new Uint8Array(2 + NONCE_BYTES + ct.length);
  blob[0] = VERSION;
  blob[1] = ALG_AES_256_GCM;
  blob.set(iv, 2);
  blob.set(ct, 2 + NONCE_BYTES);
  return blob;
}

async function open(key: CryptoKey, blob: Uint8Array, additionalData: Uint8Array) {
  // The version byte is checked before anything is interpreted, so replacing the cipher later is a
  // per-record decision this format can carry rather than a password re-entry for every user.
  if (blob[0] !== VERSION || blob[1] !== ALG_AES_256_GCM) {
    throw new Error(`kal.e2ee: unsupported blob ${blob[0]}/${blob[1]}`);
  }
  const iv = blob.subarray(2, 2 + NONCE_BYTES);
  return new Uint8Array(
    await crypto.subtle.decrypt(
      { name: "AES-GCM", iv, additionalData },
      key,
      blob.subarray(2 + NONCE_BYTES),
    ),
  );
}

async function hkdf(ikm: Uint8Array, info: string) {
  const key = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: te.encode(info) },
    key,
    256,
  );
  return new Uint8Array(bits);
}

async function pbkdf2(password: string, salt: Uint8Array, iterations: number) {
  const key = await crypto.subtle.importKey("raw", te.encode(password), "PBKDF2", false, [
    "deriveBits",
  ]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations },
    key,
    256,
  );
  return new Uint8Array(bits);
}

function aesKey(raw: Uint8Array) {
  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
}

function b64url(b: Uint8Array) {
  return btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlDecode(s: string) {
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/"));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}
