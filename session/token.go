package session

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

// NewToken @notice Mints a fresh credential: 32 bytes from crypto/rand, base64url-encoded to 43
// characters, plus the SHA-256 the database stores.
//
// @dev Only the hash is ever stored. A read-only SQL injection, a leaked backup or a query
// logger then yields hashes, not live sessions — and unlike a password, a 256-bit CSPRNG token
// has no preimage to brute-force, so a fast hash is the whole job and a KDF would burn ~100 ms
// of CPU per authenticated request buying nothing. The same pair of functions serves the
// emailed tokens in authn: one design, one set of tests.
//
// No selector/verifier split: that pattern exists to get an indexable lookup key that is not
// the secret, and the hash already is exactly that — derived, non-secret, indexable.
//
// @return token the credential for the client; never stored
// @return hash  SHA-256 of the token string, for the *_sha256 column
// @return err   only a CSPRNG failure
func NewToken() (token string, hash []byte, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, err
	}
	token = base64.RawURLEncoding.EncodeToString(raw)
	return token, HashToken(token), nil
}

// HashToken @notice SHA-256 of the token exactly as presented on the wire.
//
// @dev Hashing the string form, not decoded bytes, keeps the lookup path free of a decode
// branch: a malformed token simply hashes to something that matches no row. Lookup is then a
// single indexed equality — not constant-time, and it does not need to be, because a B-tree
// probe's timing reveals nothing about a 256-bit preimage the attacker cannot enumerate.
//
// @param token the wire form
// @return []byte the 32-byte digest for the *_sha256 column
func HashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}
