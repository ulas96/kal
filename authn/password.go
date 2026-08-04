// Package authn @notice Proving who a caller is. This file: Argon2id password hashing with the
// parameters pinned, the concurrency bounded, and the encoding self-describing so cost can be
// raised later without a password reset.
package authn

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"runtime"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/sync/semaphore"

	"github.com/ulas96/kal/kalerr"
)

// Params @notice Argon2id cost parameters, encoded into every hash they produce.
//
// @dev The defaults are one of OWASP's listed equivalent-security configurations (19 MiB, t=2,
// p=1) — the best balance of that set for a web login path.
//
// Parallelism is pinned to 1 and must never be runtime.NumCPU(). The wrapper everyone reaches
// for defaults to NumCPU, which makes the cost of hashing a password depend on which machine
// happened to serve the request: a 4-vCPU box and a 64-vCPU box do different work for the same
// password, capacity planning becomes impossible, and an autoscaler silently changes the
// security posture. Verification still works either way — p is encoded in the stored hash —
// which is precisely why that bug survives review, and most of why this file exists instead of
// a dependency.
type Params struct {
	Memory      uint32 // KiB held for the duration of one hash
	Time        uint32 // passes
	Parallelism uint8  // lanes; see above
	SaltLen     uint32 // bytes
	KeyLen      uint32 // bytes
}

// defaults @notice Returns p with zero fields filled from the OWASP configuration.
func (p Params) defaults() Params {
	if p.Memory == 0 {
		p.Memory = 19456
	}
	if p.Time == 0 {
		p.Time = 2
	}
	if p.Parallelism == 0 {
		p.Parallelism = 1
	}
	if p.SaltLen == 0 {
		p.SaltLen = 16
	}
	if p.KeyLen == 0 {
		p.KeyLen = 32
	}
	return p
}

// Hasher @notice Hashes and verifies passwords, with the Argon2 work bounded.
//
// @dev The bound is the part every Argon2 tutorial omits: at m=19456 every in-flight hash holds
// 19 MiB, and nothing else in the stack bounds concurrent logins — luima ships no rate limiting
// and the connection pool is not the bottleneck. Without the semaphore, N unauthenticated
// requests allocate 19N MiB: the parameter that makes the hash strong is the same parameter
// that makes it a remote OOM primitive. Requests beyond the bound queue briefly; the acquire
// honours ctx, so a client that gave up does not hold a slot.
//
// ponytail: a process-local semaphore, so the bound is per replica. Behind N replicas the real
// ceiling is 19·limit·N MiB — size it against the pod memory limit, not the node's.
type Hasher struct {
	params Params
	sem    *semaphore.Weighted
	dummy  string
}

// NewHasher @notice Builds a Hasher from p (zero fields defaulted) and a concurrency bound.
//
// @dev maxConcurrent ≤ 0 defaults to GOMAXPROCS: more simultaneous hashes than schedulable
// threads buys queueing latency, not throughput. Construction computes one throwaway hash for
// the unknown-user path, so it costs a single Argon2 run.
//
// @param p             cost parameters; zero fields take the OWASP defaults
// @param maxConcurrent the in-flight hash ceiling; ≤ 0 means GOMAXPROCS
// @return *Hasher      safe for concurrent use
// @return error        only a CSPRNG failure
func NewHasher(p Params, maxConcurrent int64) (*Hasher, error) {
	if maxConcurrent <= 0 {
		maxConcurrent = int64(runtime.GOMAXPROCS(0))
	}
	h := &Hasher{params: p.defaults(), sem: semaphore.NewWeighted(maxConcurrent)}

	// dummy is a real Argon2id hash of a value nothing can match, verified against when an
	// account does not exist so the unknown-user path costs the same as the wrong-password
	// path. Not a random sleep: a sleep has a different distribution from a hash, and an
	// attacker averaging over many samples sees the difference — Traefik shipped exactly that
	// bug in its BasicAuth middleware (GHSA-g3hg-j4jv-cwfr). ASVS 6.3.8 counts response time as
	// an enumeration channel alongside messages and status codes.
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	dummy, err := h.hash(secret)
	if err != nil {
		return nil, err
	}
	h.dummy = dummy
	return h, nil
}

// acquire @notice Takes a hashing slot or fails with a client-visible RATE_LIMITED.
//
// @dev A short queue, not an unbounded one: a caller that cannot start hashing within the
// timeout is told so instead of holding a goroutine open — the throttle must not become its own
// DoS. 429-shaped, never a 500: the server is fine, it is just full.
func (h *Hasher) acquire(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := h.sem.Acquire(ctx, 1); err != nil {
		return &kalerr.Error{Code: kalerr.CodeRateLimited, Message: "please try again shortly", Internal: err}
	}
	return nil
}

// hash @notice Salts and derives without touching the semaphore — the exported callers hold
// it, and NewHasher runs before any concurrency exists.
func (h *Hasher) hash(password []byte) (string, error) {
	salt := make([]byte, h.params.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey(password, salt, h.params.Time, h.params.Memory, h.params.Parallelism, h.params.KeyLen)
	return encodePHC(h.params, salt, key), nil
}

// Hash @notice Derives the PHC-encoded Argon2id hash of password, within the concurrency bound.
//
// @dev Imposes no policy of its own — call [ValidatePassword] first on user-chosen passwords.
// Keeping policy out of Hash is what keeps imports and invites possible.
//
// @param ctx      bounds the wait for a hashing slot; carries the request deadline
// @param password hashed exactly as received — no trimming, no normalisation
// @return string  the $argon2id$… PHC string for the password_hash column
// @return error   the bound rejecting the attempt, or a CSPRNG failure
func (h *Hasher) Hash(ctx context.Context, password string) (string, error) {
	if err := h.acquire(ctx); err != nil {
		return "", err
	}
	defer h.sem.Release(1)
	return h.hash([]byte(password))
}

// Verify @notice Checks password against encoded, reporting the match and whether the stored
// hash should be upgraded.
//
// @dev Two encodings are accepted. $argon2id$… is what this package writes. $2…$ is legacy
// bcrypt — verified so an imported user base can migrate, never minted, because bcrypt's
// 72-byte truncation is incompatible with "verify exactly as received"; rehash is always true
// on a bcrypt match, and rehash-on-login is the entire migration path.
//
// The comparison is subtle.ConstantTimeCompare on the derived key. Its sharp edge, for anyone
// copying this elsewhere: it returns immediately when the lengths differ. Irrelevant here — the
// key length is fixed by the encoded parameters — but anywhere secrets vary in length, hash
// both sides first.
//
// @param ctx      bounds the wait for a hashing slot; carries the request deadline
// @param password the candidate, verified exactly as received
// @param encoded  the stored hash, PHC argon2id or bcrypt
// @return ok      whether password matches
// @return rehash  whether the stored hash is weaker than the configured parameters
// @return error   the bound rejecting the attempt, or a malformed stored hash
func (h *Hasher) Verify(ctx context.Context, password, encoded string) (ok, rehash bool, err error) {
	if err := h.acquire(ctx); err != nil {
		return false, false, err
	}
	defer h.sem.Release(1)

	if strings.HasPrefix(encoded, "$2") {
		match := bcrypt.CompareHashAndPassword([]byte(encoded), []byte(password)) == nil
		return match, match, nil
	}

	stored, salt, key, err := parsePHC(encoded)
	if err != nil {
		return false, false, err
	}
	derived := argon2.IDKey([]byte(password), salt, stored.Time, stored.Memory, stored.Parallelism, stored.KeyLen)
	if subtle.ConstantTimeCompare(derived, key) != 1 {
		return false, false, nil
	}
	return true, weaker(stored, h.params), nil
}

// VerifyDummy @notice Burns a real verification against an unmatchable hash. Call it when the
// account does not exist, then return the same INVALID_CREDENTIALS a wrong password gets.
//
// @dev The timing-equalization half of the enumeration defence; the identical error text is the
// other half. See the dummy comment in NewHasher for why this is a hash and not a sleep.
//
// @param ctx      bounds the wait for a hashing slot
// @param password the candidate submitted for the account that does not exist
// @return error   only the bound rejecting the attempt
func (h *Hasher) VerifyDummy(ctx context.Context, password string) error {
	_, _, err := h.Verify(ctx, password, h.dummy)
	return err
}

// weaker @notice Whether stored provides less protection than configured.
//
// @dev Strictly lower memory, time or key length — lowering the configured cost never silently
// downgrades existing hashes on login. Parallelism is deliberately not compared: it changes the
// hash, not meaningfully its strength, and it travels inside the encoding either way.
func weaker(stored, configured Params) bool {
	return stored.Memory < configured.Memory ||
		stored.Time < configured.Time ||
		stored.KeyLen < configured.KeyLen
}

// encodePHC @notice Renders $argon2id$v=19$m=…,t=…,p=…$<salt>$<key>.
//
// @dev Parameters travel with the hash. That is what buys rehash-on-login — the only mechanism
// that raises cost over time without a password reset — and it is why parsePHC below trusts the
// stored parameters, not the configured ones, for derivation. Base64 is raw (unpadded) std
// encoding, matching the PHC reference implementation.
func encodePHC(p Params, salt, key []byte) string {
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.Memory, p.Time, p.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key))
}

// parsePHC @notice Parses exactly the form encodePHC writes.
//
// @dev Strict about the variant: argon2i and argon2d are rejected rather than best-effort
// verified. This package never wrote them, so their appearance means the column holds data of
// unknown provenance, and the safe answer is an error rather than a guess. Error text never
// echoes salt or key material.
func parsePHC(s string) (p Params, salt, key []byte, err error) {
	parts := strings.Split(s, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return p, nil, nil, fmt.Errorf("authn: not an argon2id PHC string")
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return p, nil, nil, fmt.Errorf("authn: unsupported argon2 version %q", parts[2])
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Time, &p.Parallelism); err != nil {
		return p, nil, nil, fmt.Errorf("authn: malformed argon2 parameters %q", parts[3])
	}
	if salt, err = base64.RawStdEncoding.DecodeString(parts[4]); err != nil {
		return p, nil, nil, fmt.Errorf("authn: malformed salt encoding")
	}
	if key, err = base64.RawStdEncoding.DecodeString(parts[5]); err != nil {
		return p, nil, nil, fmt.Errorf("authn: malformed key encoding")
	}
	// This package writes 16 and 32; anything outside a generous envelope means the column
	// holds something that was never a kal hash, and refusing beats deriving against it.
	if len(salt) < 8 || len(salt) > 64 || len(key) < 16 || len(key) > 128 {
		return p, nil, nil, fmt.Errorf("authn: implausible salt or key length")
	}
	p.SaltLen = uint32(len(salt)) // #nosec G115 -- bounded to [8,64] just above
	p.KeyLen = uint32(len(key))   // #nosec G115 -- bounded to [16,128] just above
	return p, salt, key, nil
}

// Password policy (ASVS 6.2, NIST 800-63B): a minimum, a generous maximum, and nothing else.
// No composition rules, no periodic rotation, and the password is used exactly as received —
// no trimming, no case folding, no Unicode normalisation that loses information. Paste and
// password managers must work.
const (
	// MinPasswordLen @notice Minimum length in characters (runes, not bytes).
	MinPasswordLen = 8
	// MaxPasswordLen @notice Maximum length in bytes — far past ASVS's "at least 64" floor.
	//
	// @dev The cap exists only to bound the hashing input; 1024 rejects nothing a human or a
	// password manager produces.
	MaxPasswordLen = 1024
)

// ValidatePassword @notice Applies the policy above with a client-visible INVALID_INPUT.
//
// @param password the candidate, checked exactly as received
// @return error   a *kalerr.Error with CodeInvalidInput, or nil
func ValidatePassword(password string) error {
	if utf8.RuneCountInString(password) < MinPasswordLen {
		return &kalerr.Error{
			Code:    kalerr.CodeInvalidInput,
			Message: fmt.Sprintf("password must be at least %d characters", MinPasswordLen),
		}
	}
	if len(password) > MaxPasswordLen {
		return &kalerr.Error{
			Code:    kalerr.CodeInvalidInput,
			Message: fmt.Sprintf("password must be at most %d bytes", MaxPasswordLen),
		}
	}
	return nil
}
