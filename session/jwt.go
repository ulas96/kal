package session

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/ulas96/kal/authz"
	"github.com/ulas96/kal/kalerr"
)

// MaxTokenTTL @notice The hard ceiling on a minted token's lifetime.
//
// @dev A constant in code, not a configuration field. These tokens are not revocable, so the
// TTL *is* the revocation window — and a config field inviting "24h" is a config field someone
// eventually sets. Five minutes is short enough that a stolen token is a narrow problem and
// long enough for any request a service makes on a caller's behalf.
const MaxTokenTTL = 5 * time.Minute

// JWT @notice Mints and verifies short-lived bearer tokens derived from a live session.
//
// @dev This exists for exactly one reason: a service that cannot reach the session table needs
// to verify a caller. If it can reach the table, it should — the session is strictly better,
// because it is revocable.
//
// Being derived from a session rather than replacing one is what lets kal ship no refresh
// token at all. The cookie remains the long-lived credential, so there is nothing to rotate, no
// reuse-detection family to track, and no two-tab race: the entire largest subsystem of every
// JWT-first auth library simply does not exist here.
//
// Separate from Sessions on purpose. Key material is optional configuration that most
// deployments never need, and folding it into Sessions would make every consumer think about
// Ed25519 keys to get a session cookie.
type JWT struct {
	issuer string
	keys   []ed25519.PrivateKey
	kids   []string
}

// NewJWT @notice Builds the minter from an issuer and one or more Ed25519 keys.
//
// @dev EdDSA only, and the algorithm is fixed here rather than read from a token header — that
// kills the algorithm-confusion class structurally instead of by discipline. Not HS256: a
// shared secret means every verifier can also mint, so any service handed the key can
// impersonate any user. Not RS256: larger, slower, and more parameters to get wrong.
//
// The first key signs; every key verifies. That is what makes rotation a deploy rather than an
// outage — publish the new key alongside the old, let tokens signed by the old one drain, then
// drop it.
//
// @param issuer the iss claim, and what verifiers must require
// @param keys   signing keys, newest first; at least one
// @return *JWT  ready for concurrent use
// @return error a missing issuer, no keys, or a malformed key
func NewJWT(issuer string, keys ...ed25519.PrivateKey) (*JWT, error) {
	if issuer == "" {
		return nil, errors.New("session: JWT issuer is required — a verifier that does not check iss accepts tokens from any issuer it trusts")
	}
	if len(keys) == 0 {
		return nil, errors.New("session: at least one Ed25519 key is required")
	}
	j := &JWT{issuer: issuer, keys: keys}
	for _, k := range keys {
		if len(k) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("session: Ed25519 private key must be %d bytes, got %d", ed25519.PrivateKeySize, len(k))
		}
		j.kids = append(j.kids, thumbprint(k.Public().(ed25519.PublicKey)))
	}
	return j, nil
}

// Claims @notice What a verified token asserts.
type Claims struct {
	UserID    string // the sub claim
	SessionID string // the sid claim
	Audience  string
	ExpiresAt time.Time
}

// Token @notice Mints a bearer token for the caller in ctx.
//
// @dev The sid claim carries the session id, so a verifier that *can* reach the database may
// check liveness and close the revocation gap entirely. Include it always; it costs 36 bytes
// and it is the only thing that makes these tokens revocable by anyone.
//
// @param ctx      the resolver context; must carry an authenticated principal
// @param ttl      requested lifetime, silently capped at MaxTokenTTL; zero means the cap
// @param audience the service this token is for; required, and the verifier must check it
// @return string  the signed compact token
// @return error   UNAUTHENTICATED with no caller, INVALID_INPUT with no audience
func (j *JWT) Token(ctx context.Context, ttl time.Duration, audience string) (string, error) {
	p, err := authz.Require(ctx)
	if err != nil {
		return "", err
	}
	if audience == "" {
		return "", &kalerr.Error{Code: kalerr.CodeInvalidInput,
			Message: "an audience is required — a token nobody checks the audience of authenticates against every service that trusts the issuer"}
	}
	if ttl <= 0 || ttl > MaxTokenTTL {
		ttl = MaxTokenTTL
	}

	now := time.Now()
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
		"iss": j.issuer,
		"sub": p.UserID,
		"aud": audience,
		"sid": p.SessionID,
		"iat": now.Unix(),
		"exp": now.Add(ttl).Unix(),
	})
	tok.Header["kid"] = j.kids[0]
	return tok.SignedString(j.keys[0])
}

// Verify @notice Checks a token's signature and every mandatory claim, and returns what it
// asserts.
//
// @dev Three things here are the difference between this and a vulnerability:
//
//   - The keyfunc receives the *parsed but unverified* token, so alg and kid are
//     attacker-controlled at that point. It type-asserts the method rather than trusting the
//     header, and WithValidMethods says the same thing again at the parser level. Belt and
//     braces on purpose: this is the algorithm-confusion attack, and it has bitten every JWT
//     library at least once.
//   - aud, iss and exp are all required. v5 does *not* require exp by default, so without
//     WithExpirationRequired a token with no expiry validates forever. Skipping aud is worse
//     than it sounds: against a shared multi-tenant issuer it means a token minted for any
//     other tenant authenticates here.
//   - One error out, never a joined one. This is the CVE-2024-51744 lesson: v5's validator
//     collects errors and joins them, so errors.Is(err, ErrTokenExpired) can be true even when
//     the signature is invalid — and the near-universal "expired, let me refresh" branch then
//     happily processes a forgery. Fatal conditions are checked before benign ones and exactly
//     one flat error is returned.
//
// @param token    the compact token
// @param audience the audience this verifier answers to
// @return *Claims what the token asserts, once every check has passed
// @return error   a single *kalerr.Error; never a joined one, never a typed JWT error
func (j *JWT) Verify(token, audience string) (*Claims, error) {
	if audience == "" {
		return nil, &kalerr.Error{Code: kalerr.CodeInvalidInput, Message: "an audience is required to verify against"}
	}

	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(token, claims, j.keyfunc,
		jwt.WithValidMethods([]string{"EdDSA"}),
		jwt.WithIssuer(j.issuer),
		jwt.WithAudience(audience),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		// Fatal first. The order is the control: a forgery that also happens to be expired
		// must read as a forgery.
		switch {
		case errors.Is(err, jwt.ErrTokenSignatureInvalid),
			errors.Is(err, jwt.ErrTokenMalformed),
			errors.Is(err, jwt.ErrTokenUnverifiable):
			return nil, invalidToken(err)
		case errors.Is(err, jwt.ErrTokenExpired), errors.Is(err, jwt.ErrTokenNotValidYet):
			return nil, &kalerr.Error{Code: kalerr.CodeUnauthenticated,
				Message: "token has expired", Internal: err}
		default:
			return nil, invalidToken(err)
		}
	}

	sub, _ := claims["sub"].(string)
	sid, _ := claims["sid"].(string)
	if sub == "" {
		return nil, invalidToken(errors.New("no sub claim"))
	}
	exp, err := claims.GetExpirationTime()
	if err != nil || exp == nil {
		return nil, invalidToken(errors.New("no exp claim"))
	}
	return &Claims{UserID: sub, SessionID: sid, Audience: audience, ExpiresAt: exp.Time}, nil
}

// invalidToken @notice The one verification failure, so a caller cannot distinguish a forgery
// from a typo.
func invalidToken(cause error) error {
	return &kalerr.Error{Code: kalerr.CodeUnauthenticated, Message: "invalid token", Internal: cause}
}

// keyfunc @notice Resolves the verification key, refusing anything that is not EdDSA.
//
// @dev The kid selects among the active keys, and an unknown or absent kid falls back to
// trying every key. Falling back is safe — a signature either verifies under some key we hold
// or it does not — and it keeps a token minted moments before a rotation from failing.
func (j *JWT) keyfunc(t *jwt.Token) (any, error) {
	if _, ok := t.Method.(*jwt.SigningMethodEd25519); !ok {
		return nil, fmt.Errorf("session: unexpected signing method %q", t.Method.Alg())
	}
	if kid, ok := t.Header["kid"].(string); ok {
		for i, k := range j.kids {
			if k == kid {
				return j.keys[i].Public(), nil
			}
		}
	}
	pubs := make([]ed25519.PublicKey, 0, len(j.keys))
	for _, k := range j.keys {
		pubs = append(pubs, k.Public().(ed25519.PublicKey))
	}
	return jwt.VerificationKeySet{Keys: keysAsAny(pubs)}, nil
}

// keysAsAny @notice Widens the public keys for jwt.VerificationKeySet.
func keysAsAny(pubs []ed25519.PublicKey) []jwt.VerificationKey {
	out := make([]jwt.VerificationKey, 0, len(pubs))
	for _, p := range pubs {
		out = append(out, p)
	}
	return out
}

// JWKS @notice An http.Handler publishing the public keys as a JWKS document.
//
// @dev Twenty-five lines, and worth every one: a non-Go verifier has no other way to learn
// these keys. Every active key is published, which is what makes rotation an overlap rather
// than a cutover.
//
// @return http.Handler serving application/json at whatever path you mount it on
func (j *JWT) JWKS() http.Handler {
	type jwk struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		X   string `json:"x"`
		Use string `json:"use"`
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	keys := make([]jwk, 0, len(j.keys))
	for i, k := range j.keys {
		pub := k.Public().(ed25519.PublicKey)
		keys = append(keys, jwk{
			Kty: "OKP", Crv: "Ed25519", Use: "sig", Alg: "EdDSA",
			X:   base64.RawURLEncoding.EncodeToString(pub),
			Kid: j.kids[i],
		})
	}
	body, err := json.Marshal(map[string]any{"keys": keys})
	if err != nil {
		panic(err) // the document is built from fixed-shape data; a failure means this file is broken
	}
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		_, _ = w.Write(body)
	})
}

// thumbprint @notice The kid for a public key: base64url of its SHA-256.
//
// @dev Derived rather than configured, so a key and its identifier cannot drift apart.
func thumbprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
