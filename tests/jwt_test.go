package tests

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/ulas96/kal/authz"
	"github.com/ulas96/kal/kalerr"
	"github.com/ulas96/kal/session"
)

// newTestJWT @notice A JWT minter over a freshly generated key, plus that key.
func newTestJWT(t *testing.T, extra ...ed25519.PrivateKey) (*session.JWT, ed25519.PrivateKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	j, err := session.NewJWT("https://kal.example.test", append([]ed25519.PrivateKey{priv}, extra...)...)
	if err != nil {
		t.Fatal(err)
	}
	return j, priv
}

// principalCtx @notice A context carrying an authenticated caller.
func principalCtx() context.Context {
	return authz.WithPrincipal(context.Background(),
		&authz.Principal{UserID: "user-1", SessionID: "session-1"})
}

// TestJWTRoundTrip @notice A minted token verifies, and carries the claims a verifier needs —
// including sid, which is what lets a verifier with database access check liveness.
//
// @param t the test handle
func TestJWTRoundTrip(t *testing.T) {
	j, _ := newTestJWT(t)

	token, err := j.Token(principalCtx(), time.Minute, "orders-service")
	if err != nil {
		t.Fatal(err)
	}
	claims, err := j.Verify(token, "orders-service")
	if err != nil {
		t.Fatal(err)
	}
	if claims.UserID != "user-1" || claims.SessionID != "session-1" {
		t.Errorf("claims = %+v", claims)
	}
	if time.Until(claims.ExpiresAt) > time.Minute+time.Second {
		t.Errorf("expiry = %v, longer than the requested ttl", claims.ExpiresAt)
	}

	t.Run("the algorithm is EdDSA and the kid is present", func(t *testing.T) {
		parsed, _, err := jwt.NewParser().ParseUnverified(token, jwt.MapClaims{})
		if err != nil {
			t.Fatal(err)
		}
		if parsed.Method.Alg() != "EdDSA" {
			t.Errorf("alg = %q, want EdDSA", parsed.Method.Alg())
		}
		if kid, _ := parsed.Header["kid"].(string); kid == "" {
			t.Error("no kid header — a JWKS verifier cannot select a key")
		}
	})

	t.Run("anonymous callers cannot mint", func(t *testing.T) {
		_, err := j.Token(context.Background(), time.Minute, "orders-service")
		var ae *kalerr.Error
		if !errors.As(err, &ae) || ae.Code != kalerr.CodeUnauthenticated {
			t.Errorf("error = %v, want UNAUTHENTICATED", err)
		}
	})

	t.Run("an audience is required to mint and to verify", func(t *testing.T) {
		if _, err := j.Token(principalCtx(), time.Minute, ""); err == nil {
			t.Error("minted a token with no audience")
		}
		if _, err := j.Verify(token, ""); err == nil {
			t.Error("verified against no audience")
		}
	})
}

// TestJWTForgery @notice The attacks this design is shaped against.
//
// @dev The HS256 case is the classic: re-sign the payload with the Ed25519 *public* key as an
// HMAC secret. A verifier that reads alg from the token header accepts it, because the public
// key is public. Fixing the algorithm at construction is what makes it structurally impossible
// rather than a thing to remember.
//
// @param t the test handle
func TestJWTForgery(t *testing.T) {
	j, priv := newTestJWT(t)
	pub := priv.Public().(ed25519.PublicKey)
	now := time.Now()

	t.Run("HS256 signed with the public key as the secret", func(t *testing.T) {
		forged := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"iss": "https://kal.example.test",
			"sub": "user-1",
			"aud": "orders-service",
			"exp": now.Add(time.Hour).Unix(),
		})
		signed, err := forged.SignedString([]byte(pub))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := j.Verify(signed, "orders-service"); err == nil {
			t.Fatal("an HS256 forgery signed with the public key was accepted")
		}
	})

	t.Run("alg none", func(t *testing.T) {
		forged := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
			"iss": "https://kal.example.test", "sub": "user-1", "aud": "orders-service",
			"exp": now.Add(time.Hour).Unix(),
		})
		signed, err := forged.SignedString(jwt.UnsafeAllowNoneSignatureType)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := j.Verify(signed, "orders-service"); err == nil {
			t.Fatal("an unsigned token was accepted")
		}
	})

	t.Run("signed by a key we do not hold", func(t *testing.T) {
		other, otherPriv := newTestJWT(t)
		_ = other
		token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
			"iss": "https://kal.example.test", "sub": "user-1", "aud": "orders-service",
			"exp": now.Add(time.Hour).Unix(),
		})
		signed, err := token.SignedString(otherPriv)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := j.Verify(signed, "orders-service"); err == nil {
			t.Fatal("a token signed by a foreign key was accepted")
		}
	})

	t.Run("a tampered payload", func(t *testing.T) {
		token, err := j.Token(principalCtx(), time.Minute, "orders-service")
		if err != nil {
			t.Fatal(err)
		}
		parts := strings.Split(token, ".")
		// Swap one character of the payload; the signature no longer covers it.
		parts[1] = "X" + parts[1][1:]
		if _, err := j.Verify(strings.Join(parts, "."), "orders-service"); err == nil {
			t.Fatal("a tampered payload was accepted")
		}
	})
}

// TestJWTMandatoryClaims @notice exp, aud and iss are each required, and each is checked.
//
// @dev The exp case matters most: v5 does not require exp by default, so without
// WithExpirationRequired a token with no expiry would validate forever.
//
// @param t the test handle
func TestJWTMandatoryClaims(t *testing.T) {
	j, priv := newTestJWT(t)
	sign := func(claims jwt.MapClaims) string {
		t.Helper()
		signed, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims).SignedString(priv)
		if err != nil {
			t.Fatal(err)
		}
		return signed
	}
	future := time.Now().Add(time.Hour).Unix()

	cases := []struct {
		name   string
		claims jwt.MapClaims
	}{
		{"no exp", jwt.MapClaims{"iss": "https://kal.example.test", "sub": "u", "aud": "orders-service"}},
		{"no aud", jwt.MapClaims{"iss": "https://kal.example.test", "sub": "u", "exp": future}},
		{"no iss", jwt.MapClaims{"sub": "u", "aud": "orders-service", "exp": future}},
		{"wrong aud", jwt.MapClaims{"iss": "https://kal.example.test", "sub": "u", "aud": "billing-service", "exp": future}},
		{"wrong iss", jwt.MapClaims{"iss": "https://evil.example", "sub": "u", "aud": "orders-service", "exp": future}},
		{"no sub", jwt.MapClaims{"iss": "https://kal.example.test", "aud": "orders-service", "exp": future}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := j.Verify(sign(c.claims), "orders-service"); err == nil {
				t.Errorf("a token with %s was accepted", c.name)
			}
		})
	}
}

// TestJWTExpiry @notice The TTL cap is enforced in code, and an expired token is refused with
// one flat error rather than a joined one.
//
// @param t the test handle
func TestJWTExpiry(t *testing.T) {
	j, priv := newTestJWT(t)

	t.Run("a longer ttl is capped, not honoured", func(t *testing.T) {
		token, err := j.Token(principalCtx(), 24*time.Hour, "orders-service")
		if err != nil {
			t.Fatal(err)
		}
		claims, err := j.Verify(token, "orders-service")
		if err != nil {
			t.Fatal(err)
		}
		if time.Until(claims.ExpiresAt) > session.MaxTokenTTL+time.Second {
			t.Errorf("expiry is %v out, want the %v cap — the TTL is the revocation window",
				time.Until(claims.ExpiresAt), session.MaxTokenTTL)
		}
	})

	t.Run("a zero ttl means the cap", func(t *testing.T) {
		token, err := j.Token(principalCtx(), 0, "orders-service")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := j.Verify(token, "orders-service"); err != nil {
			t.Errorf("a zero-ttl token does not verify: %v", err)
		}
	})

	t.Run("an expired token is refused", func(t *testing.T) {
		expired, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
			"iss": "https://kal.example.test", "sub": "u", "aud": "orders-service",
			"exp": time.Now().Add(-time.Minute).Unix(),
		}).SignedString(priv)
		if err != nil {
			t.Fatal(err)
		}
		_, err = j.Verify(expired, "orders-service")
		var ae *kalerr.Error
		if !errors.As(err, &ae) || ae.Code != kalerr.CodeUnauthenticated {
			t.Fatalf("error = %v, want UNAUTHENTICATED", err)
		}
	})

	// CVE-2024-51744: v5's validator joins its errors, so errors.Is(err, ErrTokenExpired) can be
	// true on a token whose signature never verified — and the near-universal "expired, let me
	// refresh" branch then processes a forgery. A forgery that is also expired must read as a
	// forgery, not as an expiry.
	t.Run("an expired forgery does not read as merely expired", func(t *testing.T) {
		_, foreign, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		forged, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
			"iss": "https://kal.example.test", "sub": "u", "aud": "orders-service",
			"exp": time.Now().Add(-time.Minute).Unix(),
		}).SignedString(foreign)
		if err != nil {
			t.Fatal(err)
		}
		_, err = j.Verify(forged, "orders-service")
		if err == nil {
			t.Fatal("an expired forgery was accepted")
		}
		if errors.Is(err, jwt.ErrTokenExpired) {
			t.Error("the forgery surfaced as jwt.ErrTokenExpired — a caller's refresh branch would process it")
		}
		var ae *kalerr.Error
		if !errors.As(err, &ae) || ae.Message != "invalid token" {
			t.Errorf("error = %v, want the flat invalid-token error", err)
		}
	})
}

// TestJWTRotation @notice Two active keys: the newest signs, both verify — so a rotation is a
// deploy rather than an outage.
//
// @param t the test handle
func TestJWTRotation(t *testing.T) {
	_, oldKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	// A token minted before the rotation, by the old key alone.
	oldOnly, err := session.NewJWT("https://kal.example.test", oldKey)
	if err != nil {
		t.Fatal(err)
	}
	oldToken, err := oldOnly.Token(principalCtx(), time.Minute, "orders-service")
	if err != nil {
		t.Fatal(err)
	}

	// After the rotation: new key first, old key retained.
	rotated, _ := newTestJWT(t, oldKey)
	if _, err := rotated.Verify(oldToken, "orders-service"); err != nil {
		t.Errorf("a token from before the rotation stopped verifying: %v", err)
	}
	newToken, err := rotated.Token(principalCtx(), time.Minute, "orders-service")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rotated.Verify(newToken, "orders-service"); err != nil {
		t.Errorf("a freshly minted token does not verify: %v", err)
	}
	// Once the old key is dropped, its tokens stop verifying — the point of the overlap.
	if _, err := oldOnly.Verify(newToken, "orders-service"); err == nil {
		t.Error("the retired key set verified a token signed by the new key")
	}
}

// TestJWKS @notice The published document is what a non-Go verifier needs, and it carries every
// active key.
//
// @param t the test handle
func TestJWKS(t *testing.T) {
	_, oldKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	j, priv := newTestJWT(t, oldKey)

	rec := httptest.NewRecorder()
	j.JWKS().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))

	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	var doc struct {
		Keys []struct{ Kty, Crv, X, Use, Alg, Kid string } `json:"keys"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Keys) != 2 {
		t.Fatalf("published %d keys, want both active ones", len(doc.Keys))
	}
	k := doc.Keys[0]
	if k.Kty != "OKP" || k.Crv != "Ed25519" || k.Alg != "EdDSA" || k.Use != "sig" || k.Kid == "" {
		t.Errorf("first key = %+v", k)
	}

	// The published key is the signing key's public half, and its kid matches the token header.
	token, err := j.Token(principalCtx(), time.Minute, "orders-service")
	if err != nil {
		t.Fatal(err)
	}
	parsed, _, err := jwt.NewParser().ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		t.Fatal(err)
	}
	if kid, _ := parsed.Header["kid"].(string); kid != k.Kid {
		t.Errorf("token kid %q is not the first published kid %q", kid, k.Kid)
	}
	// And a verifier rebuilding the key from x can check the signature.
	pub := priv.Public().(ed25519.PublicKey)
	rebuilt, err := jwt.NewParser(jwt.WithValidMethods([]string{"EdDSA"})).Parse(token,
		func(*jwt.Token) (any, error) { return pub, nil })
	if err != nil || !rebuilt.Valid {
		t.Errorf("the published key does not verify the token: %v", err)
	}
}

// TestNewJWTValidation @notice Construction rejects what cannot be made safe later.
//
// @param t the test handle
func TestNewJWTValidation(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.NewJWT("", priv); err == nil {
		t.Error("an empty issuer was accepted")
	}
	if _, err := session.NewJWT("https://kal.example.test"); err == nil {
		t.Error("no keys were accepted")
	}
	if _, err := session.NewJWT("https://kal.example.test", ed25519.PrivateKey("too short")); err == nil {
		t.Error("a malformed key was accepted")
	}
}
