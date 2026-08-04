package tests

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/ulas96/kal/authn"
	"github.com/ulas96/kal/kalerr"
)

// TestPasswordHash @notice Round trip, salt freshness, and the encoded prefix pinned byte for
// byte — p=1 in particular, since the popular wrapper's NumCPU default is the bug this package
// exists to not have.
//
// @param t the test handle
func TestPasswordHash(t *testing.T) {
	ctx := context.Background()
	h, err := authn.NewHasher(authn.Params{}, 0)
	if err != nil {
		t.Fatal(err)
	}

	encoded, err := h.Hash(ctx, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}

	// The whole parameter block, verbatim. If this fails on a many-core machine, someone has
	// reintroduced a machine-dependent parameter.
	if !strings.HasPrefix(encoded, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Errorf("encoded prefix = %q, want the pinned OWASP parameters", encoded)
	}

	if ok, rehash, err := h.Verify(ctx, "correct horse battery staple", encoded); err != nil || !ok || rehash {
		t.Errorf("Verify(right password) = %v, %v, %v", ok, rehash, err)
	}
	if ok, _, err := h.Verify(ctx, "correct horse battery stapl", encoded); err != nil || ok {
		t.Errorf("Verify(wrong password) = %v, %v", ok, err)
	}

	again, err := h.Hash(ctx, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if again == encoded {
		t.Error("two hashes of one password are identical — the salt is not fresh")
	}

	if err := h.VerifyDummy(ctx, "anything at all"); err != nil {
		t.Errorf("VerifyDummy = %v", err)
	}
}

// TestPasswordExactBytes @notice The password is verified exactly as received: whitespace and
// Unicode form are significant, because any silent transformation is information loss between
// what the user typed and what the server checks.
//
// @param t the test handle
func TestPasswordExactBytes(t *testing.T) {
	ctx := context.Background()
	h, err := authn.NewHasher(authn.Params{}, 0)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct{ set, try string }{
		{"pässword²µ", "pässword²µ "},               // trailing space
		{" pässword²µ", "pässword²µ"},               // leading space
		{"caf\u00e9-au-lait", "cafe\u0301-au-lait"}, // NFC \u00e9 versus NFD e + combining acute
	}
	for _, c := range cases {
		encoded, err := h.Hash(ctx, c.set)
		if err != nil {
			t.Fatal(err)
		}
		if ok, _, err := h.Verify(ctx, c.set, encoded); err != nil || !ok {
			t.Errorf("Verify(%q against itself) = %v, %v", c.set, ok, err)
		}
		if ok, _, _ := h.Verify(ctx, c.try, encoded); ok {
			t.Errorf("Verify(%q) matched a hash of %q — a transformation is being applied", c.try, c.set)
		}
	}
}

// TestPasswordRehash @notice Parameters travel with the hash, and a hash stored with weaker
// parameters is flagged for upgrade on a successful verify — the only mechanism that raises
// cost over time without a password reset. Lowering the configured cost never flags a
// downgrade.
//
// @param t the test handle
func TestPasswordRehash(t *testing.T) {
	ctx := context.Background()
	weakParams := authn.Params{Memory: 8192, Time: 1}
	strongParams := authn.Params{} // the defaults

	weak, err := authn.NewHasher(weakParams, 0)
	if err != nil {
		t.Fatal(err)
	}
	strong, err := authn.NewHasher(strongParams, 0)
	if err != nil {
		t.Fatal(err)
	}

	old, err := weak.Hash(ctx, "hunter2hunter2")
	if err != nil {
		t.Fatal(err)
	}

	ok, rehash, err := strong.Verify(ctx, "hunter2hunter2", old)
	if err != nil || !ok {
		t.Fatalf("Verify across parameter generations = %v, %v", ok, err)
	}
	if !rehash {
		t.Error("a weaker stored hash was not flagged for rehash")
	}

	// The other direction: a stronger stored hash under a weaker configuration stays put.
	newer, err := strong.Hash(ctx, "hunter2hunter2")
	if err != nil {
		t.Fatal(err)
	}
	if ok, rehash, _ := weak.Verify(ctx, "hunter2hunter2", newer); !ok || rehash {
		t.Errorf("stronger stored hash: ok=%v rehash=%v — lowering config must not downgrade", ok, rehash)
	}
}

// TestPasswordBcryptLegacy @notice bcrypt hashes verify — an imported user base logs in — and
// every match demands a rehash, which is the whole migration path off bcrypt.
//
// @param t the test handle
func TestPasswordBcryptLegacy(t *testing.T) {
	ctx := context.Background()
	h, err := authn.NewHasher(authn.Params{}, 0)
	if err != nil {
		t.Fatal(err)
	}

	legacy, err := bcrypt.GenerateFromPassword([]byte("imported-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}

	ok, rehash, err := h.Verify(ctx, "imported-password", string(legacy))
	if err != nil || !ok {
		t.Fatalf("Verify(bcrypt) = %v, %v", ok, err)
	}
	if !rehash {
		t.Error("a bcrypt match must always demand a rehash")
	}
	if ok, _, _ := h.Verify(ctx, "wrong-password", string(legacy)); ok {
		t.Error("Verify(bcrypt, wrong password) matched")
	}
}

// TestPasswordPolicy @notice Minimum in runes, maximum in bytes, nothing else — no composition
// rules, and multibyte characters count as characters.
//
// @param t the test handle
func TestPasswordPolicy(t *testing.T) {
	if err := authn.ValidatePassword("1234567"); err == nil {
		t.Error("7 characters passed")
	} else {
		var ae *kalerr.Error
		if !errors.As(err, &ae) || ae.Code != kalerr.CodeInvalidInput {
			t.Errorf("policy error = %v, want INVALID_INPUT", err)
		}
	}
	if err := authn.ValidatePassword("12345678"); err != nil {
		t.Errorf("8 characters rejected: %v", err)
	}
	// Eight runes, sixteen bytes: rune counting, not byte counting.
	if err := authn.ValidatePassword("ññññññññ"); err != nil {
		t.Errorf("8 multibyte characters rejected: %v", err)
	}
	if err := authn.ValidatePassword(strings.Repeat("a", authn.MaxPasswordLen)); err != nil {
		t.Errorf("maximum length rejected: %v", err)
	}
	if err := authn.ValidatePassword(strings.Repeat("a", authn.MaxPasswordLen+1)); err == nil {
		t.Error("over-maximum passed")
	}
}

// TestPasswordBound @notice The semaphore holds: with a bound of one and a hash in flight, a
// second caller is told RATE_LIMITED within its deadline instead of stacking another 64 MiB.
//
// @dev Timing-sensitive by nature, with margins chosen wide: the in-flight hash costs hundreds
// of milliseconds while the rejected caller carries a 50 ms deadline.
//
// @param t the test handle
func TestPasswordBound(t *testing.T) {
	ctx := context.Background()
	// Heavy parameters so the in-flight hash comfortably outlives the second caller's deadline.
	h, err := authn.NewHasher(authn.Params{Memory: 65536, Time: 8}, 1)
	if err != nil {
		t.Fatal(err)
	}

	encoded, err := h.Hash(ctx, "the reference hash")
	if err != nil {
		t.Fatal(err)
	}

	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		close(started)
		_, err := h.Hash(ctx, "the slot holder")
		done <- err
	}()
	<-started
	time.Sleep(30 * time.Millisecond) // let the goroutine actually take the slot

	quick, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	_, _, err = h.Verify(quick, "whoever", encoded)
	var ae *kalerr.Error
	if !errors.As(err, &ae) || ae.Code != kalerr.CodeRateLimited {
		t.Errorf("bounded Verify error = %v, want RATE_LIMITED", err)
	}

	if err := <-done; err != nil {
		t.Fatalf("the slot holder itself failed: %v", err)
	}
	// And the slot is released: the same call now completes.
	if ok, _, err := h.Verify(ctx, "the reference hash", encoded); err != nil || !ok {
		t.Errorf("Verify after release = %v, %v", ok, err)
	}
}
