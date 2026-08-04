package tests

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/go-pg/pg/v10"

	"github.com/ulas96/kal/authn"
	"github.com/ulas96/kal/kalerr"
	"github.com/ulas96/kal/session"
)

// tokenFromURL @notice The token query parameter out of an emailed link.
func tokenFromURL(t *testing.T, link string) string {
	t.Helper()
	_, query, ok := strings.Cut(link, "?token=")
	if !ok {
		t.Fatalf("link %q carries no token", link)
	}
	return query
}

// TestDBRegister @notice Registration cannot be used to enumerate accounts: a new address and
// an existing one produce the identical return value, and the only difference is which message
// lands in the mailbox.
//
// @dev The response comparison is the point. luima's crud.Create classifies 23505 into "…
// already exists", which on a signup mutation is exactly the oracle this test forbids — which
// is why kal inserts directly instead.
//
// @param t the test handle
func TestDBRegister(t *testing.T) {
	f := newAuthnFixture(t)
	ctx := context.Background()

	t.Run("new address creates an account and sends a verification link", func(t *testing.T) {
		f.mailer.take()
		if err := f.accounts.Register(ctx, f.db, "New.User@Example.com", "a password worth using"); err != nil {
			t.Fatalf("Register: %v", err)
		}
		sent := f.mailer.take()
		if len(sent) != 1 || sent[0].msg.Kind != authn.KindVerify {
			t.Fatalf("mail = %+v, want one verify message", sent)
		}
		if !strings.HasPrefix(sent[0].msg.URL, "https://app.example.test/verify?token=") {
			t.Errorf("verify URL = %q, want an origin from BaseURL", sent[0].msg.URL)
		}
		// Stored lowercase, unverified, with a password.
		var email string
		var verified bool
		var hash string
		if _, err := f.db.QueryOne(pg.Scan(&email, &verified, &hash),
			`select email, email_verified, password_hash from auth_users where lower(email) = 'new.user@example.com'`); err != nil {
			t.Fatal(err)
		}
		if email != "new.user@example.com" || verified || hash == "" {
			t.Errorf("row: email=%q verified=%v hash empty=%v", email, verified, hash == "")
		}
	})

	t.Run("existing address is indistinguishable to the caller", func(t *testing.T) {
		f.mailer.take()
		err := f.accounts.Register(ctx, f.db, "new.user@example.com", "a different password")
		if err != nil {
			t.Fatalf("re-registering must not error — that is the oracle: %v", err)
		}
		sent := f.mailer.take()
		if len(sent) != 1 || sent[0].msg.Kind != authn.KindAttemptedRegister {
			t.Fatalf("mail = %+v, want one attempted-register message", sent)
		}

		// One account, and the original password still works: a second registration must not
		// overwrite a credential.
		var n int
		if _, err := f.db.QueryOne(pg.Scan(&n),
			`select count(*) from auth_users where lower(email) = 'new.user@example.com'`); err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Errorf("account count = %d, want 1", n)
		}
	})

	t.Run("policy and address shape are rejected before anything is written", func(t *testing.T) {
		for _, c := range []struct{ name, email, password string }{
			{"short password", "shorty@example.com", "1234567"},
			{"no at sign", "not-an-address", "a password worth using"},
			{"empty address", "", "a password worth using"},
		} {
			err := f.accounts.Register(ctx, f.db, c.email, c.password)
			var ae *kalerr.Error
			if !errors.As(err, &ae) || ae.Code != kalerr.CodeInvalidInput {
				t.Errorf("%s: error = %v, want INVALID_INPUT", c.name, err)
			}
		}
	})

	t.Run("a soft-deleted address can register again", func(t *testing.T) {
		if err := f.accounts.Register(ctx, f.db, "gone@example.com", "a password worth using"); err != nil {
			t.Fatal(err)
		}
		if _, err := f.db.Exec(`update auth_users set deleted_at = now() where email = 'gone@example.com'`); err != nil {
			t.Fatal(err)
		}
		f.mailer.take()
		if err := f.accounts.Register(ctx, f.db, "gone@example.com", "a password worth using"); err != nil {
			t.Fatal(err)
		}
		sent := f.mailer.take()
		if len(sent) != 1 || sent[0].msg.Kind != authn.KindVerify {
			t.Errorf("mail = %+v, want a fresh verify message", sent)
		}
	})
}

// TestDBVerifyEmail @notice The verification link works once, and only as a verification link.
//
// @param t the test handle
func TestDBVerifyEmail(t *testing.T) {
	f := newAuthnFixture(t)
	ctx := context.Background()

	f.mailer.take()
	if err := f.accounts.Register(ctx, f.db, "verify@example.com", "a password worth using"); err != nil {
		t.Fatal(err)
	}
	token := tokenFromURL(t, f.mailer.take()[0].msg.URL)

	// Unverified accounts cannot log in under the default configuration.
	f.request(t, "", "192.0.2.60", func(ctx context.Context) error {
		_, err := f.accounts.Login(ctx, f.db, "verify@example.com", "a password worth using")
		return err
	})
	if f.lastErr == nil {
		t.Error("an unverified account logged in")
	}

	if err := f.accounts.VerifyEmail(ctx, f.db, token); err != nil {
		t.Fatalf("VerifyEmail: %v", err)
	}
	var verified bool
	if _, err := f.db.QueryOne(pg.Scan(&verified),
		`select email_verified from auth_users where email = 'verify@example.com'`); err != nil {
		t.Fatal(err)
	}
	if !verified {
		t.Error("the account is still unverified")
	}

	t.Run("second use fails", func(t *testing.T) {
		err := f.accounts.VerifyEmail(ctx, f.db, token)
		var ae *kalerr.Error
		if !errors.As(err, &ae) || ae.Code != kalerr.CodeInvalidToken {
			t.Errorf("error = %v, want INVALID_TOKEN", err)
		}
	})

	t.Run("purpose is enforced", func(t *testing.T) {
		f.mailer.take()
		if err := f.accounts.RequestPasswordReset(ctx, f.db, "verify@example.com"); err != nil {
			t.Fatal(err)
		}
		resetToken := tokenFromURL(t, f.mailer.take()[0].msg.URL)
		// A reset token must not verify an email, and the error must not say why.
		err := f.accounts.VerifyEmail(ctx, f.db, resetToken)
		var ae *kalerr.Error
		if !errors.As(err, &ae) || ae.Code != kalerr.CodeInvalidToken {
			t.Errorf("error = %v, want INVALID_TOKEN", err)
		}
		// And it is still usable for what it was minted for: a wrong-purpose attempt must not
		// burn the token.
		if err := f.accounts.ResetPassword(ctx, f.db, resetToken, "a brand new password"); err != nil {
			t.Errorf("the reset token was consumed by the failed verify: %v", err)
		}
	})

	t.Run("garbage token", func(t *testing.T) {
		err := f.accounts.VerifyEmail(ctx, f.db, "not-a-real-token")
		var ae *kalerr.Error
		if !errors.As(err, &ae) || ae.Code != kalerr.CodeInvalidToken {
			t.Errorf("error = %v, want INVALID_TOKEN", err)
		}
	})
}

// TestDBPasswordReset @notice The recovery path: requesting one changes nothing, completing one
// kills every session, and neither step tells a caller whether the address exists.
//
// @param t the test handle
func TestDBPasswordReset(t *testing.T) {
	f := newAuthnFixture(t)
	ctx := context.Background()
	f.createPasswordUser(t, "reset@example.com", "the original password")

	t.Run("requesting a reset is indistinguishable and mutates nothing", func(t *testing.T) {
		f.mailer.take()
		errKnown := f.accounts.RequestPasswordReset(ctx, f.db, "reset@example.com")
		knownMail := f.mailer.take()
		errUnknown := f.accounts.RequestPasswordReset(ctx, f.db, "nobody-here@example.com")
		unknownMail := f.mailer.take()

		if errKnown != nil || errUnknown != nil {
			t.Fatalf("errors = %v, %v — both must be nil", errKnown, errUnknown)
		}
		if len(knownMail) != 1 || knownMail[0].msg.Kind != authn.KindReset {
			t.Errorf("known-address mail = %+v", knownMail)
		}
		if len(unknownMail) != 1 || unknownMail[0].msg.Kind != authn.KindResetNoAccount {
			t.Errorf("unknown-address mail = %+v", unknownMail)
		}

		// The account is untouched — anything a reset *request* changes is a denial of service
		// anyone can trigger against any address.
		f.request(t, "", "192.0.2.70", func(ctx context.Context) error {
			_, err := f.accounts.Login(ctx, f.db, "reset@example.com", "the original password")
			return err
		})
		if f.lastErr != nil {
			t.Errorf("the old password stopped working on a mere reset request: %v", f.lastErr)
		}
	})

	t.Run("completing a reset revokes every session and does not sign the caller in", func(t *testing.T) {
		// Two live sessions on other devices.
		tokenA, err := f.sessions.Issue(ctx, f.db, f.userID(t, "reset@example.com"), session.Meta{})
		if err != nil {
			t.Fatal(err)
		}
		tokenB, err := f.sessions.Issue(ctx, f.db, f.userID(t, "reset@example.com"), session.Meta{})
		if err != nil {
			t.Fatal(err)
		}

		f.mailer.take()
		if err := f.accounts.RequestPasswordReset(ctx, f.db, "reset@example.com"); err != nil {
			t.Fatal(err)
		}
		resetToken := tokenFromURL(t, f.mailer.take()[0].msg.URL)

		if err := f.accounts.ResetPassword(ctx, f.db, resetToken, "a replacement password"); err != nil {
			t.Fatalf("ResetPassword: %v", err)
		}
		for name, tok := range map[string]string{"A": tokenA, "B": tokenB} {
			if p, _ := f.sessions.Lookup(ctx, f.db, tok); p != nil {
				t.Errorf("session %s survived the reset", name)
			}
		}
		if got := f.mailer.kinds(); len(got) != 1 || got[0] != string(authn.KindPasswordChanged) {
			t.Errorf("mail kinds = %v, want [password-changed]", got)
		}

		// The new password works, the old one does not.
		if _, err := f.db.Exec(`delete from auth_login_attempts`); err != nil {
			t.Fatal(err)
		}
		f.request(t, "", "192.0.2.71", func(ctx context.Context) error {
			_, err := f.accounts.Login(ctx, f.db, "reset@example.com", "the original password")
			return err
		})
		if f.lastErr == nil {
			t.Error("the pre-reset password still logs in")
		}
		if _, err := f.db.Exec(`delete from auth_login_attempts`); err != nil {
			t.Fatal(err)
		}
		f.request(t, "", "192.0.2.72", func(ctx context.Context) error {
			_, err := f.accounts.Login(ctx, f.db, "reset@example.com", "a replacement password")
			return err
		})
		if f.lastErr != nil {
			t.Errorf("the new password does not log in: %v", f.lastErr)
		}
	})

	t.Run("an expired token is refused", func(t *testing.T) {
		f.mailer.take()
		if err := f.accounts.RequestPasswordReset(ctx, f.db, "reset@example.com"); err != nil {
			t.Fatal(err)
		}
		token := tokenFromURL(t, f.mailer.take()[0].msg.URL)
		if _, err := f.db.Exec(`update auth_tokens set expires_at = now() - interval '1 second' where consumed_at is null`); err != nil {
			t.Fatal(err)
		}
		err := f.accounts.ResetPassword(ctx, f.db, token, "yet another password")
		var ae *kalerr.Error
		if !errors.As(err, &ae) || ae.Code != kalerr.CodeInvalidToken {
			t.Errorf("error = %v, want INVALID_TOKEN", err)
		}
	})
}

// TestDBTokenSingleUseUnderConcurrency @notice Two simultaneous submissions of one token
// produce exactly one success — the property the single-statement consume exists for.
//
// @dev A read-then-write implementation passes every sequential test in this file and fails
// this one, which is why it is here: a double-clicked email link, or a mail client that
// prefetches URLs, hits exactly this race.
//
// @param t the test handle
func TestDBTokenSingleUseUnderConcurrency(t *testing.T) {
	f := newAuthnFixture(t)
	ctx := context.Background()
	f.createPasswordUser(t, "race@example.com", "the original password")

	f.mailer.take()
	if err := f.accounts.RequestPasswordReset(ctx, f.db, "race@example.com"); err != nil {
		t.Fatal(err)
	}
	token := tokenFromURL(t, f.mailer.take()[0].msg.URL)

	const attempts = 8
	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make([]error, attempts)
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			errs[i] = f.accounts.ResetPassword(ctx, f.db, token, "the replacement password")
		}(i)
	}
	close(start)
	wg.Wait()

	successes := 0
	for i, err := range errs {
		if err == nil {
			successes++
			continue
		}
		var ae *kalerr.Error
		if !errors.As(err, &ae) || ae.Code != kalerr.CodeInvalidToken {
			t.Errorf("attempt %d: error = %v, want INVALID_TOKEN", i, err)
		}
	}
	if successes != 1 {
		t.Errorf("%d of %d concurrent submissions succeeded, want exactly 1", successes, attempts)
	}
}

// TestDBInvite @notice An invited account has no password until the invitation is accepted,
// and accepting it both sets the password and marks the address verified.
//
// @param t the test handle
func TestDBInvite(t *testing.T) {
	f := newAuthnFixture(t)
	ctx := context.Background()

	f.mailer.take()
	link, err := f.accounts.Invite(ctx, f.db, "Invitee@Example.com")
	if err != nil {
		t.Fatalf("Invite: %v", err)
	}
	sent := f.mailer.take()
	if len(sent) != 1 || sent[0].msg.Kind != authn.KindInvite {
		t.Fatalf("mail = %+v, want one invite", sent)
	}
	if sent[0].msg.URL != link {
		t.Errorf("returned link %q differs from the emailed one %q", link, sent[0].msg.URL)
	}

	// No password yet: the account exists but cannot be logged into.
	var hash *string
	if _, err := f.db.QueryOne(pg.Scan(&hash),
		`select password_hash from auth_users where email = 'invitee@example.com'`); err != nil {
		t.Fatal(err)
	}
	if hash != nil {
		t.Errorf("an invited account already has a password: %v", *hash)
	}
	f.request(t, "", "192.0.2.80", func(ctx context.Context) error {
		_, err := f.accounts.Login(ctx, f.db, "invitee@example.com", "")
		return err
	})
	if f.lastErr == nil {
		t.Error("a password-less account logged in with an empty password")
	}

	t.Run("accepting sets the password and verifies the address", func(t *testing.T) {
		if err := f.accounts.AcceptInvite(ctx, f.db, tokenFromURL(t, link), "the chosen password"); err != nil {
			t.Fatalf("AcceptInvite: %v", err)
		}
		var verified bool
		if _, err := f.db.QueryOne(pg.Scan(&verified),
			`select email_verified from auth_users where email = 'invitee@example.com'`); err != nil {
			t.Fatal(err)
		}
		if !verified {
			t.Error("accepting an invite left the address unverified — arriving through the link is the proof")
		}
		if _, err := f.db.Exec(`delete from auth_login_attempts`); err != nil {
			t.Fatal(err)
		}
		f.request(t, "", "192.0.2.81", func(ctx context.Context) error {
			_, err := f.accounts.Login(ctx, f.db, "invitee@example.com", "the chosen password")
			return err
		})
		if f.lastErr != nil {
			t.Errorf("the invited account cannot log in: %v", f.lastErr)
		}
	})

	t.Run("re-inviting an existing member re-issues rather than failing", func(t *testing.T) {
		f.mailer.take()
		if _, err := f.accounts.Invite(ctx, f.db, "invitee@example.com"); err != nil {
			t.Errorf("re-invite = %v, want a fresh link", err)
		}
		if got := f.mailer.kinds(); len(got) != 1 || got[0] != string(authn.KindInvite) {
			t.Errorf("mail kinds = %v, want [invite]", got)
		}
	})
}

// TestValidateBaseURL @notice The origin emailed links are built under is configuration, and
// the validation says so loudly. No database needed.
//
// @param t the test handle
func TestValidateBaseURL(t *testing.T) {
	good := []string{"https://app.example.com", "https://app.example.com/prefix", "http://localhost:3000", "http://127.0.0.1:8080"}
	for _, u := range good {
		if err := authn.ValidateBaseURL(u); err != nil {
			t.Errorf("ValidateBaseURL(%q) = %v, want nil", u, err)
		}
	}
	bad := []string{"", "app.example.com", "http://app.example.com", "https://app.example.com?x=1", "https://app.example.com#f"}
	for _, u := range bad {
		if err := authn.ValidateBaseURL(u); err == nil {
			t.Errorf("ValidateBaseURL(%q) = nil, want an error", u)
		}
	}
}
