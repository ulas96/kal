package authn

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/go-pg/pg/v10"
	"github.com/go-pg/pg/v10/orm"

	"github.com/ulas96/kal/kalerr"
	"github.com/ulas96/kal/session"
)

// Purpose @notice What an emailed token is for. Stored on the row and matched on consumption,
// so a verification link cannot be redeemed as a password reset.
type Purpose string

const (
	// PurposeVerify @notice Proves control of the address. 24 hours.
	PurposeVerify Purpose = "verify"
	// PurposeReset @notice Password recovery. 15 minutes — OWASP says at most an hour, ideally
	// far less, and this token is the account.
	PurposeReset Purpose = "reset"
	// PurposeInvite @notice An account created by someone else, awaiting its first password.
	// 7 days, because invites sit in inboxes over weekends.
	PurposeInvite Purpose = "invite"
)

// TTL for each purpose.
const (
	verifyTTL = 24 * time.Hour
	resetTTL  = 15 * time.Minute
	inviteTTL = 7 * 24 * time.Hour
)

// Register @notice Creates an account and sends either a verification link or a "someone tried
// to register with your address" notice — and answers the caller identically either way.
//
// @dev This is the enumeration boundary, and it is why kal does not use luima's crud.Create
// here. crud.Create classifies SQLSTATE 23505 into a client-visible "… already exists", which
// is exactly the oracle a signup form must not be: send an address, learn whether it is
// registered. That behaviour is correct for crud.Create and wrong for this table, so this
// inserts directly and treats a duplicate as success from the caller's point of view.
//
// The branch is in the mailbox, not in the response. The person who owns the address learns
// that someone tried to register it — which is what makes "check your email" an honest answer
// rather than merely an opaque one — while the caller cannot tell the two cases apart.
//
// @param email    normalised to lowercase before insert
// @param password policy-checked, then hashed within the concurrency bound
// @return error   INVALID_INPUT for a policy failure, otherwise only driver or mailer errors
func (a *Accounts) Register(ctx context.Context, db orm.DB, email, password string) error {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" || !strings.Contains(email, "@") {
		return &kalerr.Error{Code: kalerr.CodeInvalidInput, Message: "a valid email address is required"}
	}
	if err := ValidatePassword(password); err != nil {
		return err
	}

	hash, err := a.hasher.Hash(ctx, password)
	if err != nil {
		return err
	}

	var userID string
	_, err = db.QueryOneContext(ctx, pg.Scan(&userID), a.sql.insertUser, email, hash)
	switch {
	case err == nil:
		token, hashed, err := session.NewToken()
		if err != nil {
			return err
		}
		if _, err := db.ExecContext(ctx, a.sql.insertToken,
			hashed, userID, string(PurposeVerify), verifyTTL.Seconds()); err != nil {
			return err
		}
		a.notify(ctx, email, Message{
			Kind:    KindVerify,
			Subject: "Confirm your email address",
			Text:    "Open this link to confirm your email address and finish setting up your account.",
			URL:     a.link("verify", token),
		})
	case errors.Is(err, pg.ErrNoRows):
		// ON CONFLICT DO NOTHING matched an existing live account: tell its owner, tell the
		// caller nothing.
		a.notify(ctx, email, Message{
			Kind:    KindAttemptedRegister,
			Subject: "Someone tried to register with your address",
			Text:    "An account already exists for this address. If this was you, sign in — or reset your password if you have forgotten it.",
			URL:     a.baseURL,
		})
	default:
		return err
	}
	return nil
}

// RequestPasswordReset @notice Issues a reset token for the address, or sends a "no account
// here" notice — identical response either way, and nothing on the account changes.
//
// @dev Two rules, each of which is a real incident somewhere:
//
//   - The account is not mutated. No lock, no cleared password, no flag that changes login
//     behaviour. Anything changed on request is a denial of service anyone can trigger against
//     any address, and the test asserts the old password still logs in afterwards.
//   - The link's origin comes from Config.BaseURL, never from the request Host header. Host
//     header injection otherwise turns a reset email into an attacker-controlled link, and
//     there is deliberately no way to derive the origin from the request.
//
// Note for the consumer, documented rather than solvable here: the token is in a URL, so it
// leaks through Referer to any third-party asset on the landing page. Serve that page with
// Referrer-Policy: no-referrer and no third-party assets.
//
// @param email the address to send to; unknown addresses are indistinguishable to the caller
// @return error only driver or mailer errors
func (a *Accounts) RequestPasswordReset(ctx context.Context, db orm.DB, email string) error {
	email = strings.ToLower(strings.TrimSpace(email))

	var userID string
	_, err := db.QueryOneContext(ctx, pg.Scan(&userID), a.sql.userIDByEmail, email)
	switch {
	case errors.Is(err, pg.ErrNoRows):
		a.notify(ctx, email, Message{
			Kind:    KindResetNoAccount,
			Subject: "Password reset requested",
			Text:    "Someone asked to reset a password for this address, but no account exists here. If this was you, you may want to register.",
			URL:     a.baseURL,
		})
		return nil
	case err != nil:
		return err
	}

	token, hashed, err := session.NewToken()
	if err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx, a.sql.insertToken,
		hashed, userID, string(PurposeReset), resetTTL.Seconds()); err != nil {
		return err
	}
	a.notify(ctx, email, Message{
		Kind:    KindReset,
		Subject: "Reset your password",
		Text:    "Open this link to choose a new password. It expires in 15 minutes, and using it signs you out everywhere.",
		URL:     a.link("reset", token),
	})
	return nil
}

// ResetPassword @notice Consumes a reset token, sets the new password and kills every session
// the account had.
//
// @dev Deliberately does not sign the caller in. Sending them through normal login is what
// keeps the recovery path from bypassing whatever else login requires — and it is the ASVS
// position (6.4.3) that reset must not skip a second factor just because it feels like it
// happens before authentication.
//
// RevokeAllForUser, not Rotate: a password reset presumes the old credential is compromised,
// so every session it could have created dies with it.
//
// @param token    the raw value from the emailed link
// @param password the replacement; policy-checked here
// @return error   INVALID_TOKEN for invalid, expired or already-used, INVALID_INPUT for policy
func (a *Accounts) ResetPassword(ctx context.Context, db orm.DB, token, password string) error {
	if err := ValidatePassword(password); err != nil {
		return err
	}
	userID, err := a.consume(ctx, db, token, PurposeReset)
	if err != nil {
		return err
	}
	hash, err := a.hasher.Hash(ctx, password)
	if err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx, a.sql.setPassword, hash, userID); err != nil {
		return err
	}
	if err := a.sessions.RevokeAllForUser(ctx, db, userID); err != nil {
		return err
	}

	var email string
	if _, err := db.QueryOneContext(ctx, pg.Scan(&email), a.sql.emailByID, userID); err == nil {
		a.notify(ctx, email, Message{
			Kind:    KindPasswordChanged,
			Subject: "Your password was reset",
			Text:    "Your password has been reset and all sessions were signed out. If this was not you, act now.",
		})
	}
	return nil
}

// VerifyEmail @notice Consumes a verification token and marks the address confirmed.
//
// @param token the raw value from the emailed link
// @return error INVALID_TOKEN for invalid, expired or already-used
func (a *Accounts) VerifyEmail(ctx context.Context, db orm.DB, token string) error {
	userID, err := a.consume(ctx, db, token, PurposeVerify)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, a.sql.markVerified, userID)
	return err
}

// Invite @notice Creates a password-less account and emails an invitation, or re-invites an
// existing one. Returns the invite URL for a caller that delivers links itself.
//
// @dev Not enumeration-sensitive the way Register is: the caller here is an authenticated
// administrator who is allowed to know whether an address is already a member. Guard the
// resolver with @auth(roles: [...]) — kal will not guess which role that is.
//
// @param email the address to invite
// @return string the invite URL, also sent by mail
// @return error  driver or mailer errors
func (a *Accounts) Invite(ctx context.Context, db orm.DB, email string) (string, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" || !strings.Contains(email, "@") {
		return "", &kalerr.Error{Code: kalerr.CodeInvalidInput, Message: "a valid email address is required"}
	}

	var userID string
	_, err := db.QueryOneContext(ctx, pg.Scan(&userID), a.sql.insertInvitee, email)
	if errors.Is(err, pg.ErrNoRows) {
		// Already a member: re-issue rather than fail, since "resend the invite" is the
		// common reason this is called twice.
		_, err = db.QueryOneContext(ctx, pg.Scan(&userID), a.sql.userIDByEmail, email)
	}
	if err != nil {
		return "", err
	}

	token, hashed, err := session.NewToken()
	if err != nil {
		return "", err
	}
	if _, err := db.ExecContext(ctx, a.sql.insertToken,
		hashed, userID, string(PurposeInvite), inviteTTL.Seconds()); err != nil {
		return "", err
	}
	link := a.link("invite", token)
	a.notify(ctx, email, Message{
		Kind:    KindInvite,
		Subject: "You have been invited",
		Text:    "Open this link to choose a password and activate your account.",
		URL:     link,
	})
	return link, nil
}

// AcceptInvite @notice Consumes an invite token, sets the first password and marks the address
// verified — arriving through the link is proof of control of the mailbox.
//
// @param token    the raw value from the emailed link
// @param password the first password; policy-checked here
// @return error   INVALID_TOKEN or INVALID_INPUT
func (a *Accounts) AcceptInvite(ctx context.Context, db orm.DB, token, password string) error {
	if err := ValidatePassword(password); err != nil {
		return err
	}
	userID, err := a.consume(ctx, db, token, PurposeInvite)
	if err != nil {
		return err
	}
	hash, err := a.hasher.Hash(ctx, password)
	if err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx, a.sql.setPassword, hash, userID); err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, a.sql.markVerified, userID)
	return err
}

// consume @notice Burns a token in one statement and returns whose it was.
//
// @dev A single UPDATE … WHERE consumed_at IS NULL … RETURNING, never a read-then-write. The
// read-then-write shape leaves a window in which a double-submitted link is consumed twice, and
// "the user double-clicked the link in the email" is not a rare event — nor is a mail client
// that prefetches URLs. Zero rows means invalid, expired, already used, or the wrong purpose,
// all indistinguishable, which is the correct amount to tell someone holding a bad token.
func (a *Accounts) consume(ctx context.Context, db orm.DB, token string, p Purpose) (string, error) {
	var userID string
	_, err := db.QueryOneContext(ctx, pg.Scan(&userID), a.sql.consumeToken,
		session.HashToken(token), string(p))
	if errors.Is(err, pg.ErrNoRows) {
		return "", &kalerr.Error{
			Code:     kalerr.CodeInvalidToken,
			Message:  "this link is invalid or has expired",
			Internal: err,
		}
	}
	if err != nil {
		return "", err
	}
	return userID, nil
}

// link @notice Builds an absolute URL under Config.BaseURL.
//
// @dev The origin is configuration, never the request's Host header — see
// RequestPasswordReset. The token rides in the query string rather than the path so a consumer
// can point these at any route shape they like.
func (a *Accounts) link(kind, token string) string {
	return fmt.Sprintf("%s/%s?token=%s", a.baseURL, kind, url.QueryEscape(token))
}
