package authn

import (
	"context"
	"log"
)

// MessageKind @notice Which transactional message this is, so a consumer's Mailer can pick a
// template without parsing the subject line.
type MessageKind string

// The kinds kal sends. AttemptedRegister and ResetNoAccount are the two everyone skips: they
// are what makes "check your email" an honest answer instead of merely an opaque one — the
// person who owns the address learns what happened, and the response to the caller stays
// byte-identical either way.
const (
	KindVerify            MessageKind = "verify"
	KindReset             MessageKind = "reset"
	KindInvite            MessageKind = "invite"
	KindAttemptedRegister MessageKind = "attempted-register"
	KindResetNoAccount    MessageKind = "reset-no-account"
	KindPasswordChanged   MessageKind = "password-changed"
	KindSuspiciousLogin   MessageKind = "suspicious-login"
)

// Message @notice What to send: a subject, a plain-text body with any URL already built, and
// the URL separately so a consumer can re-template without parsing.
type Message struct {
	Kind    MessageKind
	Subject string
	Text    string
	URL     string // pre-built from Config.BaseURL; empty for kinds that carry no link
}

// Mailer @notice Delivers kal's transactional messages. One method.
//
// @dev kal ships no SMTP client and no template engine, deliberately: bundling email rendering
// is how auth libraries become unadoptable — the avatar-store-as-required-dependency story one
// step earlier. Config.Mailer is required with no default, because the silent alternative is
// password reset failing at 3am with nothing in any log.
type Mailer interface {
	Send(ctx context.Context, to string, msg Message) error
}

// LogMailer @notice A development Mailer that writes messages — including live token URLs — to
// the process log. The name is the warning: do not ship it.
type LogMailer struct{}

// Send @notice Logs the message.
//
// @param ctx unused; the interface owns the signature
// @param to  the would-be recipient
// @param msg the message, URL included
// @return error always nil
func (LogMailer) Send(_ context.Context, to string, msg Message) error {
	log.Printf("kal mail → %s [%s] %s | %s %s", to, msg.Kind, msg.Subject, msg.Text, msg.URL)
	return nil
}
