// Package kalerr @notice kal's error contract: a client-visible auth error with a stable
// machine-readable code, and the presenter that puts it on the wire.
//
// @dev Mirrors luimaerr's role and inherits its discipline. It imports luimaerr and nothing
// else in kal, so any kal package can return a typed auth error without pulling in gqlgen's
// handler, the session machinery, or a driver.
//
// Two luima behaviours this package is written around, both findings in luima's security
// review (E-01, E-04):
//
//   - luimaerr.PresentError returns any *gqlerror.Error found in the chain to the client whole —
//     message, path and extensions. Therefore nothing in kal ever wraps a *gqlerror.Error.
//   - luimaerr.CustomError.Error() concatenates the internal cause, so a message built from any
//     err.Error() undoes redaction in a line that reads like careful error handling. Therefore a
//     Message here is always literal text, never derived from another error.
package kalerr

import (
	"context"
	"errors"

	"github.com/99designs/gqlgen/graphql"
	"github.com/ulas96/luima/luimaerr"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

// The stable code vocabulary a client programs against.
//
// One code for every way authentication can fail: unknown user, wrong password, unverified
// email and disabled account are all INVALID_CREDENTIALS on the wire (ASVS 6.3.8 — accounts
// must not be deducible from messages, status codes or timing). The real reason goes to the
// server log, never to the response.
const (
	// CodeUnauthenticated @notice No principal where one is required.
	CodeUnauthenticated = "UNAUTHENTICATED"
	// CodeForbidden @notice A principal, without the right.
	CodeForbidden = "FORBIDDEN"
	// CodeInvalidCredentials @notice Login failed. Deliberately unspecific; see above.
	CodeInvalidCredentials = "INVALID_CREDENTIALS" // #nosec G101 -- an error code on the wire, not a credential
	// CodeRateLimited @notice The backoff window or the hashing bound rejected the attempt.
	CodeRateLimited = "RATE_LIMITED"
	// CodeMFARequired @notice Step-up required. Fails closed when no MFA module is installed.
	CodeMFARequired = "MFA_REQUIRED"
	// CodeInvalidToken @notice An emailed token that is invalid, expired or already used —
	// deliberately indistinguishable, since telling an attacker which is a small gift.
	CodeInvalidToken = "INVALID_TOKEN"
	// CodeInvalidInput @notice Password policy and similar shape failures.
	CodeInvalidInput = "INVALID_INPUT"
)

// Error @notice A client-visible auth error with a stable machine-readable code.
//
// @dev The Code is the piece a client branches on — "log in again" versus "you may not do that"
// is a different UI in every frontend, and matching on message text is how that branch breaks on
// a wording change. Message follows luimaerr's rule: assume it is public, and never build it
// from another error's text. Internal is for the log and for errors.Is/As, and never reaches
// the client.
type Error struct {
	Code     string
	Message  string
	Internal error
}

// Error @notice Renders code, message and, when there is one, the cause.
//
// @dev The cause is included because this string goes to the log, never to the client —
// PresentError reads Code and Message directly and ignores this method.
//
// @return string "RATE_LIMITED: too many attempts: <cause>", or without the cause when nil
func (e *Error) Error() string {
	if e.Internal == nil {
		return e.Code + ": " + e.Message
	}
	return e.Code + ": " + e.Message + ": " + e.Internal.Error()
}

// Unwrap @notice Exposes the cause to errors.Is and errors.As.
//
// @return error Internal, which may be nil
func (e *Error) Unwrap() error { return e.Internal }

// As @notice Also satisfies errors.As for a *luimaerr.CustomError target, carrying Message and
// Internal across.
//
// @dev The graceful-degradation bridge. A consumer who forgets to swap luima's default
// ErrorPresenter for [PresentError] still gets the safe Message on the wire — luimaerr's own
// errors.As finds this method — rather than "internal server error" for every auth failure.
// The extensions.code is absent in that configuration, which is the visible nudge to fix the
// wiring without the failure mode of hiding it entirely.
//
// @param target the errors.As target; only **luimaerr.CustomError is recognised
// @return bool  whether target was filled
func (e *Error) As(target any) bool {
	if ce, ok := target.(**luimaerr.CustomError); ok {
		*ce = &luimaerr.CustomError{UserMessage: e.Message, InternalError: e.Internal}
		return true
	}
	return false
}

// PresentError @notice luima's presenter, plus an extensions.code for kal's errors. Set it as
// luima's Config.ErrorPresenter.
//
// @dev Wraps rather than replaces: luimaerr.PresentError's branches are the redaction contract
// and keep running for everything that is not a *kalerr.Error. The *kalerr.Error branch must
// run first — the As bridge above means luimaerr's CustomError branch would otherwise claim
// these errors and silently drop the code.
//
// @param ctx  the resolver context, read only for the GraphQL field path
// @param err  the error a resolver returned
// @return *gqlerror.Error the message the client receives
func PresentError(ctx context.Context, err error) *gqlerror.Error {
	var ae *Error
	if errors.As(err, &ae) {
		return &gqlerror.Error{
			Message:    ae.Message,
			Path:       graphql.GetPath(ctx),
			Extensions: map[string]any{"code": ae.Code},
		}
	}
	return luimaerr.PresentError(ctx, err)
}
