package tests

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/ulas96/luima/luimaerr"
	"github.com/vektah/gqlparser/v2/gqlerror"

	"github.com/ulas96/kal/kalerr"
)

// TestPresentError @notice Pins the wire contract: a *kalerr.Error carries its message and a
// stable extensions.code; everything else stays subject to luima's redaction.
//
// @param t the test handle
func TestPresentError(t *testing.T) {
	ctx := context.Background()

	t.Run("kal error carries message and code", func(t *testing.T) {
		cause := errors.New(`pg: password authentication failed for user "postgres"`)
		err := fmt.Errorf("login: %w", &kalerr.Error{
			Code:     kalerr.CodeRateLimited,
			Message:  "too many attempts, try again shortly",
			Internal: cause,
		})

		ge := kalerr.PresentError(ctx, err)
		if ge.Message != "too many attempts, try again shortly" {
			t.Errorf("Message = %q", ge.Message)
		}
		if got := ge.Extensions["code"]; got != kalerr.CodeRateLimited {
			t.Errorf("extensions.code = %v, want %q", got, kalerr.CodeRateLimited)
		}
		if strings.Contains(ge.Message, "postgres") {
			t.Errorf("internal cause leaked to the client: %q", ge.Message)
		}
	})

	// The negative assertion from luima's redaction tests, repeated here because kal wraps the
	// presenter: wrapping must not have opened a leak for non-kal errors.
	t.Run("everything else is redacted", func(t *testing.T) {
		leak := errors.New(`ERROR #23505 duplicate key value violates unique constraint "auth_users_email_live_key"`)
		ge := kalerr.PresentError(ctx, leak)
		if ge.Message != "internal server error" {
			t.Errorf("Message = %q, want the redaction", ge.Message)
		}
		for _, fragment := range []string{"23505", "auth_users", "constraint"} {
			if strings.Contains(ge.Message, fragment) {
				t.Errorf("driver detail %q leaked", fragment)
			}
		}
		if len(ge.Extensions) != 0 {
			t.Errorf("redacted error carries extensions: %v", ge.Extensions)
		}
	})

	t.Run("gqlerror passes through", func(t *testing.T) {
		in := gqlerror.Errorf(`Cannot query field "nam" on type "User".`)
		if got := kalerr.PresentError(ctx, in); got != in {
			t.Errorf("validation error was rewritten: %v", got)
		}
	})
}

// TestCustomErrorBridge @notice A consumer who forgets to swap luima's ErrorPresenter for kal's
// must still get the safe message on the wire, not "internal server error", for every auth
// failure.
//
// @dev This is what (*kalerr.Error).As buys. The extensions.code is deliberately absent in that
// configuration — the visible nudge to wire kalerr.PresentError without punishing the whole
// login flow for a missed line.
//
// @param t the test handle
func TestCustomErrorBridge(t *testing.T) {
	ctx := context.Background()
	cause := errors.New("session row for u-1 missing")
	ae := &kalerr.Error{Code: kalerr.CodeUnauthenticated, Message: "log in to continue", Internal: cause}

	t.Run("luimaerr.PresentError shows the message", func(t *testing.T) {
		ge := luimaerr.PresentError(ctx, fmt.Errorf("resolver: %w", ae))
		if ge.Message != "log in to continue" {
			t.Errorf("Message = %q — the bridge did not carry it", ge.Message)
		}
	})

	t.Run("errors.As carries message and cause", func(t *testing.T) {
		var ce *luimaerr.CustomError
		if !errors.As(ae, &ce) {
			t.Fatal("errors.As found no CustomError in a *kalerr.Error")
		}
		if ce.UserMessage != ae.Message {
			t.Errorf("UserMessage = %q, want %q", ce.UserMessage, ae.Message)
		}
		if !errors.Is(ce, cause) {
			t.Error("the bridged CustomError lost the cause")
		}
	})

	t.Run("unwrap reaches the cause", func(t *testing.T) {
		if !errors.Is(ae, cause) {
			t.Error("errors.Is could not reach Internal")
		}
	})
}
