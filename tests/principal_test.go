package tests

import (
	"context"
	"errors"
	"testing"

	"github.com/ulas96/kal/authz"
	"github.com/ulas96/kal/kalerr"
)

// TestPrincipalContext @notice From and Require agree about presence, and Require's failure is
// the typed UNAUTHENTICATED error a resolver can hand straight back.
//
// @param t the test handle
func TestPrincipalContext(t *testing.T) {
	base := context.Background()

	t.Run("anonymous", func(t *testing.T) {
		if p, ok := authz.From(base); ok || p != nil {
			t.Errorf("From(empty ctx) = %v, %v", p, ok)
		}
		p, err := authz.Require(base)
		if p != nil {
			t.Errorf("Require returned a principal from an empty ctx: %+v", p)
		}
		var ae *kalerr.Error
		if !errors.As(err, &ae) || ae.Code != kalerr.CodeUnauthenticated {
			t.Errorf("Require error = %v, want code UNAUTHENTICATED", err)
		}
	})

	t.Run("authenticated", func(t *testing.T) {
		want := &authz.Principal{UserID: "u-1", SessionID: "s-1", Roles: []string{"admin"}}
		ctx := authz.WithPrincipal(base, want)
		if p, ok := authz.From(ctx); !ok || p != want {
			t.Errorf("From = %v, %v — the stored principal did not come back", p, ok)
		}
		if p, err := authz.Require(ctx); err != nil || p != want {
			t.Errorf("Require = %v, %v", p, err)
		}
	})

	t.Run("nil principal stores nothing", func(t *testing.T) {
		ctx := authz.WithPrincipal(base, nil)
		if _, ok := authz.From(ctx); ok {
			t.Error("a nil principal registered as authenticated")
		}
	})
}
