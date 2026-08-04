package authz

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/99designs/gqlgen/graphql"

	"github.com/ulas96/kal/kalerr"
)

// AuthLevel @notice The @auth directive's `requires` argument.
//
// @dev A kal-owned Go type rather than a generated one, so the directive implementation has a
// stable signature to match. Bind it in gqlgen.yml:
//
//	models:
//	  AuthLevel:
//	    model: github.com/ulas96/kal/authz.AuthLevel
type AuthLevel string

const (
	// LevelAnonymous @notice No authentication required. The explicit spelling of "public",
	// which is what makes AssertAuthCoverage able to tell a deliberate choice from an
	// oversight.
	LevelAnonymous AuthLevel = "ANONYMOUS"
	// LevelAuthenticated @notice A principal is required.
	LevelAuthenticated AuthLevel = "AUTHENTICATED"
)

// UnmarshalGQL @notice Parses the enum value from a GraphQL argument.
//
// @return error when the value is not one of the two levels
func (l *AuthLevel) UnmarshalGQL(v any) error {
	s, ok := v.(string)
	if !ok {
		return fmt.Errorf("AuthLevel must be a string, got %T", v)
	}
	switch AuthLevel(s) {
	case LevelAnonymous, LevelAuthenticated:
		*l = AuthLevel(s)
		return nil
	default:
		return fmt.Errorf("%q is not a valid AuthLevel", s)
	}
}

// MarshalGQL @notice Writes the enum value into a GraphQL response.
func (l AuthLevel) MarshalGQL(w io.Writer) {
	_, _ = io.WriteString(w, strconv.Quote(string(l)))
}

// DirectiveSDL @notice The schema snippet to paste into your .graphqls, verbatim.
//
// @dev One composed directive, never a stack of them, and the reason is gqlgen's chaining
// order: generated code wraps directive0 in directive1 in directive2, so the *last*-declared
// directive is the outermost and runs *first*. Written left to right, `@auth @hasRole(ADMIN)`
// runs hasRole before auth — the opposite of how every reader parses it. Rather than document
// an ordering nobody will remember, the checks compose inside one directive where the order is
// kal's.
const DirectiveSDL = `directive @auth(
  requires: AuthLevel! = AUTHENTICATED
  roles:    [String!]
  mfa:      Boolean
) on FIELD_DEFINITION | OBJECT

enum AuthLevel { ANONYMOUS AUTHENTICATED }
`

// DefaultMFAWindow @notice How recently MFA must have been satisfied for @auth(mfa: true).
const DefaultMFAWindow = 15 * time.Minute

// DirectiveOptions @notice Configuration for Directive. The zero value is the production
// posture.
type DirectiveOptions struct {
	// MFAWindow @notice How recently MFA must have been satisfied. Zero means
	// DefaultMFAWindow.
	MFAWindow time.Duration

	// BypassRole @notice A role that satisfies any `roles` requirement. Empty means none —
	// there is no implicit "admin".
	BypassRole string
}

// Directive @notice The @auth implementation, for your generated DirectiveRoot.
//
//	c.Directives.Auth = authz.Directive(authz.DirectiveOptions{})
//
// @dev Reads only the context, and never touches the database. That is a hard requirement, not
// an optimisation: a directive on a field of a list type runs once per row, so a check costing
// a query is an N+1 that appears only under production load — and luima ships no dataloader to
// soften it. Everything needed is already on the Principal, resolved once by the middleware.
//
// Nullability interacts with denial, and it is worth knowing before annotating: an error on a
// nullable field yields null plus an error entry, while on a non-null field it nulls the
// *parent*, which can blank an entire object. Prefer nullable types for conditionally visible
// fields.
//
// mfa: true always denies while no MFA module is installed. Failing closed is the only safe
// direction — a step-up requirement that silently passes is worse than one that visibly
// blocks, and the session column and this argument are the seam a later module plugs into.
//
// @param opts zero value for the defaults
// @return func the directive implementation, matching gqlgen's generated field type
func Directive(opts DirectiveOptions) func(ctx context.Context, obj any, next graphql.Resolver, requires AuthLevel, roles []string, mfa *bool) (any, error) {
	window := opts.MFAWindow
	if window == 0 {
		window = DefaultMFAWindow
	}
	return func(ctx context.Context, _ any, next graphql.Resolver, requires AuthLevel, roles []string, mfa *bool) (any, error) {
		// An unrecognised level denies. The enum makes this unreachable through a valid
		// schema, and a default that let an unknown value through would be a bypass waiting
		// for a schema edit.
		if requires != LevelAnonymous && requires != LevelAuthenticated {
			return nil, &kalerr.Error{Code: kalerr.CodeForbidden, Message: "not permitted",
				Internal: fmt.Errorf("unknown AuthLevel %q", requires)}
		}

		p, ok := From(ctx)
		if !ok {
			// Anonymous is allowed only where the schema says so, and then no role or MFA
			// requirement can be satisfied — an ANONYMOUS field carrying roles is a schema
			// mistake, and denying is the safe reading of it.
			if requires == LevelAnonymous && len(roles) == 0 && (mfa == nil || !*mfa) {
				return next(ctx)
			}
			return nil, &kalerr.Error{Code: kalerr.CodeUnauthenticated, Message: "authentication required"}
		}

		if len(roles) > 0 && !anyRole(p.Roles, roles, opts.BypassRole) {
			return nil, &kalerr.Error{Code: kalerr.CodeForbidden, Message: "not permitted"}
		}

		if mfa != nil && *mfa {
			if p.MFAAt.IsZero() || time.Since(p.MFAAt) > window {
				return nil, &kalerr.Error{Code: kalerr.CodeMFARequired,
					Message: "multi-factor authentication required"}
			}
		}

		return next(ctx)
	}
}

// anyRole @notice Whether held satisfies want — any one of them, or the bypass role.
//
// @dev Any-of, not all-of. `@auth(roles: ["admin", "editor"])` reads as "admins or editors",
// which is what a schema author means every time; all-of is spelled by requiring the narrower
// role.
func anyRole(held, want []string, bypass string) bool {
	if bypass != "" && hasRole(held, bypass) {
		return true
	}
	for _, w := range want {
		if hasRole(held, w) {
			return true
		}
	}
	return false
}
