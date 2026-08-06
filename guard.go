package kal

import (
	"context"

	"github.com/99designs/gqlgen/graphql"
	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

// Guard defaults. Every one of them is a limit on the document, not on the request, because
// GraphQL executes many operations per request and an HTTP-request rate limiter counts none of
// them.
const (
	// DefaultMaxAliases @notice Selections allowed in one document.
	DefaultMaxAliases = 100
	// DefaultMaxDepth @notice Nesting allowed in one document.
	//
	// @dev luima's ComplexityLimit does not cover this: gqlgen's complexity is per selected
	// field, so 400 levels of nesting through a cyclic schema costs about 400 and sails past a
	// 1000 limit.
	DefaultMaxDepth = 15
)

// defaultSensitiveFields @notice Fields no legitimate document selects twice.
//
// @dev The attack is aliasing:
//
//	mutation { a: login(...) b: login(...) ... ×500 }
//
// One HTTP request, five hundred password guesses, one hit on any rate limiter that counts
// requests. The same trick against a six-digit code reduces it to a handful of requests, and
// there is a PortSwigger lab for exactly this. The answer is rejection rather than throttling:
// no real client sends two logins in one document.
var defaultSensitiveFields = []string{
	"login", "register", "requestPasswordReset", "resetPassword",
	"verifyEmail", "acceptInvite", "changePassword",
	"enrollZKKnowledge", "verifyZKKnowledge", "zkLogin", "proveZKClaim",
	"issueZKCredential", "revokeZKCredential",
}

// guard @notice A gqlgen OperationInterceptor that rejects abusive documents before any
// resolver runs.
type guard struct {
	sensitive  map[string]bool
	maxAliases int
	maxDepth   int
}

// ExtensionName @notice Identifies the extension to gqlgen.
func (guard) ExtensionName() string { return "KalGuard" }

// Validate @notice Nothing to check against the schema at startup.
func (guard) Validate(graphql.ExecutableSchema) error { return nil }

// InterceptOperation @notice Rejects a document that selects a sensitive field more than once,
// or that exceeds the alias or depth caps.
//
// @dev The denial must be wrapped in graphql.OneShot. gqlgen's own source warns twice: a
// short-circuit that returns an error without calling next MUST be a OneShot, or streaming
// transports loop forever. An auth extension that denies a request is exactly that
// short-circuit case, so this is a hot infinite loop rather than a clean rejection if the
// wrapper is dropped.
func (g guard) InterceptOperation(ctx context.Context, next graphql.OperationHandler) graphql.ResponseHandler {
	opCtx := graphql.GetOperationContext(ctx)
	if opCtx == nil || opCtx.Doc == nil {
		return next(ctx)
	}

	counts := map[string]int{}
	total, depth := 0, 0
	for _, op := range opCtx.Doc.Operations {
		walkSelections(op.SelectionSet, 1, counts, &total, &depth)
	}
	for _, frag := range opCtx.Doc.Fragments {
		// Fragments are where a naive walker loses the count: the selections live here and
		// the operation only references them.
		walkSelections(frag.SelectionSet, 1, counts, &total, &depth)
	}

	for name, n := range counts {
		if n > 1 && g.sensitive[name] {
			return graphql.OneShot(graphql.ErrorResponse(ctx,
				"%s may be selected only once per document", name))
		}
	}
	if total > g.maxAliases {
		return graphql.OneShot(graphql.ErrorResponse(ctx,
			"too many selections in one document (%d, limit %d)", total, g.maxAliases))
	}
	if depth > g.maxDepth {
		return graphql.OneShot(graphql.ErrorResponse(ctx,
			"query is nested too deeply (%d, limit %d)", depth, g.maxDepth))
	}
	return next(ctx)
}

// walkSelections @notice Counts field selections by name and records the deepest nesting.
//
// @dev Hand-written because gqlparser ships no max-depth rule and gqlgen no extension for one.
// Counting by field name rather than by alias is the point: aliasing is how the same field is
// selected five hundred times.
func walkSelections(set ast.SelectionSet, level int, counts map[string]int, total, depth *int) {
	if level > *depth {
		*depth = level
	}
	for _, sel := range set {
		switch s := sel.(type) {
		case *ast.Field:
			counts[s.Name]++
			*total++
			walkSelections(s.SelectionSet, level+1, counts, total, depth)
		case *ast.InlineFragment:
			walkSelections(s.SelectionSet, level, counts, total, depth)
		case *ast.FragmentSpread:
			// Counted once at its definition above. Following the spread here would recurse
			// forever on a cyclic document, which is itself a denial-of-service shape.
		}
	}
}

// conditionalIntrospection @notice Turns introspection on per request, for callers a predicate
// approves.
//
// @dev gqlgen's executor defaults DisableIntrospection to true and extension.Introspection
// exists to turn it *on* — which luima does, with Config.DisableIntrospection since 0.2.0 as the
// all-or-nothing way back. This mutator runs after the middleware has put identity in the
// context, so the decision can be per request and role-gated rather than per deploy.
//
// Worth saying plainly: introspection off is a smaller attack surface, not confidentiality.
// gqlparser appends "Did you mean …?" to validation errors and luima's presenter passes
// validation errors through by design, so a caller guessing `nam` still learns there is a
// `name`. That is why Configure also sets SetDisableSuggestion.
type conditionalIntrospection struct {
	allow func(context.Context) bool
}

func (conditionalIntrospection) ExtensionName() string                   { return "KalConditionalIntrospection" }
func (conditionalIntrospection) Validate(graphql.ExecutableSchema) error { return nil }

func (c conditionalIntrospection) MutateOperationContext(ctx context.Context, opCtx *graphql.OperationContext) *gqlerror.Error {
	opCtx.DisableIntrospection = !c.allow(ctx)
	return nil
}

// compile-time checks that the extensions satisfy the interfaces gqlgen dispatches on. Without
// these, a signature drift makes srv.Use accept the value and silently never call it.
var (
	_ interface {
		graphql.HandlerExtension
		graphql.OperationInterceptor
	} = guard{}
	_ interface {
		graphql.HandlerExtension
		graphql.OperationContextMutator
	} = conditionalIntrospection{}
)
