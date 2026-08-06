package tests

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/99designs/gqlgen/graphql"
	"github.com/vektah/gqlparser/v2"
	"github.com/vektah/gqlparser/v2/ast"

	"github.com/ulas96/kal/authz"
	"github.com/ulas96/kal/kalerr"
)

// coverageSchema @notice A schema built from SDL, for the coverage walk to inspect.
//
// @dev Only Schema() is ever called on it, so Exec and Complexity are stubs. Building from SDL
// rather than from generated code keeps these tests independent of a codegen step.
type coverageSchema struct{ schema *ast.Schema }

func (s coverageSchema) Schema() *ast.Schema { return s.schema }
func (s coverageSchema) Complexity(context.Context, string, string, int, map[string]any) (int, bool) {
	return 0, false
}
func (s coverageSchema) Exec(context.Context) graphql.ResponseHandler {
	return func(context.Context) *graphql.Response { return &graphql.Response{Data: []byte(`{}`)} }
}

// newCoverageSchema @notice Parses sdl with kal's directive definitions prepended.
func newCoverageSchema(t *testing.T, sdl string) graphql.ExecutableSchema {
	t.Helper()
	return coverageSchema{gqlparser.MustLoadSchema(&ast.Source{
		Name:  "test",
		Input: authz.DirectiveSDL + sdl,
	})}
}

// callDirective @notice Invokes the directive with a resolver that records whether it ran.
func callDirective(
	t *testing.T,
	d func(context.Context, any, graphql.Resolver, authz.AuthLevel, []string, *bool, []string) (any, error),
	ctx context.Context, requires authz.AuthLevel, roles []string, mfa *bool,
) (ran bool, err error) {
	t.Helper()
	next := func(context.Context) (any, error) {
		ran = true
		return "resolved", nil
	}
	_, err = d(ctx, nil, next, requires, roles, mfa, nil)
	return ran, err
}

// TestAuthDirective @notice The access matrix, and the rule underneath it: the resolver must
// not run when the check fails.
//
// @dev Asserting on the error alone would miss the worst possible bug — a directive that
// denies while still executing the field it was guarding.
//
// @param t the test handle
func TestAuthDirective(t *testing.T) {
	d := authz.Directive(authz.DirectiveOptions{BypassRole: "root"})
	anon := context.Background()
	user := authz.WithPrincipal(anon, &authz.Principal{UserID: "u1", Roles: []string{"Editor"}})
	admin := authz.WithPrincipal(anon, &authz.Principal{UserID: "u2", Roles: []string{"admin"}})
	rootUser := authz.WithPrincipal(anon, &authz.Principal{UserID: "u3", Roles: []string{"root"}})
	yes := true

	cases := []struct {
		name     string
		ctx      context.Context
		requires authz.AuthLevel
		roles    []string
		mfa      *bool
		wantRun  bool
		wantCode string
	}{
		{"anonymous field, anonymous caller", anon, authz.LevelAnonymous, nil, nil, true, ""},
		{"anonymous field, authenticated caller", user, authz.LevelAnonymous, nil, nil, true, ""},
		{"authenticated field, anonymous caller", anon, authz.LevelAuthenticated, nil, nil, false, kalerr.CodeUnauthenticated},
		{"authenticated field, authenticated caller", user, authz.LevelAuthenticated, nil, nil, true, ""},
		{"role held, case-insensitively", user, authz.LevelAuthenticated, []string{"editor"}, nil, true, ""},
		{"role not held", user, authz.LevelAuthenticated, []string{"admin"}, nil, false, kalerr.CodeForbidden},
		{"any of several roles", admin, authz.LevelAuthenticated, []string{"admin", "editor"}, nil, true, ""},
		{"bypass role satisfies any requirement", rootUser, authz.LevelAuthenticated, []string{"admin"}, nil, true, ""},
		{"roles on an anonymous caller deny", anon, authz.LevelAnonymous, []string{"admin"}, nil, false, kalerr.CodeUnauthenticated},
		{"mfa without a module fails closed", user, authz.LevelAuthenticated, nil, &yes, false, kalerr.CodeMFARequired},
		{"mfa on an anonymous caller denies", anon, authz.LevelAnonymous, nil, &yes, false, kalerr.CodeUnauthenticated},
		{"unknown level denies", user, authz.AuthLevel("SOMETHING_ELSE"), nil, nil, false, kalerr.CodeForbidden},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ran, err := callDirective(t, d, c.ctx, c.requires, c.roles, c.mfa)
			if ran != c.wantRun {
				t.Errorf("resolver ran = %v, want %v", ran, c.wantRun)
			}
			if c.wantCode == "" {
				if err != nil {
					t.Errorf("error = %v, want nil", err)
				}
				return
			}
			var ae *kalerr.Error
			if !errors.As(err, &ae) || ae.Code != c.wantCode {
				t.Errorf("error = %v, want code %s", err, c.wantCode)
			}
		})
	}
}

// TestAuthDirectiveMFAWindow @notice Step-up is satisfied by recent MFA and expires with it.
//
// @param t the test handle
func TestAuthDirectiveMFAWindow(t *testing.T) {
	d := authz.Directive(authz.DirectiveOptions{MFAWindow: time.Minute})
	yes := true

	recent := authz.WithPrincipal(context.Background(),
		&authz.Principal{UserID: "u1", MFAAt: time.Now().Add(-10 * time.Second)})
	if ran, err := callDirective(t, d, recent, authz.LevelAuthenticated, nil, &yes); !ran || err != nil {
		t.Errorf("recent MFA: ran=%v err=%v", ran, err)
	}

	stale := authz.WithPrincipal(context.Background(),
		&authz.Principal{UserID: "u1", MFAAt: time.Now().Add(-2 * time.Minute)})
	ran, err := callDirective(t, d, stale, authz.LevelAuthenticated, nil, &yes)
	var ae *kalerr.Error
	if ran || !errors.As(err, &ae) || ae.Code != kalerr.CodeMFARequired {
		t.Errorf("stale MFA: ran=%v err=%v, want MFA_REQUIRED", ran, err)
	}
}

// TestAssertAuthCoverage @notice The forgotten-check detector: an unannotated field is named,
// an annotated one is not, and every miss is reported at once.
//
// @param t the test handle
func TestAssertAuthCoverage(t *testing.T) {
	t.Run("an unannotated mutation is caught", func(t *testing.T) {
		s := newCoverageSchema(t, `
			type Query { me: String @auth }
			type Mutation { deleteEverything: Boolean }
		`)
		err := authz.AssertAuthCoverage(s)
		if err == nil {
			t.Fatal("an unannotated mutation passed")
		}
		if !strings.Contains(err.Error(), "Mutation.deleteEverything") {
			t.Errorf("error does not name the field: %v", err)
		}
	})

	t.Run("a fully annotated schema passes", func(t *testing.T) {
		s := newCoverageSchema(t, `
			type Query {
			  health: String @auth(requires: ANONYMOUS)
			  me: User @auth
			}
			type Mutation { rename(name: String!): Boolean @auth(roles: ["editor"]) }
			type User @auth { id: ID! name: String }
		`)
		if err := authz.AssertAuthCoverage(s); err != nil {
			t.Errorf("AssertAuthCoverage = %v, want nil", err)
		}
	})

	t.Run("object-level annotation covers its fields", func(t *testing.T) {
		s := newCoverageSchema(t, `
			type Query { profile: Profile @auth }
			type Profile @auth(requires: ANONYMOUS) { bio: String avatar: String }
		`)
		if err := authz.AssertAuthCoverage(s); err != nil {
			t.Errorf("an @auth-annotated object left its fields uncovered: %v", err)
		}
	})

	t.Run("every miss is reported at once", func(t *testing.T) {
		s := newCoverageSchema(t, `
			type Query { a: String b: String }
			type Mutation { c: Boolean }
		`)
		err := authz.AssertAuthCoverage(s)
		if err == nil {
			t.Fatal("three unannotated fields passed")
		}
		for _, want := range []string{"Query.a", "Query.b", "Mutation.c"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error does not name %s: %v", want, err)
			}
		}
	})

	t.Run("exemptions are honoured", func(t *testing.T) {
		s := newCoverageSchema(t, `
			type Query { health: String }
			type Mutation { login(email: String!): Boolean }
		`)
		if err := authz.AssertAuthCoverage(s, "Query.health", "Mutation.login"); err != nil {
			t.Errorf("exempt fields still reported: %v", err)
		}
		// An exemption is per field, not a blanket.
		if err := authz.AssertAuthCoverage(s, "Query.health"); err == nil {
			t.Error("Mutation.login passed without an exemption")
		}
	})

	t.Run("introspection types are not the consumer's to annotate", func(t *testing.T) {
		s := newCoverageSchema(t, `type Query { me: String @auth }`)
		err := authz.AssertAuthCoverage(s)
		if err != nil && strings.Contains(err.Error(), "__") {
			t.Errorf("introspection types reported: %v", err)
		}
	})

	t.Run("a nil schema is an error, not a pass", func(t *testing.T) {
		if err := authz.AssertAuthCoverage(nil); err == nil {
			t.Error("AssertAuthCoverage(nil) = nil — a typo in the test setup would read as coverage")
		}
	})
}

// TestAssertDirectivesWired @notice The nil-directive trap: gqlgen validates none of this at
// startup, so every annotated field would fail at request time.
//
// @param t the test handle
func TestAssertDirectivesWired(t *testing.T) {
	// The shape gqlgen generates.
	type directiveRoot struct {
		Auth     func(context.Context, any, graphql.Resolver, authz.AuthLevel, []string, *bool, []string) (any, error)
		HasScope func(context.Context, any, graphql.Resolver, string) (any, error)
	}

	t.Run("nil directives are named", func(t *testing.T) {
		err := authz.AssertDirectivesWired(directiveRoot{})
		if err == nil {
			t.Fatal("an entirely unwired DirectiveRoot passed")
		}
		for _, want := range []string{"Auth", "HasScope"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error does not name %s: %v", want, err)
			}
		}
	})

	t.Run("a wired root passes, by value and by pointer", func(t *testing.T) {
		root := directiveRoot{
			Auth: authz.Directive(authz.DirectiveOptions{}),
			HasScope: func(ctx context.Context, _ any, next graphql.Resolver, _ string) (any, error) {
				return next(ctx)
			},
		}
		if err := authz.AssertDirectivesWired(root); err != nil {
			t.Errorf("by value: %v", err)
		}
		if err := authz.AssertDirectivesWired(&root); err != nil {
			t.Errorf("by pointer: %v", err)
		}
	})

	t.Run("a partly wired root is caught", func(t *testing.T) {
		err := authz.AssertDirectivesWired(directiveRoot{Auth: authz.Directive(authz.DirectiveOptions{})})
		if err == nil || !strings.Contains(err.Error(), "HasScope") {
			t.Errorf("error = %v, want HasScope named", err)
		}
	})

	t.Run("a non-struct is an error", func(t *testing.T) {
		if err := authz.AssertDirectivesWired("not a directive root"); err == nil {
			t.Error("a string passed as a DirectiveRoot")
		}
		if err := authz.AssertDirectivesWired((*directiveRoot)(nil)); err == nil {
			t.Error("a nil pointer passed")
		}
	})
}

// TestDirectiveSDLParses @notice The pasteable snippet is valid SDL and declares what the
// directive implementation expects.
//
// @param t the test handle
func TestDirectiveSDLParses(t *testing.T) {
	s := newCoverageSchema(t, `type Query { me: String @auth }`)
	def := s.Schema().Directives["auth"]
	if def == nil {
		t.Fatal("DirectiveSDL does not declare @auth")
	}
	var names []string
	for _, a := range def.Arguments {
		names = append(names, a.Name)
	}
	want := "requires roles mfa proves"
	if got := strings.Join(names, " "); got != want {
		t.Errorf("argument order = %q, want %q — the generated Go signature follows this order", got, want)
	}
	// The default is what makes a bare @auth mean "logged in".
	if def.Arguments.ForName("requires").DefaultValue.Raw != string(authz.LevelAuthenticated) {
		t.Error("a bare @auth does not default to AUTHENTICATED")
	}
}
