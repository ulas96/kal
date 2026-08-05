package authz

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/99designs/gqlgen/graphql"
	"github.com/vektah/gqlparser/v2/ast"
)

// AssertAuthCoverage @notice Fails if any field reachable through the schema can be resolved
// without an @auth annotation. Call it from a test.
//
//	func TestAuthCoverage(t *testing.T) {
//	    schema := generated.NewExecutableSchema(generated.Config{Resolvers: &graph.Resolver{}})
//	    if err := authz.AssertAuthCoverage(schema, "Query.health", "Mutation.login"); err != nil {
//	        t.Fatal(err)
//	    }
//	}
//
// @dev Deny-by-default, enforced by a test rather than by discipline, and it is the highest
// value component in this library. The failure mode of resolver-level authorization is a
// *forgotten* check, and a forgotten check is invisible: it compiles, it passes review, and it
// returns data. Walking the schema is the only way to see the absence of something.
//
// It is a test and not a check inside New on purpose. A schema author adding a public field
// should get a red test they can annotate away, not a server that refuses to boot in
// production because someone shipped a schema change on a Friday.
//
// Every uncovered field is reported at once, sorted, because an implementer annotating a
// schema wants the whole list and not a fifty-iteration game of whack-a-mole.
//
// Covered means: the field carries @auth, or its parent type does. A field whose parent type
// is annotated @auth(requires: ANONYMOUS) is public by explicit decision, which is exactly the
// distinction this function exists to be able to draw.
//
// @param schema the generated executable schema
// @param exempt field paths deliberately left unannotated, e.g. "Query.health"
// @return error naming every uncovered field, or nil
func AssertAuthCoverage(schema graphql.ExecutableSchema, exempt ...string) error {
	if schema == nil {
		return errors.New("authz: AssertAuthCoverage got a nil schema")
	}
	s := schema.Schema()
	if s == nil {
		return errors.New("authz: the schema has no AST")
	}

	skip := make(map[string]bool, len(exempt))
	for _, e := range exempt {
		skip[e] = true
	}

	var uncovered []string
	for _, def := range s.Types {
		if !isSelectableType(def) {
			continue
		}
		if hasAuth(def.Directives) {
			continue // the whole type is annotated, including ANONYMOUS
		}
		for _, f := range def.Fields {
			if strings.HasPrefix(f.Name, "__") {
				continue // __typename and the introspection fields are not yours to annotate
			}
			path := def.Name + "." + f.Name
			if skip[path] || hasAuth(f.Directives) {
				continue
			}
			uncovered = append(uncovered, path)
		}
	}
	if len(uncovered) == 0 {
		return nil
	}
	sort.Strings(uncovered)
	return fmt.Errorf(
		"authz: %d field(s) reachable without an @auth annotation:\n\t%s\n"+
			"Annotate each with @auth(...), mark it @auth(requires: ANONYMOUS) if it is deliberately public, "+
			"or pass its path to AssertAuthCoverage as an exemption",
		len(uncovered), strings.Join(uncovered, "\n\t"))
}

// isSelectableType @notice Whether def has fields a client can select, as opposed to an input,
// an enum, a scalar or a union.
//
// @dev Introspection types are excluded — they are gqlgen's, not the consumer's, and there is
// no way to annotate them. Introspection is turned off separately (kal's Configure does it);
// coverage is about the application's own fields.
func isSelectableType(def *ast.Definition) bool {
	if def.Kind != ast.Object && def.Kind != ast.Interface {
		return false
	}
	return !strings.HasPrefix(def.Name, "__")
}

// hasAuth @notice Whether the directive list carries @auth.
func hasAuth(list ast.DirectiveList) bool {
	return list.ForName("auth") != nil
}

// AssertDirectivesWired @notice Fails if any directive implementation on a generated
// DirectiveRoot is nil.
//
//	authz.AssertDirectivesWired(generated.DirectiveRoot{Auth: authz.Directive(...)})
//
// @dev A companion to AssertAuthCoverage rather than part of it, because the two see different
// things: the schema walk cannot reach the consumer's generated DirectiveRoot struct, which is
// a type in their module.
//
// It exists because forgetting to wire a directive is a *runtime* error in gqlgen — every
// annotated field fails with "directive auth is not implemented" on the first request that
// touches it, and there is no startup validation. Reflection over the struct's func fields is
// the only way to see that from outside.
//
// @param directiveRoot the generated DirectiveRoot value or pointer
// @return error naming every unset directive, or nil
func AssertDirectivesWired(directiveRoot any) error {
	v := reflect.ValueOf(directiveRoot)
	for v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return errors.New("authz: AssertDirectivesWired got a nil pointer")
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return fmt.Errorf("authz: AssertDirectivesWired wants a DirectiveRoot struct, got %T", directiveRoot)
	}

	var missing []string
	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		if f.Kind() != reflect.Func {
			continue
		}
		if f.IsNil() {
			missing = append(missing, t.Field(i).Name)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	sort.Strings(missing)
	return fmt.Errorf(
		"authz: directive(s) not wired: %s — every annotated field fails at request time with "+
			"\"directive is not implemented\", and gqlgen validates none of this at startup",
		strings.Join(missing, ", "))
}
