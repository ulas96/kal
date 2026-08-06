// Package zkauthz @notice Request-local authorization for claims verified by zkauthn.
package zkauthz

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"sync"

	"github.com/go-pg/pg/v10"
	"github.com/go-pg/pg/v10/orm"
	"github.com/go-pg/pg/v10/types"

	"github.com/ulas96/kal/authz"
	"github.com/ulas96/kal/kalerr"
	"github.com/ulas96/kal/zkauthn"
)

var identRe = regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)

// Claims @notice Loads recurring session claims once and consumes request-local one-shot claims.
type Claims struct{ sql statements }

// New @notice Validates and renders the optional table schema.
func New(schema string) (*Claims, error) {
	prefix := ""
	if schema != "" {
		if !identRe.MatchString(schema) {
			return nil, &kalerr.Error{Code: kalerr.CodeInvalidInput,
				Message: "table schema must match ^[a-z_][a-z0-9_]*$"}
		}
		prefix = string(types.AppendIdent(nil, schema, 1)) + "."
	}
	return &Claims{sql: render(prefix)}, nil
}

type holderKey struct{}

type holder struct {
	mu        sync.Mutex
	recurring map[string]bool
	oneShot   map[string]int
	loadErr   error
}

// Middleware @notice Loads recurring claims after session middleware has resolved Principal.
func (c *Claims) Middleware(db orm.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := &holder{recurring: map[string]bool{}, oneShot: map[string]int{}}
			if p, ok := authz.From(r.Context()); ok {
				var names []string
				_, h.loadErr = db.QueryOneContext(r.Context(), pg.Scan(pg.Array(&names)), c.sql.forSession, p.SessionID)
				for _, name := range names {
					h.recurring[name] = true
				}
			}
			ctx := context.WithValue(r.Context(), holderKey{}, h)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// Add @notice Adds a just-verified claim to the current request's holder.
func (c *Claims) Add(ctx context.Context, claim zkauthn.VerifiedClaim) error {
	h, ok := ctx.Value(holderKey{}).(*holder)
	if !ok {
		return errors.New("zkauthz: middleware not mounted — verified claim has no request holder")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if claim.Kind == zkauthn.ClaimOneShot {
		h.oneShot[claim.Name]++
	} else {
		h.recurring[claim.Name] = true
	}
	return nil
}

// Proofs @notice Satisfies every named claim from context and consumes one-shot grants atomically.
//
// @dev No database access occurs here. gqlgen can invoke a directive once per row and execute
// sibling fields concurrently, so the holder lock checks the complete all-of set before it
// consumes any one-shot member.
func (c *Claims) Proofs(ctx context.Context, claims []string) error {
	if len(claims) == 0 {
		return nil
	}
	h, ok := ctx.Value(holderKey{}).(*holder)
	if !ok {
		return invalidProof()
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.loadErr != nil {
		return h.loadErr
	}
	// Counted per name, not tested per entry: proves: ["vote","vote"] asked the same question twice
	// and a single grant answered both, taking the counter to -1. A duplicate is a request for two
	// allowances and one grant does not cover it.
	required := make(map[string]int, len(claims))
	for _, claim := range claims {
		if claim == "" {
			return invalidProof()
		}
		if h.recurring[claim] {
			continue
		}
		required[claim]++
	}
	for claim, count := range required {
		if h.oneShot[claim] < count {
			return invalidProof()
		}
	}
	for claim, count := range required {
		h.oneShot[claim] -= count
	}
	return nil
}

func invalidProof() error {
	return &kalerr.Error{Code: kalerr.CodeInvalidProof, Message: "zero-knowledge proof required"}
}
