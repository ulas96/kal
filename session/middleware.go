package session

import (
	"context"
	"log"
	"mime"
	"net"
	"net/http"

	"github.com/go-pg/pg/v10/orm"

	"github.com/ulas96/kal/authz"
)

// MiddlewareOptions @notice Configuration for Middleware. The zero value is the production
// posture.
type MiddlewareOptions struct {
	// CookieName @notice Which cookie carries the session. Default DefaultCookieName.
	CookieName string

	// ClientIP @notice How to attribute a request to a client address, for rate limiting and
	// session metadata. Default: the host part of RemoteAddr.
	//
	// @dev Deliberately not X-Forwarded-For by default — that header is client-supplied unless
	// a trusted proxy overwrites it, and a spoofable address turns per-IP rate limiting into a
	// bypass. Deployments behind a proxy set this to read the header their proxy guarantees.
	ClientIP func(*http.Request) string
}

// Middleware @notice Resolves the session cookie into an authz.Principal on the request
// context, carries the cookie jar for resolvers, and enforces the cross-site transport guard.
// Plug it into luima's Config.HTTPMiddleware (luima ≥ 0.2.0) or any net/http stack.
//
// @dev The middleware never returns 401. It resolves a session or it does not, populates the
// context accordingly, and calls next — the graph decides what anonymous may see, because one
// GraphQL endpoint serves public and private fields in the same document and a transport-level
// 401 would make every public field unreachable while logged out. An invalid or expired token
// is not an error either: clear the cookie, proceed anonymously. The only outright rejection is
// the transport guard below.
//
// A lookup that fails on the driver (database down) also proceeds anonymously, after logging:
// no identity is granted (fail closed), and the resolvers' own queries will surface the outage
// with a proper error.
//
// @param db   the pool Lookup runs on; orm.DB so a test can hand in anything
// @param opts zero value for the defaults
// @return func(http.Handler) http.Handler the outermost-first middleware
func (s *Sessions) Middleware(db orm.DB, opts MiddlewareOptions) func(http.Handler) http.Handler {
	name := opts.CookieName
	if name == "" {
		name = DefaultCookieName
	}
	clientIP := opts.ClientIP
	if clientIP == nil {
		clientIP = remoteHost
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// The guard runs before anything else spends work on the request. OPTIONS is
			// exempt: the CORS preflight must reach gqlgen's transport, and it carries no
			// cookies' worth of authority anyway.
			if r.Method != http.MethodOptions && !passesTransportGuard(r) {
				writeGuardError(w)
				return
			}

			j := &jar{}
			fw := &flushWriter{ResponseWriter: w, jar: j}
			ctx := context.WithValue(r.Context(), jarKey{}, j)
			ctx = withMeta(ctx, Meta{UserAgent: r.UserAgent(), IP: clientIP(r)})

			if c, err := r.Cookie(name); err == nil {
				switch p, lookupErr := s.lookupCookie(ctx, db, c.Value); {
				case lookupErr != nil:
					// log.Printf for the same reason luimaerr does: wrapping the middleware
					// is the logging seam, and a Logger field would be a second way to do it.
					log.Printf("kal/session: lookup failed, proceeding anonymously: %v", lookupErr)
				case p != nil:
					ctx = authz.WithPrincipal(ctx, p)
				default:
					// Unknown, expired, revoked or empty: take the dead cookie back off the
					// client so it stops being sent.
					j.add(ClearCookie(name))
				}
			}

			next.ServeHTTP(fw, r.WithContext(ctx))
			// A handler that never wrote anything still gets its cookies: net/http sends an
			// implicit 200 after return, reading the header map this flush appends to. The
			// sync.Once makes it free in every other case.
			fw.flush()
		})
	}
}

// lookupCookie @notice Lookup, minus the pointless round trip for an empty value.
func (s *Sessions) lookupCookie(ctx context.Context, db orm.DB, value string) (*authz.Principal, error) {
	if value == "" {
		return nil, nil
	}
	return s.Lookup(ctx, db, value)
}

// remoteHost @notice The default ClientIP: RemoteAddr without the port.
func remoteHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// passesTransportGuard @notice Apollo's CSRF-prevention shape: the request must prove a
// preflight happened, by carrying something a cross-origin simple request cannot.
//
// @dev The CORS simple set is {text/plain, application/x-www-form-urlencoded,
// multipart/form-data} plus a header-free GET — exactly the requests a browser sends
// cross-origin with cookies and no preflight. Requiring a Content-Type outside that set, or a
// custom header, forces a preflight the attacker's origin cannot pass (luima sets no
// Access-Control-Allow-Origin anywhere). gqlgen's transport.POST wants application/json, so
// every normal GraphQL client passes without noticing; a GET-based persisted-query client must
// send X-Kal-Operation, and that cost is documented rather than silently waived.
//
// No token, no state, ten lines — and none of the naive double-submit weaknesses, since there
// is nothing here a sibling-subdomain cookie write could influence.
func passesTransportGuard(r *http.Request) bool {
	if r.Header.Get("X-Kal-Operation") != "" || r.Header.Get("X-Requested-With") != "" {
		return true
	}
	ct := r.Header.Get("Content-Type")
	if ct == "" {
		return false // header-free request: the simple-GET shape
	}
	mediaType, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return false // unparseable claims no proof; fail closed
	}
	switch mediaType {
	case "text/plain", "application/x-www-form-urlencoded", "multipart/form-data":
		return false
	}
	return true
}

// writeGuardError @notice A GraphQL-shaped 403, so every client library surfaces it readably.
func writeGuardError(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(`{"errors":[{"message":"cross-site request blocked: send Content-Type application/json or an X-Kal-Operation header","extensions":{"code":"FORBIDDEN"}}]}`))
}

// metaKey @notice Context key for request Meta; unexported like the others.
type metaKey struct{}

// withMeta @notice Stashes the request attribution for authn's rate limiter and Issue calls.
func withMeta(ctx context.Context, m Meta) context.Context {
	return context.WithValue(ctx, metaKey{}, m)
}

// MetaFromContext @notice The request attribution the middleware recorded — user agent and
// client address — for anything issuing sessions or counting failures per IP.
//
// @param ctx the resolver context
// @return Meta zero when the middleware is not mounted
func MetaFromContext(ctx context.Context) Meta {
	m, _ := ctx.Value(metaKey{}).(Meta)
	return m
}
