package session

import (
	"context"
	"errors"
	"net/http"
	"sync"
)

// jar @notice Collects cookies resolvers ask for, and flushes them exactly once, at the moment
// the response headers are written.
//
// @dev Resolvers may run concurrently — gqlgen executes sibling fields in goroutines — so the
// mutex is load-bearing, not defensive. The flush happens on first Write/WriteHeader rather
// than after ServeHTTP returns because net/http ignores header mutations after the header is
// sent; relying on fasthttpadaptor's buffering, which happens to read the header map late,
// would work behind Fiber and break on every other router this middleware is portable to.
type jar struct {
	mu      sync.Mutex
	cookies []*http.Cookie
}

func (j *jar) add(c *http.Cookie) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.cookies = append(j.cookies, c)
}

// flushWriter @notice The ResponseWriter wrapper that writes the jar out ahead of the first
// byte of response.
type flushWriter struct {
	http.ResponseWriter
	jar  *jar
	once sync.Once
}

func (w *flushWriter) flush() {
	w.once.Do(func() {
		w.jar.mu.Lock()
		defer w.jar.mu.Unlock()
		for _, c := range w.jar.cookies {
			http.SetCookie(w.ResponseWriter, c)
		}
	})
}

func (w *flushWriter) WriteHeader(code int) { w.flush(); w.ResponseWriter.WriteHeader(code) }
func (w *flushWriter) Write(b []byte) (int, error) {
	w.flush()
	return w.ResponseWriter.Write(b)
}

// jarKey @notice Context key for the jar; unexported for the same reason as the principal's.
type jarKey struct{}

// SetCookie @notice Queues c on the response from anywhere that has the request context — which
// is how a login resolver, holding only a ctx, sets the session cookie.
//
// @dev gqlgen's transports write headers after resolvers return in the common POST path, but
// that is a transport implementation detail that differs on the streaming paths — the jar works
// regardless of who writes first.
//
// The error for a missing jar is a plain error, not a *kalerr.Error: it means the middleware is
// not mounted, which is server misconfiguration — the presenter redacts it to "internal server
// error", which is exactly right.
//
// @param ctx the resolver context, as passed through Middleware
// @param c   the cookie to send
// @return error nil, or "middleware not mounted"
func SetCookie(ctx context.Context, c *http.Cookie) error {
	j, ok := ctx.Value(jarKey{}).(*jar)
	if !ok {
		return errors.New("session: middleware not mounted — SetCookie has no response to attach to")
	}
	j.add(c)
	return nil
}
