package session

import "net/http"

// DefaultCookieName @notice The session cookie's name, __Host- prefixed.
//
// @dev The prefix is the important part: a browser rejects a __Host- cookie unless it has
// Secure, Path=/ and no Domain attribute — which means a compromised or attacker-controlled
// sibling subdomain cannot overwrite it. That property is what makes session fixation via
// cookie injection impossible (ASVS 3.3.1, 3.3.3). One layer owns each cookie name: this one is
// kal's, and nothing else — no Fiber session middleware, no CSRF middleware — may set it.
const DefaultCookieName = "__Host-kal_session"

// Cookie @notice The session cookie, with every attribute the way it must be.
//
// @dev Each attribute is load-bearing:
//
//   - Secure always, and there is deliberately no knob to turn it off. Chrome and Firefox
//     accept Secure cookies from http://localhost, so local development works unmodified;
//     Safari's answer is a local certificate (mkcert), not a flag that will be found and set in
//     production.
//   - HttpOnly always — nothing in the token is useful to client-side script.
//   - SameSite=Lax, not Strict: Strict drops the cookie on top-level navigation from another
//     site, which breaks every link in every email — including kal's own verification links, so
//     the user clicks "verify" and lands logged out. Lax is not sufficient alone; the
//     middleware's transport guard covers the rest.
//   - No Max-Age and no Expires: a browser-session cookie. Server-side idle and absolute
//     expiry are the real lifetime, and they cannot be extended by a client-held attribute.
//
// @param name  the cookie name; use DefaultCookieName unless there are two kal instances
// @param token the raw session token from Issue or Rotate
// @return *http.Cookie ready for SetCookie
func Cookie(name, token string) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    token,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}

// ClearCookie @notice The deletion twin of Cookie.
//
// @dev It carries the same Secure/Path/SameSite attributes, because a browser will not let a
// non-compliant cookie overwrite a __Host- one — a bare "name=; Max-Age=0" would be silently
// ignored and the stale token would ride along forever.
//
// @param name the cookie name to delete
// @return *http.Cookie with MaxAge -1
func ClearCookie(name string) *http.Cookie {
	c := Cookie(name, "") // #nosec G124 -- Secure/HttpOnly/SameSite all come from Cookie
	c.MaxAge = -1
	return c
}
