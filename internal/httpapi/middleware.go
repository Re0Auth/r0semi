package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/Re0Auth/r0semi/oauth"
)

type ctxKey int

const requestIDCtxKey ctxKey = iota

// Security response headers. They are applied to every response on both planes,
// for the same reason request ids are: the rule is identical on either side and
// has no plane-specific shape. (The error *writers* are the opposite: each plane
// must render its own format, which is why they are not shared.)
//
// The values are chosen for an OAuth 2.0 server specifically, not copied from a
// generic checklist:
//
//   - Referrer-Policy: no-referrer. Authorization, consent and bind URLs carry
//     `client_id`, `redirect_uri`, `state` and, on the way back, `code`. Handing
//     those to a third party through a Referer header is an OAuth-specific
//     disclosure, and the default policy leaks the full URL cross-origin.
//   - frame-ancestors 'none' + X-Frame-Options: DENY. A consent or
//     device-approval screen rendered inside an attacker's frame is the textbook
//     clickjacking target, and the button it protects hands out access.
//   - X-Content-Type-Options: nosniff. The raw proxy passes a source's
//     Content-Type through verbatim, so the browser must never second-guess it.
//
// A handler that needs a different policy for its own response — the HTML plane
// will need a full `script-src` — calls Header().Set after this middleware has
// run; Set replaces, so the later value wins.
const (
	// cspFrameAncestorsNone is the policy for responses that are not HTML. It is
	// deliberately not a full policy: a JSON body has no scripts to constrain.
	cspFrameAncestorsNone = "frame-ancestors 'none'"

	// hstsValue omits includeSubDomains and preload on purpose. Those are
	// domain-wide commitments that can break unrelated subdomains, so they belong
	// to the edge/reverse-proxy policy of a deployment, not to this binary. A
	// deployment that wants them adds them where it terminates TLS.
	hstsValue = "max-age=31536000"
)

// withSecurityHeaders sets the defensive headers. It sits outside the limiter
// and the handlers, so a rejected request carries them too.
func (s *Server) withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy", cspFrameAncestorsNone)
		// HSTS is only meaningful over https, and `secure` is the deployment's
		// own declaration that this issuer is reached that way (the same fact
		// that makes the session cookie Secure).
		if s.secure {
			h.Set("Strict-Transport-Security", hstsValue)
		}
		next.ServeHTTP(w, r)
	})
}

// withBodyLimit caps how large a body a handler can be made to read.
//
// Every endpoint here takes something small — a form, or a few hundred bytes of
// JSON — so the ten megabytes the standard library allows a form is room nobody
// needs and everyone pays for. It sits inside the rate limiter, because shedding
// load is cheaper than reading it, and outside every handler.
//
// The refusal is rendered per plane, using the same dispatch the limiter uses. A
// 413 in the wrong shape would be the one response in this service that a client
// parsing its own plane could not understand.
func (s *Server) withBodyLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := oauth.LimitFormBody(w, r); err != nil {
			if isProtocolPath(r.URL.Path) {
				writeOAuthError(w, r, http.StatusRequestEntityTooLarge, "invalid_request", "request body too large")
				return
			}
			s.writeProblem(w, r, http.StatusRequestEntityTooLarge, "invalid_request", "request body too large")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// withRequestID assigns a request id, echoes it on the response, and puts it in
// the context so the problem writer can include it.
//
// It is the outermost middleware, so a response produced by the limiter (or by a
// panic) carries one too: a request id is most needed on exactly the responses
// that never reach a handler.
func withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-Id")
		if id == "" {
			id = newRequestID()
		}
		w.Header().Set("X-Request-Id", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDCtxKey, id)))
	})
}

func requestID(r *http.Request) string {
	if id, ok := r.Context().Value(requestIDCtxKey).(string); ok {
		return id
	}
	return ""
}

func newRequestID() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "req_unknown"
	}
	return "req_" + hex.EncodeToString(b)
}

// withRateLimit rejects a caller that exceeds its budget. It runs before the
// session middleware so a flood is turned away before any storage work, and it
// writes each plane's own error shape: a rate-limited /oauth request must still
// be an OAuth error, never problem+json.
func (s *Server) withRateLimit(next http.Handler) http.Handler {
	if s.limiter == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := clientKey(r)
		if !s.limiter.Allow(key) {
			if after := s.limiter.RetryAfter(key); after > 0 {
				seconds := int(after.Seconds() + 0.999)
				if seconds < 1 {
					seconds = 1
				}
				w.Header().Set("Retry-After", strconv.Itoa(seconds))
			}
			if isProtocolPath(r.URL.Path) {
				writeOAuthError(w, r, http.StatusTooManyRequests, "temporarily_unavailable", "rate limit exceeded")
				return
			}
			s.writeProblem(w, r, http.StatusTooManyRequests, "rate_limited", "rate limit exceeded")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// clientKey derives the limiter key. It uses the peer address only: trusting
// X-Forwarded-For without a known proxy list would let a caller pick its own
// bucket; a trusted-proxy mode is a deliberate later change.
func clientKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func isProtocolPath(path string) bool {
	return strings.HasPrefix(path, "/oauth/") || strings.HasPrefix(path, "/.well-known/")
}

// recoverProtocol turns a panic into an OAuth-format 500.
func recoverProtocol(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				writeOAuthError(w, r, http.StatusInternalServerError, "server_error", "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// recoverBusiness turns a panic into a problem+json 500.
func recoverBusiness(s *Server, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.writeProblem(w, r, http.StatusInternalServerError, "internal_error", "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// tokenHandler is a business-plane handler that has already been authenticated.
type tokenHandler func(w http.ResponseWriter, r *http.Request, info oauth.TokenInfo)

// withBearer resolves the bearer token through introspection and rejects an
// absent, invalid or expired one with 401 problem+json.
func (s *Server) withBearer(next tokenHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := bearerToken(r)
		if tok == "" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="r0semi"`)
			s.writeProblem(w, r, http.StatusUnauthorized, "unauthenticated", "an access token is required")
			return
		}
		info, err := s.as.Introspect(r.Context(), tok)
		if err != nil {
			s.writeProblem(w, r, http.StatusInternalServerError, "internal_error", "token introspection failed")
			return
		}
		if !info.Active {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			s.writeProblem(w, r, http.StatusUnauthorized, "invalid_token", "the access token is invalid or has expired")
			return
		}
		next(w, r, info)
	}
}

// requireScope enforces one scope on an authenticated call, returning 403 with
// the missing scope when it is absent.
func (s *Server) requireScope(w http.ResponseWriter, r *http.Request, info oauth.TokenInfo, scope oauth.Scope) bool {
	for _, got := range info.Scopes {
		if got == scope {
			return true
		}
	}
	s.writeProblem(w, r, http.StatusForbidden, "scope_not_granted",
		"this token does not include '"+scope.String()+"'", withRequiredScope(scope.String()))
	return false
}

func bearerToken(r *http.Request) string {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if len(h) > len(prefix) && strings.EqualFold(h[:len(prefix)], prefix) {
		return strings.TrimSpace(h[len(prefix):])
	}
	return ""
}
