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

// withRequestID is the only middleware both planes share: it assigns a request
// id, echoes it on the response, and puts it in the context so the problem
// writer can include it.
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
