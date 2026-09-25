package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Re0Auth/r0semi/oauth"
)

type ctxKey int

const (
	requestIDCtxKey ctxKey = iota
	traceIDCtxKey
)

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
			switch planeOf(r.URL.Path) {
			case planeProtocol:
				writeOAuthError(w, r, http.StatusRequestEntityTooLarge, "invalid_request", "request body too large")
			case planeBusiness:
				s.writeProblem(w, r, http.StatusRequestEntityTooLarge, "invalid_request", "request body too large")
			default:
				http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			}
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

// withTrace adopts the caller's W3C trace context when it is well formed and
// generates one otherwise, so every request has a trace id to log and to
// propagate to upstreams. It is deliberately minimal: this service does not run
// an OpenTelemetry exporter, so the id is correlated, not exported. An invalid
// traceparent is ignored rather than rejected — a broken tracing header is not a
// reason to fail an authorization request.
func withTrace(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		traceID := traceIDFromTraceparent(r.Header.Get("traceparent"))
		if traceID == "" {
			traceID = newTraceID()
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), traceIDCtxKey, traceID)))
	})
}

// traceIDFromTraceparent parses the version 00 form
// `00-<32 hex trace-id>-<16 hex span-id>-<2 hex flags>`. Anything else yields "".
func traceIDFromTraceparent(header string) string {
	if header == "" {
		return ""
	}
	parts := strings.Split(header, "-")
	if len(parts) != 4 || parts[0] != "00" {
		return ""
	}
	traceID, spanID, flags := parts[1], parts[2], parts[3]
	if len(traceID) != 32 || len(spanID) != 16 || len(flags) != 2 {
		return ""
	}
	for _, s := range []string{traceID, spanID, flags} {
		if _, err := hex.DecodeString(s); err != nil {
			return ""
		}
	}
	if traceID == strings.Repeat("0", 32) {
		return ""
	}
	return traceID
}

func newTraceID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

func traceID(r *http.Request) string {
	if id, ok := r.Context().Value(traceIDCtxKey).(string); ok {
		return id
	}
	return ""
}

// withAccessLog writes one line per request: what was asked for, what came back,
// how long it took, and under which request id.
//
// It sits inside withRequestID, so the id it logs is the one the caller was told
// to quote, and outside the recoverer, so a panic that becomes a 500 is logged as
// a 500 rather than as a request that never finished.
//
// The path is logged; the query string is not. Every authorization, bind callback
// and device verification carries a `code`, `state` or `user_code` in its query,
// and a log line is a file that gets copied into tickets — the same reasoning
// behind Referrer-Policy: no-referrer. The request id is enough to correlate with
// anything else that logs, and the path is enough to know what was asked for.
//
// Probes are logged at debug. An orchestrator polls /healthz and /readyz every
// few seconds for the life of the process, and at info that is the log's steady
// state rather than a signal in it. Nothing is lost — the line is still written,
// just below the level a default deployment shows.
//
// The line is written with a detached context, because the request that produced
// it may already be gone: a client that hung up mid-response is one of the cases
// most worth recording, and a cancelled context is the wrong reason to lose it.
func (s *Server) withAccessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &accessRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)

		level := slog.LevelInfo
		if isProbe(r.URL.Path) {
			level = slog.LevelDebug
		}
		slog.LogAttrs(context.Background(), level, "request",
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", rec.status),
			slog.Int64("duration_ms", time.Since(start).Milliseconds()),
			slog.Int64("bytes", rec.bytes),
			slog.String("plane", planeOf(r.URL.Path).String()),
			slog.String("request_id", requestID(r)),
			slog.String("trace_id", traceID(r)),
			slog.String("client", s.clientKey(r)),
		)
	})
}

// accessRecorder captures the status code and the body size for the access log
// while forwarding everything else.
//
// Flush is re-declared for the same reason observability.statusRecorder declares
// it: the compression middleware type-asserts for http.Flusher directly, and a
// wrapper that does not implement it makes a streaming response lose its flushes
// without an error anywhere. Unwrap lets http.ResponseController reach any other
// optional interface (Hijack, SetReadDeadline) without this type naming each one.
type accessRecorder struct {
	http.ResponseWriter
	status int
	bytes  int64
	wrote  bool
}

func (r *accessRecorder) WriteHeader(code int) {
	if !r.wrote {
		r.status = code
		r.wrote = true
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *accessRecorder) Write(p []byte) (int, error) {
	if !r.wrote {
		r.status = http.StatusOK
		r.wrote = true
	}
	n, err := r.ResponseWriter.Write(p)
	r.bytes += int64(n)
	return n, err
}

func (r *accessRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (r *accessRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

var (
	_ http.ResponseWriter = (*accessRecorder)(nil)
	_ http.Flusher        = (*accessRecorder)(nil)
)

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
		// Probes are exempt: a saturated bucket must not be able to fail a
		// liveness probe and get a healthy process restarted, nor a readiness
		// probe and pull a serving instance out of rotation.
		if isProbe(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		// One bucket per (plane, address), not one per address.
		//
		// The planes carry different traffic with different costs, and one address is
		// routinely many people: everyone behind a NAT or an office egress shares it.
		// With a single bucket, a client hammering business-plane reads spent the
		// budget those same people needed to sign in — the flood took down the one
		// thing this service exists to do. The cost of splitting is that an address
		// can now hold one bucket per plane, so what it may spend in total is the
		// configured rate times the number of planes; that is a bounded multiple of
		// a number an operator already chose, rather than an unbounded one.
		key := planeOf(r.URL.Path).String() + "|" + s.clientKey(r)
		limit, remaining, reset := s.limiter.Status(key)
		setRateLimitHeaders(w, limit, remaining, reset)
		if !s.limiter.Allow(key) {
			if after := s.limiter.RetryAfter(key); after > 0 {
				seconds := int(after.Seconds() + 0.999)
				if seconds < 1 {
					seconds = 1
				}
				w.Header().Set("Retry-After", strconv.Itoa(seconds))
			}
			switch planeOf(r.URL.Path) {
			case planeProtocol:
				writeOAuthError(w, r, http.StatusTooManyRequests, "temporarily_unavailable", "rate limit exceeded")
			case planeBusiness:
				s.writeProblem(w, r, http.StatusTooManyRequests, "rate_limited", "rate limit exceeded")
			default:
				http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			}
			return
		}
		next.ServeHTTP(w, r)
	})
}

// setRateLimitHeaders publishes the bucket's state as the IETF RateLimit-* fields
// so a client can back off before being rejected rather than after.
func setRateLimitHeaders(w http.ResponseWriter, limit, remaining int, reset time.Duration) {
	h := w.Header()
	h.Set("RateLimit-Limit", strconv.Itoa(limit))
	h.Set("RateLimit-Remaining", strconv.Itoa(remaining))
	seconds := int(reset.Seconds() + 0.999)
	if seconds < 0 {
		seconds = 0
	}
	h.Set("RateLimit-Reset", strconv.Itoa(seconds))
}

// withInFlightLimit is the inbound counterpart of the outbound bulkhead: a hard
// cap on requests being served at once. The limiter bounds rate over time; this
// bounds concurrency, which is what protects memory and database connections
// when many slow requests arrive together. Probes are exempt for the same reason
// the limiter exempts them, and the refusal is rendered per plane.
func (s *Server) withInFlightLimit(next http.Handler) http.Handler {
	if s.maxInFlight <= 0 {
		return next
	}
	sem := make(chan struct{}, s.maxInFlight)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isProbe(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		select {
		case sem <- struct{}{}:
			defer func() { <-sem }()
			next.ServeHTTP(w, r)
		default:
			w.Header().Set("Retry-After", "1")
			switch planeOf(r.URL.Path) {
			case planeProtocol:
				writeOAuthError(w, r, http.StatusServiceUnavailable, "temporarily_unavailable", "server busy")
			case planeBusiness:
				s.writeProblem(w, r, http.StatusServiceUnavailable, "temporarily_unavailable", "server busy")
			default:
				http.Error(w, "server busy", http.StatusServiceUnavailable)
			}
		}
	})
}

// It delegates to clientAddr, which is the peer address unless the peer is a
// configured trusted proxy — in which case the proxy's X-Forwarded-For is
// believed as far as the first hop we do not trust. Without a trust list a
// caller would pick its own bucket by choosing the header value; with one that
// is too broad, the same. The list is the deployment's statement of which
// addresses in front of it are its own.
func (s *Server) clientKey(r *http.Request) string {
	return clientAddr(r, s.trustedProxies)
}

// plane is which of the service's three surfaces a path belongs to.
//
// The classification is positive — each plane is a namespace that is named —
// rather than "protocol, otherwise business". The negative form is what handed
// /auth/*, /bind and every unknown path the business plane's error shape by
// accident, so that an operator tuning the rate limit also changed the wire
// contract of a browser navigation.
type plane int

const (
	// planeBrowser is a path that belongs to no plane: a surface a person reaches
	// by navigating with a browser. Its failures are plain text or a redirect —
	// never problem+json, never an OAuth error object.
	planeBrowser plane = iota
	// planeProtocol is /oauth and /.well-known: RFC 6749 requests and the metadata
	// documents. Failures are `{error,error_description}`.
	planeProtocol
	// planeBusiness is /v1: JSON in, and every failure an RFC 9457 problem+json.
	planeBusiness
)

// String names a plane for logs and metric labels. The names are stable: they
// appear in dashboards and alerts, so renaming one is a breaking change to
// observability even though no API depends on it.
func (p plane) String() string {
	switch p {
	case planeProtocol:
		return "protocol"
	case planeBusiness:
		return "business"
	default:
		return "browser"
	}
}

// planeOf classifies a path. It is the single definition of that question, shared
// by every middleware that has to choose an error shape or decide whether a
// response may be transformed at all. Two definitions is exactly how
// /.well-known/* came to be protocol plane to one caller and business plane to
// another.
//
// Each namespace matches its root as well as its contents: `/oauth`,
// `/.well-known` and `/v1` are URLs a client constructs by hand, and a rejection at
// the root has to answer like everything under it.
func planeOf(path string) plane {
	switch {
	case inNamespace(path, "/oauth"), inNamespace(path, "/.well-known"):
		return planeProtocol
	case inNamespace(path, "/v1"):
		return planeBusiness
	default:
		return planeBrowser
	}
}

// inNamespace reports whether path is prefix itself, or lies under it.
func inNamespace(path, prefix string) bool {
	return path == prefix || strings.HasPrefix(path, prefix+"/")
}

// recoverBusiness turns a panic into a problem+json 500.
func recoverBusiness(s *Server, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				slog.Error("panic while serving", "plane", "business", "method", r.Method, "path", r.URL.Path, "panic", rec)
				s.writeProblem(w, r, http.StatusInternalServerError, "internal_error", "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// recoverProtocol turns a panic on the protocol plane into an OAuth error.
//
// It exists because net/http's own handling of a panic is to log it and close the
// connection: the caller gets nothing, which is not a shape any plane promises.
// A crash has to answer in the format of the plane it happened on, and the two
// planes never borrow each other's — the same rule that governs every other error
// here.
func recoverProtocol(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				slog.Error("panic while serving", "plane", "protocol", "method", r.Method, "path", r.URL.Path, "panic", rec)
				writeOAuthError(w, r, http.StatusInternalServerError, "server_error", "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// recoverBrowser is the outermost recoverer, catching what the plane-specific ones
// cannot: a panic in shared middleware, in the login plane, in the frontend, or in
// the catch-all.
//
// It answers with a bare text/plain 500 rather than either plane's format. Those
// paths belong to neither plane, and docs/api-design.md §6 does not decide a
// format for them yet — answering problem+json would make that decision by
// accident, while text/plain is what the login plane already answers with.
func recoverBrowser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				slog.Error("panic while serving", "plane", "neither", "method", r.Method, "path", r.URL.Path, "panic", rec)
				http.Error(w, "internal error", http.StatusInternalServerError)
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
		tok := oauth.BearerToken(r)
		if tok == "" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="r0semi"`)
			s.writeProblem(w, r, http.StatusUnauthorized, "unauthenticated", "an access token is required")
			return
		}
		info, err := s.introspector.Introspect(r.Context(), tok)
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
	if slices.Contains(info.Scopes, scope) {
		return true
	}
	s.insufficientScope(w, r, scope.String(), "this token does not include '"+scope.String()+"'")
	return false
}

// insufficientScope writes the 403 for a token that is valid but lacks the scope
// a call needs, together with the RFC 6750 §3.1 challenge.
//
// The challenge is not decoration: `WWW-Authenticate` is the only standard way a
// client tells "your token is no good" (401, error="invalid_token") apart from
// "your token is fine but too narrow" (403, error="insufficient_scope"). Without
// it a standard OAuth client reports a bare 403 and cannot learn from the
// protocol which scope to ask for; the body's `required_scope` only helps a
// reader of this API's own spec.
//
// required may be empty when the requirement is a set rather than one scope — the
// raw proxy accepts any of a source's resource scopes — and the scope parameter is
// then omitted, which RFC 6750 §3.1 permits.
func (s *Server) insufficientScope(w http.ResponseWriter, r *http.Request, required, detail string) {
	challenge := `Bearer error="insufficient_scope"`
	var opts []func(*problem)
	if required != "" {
		challenge += fmt.Sprintf(", scope=%q", required)
		opts = append(opts, withRequiredScope(required))
	}
	w.Header().Set("WWW-Authenticate", challenge)
	s.writeProblem(w, r, http.StatusForbidden, "scope_not_granted", detail, opts...)
}
