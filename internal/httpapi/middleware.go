package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Re0Auth/r0semi/internal/ratelimit"
	"github.com/Re0Auth/r0semi/oauth"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

type ctxKey int

// requestIDs are the identities a request carries: what it is called in a log
// line, what it is called in a trace, and which bucket it is rate limited under.
// They travel as one value because three context.WithValue calls meant three
// context nodes allocated on every request, and a lookup that walked all of them.
type requestIDs struct {
	request   string
	trace     string
	clientKey string
}

const idsCtxKey ctxKey = iota

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

	// cspRawProxy is the policy for the one response on this service that can
	// carry a document written somewhere else: the raw passthrough proxy. Its
	// Content-Type is the source's by contract, so a source answering text/html
	// would otherwise be markup running on this issuer's own origin — the origin
	// that holds the session cookie and hands out a CSRF token at
	// /v1/sessions/current. `default-src 'none'` covers script-src, and `sandbox`
	// puts the document in an opaque origin with no script execution; the
	// handler additionally sends Content-Disposition: attachment so a browser
	// downloads rather than renders. frame-ancestors is restated because this
	// value *replaces* cspFrameAncestorsNone rather than adding to it.
	cspRawProxy = "default-src 'none'; frame-ancestors 'none'; sandbox"
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

// decodeJSONBody reads a bounded JSON body, reporting an oversized one as the
// middleware's own plane-shaped 413 rather than as malformed JSON.
//
// withBodyLimit has already wrapped r.Body in http.MaxBytesReader (via
// oauth.LimitFormBody) and answers 413 itself when the length is DECLARED over
// the cap. A chunked body declares nothing, so the cap is enforced while reading
// and the reader returns *http.MaxBytesError in the middle of the decode — which
// every JSON handler here classified as "malformed JSON body", giving one
// oversized body two different answers depending on how the client framed it
// (S13-9). The refusal below is deliberately byte-for-byte the middleware's.
//
// The cap is applied with a second MaxBytesReader rather than an io.LimitReader:
// a LimitReader that stops at the same count as the reader underneath it returns
// EOF one read before that reader would have reported the overflow, which is how
// the oversized body became a truncated one in the first place.
func (s *Server) decodeJSONBody(w http.ResponseWriter, r *http.Request, dst any, limit int64) bool {
	if limit <= 0 || limit > int64(oauth.MaxFormBytes) {
		limit = int64(oauth.MaxFormBytes)
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			s.writeProblem(w, r, http.StatusRequestEntityTooLarge, "invalid_request", "request body too large")
			return false
		}
		s.writeProblem(w, r, http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return false
	}
	return true
}

// withRequestContext assigns the identifiers every request carries — the request
// id, the trace id, and the client key the limiter and the access log both need —
// in one pass.
//
// They used to be two middlewares, which cost a request copy each (r.WithContext
// allocates a shallow copy of the Request) and derived the client key twice, once
// for the limiter and once for the log. Both derivations walk the trusted-proxy
// list. One copy and one derivation; the values are unchanged.
//
// It is the outermost middleware, so a response produced by the limiter (or by a
// panic) carries a request id too: a request id is most needed on exactly the
// responses that never reach a handler.
func (s *Server) withRequestContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-Id")
		if !validRequestID(id) {
			id = newRequestID()
		}
		w.Header().Set("X-Request-Id", id)

		trace := remoteTraceID(r)
		if trace == "" {
			trace = newTraceID()
		}

		ctx := context.WithValue(r.Context(), idsCtxKey, requestIDs{
			request:   id,
			trace:     trace,
			clientKey: s.clientKey(r),
		})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// idsOf returns the identities this request was tagged with, if the middleware
// ran. Handlers mounted without it see the zero value.
func idsOf(r *http.Request) requestIDs {
	ids, _ := r.Context().Value(idsCtxKey).(requestIDs)
	return ids
}

func requestID(r *http.Request) string { return idsOf(r).request }

// withTrace is withRequestContext's trace half on its own: it adopts the caller's
// W3C trace context when it is well formed and generates one otherwise, so a
// handler mounted without the full chain (a test, an embedding) still has an id to
// correlate. The server does not use it — see withRequestContext, which assigns
// every identifier in one pass.
//
// It is deliberately minimal: this service does not run an OpenTelemetry exporter,
// so the id is correlated, not exported. An invalid traceparent is ignored rather
// than rejected — a broken tracing header is not a reason to fail an authorization
// request.
func withTrace(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		trace := remoteTraceID(r)
		if trace == "" {
			trace = newTraceID()
		}
		ids := idsOf(r)
		ids.trace = trace
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), idsCtxKey, ids)))
	})
}

// remoteTraceID returns the trace id of the caller's W3C traceparent, or "" when
// the header is absent, malformed, or carries an invalid context.
//
// It parses with the OpenTelemetry propagator rather than by hand, so the rules
// are the specification's rather than this file's reading of them: lowercase hex
// only, both the trace id and the span id non-zero, versions up to 0xfe accepted
// (for version 00 the flags field is constrained too), and a tracestate that is
// parsed but not used here. The id alone is taken from the extracted context,
// because this service correlates traces rather than exporting them — the remote
// span context does not travel any further, and nothing here can observe the
// tracestate.
//
// IsRemote is required so that a span context already in the request context —
// put there by an enclosing instrumentation, not by a header — is never mistaken
// for the caller's. Extract marks what it reads from the header remote.
func remoteTraceID(r *http.Request) string {
	ctx := propagation.TraceContext{}.Extract(r.Context(), propagation.HeaderCarrier(r.Header))
	sc := trace.SpanContextFromContext(ctx)
	if !sc.IsValid() || !sc.IsRemote() {
		return ""
	}
	return sc.TraceID().String()
}

func newTraceID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

func traceID(r *http.Request) string { return idsOf(r).trace }

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
			slog.String("client", s.clientKeyOf(r)),
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

// maxRequestIDBytes and validRequestID bound what this service adopts from the
// caller. The adopted id is echoed in a response header (above), written into
// every problem+json body (responses.go RequestID) and put on every access log
// line, so without a gate its size and content are priced by the request: one
// unauthenticated 64 KiB header produces a 64 KiB log line and two 64 KiB
// echoes, and the shipped rate limit bounds that only per address. Anything that
// is not a short opaque token is replaced with a generated id rather than
// truncated — a truncated caller-chosen id is still caller-chosen, and could
// still collide with another caller's.
const maxRequestIDBytes = 128

func validRequestID(id string) bool {
	if len(id) == 0 || len(id) > maxRequestIDBytes {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-' {
			continue
		}
		return false
	}
	return true
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
		key := s.bucketKey(r)
		// One call, one lock acquisition: the verdict and the three header values
		// come from the same read of the bucket. Asking separately (status, then
		// allow, then the retry hint) took the limiter's process-wide lock up to
		// three times per request and could report a bucket another request had
		// already moved past.
		verdict := s.limiter.Check(key)
		setRateLimitHeaders(w, verdict)
		if !verdict.Allowed {
			if seconds := int(verdict.Reset.Seconds() + 0.999); seconds > 0 {
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
func setRateLimitHeaders(w http.ResponseWriter, v ratelimit.Verdict) {
	h := w.Header()
	h.Set("RateLimit-Limit", strconv.Itoa(v.Limit))
	h.Set("RateLimit-Remaining", strconv.Itoa(v.Remaining))
	seconds := int(v.Reset.Seconds() + 0.999)
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
//
// The cap is shared, not owned by whoever arrives first: one CLIENT may hold at
// most half of it, and the other half is headroom every other client draws from.
// The counter is keyed by the client alone, never by (plane, client): the
// semaphore is process-wide, so a per-plane counter let one address hold
// maxInFlight/2 on each of two planes and consume the whole cap — the same
// single-address denial the per-client share exists to prevent, split across two
// namespaces. The rate limiter keeps its (plane, client) key; its budget is
// per-kind, and its arithmetic is unaffected.
//
// The map holds only clients with a request in flight, so it is bounded by
// maxInFlight.
func (s *Server) withInFlightLimit(next http.Handler) http.Handler {
	if s.maxInFlight <= 0 {
		return next
	}
	sem := make(chan struct{}, s.maxInFlight)
	perClient := s.maxInFlight / 2
	if perClient < 1 {
		perClient = 1
	}
	var (
		mu     sync.Mutex
		active = make(map[string]int)
	)
	refuse := func(w http.ResponseWriter, r *http.Request) {
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
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isProbe(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		key := aggregateClientKey(s.clientKeyOf(r))
		mu.Lock()
		if active[key] >= perClient {
			mu.Unlock()
			refuse(w, r)
			return
		}
		active[key]++
		mu.Unlock()
		release := func() {
			mu.Lock()
			active[key]--
			if active[key] <= 0 {
				delete(active, key)
			}
			mu.Unlock()
		}
		select {
		case sem <- struct{}{}:
			defer func() { <-sem }()
			defer release()
			next.ServeHTTP(w, r)
		default:
			release()
			refuse(w, r)
		}
	})
}

// bucketKey is the (plane, client) key the rate limiter uses. The in-flight cap
// deliberately does NOT share it: its counter is keyed by the client alone, because
// its semaphore is process-wide (see withInFlightLimit).
func (s *Server) bucketKey(r *http.Request) string {
	return planeOf(r.URL.Path).String() + "|" + aggregateClientKey(s.clientKeyOf(r))
}

// aggregateClientKey coarsens an IPv6 client key to its /64.
//
// A single delegated IPv6 /64 is 2^64 addresses. Keying each /128 separately let
// one host fill the whole bucket table from one prefix and leave every client the
// limiter had not already seen sharing a drained overflow bucket — anonymous
// denial of service against unrelated clients, silent because the probes stayed
// green. The HTTP layer owns what a key is, so the coarsening belongs here rather
// than in the transport-agnostic limiter. The trade is explicit and in the
// opposite direction from a /128-per-key budget: every host inside one /64 now
// shares one budget. A /64 is a single subscriber's allocation, which is the
// right granularity for that trade; an operator allocating from a much wider
// prefix accepts the same sharing.
func aggregateClientKey(key string) string {
	addr, err := netip.ParseAddr(key)
	if err != nil || !addr.Is6() || addr.Is4In6() {
		return key
	}
	prefix, err := addr.Prefix(64)
	if err != nil {
		return key
	}
	return prefix.String()
}

// It delegates to clientAddr, which is the peer address unless the deployment has
// declared BOTH that the peer is one of its own reverse proxies and which header
// that proxy writes. Only then is the header read, and only its rightmost entry.
//
// The trust list alone used to be enough, and that was wrong in a way no config
// could express: a proxy that forwards the caller's own X-Forwarded-For verbatim
// (nginx's default) makes every entry caller-written, and a chain whose appended
// hop is itself inside the list (SNAT, a mesh) makes the walk step past the real
// client. A caller who varies its own header then varies its bucket key, which is
// the whole of the rate limit. Both facts are properties of the deployment, not of
// the request, so the deployment states them: `server.client_addr_header`.
func (s *Server) clientKey(r *http.Request) string {
	s.warnUntrustedProxyPeer(r)
	return clientAddr(r, s.trustedProxies, s.clientAddrHeader)
}

// clientKeyOf returns the client key withRequestContext derived for this request.
//
// The limiter and the access log both need it, and deriving it twice meant walking
// the trusted-proxy list twice per request. A handler mounted without that
// middleware — a test, a future mount — still gets a key rather than an empty
// bucket, which is why the fallback is here rather than an assumption that the
// context is populated.
func (s *Server) clientKeyOf(r *http.Request) string {
	if key := idsOf(r).clientKey; key != "" {
		return key
	}
	return s.clientKey(r)
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
