// Package observability is the operational surface that belongs to no API
// plane: Prometheus metrics and the Go runtime's profiling endpoints.
//
// Both are served on a separate, internal listener (see cmd/re0auth) rather than
// the public one. Neither is part of the API contract, and the profiling
// endpoints in particular expose process internals — the goroutine dump, the
// heap, a 30-second CPU profile. They are for an operator or a scraper on the
// private network, never for the internet.
//
// Nothing here is required for the service to serve: metrics are cheap enough to
// keep always on, and the listener is opt-in.
package observability

import (
	"net/http"
	"net/http/pprof"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// namespace prefixes every metric this service exports, so a scrape of a shared
// Prometheus cannot confuse them with another service's.
const namespace = "re0auth"

// Metrics is the service's Prometheus instrumentation.
//
// Two layers. The first is the four golden signals of any HTTP service — traffic
// and errors (requests_total), latency (request_duration_seconds), and saturation
// (in_flight_requests) — plus the Go runtime and process collectors, which answer
// "is it running out of memory, goroutines or file descriptors".
//
// The second is the domain layer: the security-relevant events an authorization
// server has to be able to alert on, which no HTTP status code carries. A login
// that failed because an identity was already taken, a refresh grant the upstream
// rejected, a credential the vault could not open, an audit chain that no longer
// verifies — each is a 4xx or a redirect on the wire, indistinguishable from the
// routine case. They exist so the alerting rules in docs/observability-decision.md
// (ADR-0007) have something to fire on.
//
// Every label here is bounded by construction: provider and grant_type are
// normalized against a fixed set, revocation kinds, decisions, results and admin
// actions are constants, and the one free-form pair (game, source) is only ever
// recorded for a source the deployment actually configured. An unbounded label is
// a way to make a metrics endpoint into a memory leak.
type Metrics struct {
	registry *prometheus.Registry
	requests *prometheus.CounterVec
	duration *prometheus.HistogramVec
	inFlight *prometheus.GaugeVec

	// Domain signals. See the Observe* methods for what feeds each.
	logins          *prometheus.CounterVec
	tokensIssued    *prometheus.CounterVec
	tokenErrors     *prometheus.CounterVec
	deviceDecision  *prometheus.CounterVec
	revocations     *prometheus.CounterVec
	tokensRevoked   *prometheus.CounterVec
	adminActions    *prometheus.CounterVec
	auditVerify     *prometheus.CounterVec
	upstreamFetch   *prometheus.CounterVec
	upstreamRefresh *prometheus.CounterVec
	vaultOps        *prometheus.CounterVec
	vaultLatency    *prometheus.HistogramVec
}

// New builds the instrumentation on its own registry. A private registry rather
// than prometheus.DefaultRegisterer keeps the exported set exact: what this
// service exposes is what this file registers, not whatever a dependency
// happened to add to the global one.
func New() *Metrics {
	reg := prometheus.NewRegistry()
	m := &Metrics{
		registry: reg,
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "http_requests_total",
			Help:      "Total HTTP requests handled, by plane, method and status code.",
		}, []string{"plane", "method", "status"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "http_request_duration_seconds",
			Help:      "HTTP request latency in seconds, by plane and method.",
			Buckets:   prometheus.DefBuckets,
		}, []string{"plane", "method"}),
		inFlight: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "http_in_flight_requests",
			Help:      "HTTP requests currently being served, by plane.",
		}, []string{"plane"}),

		logins: counter("auth_logins_total",
			"Sign-in attempts that reached a terminal outcome, by provider and result.", "provider", "result"),
		tokensIssued: counter("tokens_issued_total",
			"Access tokens issued by the token endpoint, by grant type.", "grant_type"),
		tokenErrors: counter("token_errors_total",
			"Token endpoint failures, by grant type and OAuth error code.", "grant_type", "error"),
		deviceDecision: counter("device_decisions_total",
			"Device-flow decisions a person made, by decision.", "decision"),
		revocations: counter("revocations_total",
			"Revocation operations performed, by kind.", "kind"),
		tokensRevoked: counter("tokens_revoked_total",
			"Individual tokens revoked, by kind.", "kind"),
		adminActions: counter("admin_actions_total",
			"Operator-plane mutations that succeeded, by action.", "action"),
		auditVerify: counter("audit_verify_total",
			"Audit-chain verification outcomes, by result.", "result"),
		upstreamFetch: counter("upstream_fetches_total",
			"Data-plane reads proxied to a configured source, by game, source and result.", "game", "source", "result"),
		upstreamRefresh: counter("upstream_refreshes_total",
			"Upstream token refreshes, by result.", "result"),
		vaultOps: counter("vault_operations_total",
			"Credential-vault operations, by operation and result.", "operation", "result"),
		vaultLatency: histogram("vault_operation_duration_seconds",
			"Credential-vault operation latency in seconds, by operation.", "operation"),
	}
	reg.MustRegister(m.requests, m.duration, m.inFlight)
	reg.MustRegister(
		m.logins, m.tokensIssued, m.tokenErrors, m.deviceDecision,
		m.revocations, m.tokensRevoked, m.adminActions, m.auditVerify,
		m.upstreamFetch, m.upstreamRefresh, m.vaultOps, m.vaultLatency,
	)
	// The runtime and process collectors are what make /metrics useful during an
	// incident that is not a request: a goroutine leak, a GC cliff, an open
	// file-descriptor ceiling.
	reg.MustRegister(collectors.NewGoCollector())
	reg.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	return m
}

// counter and histogram build a domain signal with the shared namespace. They
// exist because there are enough of them that repeating the opts struct at each
// site would bury the one thing that differs: the name and its labels.
func counter(name, help string, labels ...string) *prometheus.CounterVec {
	return prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Name: name, Help: help,
	}, labels)
}

func histogram(name, help string, labels ...string) *prometheus.HistogramVec {
	return prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace, Name: name, Help: help, Buckets: prometheus.DefBuckets,
	}, labels)
}

// Handler returns the Prometheus scrape handler for this registry.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

// Middleware instruments every request. classify labels the request with its
// plane; it is a function rather than a fixed label because plane is the HTTP
// layer's own concept (internal/httpapi) and this package must not have an
// opinion about it.
//
// It is installed outermost, so a request that never reaches a handler — a 404,
// a rate-limit rejection, a recovered panic — is still counted. A metric that
// only sees successful routing answers the wrong question.
func (m *Metrics) Middleware(classify func(*http.Request) string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		plane := classify(r)
		m.inFlight.WithLabelValues(plane).Inc()
		defer m.inFlight.WithLabelValues(plane).Dec()

		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		start := time.Now()
		next.ServeHTTP(rec, r)

		method := normalizeMethod(r.Method)
		m.requests.WithLabelValues(plane, method, strconv.Itoa(rec.status)).Inc()
		m.duration.WithLabelValues(plane, method).Observe(time.Since(start).Seconds())
	})
}

// Label vocabulary for the domain signals. They are constants rather than
// scattered string literals so the code that emits a value and the alerting
// rules that match on it cannot drift apart without a compile error on one side.
const (
	// LoginSuccess is the one non-failure login result.
	LoginSuccess = "success"

	// Revocation kinds.
	RevocationGrant      = "grant"
	RevocationBinding    = "binding"
	RevocationCascade    = "cascade"
	RevocationKillSwitch = "kill_switch"
	RevocationErasure    = "erasure"

	// Device-flow decisions.
	DeviceApproved = "approved"
	DeviceDenied   = "denied"

	// Operator-plane actions.
	AdminRegister   = "register"
	AdminSuspend    = "suspend"
	AdminActivate   = "activate"
	AdminDelete     = "delete"
	AdminKillSwitch = "kill_switch"

	// Upstream data-plane read results.
	UpstreamOK          = "ok"
	UpstreamDegraded    = "degraded"
	UpstreamNotBound    = "not_bound"
	UpstreamUnavailable = "unavailable"

	// Upstream refresh results.
	RefreshOK        = "ok"
	RefreshRejected  = "rejected"
	RefreshTransient = "transient"
	RefreshLost      = "lost_race"
	RefreshNoToken   = "no_refresh_token"

	// Audit-chain verification results.
	VerifyOK     = "ok"
	VerifyFailed = "failed"
	VerifyError  = "error"
)

// ObserveLogin records one sign-in attempt that reached a terminal outcome.
// provider is a configured identity provider's name (or "unknown"); result is
// LoginSuccess or a short failure code of this service's own choosing.
func (m *Metrics) ObserveLogin(provider, result string) {
	if m == nil {
		return
	}
	m.logins.WithLabelValues(provider, result).Inc()
}

// ObserveTokenIssued records a successful token response.
func (m *Metrics) ObserveTokenIssued(grantType string) {
	if m == nil {
		return
	}
	m.tokensIssued.WithLabelValues(normalizeGrantType(grantType)).Inc()
}

// ObserveTokenError records a failed token response by its OAuth error code.
func (m *Metrics) ObserveTokenError(grantType, code string) {
	if m == nil {
		return
	}
	m.tokenErrors.WithLabelValues(normalizeGrantType(grantType), normalizeOAuthErrorCode(code)).Inc()
}

// ObserveDeviceDecision records a device-flow approval or denial.
func (m *Metrics) ObserveDeviceDecision(decision string) {
	if m == nil {
		return
	}
	m.deviceDecision.WithLabelValues(decision).Inc()
}

// ObserveRevocation records one revocation operation. kind is one of the
// Revocation* constants.
func (m *Metrics) ObserveRevocation(kind string) {
	if m == nil {
		return
	}
	m.revocations.WithLabelValues(kind).Inc()
}

// ObserveTokensRevoked adds a count of individual tokens one operation removed.
// A non-positive count is ignored, so a revocation that found nothing does not
// create a series that looks like activity.
func (m *Metrics) ObserveTokensRevoked(kind string, n int) {
	if m == nil || n <= 0 {
		return
	}
	m.tokensRevoked.WithLabelValues(kind).Add(float64(n))
}

// ObserveAdminAction records a successful operator-plane mutation.
func (m *Metrics) ObserveAdminAction(action string) {
	if m == nil {
		return
	}
	m.adminActions.WithLabelValues(action).Inc()
}

// ObserveAuditVerify records the outcome of walking the audit chain.
func (m *Metrics) ObserveAuditVerify(result string) {
	if m == nil {
		return
	}
	m.auditVerify.WithLabelValues(result).Inc()
}

// ObserveUpstreamFetch records one data-plane read. game and source MUST name a
// source the deployment configured — callers must not pass a raw request value
// — because it is the only label pair here whose values are not from a fixed
// set, and an unconfigured name would let a caller grow the metric set.
func (m *Metrics) ObserveUpstreamFetch(game, source, result string) {
	if m == nil {
		return
	}
	m.upstreamFetch.WithLabelValues(game, source, result).Inc()
}

// ObserveUpstreamRefresh records one attempt to refresh an upstream token.
func (m *Metrics) ObserveUpstreamRefresh(result string) {
	if m == nil {
		return
	}
	m.upstreamRefresh.WithLabelValues(result).Inc()
}

// ObserveVaultOperation records a credential-vault operation and its latency.
//
// It is the method the vault package's Metrics interface is satisfied by, which
// is why operation and result are strings chosen by the vault rather than typed
// constants here: vault is a public library and cannot import this package, so
// the vocabulary travels with the values it passes.
func (m *Metrics) ObserveVaultOperation(operation, result string, d time.Duration) {
	if m == nil {
		return
	}
	m.vaultOps.WithLabelValues(operation, result).Inc()
	if d >= 0 {
		m.vaultLatency.WithLabelValues(operation).Observe(d.Seconds())
	}
}

// normalizeGrantType collapses anything outside the grant types this server
// implements into "other". The value arrives straight from the request, so
// without this a caller could mint one time series per made-up grant_type and
// turn the metrics endpoint into unbounded memory.
func normalizeGrantType(grantType string) string {
	switch grantType {
	case "authorization_code", "refresh_token", "device_code":
		return grantType
	default:
		return "other"
	}
}

// normalizeOAuthErrorCode keeps the error label bounded. It is parsed from a
// response body, and only the codes this server can actually emit are named.
func normalizeOAuthErrorCode(code string) string {
	switch code {
	case "invalid_request", "invalid_client", "invalid_grant", "unauthorized_client",
		"unsupported_grant_type", "invalid_scope", "access_denied",
		"invalid_token", "insufficient_scope", "temporarily_unavailable",
		"server_error", "unsupported_response_type":
		return code
	default:
		return "other"
	}
}

// normalizeMethod keeps the method label bounded. net/http accepts any valid
// token as a request method, so a caller can invent one per request; labelling
// by the raw value would let it grow the metric set without bound.
func normalizeMethod(method string) string {
	switch method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch,
		http.MethodDelete, http.MethodHead, http.MethodOptions:
		return method
	default:
		return "other"
	}
}

// InternalHandler builds the internal listener's handler: the metrics endpoint
// and the runtime profiling endpoints. It is deliberately not mounted on the
// public mux; serve it on an address only your operator plane can reach.
func (m *Metrics) InternalHandler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", m.Handler())
	registerPprof(mux)
	return mux
}

// registerPprof mounts net/http/pprof explicitly rather than importing it for
// its side effect, which would publish these handlers on http.DefaultServeMux —
// the one mux a later dependency might also serve from.
func registerPprof(mux *http.ServeMux) {
	// Index serves /debug/pprof/ and every named profile under it (heap,
	// goroutine, allocs, block, mutex, threadcreate), resolved at request time.
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
}

// statusRecorder captures the response status for the counter while forwarding
// everything else.
type statusRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (r *statusRecorder) WriteHeader(code int) {
	if !r.wrote {
		r.status = code
		r.wrote = true
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(p []byte) (int, error) {
	if !r.wrote {
		r.status = http.StatusOK
		r.wrote = true
	}
	return r.ResponseWriter.Write(p)
}

// Flush forwards an explicit flush. It is declared (rather than left to Unwrap)
// because the compression middleware type-asserts for http.Flusher directly, and
// a streaming response would otherwise lose its flushes through this wrapper.
func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets http.ResponseController reach any other optional interface the
// underlying writer implements (Hijack, SetReadDeadline) without this type
// re-declaring each one.
func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

var (
	_ http.ResponseWriter = (*statusRecorder)(nil)
	_ http.Flusher        = (*statusRecorder)(nil)
)
