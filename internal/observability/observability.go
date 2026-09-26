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

// latencyBuckets are the histogram buckets for HTTP request and vault-operation
// latency. They are tuned to this service rather than Prometheus's defaults: the
// auth hot paths run in tens of microseconds, which the default's 5ms floor cannot
// resolve at all, and the business-plane p99 SLO is 1s, which the default's 1→2.5s
// jump estimates from a range wider than the SLO itself. The set keeps
// sub-millisecond resolution at the fast end and brackets 1s closely at the slow
// end.
var latencyBuckets = []float64{
	0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5,
}

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
	logins                *prometheus.CounterVec
	tokensIssued          *prometheus.CounterVec
	tokenErrors           *prometheus.CounterVec
	deviceDecision        *prometheus.CounterVec
	revocations           *prometheus.CounterVec
	tokensRevoked         *prometheus.CounterVec
	adminActions          *prometheus.CounterVec
	auditVerify           *prometheus.CounterVec
	auditAppend           *prometheus.HistogramVec
	upstreamFetch         *prometheus.CounterVec
	upstreamFetchDuration *prometheus.HistogramVec
	upstreamRefresh       *prometheus.CounterVec
	circuitTransitions    *prometheus.CounterVec
	vaultOps              *prometheus.CounterVec
	vaultLatency          *prometheus.HistogramVec
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
			Buckets:   latencyBuckets,
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
		auditAppend: histogram("audit_append_duration_seconds",
			"Time to append one chained audit record, including the wait for the chain-head lock."),
		upstreamFetch: counter("upstream_fetches_total",
			"Data-plane reads proxied to a configured source, by game, source and result.", "game", "source", "result"),
		upstreamFetchDuration: histogram("upstream_fetch_duration_seconds",
			"Data-plane read latency in seconds, by game, source and result.", "game", "source", "result"),
		upstreamRefresh: counter("upstream_refreshes_total",
			"Upstream token refreshes, by result.", "result"),
		circuitTransitions: counter("upstream_circuit_transitions_total",
			"Upstream circuit breaker state transitions, by the state entered.", "state"),
		vaultOps: counter("vault_operations_total",
			"Credential-vault operations, by operation and result.", "operation", "result"),
		vaultLatency: histogram("vault_operation_duration_seconds",
			"Credential-vault operation latency in seconds, by operation.", "operation"),
	}
	reg.MustRegister(m.requests, m.duration, m.inFlight)
	reg.MustRegister(
		m.logins, m.tokensIssued, m.tokenErrors, m.deviceDecision,
		m.revocations, m.tokensRevoked, m.adminActions, m.auditVerify, m.auditAppend,
		m.upstreamFetch, m.upstreamFetchDuration, m.upstreamRefresh, m.circuitTransitions,
		m.vaultOps, m.vaultLatency,
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
		Namespace: namespace, Name: name, Help: help, Buckets: latencyBuckets,
	}, labels)
}

// Register adds an external collector to this service's registry. It exists for
// signals this package does not own — most visibly the Postgres pool, whose
// numbers live in the store — so they export under the same re0auth_ namespace
// without this package having to know about the store.
//
// It returns the registration error rather than panicking: metrics are not
// required for the service to serve (see the package doc), so a duplicate or
// invalid collector is something to log, not something to die on.
func (m *Metrics) Register(c prometheus.Collector) error {
	return m.registry.Register(c)
}

// PoolStats is the subset of pgxpool's statistics this package exports. It is an
// interface so the metrics package does not depend on the database driver, and so
// a test can declare the pool metric names without a live pool. *pgxpool.Stat
// satisfies it structurally; the composition root passes one in.
type PoolStats interface {
	TotalConns() int32
	IdleConns() int32
	AcquiredConns() int32
	MaxConns() int32
	AcquireCount() int64
	EmptyAcquireCount() int64
	CanceledAcquireCount() int64
	NewConnsCount() int64
	AcquireDuration() time.Duration
}

// RegisterPoolStats registers a collector that exports a connection pool's
// statistics as re0auth_db_pool_* series. The names live here so the dashboard and
// rules that read them have one source of truth the artifacts test can see.
//
// stats is a function rather than a value because the pool's numbers are read at
// scrape time; a gauge refreshed by a background loop would add a tick of
// staleness to exactly the signal — saturation — an incident is about.
func (m *Metrics) RegisterPoolStats(stats func() PoolStats) error {
	return m.registry.Register(newPoolCollector(stats))
}

// poolCollector exports a pool's statistics under the re0auth_db_pool_* names.
type poolCollector struct {
	stats func() PoolStats

	totalConns      *prometheus.Desc
	idleConns       *prometheus.Desc
	acquiredConns   *prometheus.Desc
	maxConns        *prometheus.Desc
	acquireCount    *prometheus.Desc
	emptyAcquire    *prometheus.Desc
	canceledAcquire *prometheus.Desc
	newConns        *prometheus.Desc
	acquireDuration *prometheus.Desc
}

func newPoolCollector(stats func() PoolStats) *poolCollector {
	const sub = "db_pool"
	desc := func(name, help string) *prometheus.Desc {
		return prometheus.NewDesc(prometheus.BuildFQName(namespace, sub, name), help, nil, nil)
	}
	return &poolCollector{
		stats:           stats,
		totalConns:      desc("total_conns", "Connections currently held by the pool."),
		idleConns:       desc("idle_conns", "Idle connections in the pool."),
		acquiredConns:   desc("acquired_conns", "Connections currently acquired by a caller."),
		maxConns:        desc("max_conns", "Maximum connections this pool may open."),
		acquireCount:    desc("acquire_count_total", "Successful connection acquisitions."),
		emptyAcquire:    desc("empty_acquire_count_total", "Acquisitions that had to wait for a connection."),
		canceledAcquire: desc("canceled_acquire_count_total", "Acquisitions abandoned with their context."),
		newConns:        desc("new_conns_count_total", "New connections opened by the pool."),
		acquireDuration: desc("acquire_duration_seconds_total", "Cumulative time spent acquiring connections."),
	}
}

func (c *poolCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.totalConns
	ch <- c.idleConns
	ch <- c.acquiredConns
	ch <- c.maxConns
	ch <- c.acquireCount
	ch <- c.emptyAcquire
	ch <- c.canceledAcquire
	ch <- c.newConns
	ch <- c.acquireDuration
}

func (c *poolCollector) Collect(ch chan<- prometheus.Metric) {
	s := c.stats()
	gauge := func(d *prometheus.Desc, v float64) {
		ch <- prometheus.MustNewConstMetric(d, prometheus.GaugeValue, v)
	}
	counter := func(d *prometheus.Desc, v float64) {
		ch <- prometheus.MustNewConstMetric(d, prometheus.CounterValue, v)
	}
	gauge(c.totalConns, float64(s.TotalConns()))
	gauge(c.idleConns, float64(s.IdleConns()))
	gauge(c.acquiredConns, float64(s.AcquiredConns()))
	gauge(c.maxConns, float64(s.MaxConns()))
	counter(c.acquireCount, float64(s.AcquireCount()))
	counter(c.emptyAcquire, float64(s.EmptyAcquireCount()))
	counter(c.canceledAcquire, float64(s.CanceledAcquireCount()))
	counter(c.newConns, float64(s.NewConnsCount()))
	counter(c.acquireDuration, s.AcquireDuration().Seconds())
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
	AdminRegister     = "register"
	AdminRotateSecret = "rotate_secret"
	AdminSuspend      = "suspend"
	AdminActivate     = "activate"
	AdminDelete       = "delete"
	AdminKillSwitch   = "kill_switch"

	// Upstream data-plane read results.
	UpstreamOK          = "ok"
	UpstreamDegraded    = "degraded"
	UpstreamNotBound    = "not_bound"
	UpstreamUnavailable = "unavailable"
	// UpstreamCircuitOpen is a read refused locally because the source's circuit
	// breaker is open. It is distinct from unavailable so an operator can tell
	// "we stopped calling" from "the source is down".
	UpstreamCircuitOpen = "circuit_open"

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

// ObserveAuditAppend records how long one chained audit write took, including the
// wait for the chain-head lock.
//
// The chain serialises every writer on a single row. That is the design — two
// concurrent inserts that each read the same predecessor would fork it — but it
// also means the data plane's real ceiling can be set by something no request
// metric shows: every vault-backed fetch writes an audit row before it hands over
// a credential, so the append path is on the critical path of reads that look
// unrelated to auditing. This number is what says whether that serialisation is
// still cheap or has become the bottleneck (docs/capacity-planning.md §4).
func (m *Metrics) ObserveAuditAppend(d time.Duration) {
	if m == nil {
		return
	}
	m.auditAppend.WithLabelValues().Observe(d.Seconds())
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

// ObserveUpstreamFetchDuration records how long one data-plane read took, using
// the same (game, source, result) labels as ObserveUpstreamFetch so a slow
// source can be found by name instead of inferred from an outcome. It is not
// observed for the not-bound case, where no upstream call was made.
func (m *Metrics) ObserveUpstreamFetchDuration(game, source, result string, d time.Duration) {
	if m == nil {
		return
	}
	m.upstreamFetchDuration.WithLabelValues(game, source, result).Observe(d.Seconds())
}

// ObserveUpstreamRefresh records one attempt to refresh an upstream token.
func (m *Metrics) ObserveUpstreamRefresh(result string) {
	if m == nil {
		return
	}
	m.upstreamRefresh.WithLabelValues(result).Inc()
}

// ObserveCircuitTransition records a circuit breaker entering a state.
//
// It is the method httpclient's CircuitMetrics interface is satisfied by, so the
// state names travel in from that package rather than being constants here — same
// reason as ObserveVaultOperation. What this signal adds over the data plane's own
// counters is the shedding: once a breaker is open the requests it refuses never
// reach the network, so they show up nowhere else.
func (m *Metrics) ObserveCircuitTransition(state string) {
	if m == nil {
		return
	}
	m.circuitTransitions.WithLabelValues(state).Inc()
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
