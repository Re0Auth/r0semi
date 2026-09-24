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

// Metrics is the service's Prometheus instrumentation. It covers the four golden
// signals — traffic and errors (requests_total), latency
// (request_duration_seconds), and saturation (in_flight_requests) — plus the Go
// runtime and process collectors, which answer "is it running out of memory,
// goroutines or file descriptors".
type Metrics struct {
	registry *prometheus.Registry
	requests *prometheus.CounterVec
	duration *prometheus.HistogramVec
	inFlight *prometheus.GaugeVec
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
	}
	reg.MustRegister(m.requests, m.duration, m.inFlight)
	// The runtime and process collectors are what make /metrics useful during an
	// incident that is not a request: a goroutine leak, a GC cliff, an open
	// file-descriptor ceiling.
	reg.MustRegister(collectors.NewGoCollector())
	reg.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	return m
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

		m.requests.WithLabelValues(plane, r.Method, strconv.Itoa(rec.status)).Inc()
		m.duration.WithLabelValues(plane, r.Method).Observe(time.Since(start).Seconds())
	})
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
