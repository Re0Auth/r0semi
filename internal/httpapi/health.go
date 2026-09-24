package httpapi

import (
	"context"
	"log/slog"
	"net/http"
	"time"
)

// readinessTimeout bounds the dependency check, so a hung database cannot hang
// the probe. A readiness endpoint that never answers is indistinguishable from a
// dead process to an orchestrator — and worse, it holds the probe connection
// open while the dependency it is waiting on is already the problem.
const readinessTimeout = 2 * time.Second

// ReadinessProbe reports whether the service can serve: a nil return means every
// dependency it needs is reachable. It is the readiness half of the health
// endpoints; liveness needs nothing but the process running.
type ReadinessProbe func(ctx context.Context) error

// handleHealth is the liveness probe. It answers as long as the process can
// serve a request, and deliberately checks nothing else: a liveness probe that
// fails when a dependency is down turns one outage into a restart loop, because
// the orchestrator restarts a process that was never the problem.
func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeProbe(w, http.StatusOK, "ok")
}

// handleReady is the readiness probe. It answers 200 only when every dependency
// the service needs to serve is usable, and 503 otherwise, so an orchestrator
// stops routing to an instance that cannot answer rather than one that is merely
// busy.
//
// Without a configured probe there is nothing to reach — the in-memory
// deployment — so it is always ready. That is an honest answer, not a shortcut:
// there is no dependency whose loss would make this instance unable to serve.
func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	if s.ready == nil {
		writeProbe(w, http.StatusOK, "ok")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), readinessTimeout)
	defer cancel()
	if err := s.ready(ctx); err != nil {
		// The reason goes to the log, not the body: this endpoint is reachable
		// without credentials, and a dependency error can name an internal host
		// or topology an anonymous caller has no business learning.
		slog.Debug("readiness check failed", "err", err)
		writeProbe(w, http.StatusServiceUnavailable, "not ready")
		return
	}
	writeProbe(w, http.StatusOK, "ok")
}

// writeProbe writes a probe response. Probes are plain text on purpose: they are
// not API, and an orchestrator reads the status code rather than the body. The
// body exists so a human running curl gets an answer instead of an empty reply.
//
// no-store, because a cached readiness result is worse than no probe at all: a
// proxy that remembers "ready" would keep routing to an instance that has since
// lost its database.
func writeProbe(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body + "\n"))
}

// isProbe reports whether a path is an operational probe.
//
// Probes are exempt from the limiter. A saturated bucket must not be able to
// fail a liveness probe and get a healthy process restarted, nor a readiness
// probe and pull a serving instance out of rotation — which is exactly what
// would happen under the load that made the bucket full in the first place.
func isProbe(path string) bool {
	return path == "/healthz" || path == "/readyz"
}
