package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// readinessTimeout bounds the dependency check, so a hung database cannot hang
// the probe. A readiness endpoint that never answers is indistinguishable from a
// dead process to an orchestrator — and worse, it holds the probe connection
// open while the dependency it is waiting on is already the problem.
const readinessTimeout = 2 * time.Second

// readinessTTL is how long one readiness result is reused.
//
// It is the price of the probe's exemption, and it is deliberately small: probes
// skip the rate limiter and the in-flight cap (see isProbe for why that must not
// change), so they are the one path an anonymous caller can drive without limit —
// and this endpoint's check is a database round trip that takes a pooled
// connection. Without a cache, N requests are N pool acquisitions, and the
// endpoint that exists to report on the pool is the one that can exhaust it.
// With it, the round trips are bounded at one per TTL per replica no matter the
// request rate.
//
// One second is far below any orchestrator's probe period (the shipped manifest
// asks every 5s), so a real kubelet sees every answer freshly checked; what the
// TTL costs is that a probe may report ready for up to a second after the
// dependency went away, which is inside the same failureThreshold window every
// probe already has.
const readinessTTL = time.Second

// readinessColdStartWait bounds how long a caller that races the process's
// FIRST-ever check waits for that check before it is told "checking".
//
// Before any verdict exists there is nothing to answer from: reporting ready
// would be a claim about a dependency nobody has reached (the cold-start
// fail-open), and asserting "not ready" the instant a check that a same-host
// ping finishes in microseconds is running would fail a probe on a race rather
// than on the dependency. The wait is long enough to cover a dependency that
// answers within the readiness budget but short enough to fail closed well
// inside the orchestrator's period, and it applies ONLY while the verdict is
// unknown; once one exists, a refresh never makes a caller wait.
const readinessColdStartWait = 500 * time.Millisecond

// readinessState is the cache's explicit verdict. "unknown" is a first-class
// value: before the first check returns there is no verdict, and an unknown
// verdict must never be rendered as ready.
type readinessState uint8

const (
	// readinessUnknown means no check has produced a verdict yet.
	readinessUnknown readinessState = iota
	// readinessReady means the last completed check found every dependency.
	readinessReady
	// readinessNotReady means the last completed check found a dependency down.
	readinessNotReady
)

// readinessCache holds the last readiness result for readinessTTL, and lets AT
// MOST ONE check run at a time.
//
// A request that finds a check already running is answered from the cached result
// instead of queueing behind it: queueing would rebuild the amplification this
// exists to remove (each waiter still holds a connection and a request), and
// answering from a result at most one second old is what a probe asked for
// anyway. It never fails because of load — that is the ruling this endpoint's
// exemption rests on, and a 503 caused by someone else's traffic would pull a
// healthy instance out of rotation.
//
// The cache is process-wide, so its verdict is a statement about the
// DEPENDENCIES, never about the caller that happened to trigger the check.
type readinessCache struct {
	mu        sync.Mutex
	checkedAt time.Time
	err       error
	state     readinessState
	running   bool
	// settled is closed when the in-flight check finishes, so a caller that
	// arrives during the first-ever check can wait for that one result instead
	// of either queueing behind a fresh check or being told an unverified
	// "ready".
	settled chan struct{}
}

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
//
// The check itself runs at most once per readinessTTL (see readinessCache), and a
// caller with a verdict to answer from never waits for another caller's check.
// What it must never do is answer "not ready" because the service is busy: that is
// the ruling in docs/operations.md, and the reason probes are exempt from the
// limiter and the in-flight cap in the first place.
func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	// A draining instance is not ready, whatever its dependencies say: readiness is
	// "may new traffic come here", and during shutdown the answer is no. This is
	// what lets the orchestrator remove the endpoint before the listener closes,
	// so new connections are not routed to a socket that is about to stop
	// accepting (the connection-refused window of a rolling update).
	if s.draining.Load() {
		writeProbe(w, http.StatusServiceUnavailable, "draining")
		return
	}
	if s.ready == nil {
		writeProbe(w, http.StatusOK, "ok")
		return
	}
	switch state, err := s.readiness.check(r.Context(), s.ready); state {
	case readinessReady:
		writeProbe(w, http.StatusOK, "ok")
	case readinessUnknown:
		// No verdict exists yet (a check is still running and none has ever
		// completed). Fail closed: "checking" is not "not ready" — the body
		// says which — but neither is it the unverified 200 the cold start
		// used to report.
		writeProbe(w, http.StatusServiceUnavailable, "checking")
	default:
		// The reason goes to the log, not the body: this endpoint is reachable
		// without credentials, and a dependency error can name an internal host
		// or topology an anonymous caller has no business learning.
		slog.Debug("readiness check failed", "err", err)
		writeProbe(w, http.StatusServiceUnavailable, "not ready")
	}
}

// check returns the readiness verdict, running the probe only when the cached one
// is missing or older than readinessTTL.
//
// It holds the lock only around the state, never around the probe call: a slow
// dependency must not serialize the probes that arrive while it is slow, and those
// probes are answered from the previous verdict.
//
// The probe runs on a context derived from context.WithoutCancel(ctx): this cache
// is shared by every caller, so a caller hanging up must not be able to end the
// check and have its cancellation recorded as the process's readiness. The
// readinessTimeout still bounds a genuinely hung dependency. A cancellation-class
// error is treated as "no verdict" rather than a 503, for the same reason.
func (c *readinessCache) check(ctx context.Context, probe ReadinessProbe) (readinessState, error) {
	c.mu.Lock()
	fresh := c.state != readinessUnknown && time.Since(c.checkedAt) < readinessTTL
	if fresh || c.running {
		state, err, settled := c.state, c.err, c.settled
		c.mu.Unlock()
		if state != readinessUnknown || settled == nil {
			return state, err
		}
		// Cold start: a check is running and the process has never produced a
		// verdict. There is nothing honest to answer from, so wait a short,
		// bounded time for that one check — a same-host dependency resolves the
		// race — and then fail closed if it has still produced nothing.
		select {
		case <-settled:
		case <-time.After(readinessColdStartWait):
		case <-ctx.Done():
		}
		c.mu.Lock()
		state, err = c.state, c.err
		c.mu.Unlock()
		return state, err
	}
	c.running = true
	c.settled = make(chan struct{})
	settled := c.settled
	c.mu.Unlock()

	probeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), readinessTimeout)
	defer cancel()
	err := probe(probeCtx)

	c.mu.Lock()
	c.running = false
	close(settled)
	if errors.Is(err, context.Canceled) {
		// Not a statement about the dependency, so it must not replace the last
		// one. The verdict stays whatever it was — ready, not-ready, or still
		// unknown — and the caller sees that.
		state, prevErr := c.state, c.err
		c.mu.Unlock()
		return state, prevErr
	}
	c.err = err
	c.checkedAt = time.Now()
	if err == nil {
		c.state = readinessReady
	} else {
		c.state = readinessNotReady
	}
	state, recordedErr := c.state, c.err
	c.mu.Unlock()
	return state, recordedErr
}

// writeProbe writes a probe response. Probes are plain text on purpose: they are
// not API, and an orchestrator reads the status code rather than the body. The
// body exists so a human running curl gets an answer instead of an empty reply.
//
// no-store, because a cached readiness result is worse than no probe at all: a
// proxy that remembers "ready" would keep routing to an instance that has since
// lost its database. That is a statement about the CLIENT's cache; the server's
// own one-second reuse above is a different thing, bounded and refreshed by this
// process.
func writeProbe(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body + "\n"))
}

// isProbe reports whether a path is an operational probe.
//
// Probes are exempt from the limiter AND from the in-flight cap. A saturated
// bucket must not be able to fail a liveness probe and get a healthy process
// restarted, nor a readiness probe and pull a serving instance out of rotation —
// which is exactly what would happen under the load that made the bucket full in
// the first place.
//
// The exemption is safe only because the exempted work is cheap, so it must stay
// cheap: /healthz checks nothing, and /readyz answers from a cached result that is
// refreshed at most once per readinessTTL. This is the ruling recorded in
// docs/operations.md — "probes answer from a bounded amount of work, and never a
// 503 because of load".
func isProbe(path string) bool {
	return path == "/healthz" || path == "/readyz"
}
