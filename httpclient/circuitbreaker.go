package httpclient

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/failsafe-go/failsafe-go"
	"github.com/failsafe-go/failsafe-go/circuitbreaker"
)

// ErrCircuitOpen is returned when a host's breaker is open and the request was
// rejected without being attempted.
var ErrCircuitOpen = errors.New("httpclient: circuit breaker is open")

// BreakerOptions tunes a CircuitBreaker. A zero field takes its default.
type BreakerOptions struct {
	// FailureThreshold is how many consecutive qualifying failures trip the
	// breaker. Defaults to 5.
	FailureThreshold int
	// Cooldown is how long the breaker stays open before it admits trial
	// requests. Defaults to 30s.
	Cooldown time.Duration
	// HalfOpenSuccesses is how many consecutive trial successes close the
	// breaker. Defaults to 2.
	HalfOpenSuccesses int
}

const (
	defaultBreakerFailures  = 5
	defaultBreakerCooldown  = 30 * time.Second
	defaultBreakerHalfOpens = 2
)

// CircuitBreaker wraps next with a per-host circuit breaker.
//
// A host that keeps failing is skipped for a cooldown window instead of charging
// every request a full timeout: the data plane already has a bulkhead and
// per-request deadlines, and a source that is down would otherwise turn each user
// read into a 20-second wait. After the cooldown trial requests are admitted;
// the configured number of consecutive successes closes the breaker, and any
// failure trips it again.
//
// Only failures that say something about the upstream count: a transport error
// the caller did not cause, or a 5xx. A 4xx is the request's problem, and a
// caller-side cancellation is nobody's fault here, so neither is recorded.
//
// The state machine, the cooldown, the half-open probes and the recording are
// failsafe-go's circuitbreaker. What remains here is the per-host map — the
// library keys a breaker by its own instance, and this client needs one breaker
// per upstream rather than one per process — and the failure classification
// above, which is this service's rule rather than a general one.
//
// The map is keyed by URL host and kept for the process's life; the set of hosts
// is the deployment's configured sources, so it is bounded.
//
// docs/resilience-decision.md (ADR-0009) records why this is a library and what
// changed when it stopped being one.
func CircuitBreaker(next http.RoundTripper, opts BreakerOptions) http.RoundTripper {
	if opts.FailureThreshold <= 0 {
		opts.FailureThreshold = defaultBreakerFailures
	}
	if opts.Cooldown <= 0 {
		opts.Cooldown = defaultBreakerCooldown
	}
	if opts.HalfOpenSuccesses <= 0 {
		opts.HalfOpenSuccesses = defaultBreakerHalfOpens
	}
	return &breakerTransport{
		next:  next,
		opts:  opts,
		hosts: map[string]failsafe.Executor[guardedResponse]{},
	}
}

// breakerTransport holds one executor per upstream host. The executor bundles
// that host's breaker, so a request is judged against its own source and a
// request that is rejected never reaches the transport below.
type breakerTransport struct {
	next  http.RoundTripper
	opts  BreakerOptions
	mu    sync.Mutex
	hosts map[string]failsafe.Executor[guardedResponse]
}

func (b *breakerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	exec := b.executorFor(req.URL.Host)
	resp, err := exec.
		WithContext(req.Context()).
		Get(func() (*http.Response, error) { return b.next.RoundTrip(req) })
	// The library's sentinel is translated into this package's, so a caller keeps
	// one error to match on no matter which decorator rejected the request.
	if errors.Is(err, circuitbreaker.ErrOpen) {
		return nil, ErrCircuitOpen
	}
	return resp, err
}

// executorFor returns the host's executor, building it on first use.
func (b *breakerTransport) executorFor(host string) failsafe.Executor[guardedResponse] {
	b.mu.Lock()
	defer b.mu.Unlock()
	if exec, ok := b.hosts[host]; ok {
		return exec
	}
	breaker := circuitbreaker.NewBuilder[guardedResponse]().
		// HandleIf replaces the library's default "any error is a failure", so
		// a caller-side cancellation is not recorded against the host.
		HandleIf(breakerFailure).
		WithFailureThreshold(uint(b.opts.FailureThreshold)).
		WithSuccessThreshold(uint(b.opts.HalfOpenSuccesses)).
		WithDelay(b.opts.Cooldown).
		Build()
	exec := failsafe.With[guardedResponse](breaker)
	b.hosts[host] = exec
	return exec
}

// breakerFailure reports whether an attempt says something about the upstream's
// health. A transport error the caller did not cause, or a 5xx, does; anything
// else — a 4xx, or a cancellation — is the request's own business.
func breakerFailure(resp *http.Response, err error) bool {
	if err != nil {
		return !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded)
	}
	return resp != nil && resp.StatusCode >= http.StatusInternalServerError
}
