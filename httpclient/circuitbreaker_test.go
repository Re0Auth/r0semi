package httpclient

import (
	"context"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// recordingCircuitMetrics captures the transitions a breaker reports, in order.
type recordingCircuitMetrics struct {
	mu     sync.Mutex
	states []string
}

func (r *recordingCircuitMetrics) ObserveCircuitTransition(state string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.states = append(r.states, state)
}

func (r *recordingCircuitMetrics) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.states...)
}

// The transitions are the only signal this client emits, and the only way to see a
// breaker that is open: the requests it refuses never reach the transport, so
// nothing on the network side records them. The whole cycle is asserted — open,
// half open, closed — because a breaker stuck in half-open is a source that never
// recovers, and a listener that only reported "open" would not show it.
func TestCircuitBreakerReportsStateTransitions(t *testing.T) {
	ft := &fakeTransport{err: errors.New("dial tcp: connection refused")}
	rec := &recordingCircuitMetrics{}
	// A real, short cooldown rather than an injected clock, for the reason
	// TestCircuitBreakerOpensThenRecovers gives: the breaker's clock is the
	// library's, and what recovery depends on is that the window really elapses.
	const cooldown = 50 * time.Millisecond
	cb := CircuitBreaker(ft, BreakerOptions{
		FailureThreshold:  2,
		Cooldown:          cooldown,
		HalfOpenSuccesses: 1,
		Metrics:           rec,
	})
	req := breakerReq(t)

	for i := 0; i < 2; i++ {
		if _, err := cb.RoundTrip(req); err == nil {
			t.Fatalf("attempt %d succeeded, want the transport's failure", i)
		}
	}
	if got := rec.snapshot(); !slices.Equal(got, []string{CircuitOpen}) {
		t.Fatalf("after tripping, transitions = %v, want [%s]", got, CircuitOpen)
	}

	// Past the cooldown the breaker admits a trial; a success closes it.
	ft.set(nil, http.StatusOK)
	time.Sleep(cooldown + 30*time.Millisecond)
	if _, err := cb.RoundTrip(req); err != nil {
		t.Fatalf("the trial request was refused: %v", err)
	}
	want := []string{CircuitOpen, CircuitHalfOpen, CircuitClosed}
	if got := rec.snapshot(); !slices.Equal(got, want) {
		t.Fatalf("transitions = %v, want %v", got, want)
	}
}

// fakeTransport stands in for the network: it records how many round trips
// reached it and answers with a fixed outcome, so a test can tell a short-
// circuited request (no call) from a real one.
type fakeTransport struct {
	mu     sync.Mutex
	calls  int
	err    error
	status int
}

func (f *fakeTransport) RoundTrip(*http.Request) (*http.Response, error) {
	f.mu.Lock()
	f.calls++
	err, status := f.err, f.status
	f.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if status == 0 {
		status = http.StatusOK
	}
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("")),
	}, nil
}

func (f *fakeTransport) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fakeTransport) set(err error, status int) {
	f.mu.Lock()
	f.err, f.status = err, status
	f.mu.Unlock()
}

func breakerReq(t *testing.T) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "https://source.example/resource", nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

// A host that keeps failing is skipped rather than charged a full timeout each
// time, and it recovers on its own once the cooldown has passed.
func TestCircuitBreakerOpensThenRecovers(t *testing.T) {
	ft := &fakeTransport{err: errors.New("dial tcp: connection refused")}
	// The cooldown is a real, short window rather than an injected clock: the
	// breaker's clock is the library's, and what the recovery depends on is that
	// the window really elapses. The wait after tripping is explicit.
	const cooldown = 50 * time.Millisecond
	cb := CircuitBreaker(ft, BreakerOptions{
		FailureThreshold:  3,
		Cooldown:          cooldown,
		HalfOpenSuccesses: 2,
	})
	req := breakerReq(t)

	for i := 0; i < 3; i++ {
		if _, err := cb.RoundTrip(req); err == nil {
			t.Fatalf("attempt %d: want a failure", i)
		}
	}
	reached := ft.callCount()
	if _, err := cb.RoundTrip(req); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("err = %v, want ErrCircuitOpen", err)
	}
	if ft.callCount() != reached {
		t.Fatal("an open breaker still called the transport")
	}

	// After the cooldown, trials are admitted and successes close the breaker.
	ft.set(nil, http.StatusOK)
	time.Sleep(cooldown + 20*time.Millisecond)
	for i := 0; i < 2; i++ {
		if _, err := cb.RoundTrip(req); err != nil {
			t.Fatalf("trial %d = %v, want success", i, err)
		}
	}
	// Closed again: ordinary requests flow.
	for i := 0; i < 5; i++ {
		resp, err := cb.RoundTrip(req)
		if err != nil {
			t.Fatalf("after recovery, request %d = %v", i, err)
		}
		resp.Body.Close()
	}
}

// A 4xx is the request's problem, not the upstream's health, so it does not trip
// the breaker; a 5xx does.
func TestCircuitBreakerCounts5xxNot4xx(t *testing.T) {
	ft := &fakeTransport{status: http.StatusNotFound}
	cb := CircuitBreaker(ft, BreakerOptions{FailureThreshold: 2})
	req := breakerReq(t)

	for i := 0; i < 5; i++ {
		resp, err := cb.RoundTrip(req)
		if err != nil {
			t.Fatalf("4xx = %v, want a response", err)
		}
		resp.Body.Close()
	}

	ft.set(nil, http.StatusInternalServerError)
	for i := 0; i < 2; i++ {
		resp, err := cb.RoundTrip(req)
		if err != nil {
			t.Fatalf("5xx = %v, want a response", err)
		}
		resp.Body.Close()
	}
	if _, err := cb.RoundTrip(req); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("err = %v, want ErrCircuitOpen after two 5xx", err)
	}
}

// A caller who cancels is not the upstream failing, so the breaker must not open.
func TestCircuitBreakerIgnoresCallerCancellation(t *testing.T) {
	ft := &fakeTransport{err: context.Canceled}
	cb := CircuitBreaker(ft, BreakerOptions{FailureThreshold: 2})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := breakerReq(t).WithContext(ctx)

	for i := 0; i < 4; i++ {
		if _, err := cb.RoundTrip(req); err == nil {
			t.Fatal("want the transport error")
		}
	}
	if _, err := cb.RoundTrip(req); errors.Is(err, ErrCircuitOpen) {
		t.Fatal("a caller cancellation tripped the breaker")
	}
}
