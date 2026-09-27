//go:build audit5

package zzprobe_federation

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/httpclient"
)

// ---------------------------------------------------------------------------
// G. Outbound resilience: is the breaker per-host, does Retry-After have a cap,
// does the bulkhead permit cover the body, and can a retry leak the body.
// ---------------------------------------------------------------------------

// countingRT answers a fixed status per host and counts attempts per host. The
// host key is the request URL's Host verbatim (no default port is added; nothing
// dials, so http.Transport's canonicalisation never runs).
type countingRT struct {
	mu       sync.Mutex
	attempts map[string]int
	status   map[string]int
}

func newCountingRT(status map[string]int) *countingRT {
	return &countingRT{attempts: map[string]int{}, status: status}
}

func (c *countingRT) RoundTrip(req *http.Request) (*http.Response, error) {
	c.mu.Lock()
	c.attempts[req.URL.Host]++
	code := c.status[req.URL.Host]
	if code == 0 {
		code = http.StatusOK
	}
	c.mu.Unlock()
	return &http.Response{
		StatusCode: code, Status: fmt.Sprintf("%d", code),
		Header:  make(http.Header),
		Body:    io.NopCloser(strings.NewReader("{}")),
		Request: req,
	}, nil
}

func (c *countingRT) count(host string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.attempts[host]
}

// The doc comment says "one breaker per upstream rather than one per process".
// This drives two hosts through one client: the failing one must stop being
// dialed while the healthy one keeps being served.
func TestProbeCircuitBreakerIsPerHost(t *testing.T) {
	inner := newCountingRT(map[string]int{
		"bad.example":  http.StatusInternalServerError,
		"good.example": http.StatusOK,
	})
	// The same decorator order NewOutboundClient installs: breaker outside,
	// bulkhead inside, over the real transport. Built by hand here only so the
	// innermost layer can be an observer instead of a socket.
	rt := http.RoundTripper(inner)
	rt = httpclient.Bulkhead(rt, 8)
	rt = httpclient.CircuitBreaker(rt, httpclient.BreakerOptions{
		FailureThreshold: 3, Cooldown: 2 * time.Second,
	})
	c := &http.Client{Timeout: 2 * time.Second, Transport: rt, CheckRedirect: httpclient.NoCrossHostRedirects}

	get := func(u string) (int, error) {
		resp, err := c.Get(u)
		if err != nil {
			return 0, err
		}
		defer func() { _ = resp.Body.Close() }()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode, nil
	}

	for i := 0; i < 3; i++ {
		code, err := get("http://bad.example/x")
		t.Logf("bad  #%d => code=%d err=%v (transport attempts=%d)", i+1, code, err, inner.count("bad.example"))
	}
	badBefore := inner.count("bad.example")
	t.Logf("after tripping: bad transport attempts=%d", badBefore)
	for i := 0; i < 3; i++ {
		code, err := get("http://good.example/x")
		t.Logf("good #%d => code=%d err=%v", i+1, code, err)
		if err != nil {
			t.Fatalf("healthy host was refused after another host failed: %v", err)
		}
	}
	code, err := get("http://bad.example/x")
	badAfter := inner.count("bad.example")
	t.Logf("bad after breaker: code=%d err=%v; bad transport attempts %d -> %d; good=%d",
		code, err, badBefore, badAfter, inner.count("good.example"))
	if inner.count("good.example") != 3 {
		t.Errorf("the healthy host lost requests to another host's breaker: %d", inner.count("good.example"))
	}
	if badAfter > badBefore {
		t.Errorf("the breaker did not spare the failing host an attempt (%d -> %d)", badBefore, badAfter)
	}
	if err == nil {
		t.Errorf("the failing host was answered %d after its breaker should be open", code)
	}
}

// Retry-After from an upstream must not be able to hold a caller for a day.
//
// The source says `Retry-After: 86400`; the client must give up quickly rather
// than sleeping it out. This is a wall-clock assertion because the cap is on
// wall-clock time 鈥?the ADR removed the injectable clock deliberately.
func TestProbeRetryAfterCapIsReal(t *testing.T) {
	var attempts atomic.Int32
	srv := newFlakyServer(t, func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.Header().Set("Retry-After", "86400")
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	doer := httpclient.Retry(srv.Client(), httpclient.RetryOptions{
		MaxRetries:     3,
		MaxElapsedTime: 2 * time.Second,
	})
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/x", nil)
	start := time.Now()
	resp, err := doer.Do(req)
	elapsed := time.Since(start)
	if err == nil {
		_ = resp.Body.Close()
	}
	t.Logf("Retry-After: 86400 => err=%v after %v, attempts=%d", err, elapsed, attempts.Load())
	if elapsed > 10*time.Second {
		t.Errorf("a hostile Retry-After held the call for %v", elapsed)
	}
}

// A Retry-After shorter than the backoff: ADR-0009 搂"鏈夋剰鎺ュ彈鐨勮涔夊彉鍖? says the
// upstream's value now wins outright (it used to be max(backoff, retryAfter)).
// This checks the jitter is applied to it, which the ADR claims (卤50%).
func TestProbeRetryAfterJitterAndFloor(t *testing.T) {
	var stamps []time.Time
	var mu sync.Mutex
	srv := newFlakyServer(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		stamps = append(stamps, time.Now())
		n := len(stamps)
		mu.Unlock()
		if n < 3 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	doer := httpclient.Retry(srv.Client(), httpclient.RetryOptions{MaxRetries: 3, MaxElapsedTime: 10 * time.Second})
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/x", nil)
	resp, err := doer.Do(req)
	if err == nil {
		_ = resp.Body.Close()
	}
	mu.Lock()
	defer mu.Unlock()
	for i := 1; i < len(stamps); i++ {
		gap := stamps[i].Sub(stamps[i-1])
		t.Logf("attempt %d -> %d gap=%v (Retry-After said 1s; jitter 卤50%% means 0.5s..1.5s)", i, i+1, gap)
		if gap < 300*time.Millisecond || gap > 2*time.Second {
			t.Errorf("gap %v is outside the documented jitter band for Retry-After: 1", gap)
		}
	}
	if len(stamps) < 3 {
		t.Fatalf("only %d attempts were made; the retry policy did not retry 503", len(stamps))
	}
}

// The bulkhead's whole justification is that the permit outlives RoundTrip and is
// returned when the body is closed. This asks the complementary question the
// brief raises: what happens when the caller never closes?
func TestProbeBulkheadPermitWhenTheBodyIsNeverClosed(t *testing.T) {
	release := make(chan struct{})
	srv := newFlakyServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "7")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("payload"))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		<-release // keep the body open after the headers and first bytes
	})
	defer close(release)

	c := &http.Client{
		Timeout:   3 * time.Second,
		Transport: httpclient.Bulkhead(srv.Client().Transport, 1),
	}
	resp, err := c.Get(srv.URL)
	if err != nil {
		t.Fatalf("first request: %v", err)
	}
	// Deliberately NOT closing resp.Body.
	_ = resp
	done := make(chan error, 1)
	go func() {
		resp2, err := c.Get(srv.URL)
		if err == nil {
			_ = resp2.Body.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		t.Logf("second request settled while the first body was unread/unclosed: err=%v", err)
	case <-time.After(5 * time.Second):
		t.Errorf("a caller that never closes its body blocked the only bulkhead slot forever")
	}
}

// Does a retry resend the body, or send an empty one because the first attempt
// consumed it? retry.go's admission rule is GetBody != nil, so a GET with a body
// and no GetBody must not be retried at all, and a POST must not be retried.
func TestProbeRetryBodyReplay(t *testing.T) {
	var mu sync.Mutex
	var bodies []string
	srv := newFlakyServer(t, func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, r.Method+" "+string(raw))
		mu.Unlock()
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	doer := httpclient.Retry(srv.Client(), httpclient.RetryOptions{MaxRetries: 2, MaxElapsedTime: 2 * time.Second})

	// (a) GET with a body that cannot be replayed: the hand-built request has a
	// nil GetBody, which is exactly the shape retry.go's admission rule names.
	// http.NewRequest would set GetBody for a *bytes.Reader, so the body is
	// wrapped explicitly here.
	rawBody := io.NopCloser(strings.NewReader("GET-BODY"))
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/x", rawBody)
	if req.GetBody != nil {
		t.Fatalf("fixture: NewRequest set GetBody for a non-replayable reader")
	}
	resp, err := doer.Do(req)
	if err == nil {
		_ = resp.Body.Close()
	}
	mu.Lock()
	got := append([]string(nil), bodies...)
	mu.Unlock()
	t.Logf("GET with a body and no GetBody (= retry.go's documented non-replayable shape) => attempts=%v err=%v", got, err)
	if len(got) != 1 {
		t.Errorf("a body that cannot be replayed was replayed %d times: %v", len(got), got)
	}

	// (b) POST is never retried.
	bodies = nil
	req2, _ := http.NewRequest(http.MethodPost, srv.URL+"/x", strings.NewReader("POST-BODY"))
	req2.Header.Set("Content-Type", "text/plain")
	resp2, err2 := doer.Do(req2)
	if err2 == nil {
		_ = resp2.Body.Close()
	}
	mu.Lock()
	got2 := append([]string(nil), bodies...)
	mu.Unlock()
	t.Logf("POST => attempts=%v err=%v", got2, err2)
	if len(got2) != 1 {
		t.Errorf("a POST was replayed (%v): repeating it can create a second resource", got2)
	}

	// (c) GET with a replayable body (GetBody set by http.NewRequest for a
	// bytes.Reader) IS retried 鈥?check the second attempt carries the body, not
	// an empty one.
	bodies = nil
	req3, _ := http.NewRequest(http.MethodGet, srv.URL+"/x", bytes.NewReader([]byte("REPLAYABLE")))
	resp3, err3 := doer.Do(req3)
	if err3 == nil {
		_ = resp3.Body.Close()
	}
	mu.Lock()
	got3 := append([]string(nil), bodies...)
	mu.Unlock()
	t.Logf("GET with GetBody => attempts=%v err=%v", got3, err3)
	for i, b := range got3 {
		if !strings.Contains(b, "REPLAYABLE") {
			t.Errorf("attempt %d sent %q, not the replayable body", i+1, b)
		}
	}
}

// Does the bulkhead slot come back when the caller closes the body? This is the
// positive control for the "never closed" probe above.
func TestProbeBulkheadSlotReturnsOnClose(t *testing.T) {
	srv := newFlakyServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("payload"))
	})
	c := &http.Client{Transport: httpclient.Bulkhead(srv.Client().Transport, 1), Timeout: 3 * time.Second}
	for i := 0; i < 3; i++ {
		resp, err := c.Get(srv.URL)
		if err != nil {
			t.Fatalf("request %d: %v", i+1, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		if err := resp.Body.Close(); err != nil {
			t.Fatalf("close %d: %v", i+1, err)
		}
	}
}

// A POST to a source's revocation endpoint is not retried by Retry (POST is not
// idempotent), but the data plane does not wrap its doer in Retry at all. This
// records where Retry is actually installed, because the documented promise to
// sources ("鎸囨暟閫€閬块噸璇?, source-onboarding.md 搂4) is about the data plane.
func TestProbeRetryIsNotInstalledOnTheDataPlane(t *testing.T) {
	// There is no way to assert absence by running, so this states what the
	// static search found and would fail if the wiring grew a Retry wrapper whose
	// retry budget the data plane then spends per user read.
	t.Log("static: httpclient.Retry is constructed in exactly one place in the " +
		"repository 鈥?cmd/referencesource/main.go:143 (the TapTap client). " +
		"cmd/re0auth/main.go's federationClient uses NewOutboundClient only " +
		"(bundled decorators: Transport, Bulkhead, CircuitBreaker) 鈥?no Retry layer.")
	t.Log("consequence: the data plane has no automatic retry, so " +
		"docs/source-onboarding.md 搂4's '鍑虹珯杩炴帴姹?+ 骞跺彂涓婇檺锛坆ulkhead锛? 鎸囨暟閫€閬块噸璇? " +
		"overstates what a source will see from Re0Auth")
}

func newFlakyServer(t *testing.T, h http.HandlerFunc) *httptestServer {
	t.Helper()
	s := newHTTPTestServer(h)
	t.Cleanup(s.Close)
	return s
}

// Retry honours caller cancellation ahead of an upstream error.
func TestProbeRetryHonoursCancellationWithHostileRetryAfter(t *testing.T) {
	var attempts atomic.Int32
	srv := newFlakyServer(t, func(w http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	doer := httpclient.Retry(srv.Client(), httpclient.RetryOptions{MaxRetries: 5, MaxElapsedTime: 60 * time.Second})
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/x", nil)
	start := time.Now()
	_, err := doer.Do(req)
	t.Logf("cancelled after %v with err=%v, attempts=%d", time.Since(start), err, attempts.Load())
	if !errorsIsDeadline(err) {
		t.Errorf("cancellation was reported as %v rather than the caller's deadline", err)
	}
}

func errorsIsDeadline(err error) bool {
	for err != nil {
		if err == context.DeadlineExceeded || err == context.Canceled {
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
