package httpclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The default transport keeps two idle connections per host. A proxy fronting a
// handful of sources must not, or it redials on nearly every request.
func TestNewOutboundClientPoolsConnections(t *testing.T) {
	c := NewOutboundClient(OutboundConfig{})
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport = %T, want *http.Transport", c.Transport)
	}
	if tr.MaxIdleConnsPerHost <= 2 {
		t.Fatalf("MaxIdleConnsPerHost = %d, want more than the standard library's 2", tr.MaxIdleConnsPerHost)
	}
	if tr.MaxIdleConns <= 0 || tr.IdleConnTimeout <= 0 || tr.ResponseHeaderTimeout <= 0 {
		t.Fatalf("transport not fully configured: %+v", tr)
	}
	if c.Timeout <= 0 {
		t.Fatal("no overall request timeout")
	}
}

func TestNewTransportFillsDefaults(t *testing.T) {
	tr := NewTransport(TransportConfig{MaxIdleConnsPerHost: 7})
	if tr.MaxIdleConnsPerHost != 7 {
		t.Fatalf("MaxIdleConnsPerHost = %d, want the configured 7", tr.MaxIdleConnsPerHost)
	}
	def := DefaultTransportConfig()
	if tr.MaxIdleConns != def.MaxIdleConns || tr.DialContext == nil {
		t.Fatalf("zero fields were not defaulted: %+v", tr)
	}
}

func TestNewOutboundClientWorks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	c := NewOutboundClient(OutboundConfig{MaxConcurrent: 4})
	resp, err := c.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

// The bulkhead is the whole point: eight callers against a cap of two must never
// exceed two requests in flight.
func TestBulkheadCapsConcurrency(t *testing.T) {
	var inFlight, peak int32
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := atomic.AddInt32(&inFlight, 1)
		for {
			p := atomic.LoadInt32(&peak)
			if n <= p || atomic.CompareAndSwapInt32(&peak, p, n) {
				break
			}
		}
		<-release
		atomic.AddInt32(&inFlight, -1)
	}))
	defer srv.Close()

	client := &http.Client{Transport: Bulkhead(srv.Client().Transport, 2)}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := client.Get(srv.URL)
			if err == nil {
				_ = resp.Body.Close()
			}
		}()
	}

	// Let the four requests that can proceed reach the handler, then confirm the
	// cap held before releasing everyone.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && atomic.LoadInt32(&inFlight) < 2 {
		time.Sleep(time.Millisecond)
	}
	if got := atomic.LoadInt32(&inFlight); got > 2 {
		t.Fatalf("%d requests in flight, want at most 2", got)
	}
	close(release)
	wg.Wait()
	if got := atomic.LoadInt32(&peak); got > 2 {
		t.Fatalf("peak concurrency = %d, want at most 2", got)
	}
}

// A request that cannot get a slot must give up when its context is cancelled,
// not wait forever. A deterministic version: hold the only slot from a handler,
// then try with an already-cancelled context.
func TestBulkheadHonoursContext(t *testing.T) {
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		entered <- struct{}{}
		<-release
	}))
	defer srv.Close()

	rt := Bulkhead(srv.Client().Transport, 1)

	// Occupy the single slot.
	go func() {
		req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
		resp, err := rt.RoundTrip(req)
		if err == nil {
			_ = resp.Body.Close()
		}
	}()
	<-entered // the slot is held: the handler is running

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	if _, err := rt.RoundTrip(req); err == nil {
		t.Fatal("a cancelled request took a bulkhead slot instead of returning an error")
	}
	close(release)
}

// A non-positive cap disables the bulkhead, and the wrapper is not inserted at
// all rather than being a pass-through object.
func TestBulkheadDisabledWhenUnlimited(t *testing.T) {
	base := http.DefaultTransport
	if got := Bulkhead(base, 0); got != base {
		t.Fatalf("Bulkhead(_, 0) = %T, want the original transport", got)
	}
	if got := Bulkhead(base, -1); got != base {
		t.Fatalf("Bulkhead(_, -1) = %T, want the original transport", got)
	}
}

// The slot must cover the whole transfer, not merely the wait for headers. If it
// were released when RoundTrip returned, a caller reading a multi-megabyte body
// would be outside the cap — which is exactly the load the cap exists for.
func TestBulkheadHoldsSlotUntilBodyClosed(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Send the headers at once, then keep the body open, so the caller's
		// RoundTrip returns while the transfer is still in progress.
		_, _ = w.Write([]byte("x"))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		<-release
	}))
	defer srv.Close()

	rt := Bulkhead(srv.Client().Transport, 1)
	newReq := func(ctx context.Context) *http.Request {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
		if err != nil {
			t.Fatal(err)
		}
		return req
	}

	resp, err := rt.RoundTrip(newReq(context.Background()))
	if err != nil {
		t.Fatal(err)
	}

	// Headers are in and RoundTrip has returned, but the body is open. The slot
	// is still taken, so a second request with a dead context cannot get in.
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := rt.RoundTrip(newReq(cancelled)); err == nil {
		t.Fatal("the slot was free while a response body was still open")
	}

	if err := resp.Body.Close(); err != nil {
		t.Fatalf("close body: %v", err)
	}
	// Double close must not release the slot twice and corrupt the count.
	_ = resp.Body.Close()

	second, err := rt.RoundTrip(newReq(context.Background()))
	if err != nil {
		t.Fatalf("the slot was not returned when the body was closed: %v", err)
	}
	close(release)
	_ = second.Body.Close()
}
