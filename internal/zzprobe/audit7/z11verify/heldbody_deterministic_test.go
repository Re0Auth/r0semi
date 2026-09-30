//go:build audit7

// Z11-2 verification: the byte reservation is released BEFORE the response body is
// written, so the budget bounds the READ phase and not the held-body phase.
//
// Config.MaxBufferedBytes is documented as the joint budget for upstream bodies
// held in memory at once (internal/federation/service.go), but rawFetch and
// fetchResource released their reservation when they returned — and the body is
// written later, in internal/httpapi/federation_routes.go's handler. A handler
// parked in w.Write therefore held a whole 4 MiB slice that the budget reported as
// free.
//
// This probe is DETERMINISTIC and platform-independent: it drives the real httpapi
// handler with a ResponseWriter whose Write parks, so the handler is provably
// inside `w.Write(result.Body)` holding the body. It deliberately does not use a
// socket-slow client, because whether a socket write blocks is a property of the
// host's buffers (heldbody_live_test.go measures 48/48 handlers returning on a
// Windows host, which is why that probe is inconclusive there).
package zzprobe_z11verify

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// blockingResponseWriter parks inside Write after recording what was handed to it.
// The "entered" signal is closed from inside Write, so "the handler is inside
// Write" is an observed fact rather than a sleep.
type blockingResponseWriter struct {
	header http.Header

	entered chan struct{}
	release chan struct{}
	enter   sync.Once

	mu      sync.Mutex
	status  int
	written int
}

func newBlockingResponseWriter() *blockingResponseWriter {
	return &blockingResponseWriter{
		header:  make(http.Header),
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (w *blockingResponseWriter) Header() http.Header { return w.header }

func (w *blockingResponseWriter) WriteHeader(code int) {
	w.mu.Lock()
	w.status = code
	w.mu.Unlock()
}

func (w *blockingResponseWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	w.written += len(p)
	w.mu.Unlock()
	w.enter.Do(func() { close(w.entered) })
	<-w.release
	return len(p), nil
}

// unblock lets the parked Write return.
func (w *blockingResponseWriter) unblock() { close(w.release) }

func (w *blockingResponseWriter) state() (status, written int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.status, w.written
}

// TestZ11WAWriteWindowKeepsItsReservation is the deterministic reproduction. It
// parks the real raw-proxy handler inside Write, asserts it holds the whole body
// there, and then asks for a second full-cap read: that read must be shed (503)
// because the first reservation has not been returned. Before the fix the second
// read was admitted (200), which is the RED this probe was written to show.
func TestZ11WAWriteWindowKeepsItsReservation(t *testing.T) {
	const budget = zzMaxBody + 1

	// The stall channel is never closed: this probe only reads /native/big.
	up := zzUpstream(t, make(chan struct{}), new(int64))
	srv, token := dataAPI(t, dataConfig{Upstream: up.URL, MaxBufferedBytes: budget})
	handler := srv.Config.Handler
	path := "/v1/games/" + zzGame + "/sources/src/raw/big"

	bw := newBlockingResponseWriter()
	done := make(chan struct{})
	go func() {
		defer close(done)
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		handler.ServeHTTP(bw, req)
	}()

	select {
	case <-bw.entered:
	case <-time.After(10 * time.Second):
		t.Fatalf("the raw handler never entered Write; the fixture cannot park it")
	}
	status, written := bw.state()
	if status != http.StatusOK || written < zzMaxBody {
		t.Fatalf("the handler is inside Write with status=%d and %d bytes, want 200 and the whole %d-byte body",
			status, written, zzMaxBody)
	}
	select {
	case <-done:
		t.Fatalf("the handler returned while Write was parked, so the writer is not blocking")
	default:
	}
	t.Logf("the real handler is parked inside Write, holding %d bytes (budget %d)", written, budget)

	// The defect: is that held body counted? A second full-cap read must not fit.
	code, _, _ := getAuth(t, srv.Client(), srv.URL+path, token)
	t.Logf("with one handler parked inside Write and a %d-byte budget, a second full-cap read = %d", budget, code)
	if code != http.StatusServiceUnavailable {
		t.Errorf("the second full-cap read was ADMITTED (%d): the reservation is released when rawFetch returns, "+
			"before the body is written, so the budget bounds the read phase and not the held body. "+
			"With max_in_flight readers each parked in w.Write the live bodies are unbounded by MaxBufferedBytes.", code)
	}

	// Control: completing the write returns the reservation and the same read is
	// served, so the 503 above is attributable to the held body and not to the
	// budget being permanently spent.
	bw.unblock()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatalf("the parked handler never returned after the writer was unblocked")
	}
	code, _, body := getAuth(t, srv.Client(), srv.URL+path, token)
	t.Logf("after the parked write completed: the same read = %d (%d bytes)", code, len(body))
	if code != http.StatusOK {
		t.Errorf("after the write completed the read = %d, want 200: the shed above was not the held reservation", code)
	}
}
