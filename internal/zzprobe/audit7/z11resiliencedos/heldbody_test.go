//go:build audit7

// Z11-2: the upstream byte budget is released before the response body is written
// out, so it does not bound "in flight x body size".
//
// P0-3 ("在途请求数 × 响应体没有联合上限 → OOMKill") was answered with
// Config.MaxBufferedBytes: "the joint budget for upstream response bodies held in
// memory at once, across every in-flight read on BOTH data-plane paths"
// (internal/federation/service.go), and deploy/k8s/base/configmap.yaml states it
// is "what actually caps 'in flight x body size'".
//
// The implementation reserved in rawFetch and released with
// `defer s.buffers.release(reserve)` — which ran when rawFetch RETURNED, i.e.
// before the caller writes the body. handleGameRaw then does
// `w.Write(result.Body)`, and a slow-reading client blocks that write while the
// whole 4 MiB slice is still live. Every such request was invisible to the budget.
//
// This test is INVERTED for the fix (Z11-2, docs/issues/P2-medium.md): the
// reservation is transferred to RawResult.Release and returned after w.Write, so a
// handler parked inside Write holds the budget and a further full-cap read must be
// SHED (503). It used to assert the opposite, and the extra read being shed was
// the failure.
//
// The write window is parked IN PROCESS (parkingWriter) rather than with a
// socket-slow client, because whether a socket write blocks is a property of the
// host's buffers: heldbody_live_test.go (the Linux confirmation) measures 48/48
// handlers returning on a Windows host. The deterministic in-process park is what
// makes this test platform-independent.
package zzprobe_z11resiliencedos

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// zzUpstream serves two shapes:
//
//	/native/big   — exactly maxBody bytes with a declared Content-Length, so the
//	                reservation is exactly maxBody+1;
//	/native/stall — headers flushed, then blocked, so a reader holds its
//	                reservation while transferring zero bytes (the control).
func zzUpstream(t *testing.T, release <-chan struct{}, stalled *int64) *httptest.Server {
	t.Helper()
	body := bytes.Repeat([]byte{'x'}, zzMaxBody)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/native/stall" {
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(http.StatusOK)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			atomicAdd(stalled, 1)
			<-release
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	t.Cleanup(up.Close)
	return up
}

// parkingWriter is an http.ResponseWriter that parks inside Write after recording
// what the handler handed it. The "entered" signal is closed from inside Write, so
// "the handler is inside Write" is observed rather than assumed.
type parkingWriter struct {
	header  http.Header
	entered chan struct{}
	release chan struct{}
	once    sync.Once

	mu      sync.Mutex
	status  int
	written int
}

func newParkingWriter() *parkingWriter {
	return &parkingWriter{
		header:  make(http.Header),
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (w *parkingWriter) Header() http.Header { return w.header }

func (w *parkingWriter) WriteHeader(code int) {
	w.mu.Lock()
	w.status = code
	w.mu.Unlock()
}

func (w *parkingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	w.written += len(p)
	w.mu.Unlock()
	w.once.Do(func() { close(w.entered) })
	<-w.release
	return len(p), nil
}

func (w *parkingWriter) unblock() { close(w.release) }

func (w *parkingWriter) state() (status, written int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.status, w.written
}

// TestZ11ABodyOutlivesTheReservationThatAdmittedIt is the inverted guard for
// Z11-2: a body parked inside the handler's Write keeps its reservation, so a
// further full-cap read is shed; once the write completes the reservation is back.
func TestZ11ABodyOutlivesTheReservationThatAdmittedIt(t *testing.T) {
	// The budget under test is exactly ONE raw reservation (maxBody + 1). If it
	// bounded the bodies held by in-flight requests — as its documentation says —
	// then only one full-cap body could be mid-write at a time.
	const budget = zzMaxBody + 1

	release := make(chan struct{})
	var releaseOnce sync.Once
	stop := func() { releaseOnce.Do(func() { close(release) }) }
	var stalled int64
	up := zzUpstream(t, release, &stalled)
	t.Cleanup(stop) // registered after the upstream, so it runs first
	srv, token := dataAPI(t, dataConfig{Upstream: up.URL, MaxBufferedBytes: budget})

	bigURL := srv.URL + "/v1/games/" + zzGame + "/sources/src/raw/big"
	stallURL := srv.URL + "/v1/games/" + zzGame + "/sources/src/raw/stall"

	// ---- control: the budget really is one reservation -------------------
	// One stalled read holds it (headers arrived, no body byte yet); a second
	// concurrent read must be shed with 503. Without this the rest of the probe
	// could not tell "the budget is free because the bodies are untracked" from
	// "the budget is not in force at all".
	//
	// The stall read is driven from a goroutine because the server does not write
	// ANY response header until its handler has the whole body: a synchronous
	// client would block until the handler returns and the two requests would
	// never overlap.
	stallDone := make(chan int, 1)
	go func() {
		req, err := http.NewRequest(http.MethodGet, stallURL, nil)
		if err != nil {
			stallDone <- -1
			return
		}
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := srv.Client().Do(req)
		if err != nil {
			stallDone <- -2
			return
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		stallDone <- resp.StatusCode
	}()
	waitUntil(t, 3*time.Second, func() bool { return atomicLoad(&stalled) >= 1 })
	// The upstream increments `stalled` a hair after it flushes, and the client
	// acquires the reservation a hair after it sees the headers; let the acquire
	// land or the control tests the race instead of the budget.
	time.Sleep(150 * time.Millisecond)

	code, _, _ := getAuth(t, srv.Client(), stallURL, token)
	t.Logf("control: with one zero-byte read holding the whole %d-byte budget, a second concurrent read = %d",
		budget, code)
	if code != http.StatusServiceUnavailable {
		t.Fatalf("the control did not hold: a second concurrent read was admitted (%d) although the budget is "+
			"one reservation. The budget arithmetic changed, so this probe proves nothing.", code)
	}
	stop()
	if got := <-stallDone; got != http.StatusOK && got != http.StatusBadGateway {
		t.Logf("note: the parked read finished as %d", got)
	}
	time.Sleep(100 * time.Millisecond)

	// ---- the fix: the write window holds the reservation -----------------
	// Drive the REAL handler with a writer that parks inside Write. The whole body
	// has been handed to Write by then, which is exactly the window this finding is
	// about.
	handler := srv.Config.Handler
	bw := newParkingWriter()
	done := make(chan struct{})
	go func() {
		defer close(done)
		req := httptest.NewRequest(http.MethodGet, "/v1/games/"+zzGame+"/sources/src/raw/big", nil)
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
	t.Logf("one handler is parked inside Write holding %d bytes; the joint budget is %d bytes (%.1f MiB)",
		written, budget, float64(budget)/(1<<20))

	// The defect, inverted: the held body must spend the budget, so a further
	// full-cap read is refused.
	code, _, _ = getAuth(t, srv.Client(), bigURL, token)
	t.Logf("with that body held inside Write and a %d-byte budget, one more full-cap read = %d", budget, code)
	if code != http.StatusServiceUnavailable {
		t.Errorf("the extra read was ADMITTED (%d) while a handler is parked inside Write holding the whole "+
			"%d-byte body: the reservation is released when rawFetch returns, before the body is written, so the "+
			"budget still bounds the READ phase and not the held body (Z11-2). With max_in_flight readers each "+
			"parked in w.Write the live bodies are unbounded by MaxBufferedBytes.", code, zzMaxBody)
	}

	// Control: completing the write returns the reservation, so the 503 above is
	// attributable to the held body and not to a permanently spent budget.
	bw.unblock()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatalf("the parked handler never returned after the writer was unblocked")
	}
	code, _, _ = getAuth(t, srv.Client(), bigURL, token)
	t.Logf("after the parked write completed, the same read = %d", code)
	if code != http.StatusOK {
		t.Errorf("after the write completed the read = %d, want 200: the shed above was not the held reservation", code)
	}
}
