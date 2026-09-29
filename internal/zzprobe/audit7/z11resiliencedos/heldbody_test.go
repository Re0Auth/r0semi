//go:build audit7

// Z11-2: the upstream byte budget is released before the body is written out,
// so it does not bound "in flight x body size".
//
// P0-3 ("在途请求数 × 响应体没有联合上限 → OOMKill") was answered with
// Config.MaxBufferedBytes: "the joint budget for upstream response bodies held in
// memory at once, across every in-flight read on BOTH data-plane paths"
// (internal/federation/service.go:46-54), and deploy/k8s/base/configmap.yaml
// states it is "what actually caps 'in flight x body size'".
//
// The implementation reserves in rawFetch (service.go:725-729) and releases with
// `defer s.buffers.release(reserve)` — which runs when rawFetch RETURNS, i.e.
// before the caller writes the body. handleGameRaw then does
// `w.Write(result.Body)`, and a slow-reading client blocks that write for up to
// the server's writeTimeout (60s), holding the whole 4 MiB slice. Every such
// request is invisible to the budget. The shipped manifest runs
// max_in_flight = 128 against a 512Mi container limit: 128 x 4 MiB = 512 MiB of
// live bodies with the budget reporting itself free.
//
// This is NOT Z09-4 (the budget is global first-come-first-served, so sleepers
// shed another user's read). Z09-4 is about who gets the reservation while a read
// is IN PROGRESS; this is about the reservation being gone while the body is
// still held. Both are consequences of the same accounting, and the fix for one
// does not touch the other.
//
// The probe drives the real HTTP surface with the budget set to exactly one raw
// reservation, holds N bodies in their write phase, and shows the budget admits
// yet another read.
package zzprobe_z11resiliencedos

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
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

// TestZ11ABodyOutlivesTheReservationThatAdmittedIt is red while the budget is
// released before the response is written.
func TestZ11ABodyOutlivesTheReservationThatAdmittedIt(t *testing.T) {
	// The budget under test is exactly ONE raw reservation (maxBody + 1). If it
	// bounded the bodies held by in-flight requests — as its documentation says —
	// then only one of the readers below could be mid-write at a time.
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
	// never overlap, which is exactly what an earlier version of this probe got
	// wrong (it measured 40s of sequential time and a 504 control).
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

	// ---- the finding: N bodies held, budget free -------------------------
	const n = 8
	held := make([]*http.Response, 0, n)
	defer func() {
		for _, resp := range held {
			_ = resp.Body.Close()
		}
	}()

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	for i := 0; i < n; i++ {
		// Start the read, wait until its first body byte arrives — which proves
		// rawFetch already returned and released its reservation — and then stop
		// reading. The handler is now inside `w.Write(result.Body)`, holding the
		// whole 4 MiB slice, and the client is a slow reader by construction.
		resp := startRaw(t, srv.Client(), bigURL, token, true)
		held = append(held, resp)
	}
	runtime.ReadMemStats(&after)
	liveMiB := float64(after.HeapAlloc-before.HeapAlloc) / (1 << 20)
	t.Logf("%d raw reads are each blocked mid-write holding a %d-byte body (%d MiB total); "+
		"the joint budget is %d bytes (%.1f MiB) and the heap grew by %.1f MiB",
		n, zzMaxBody, n*zzMaxBody>>20, budget, float64(budget)/(1<<20), liveMiB)

	// The budget is free while those bodies are live: a read that needs the
	// WHOLE budget completes.
	code, _, body := getAuth(t, srv.Client(), bigURL, token)
	t.Logf("with %d x 4 MiB bodies held by in-flight requests and a %d-byte budget, one more full-cap read = %d (%d bytes)",
		n, budget, code, len(body))
	if code != http.StatusOK {
		t.Errorf("the extra read was shed (%d): the budget did notice the held bodies — re-derive the probe", code)
		return
	}

	live := int64(n) * zzMaxBody
	if live <= int64(budget) {
		t.Fatalf("the probe's premise is wrong: %d bytes held vs a %d-byte budget", live, budget)
	}
	t.Errorf("the byte budget bounds READS, not bodies HELD: %d bodies of %d bytes (%.0f MiB) are alive inside "+
		"in-flight handlers, the budget reports itself free (a further full-cap read was admitted), and the "+
		"declared invariant `held <= MaxBufferedBytes` is violated by %.0fx. With the shipped manifest "+
		"(max_in_flight = 128, 512Mi limit) the same shape is 512 MiB of live bodies with the budget untouched.",
		n, zzMaxBody, float64(live)/(1<<20), float64(live)/float64(budget))
}

// startRaw issues an authenticated GET to the raw proxy and returns once the
// response is usable. When firstByte is set it also reads one body byte, which
// proves the server has left rawFetch (and released its reservation) and is
// inside the response write.
func startRaw(t *testing.T, c *http.Client, url, token string, firstByte bool) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	if !firstByte {
		return resp
	}
	var one [1]byte
	if _, err := io.ReadFull(resp.Body, one[:]); err != nil {
		t.Fatalf("first body byte of %s: %v", url, err)
	}
	return resp
}
