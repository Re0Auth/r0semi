//go:build audit7

// Z11-2 verification: is the "held" body actually live while the handler is
// inside w.Write?
//
// The reviewed probe (z11resiliencedos/heldbody_test.go) prints a heap delta of
// 4.2 MiB for 8 x 4 MiB bodies and calls them "alive inside in-flight handlers".
// A delta of one body with eight held is what you would see if the writes had
// already completed and a GC had collected the rest, so that print does not
// prove the premise.
//
// This probe measures live heap after a forced collection. Its first phase is a
// POSITIVE CONTROL for the instrument: the same measurement, in the same
// process, with 12 x 4 MiB slices deliberately kept alive. If that control does
// not see ~48 MiB, the real measurement below proves nothing. The real phase
// parks 12 slow readers with a 4 KiB receive buffer so the server's write has
// nowhere to go.
package zzprobe_z11verify

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// readHeaders reads an HTTP response head one byte at a time, so the probe
// consumes no more of the body than a real slow client would.
func readHeaders(t *testing.T, c net.Conn) string {
	t.Helper()
	if err := c.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	one := make([]byte, 1)
	for b.Len() < 16<<10 {
		if _, err := c.Read(one); err != nil {
			t.Fatalf("reading response head: %v (after %q)", err, b.String())
		}
		b.WriteByte(one[0])
		if strings.HasSuffix(b.String(), "\r\n\r\n") {
			return b.String()
		}
	}
	t.Fatalf("response head did not terminate")
	return ""
}

// liveHeapAfterGC returns HeapAlloc after a forced, fully-swept collection.
func liveHeapAfterGC() uint64 {
	debug.FreeOSMemory()
	runtime.GC()
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return ms.HeapAlloc
}

// TestZ11VHeldBodiesAreLiveWhileTheHandlerWrites measures the live heap of the
// raw handler's response write.
func TestZ11VHeldBodiesAreLiveWhileTheHandlerWrites(t *testing.T) {
	const n = 48
	const bodyBytes = int64(zzMaxBody)

	// ---- phase 0: positive control for the instrument --------------------
	// If a full GC + scavenge cannot see 12 deliberately-live 4 MiB slices, the
	// measurement is blind and phase 1 means nothing.
	before := liveHeapAfterGC()
	hold := make([][]byte, n)
	touched := 0
	for i := range hold {
		hold[i] = bytes.Repeat([]byte{'y'}, zzMaxBody)
		touched += int(hold[i][len(hold[i])-1])
	}
	after := liveHeapAfterGC()
	runtime.KeepAlive(hold)
	heldDelta := int64(after) - int64(before)
	t.Logf("control: %d deliberately-live 4 MiB slices moved HeapAlloc by %.1f MiB (%.1f needed); absolute %d -> %d, touched=%d",
		n, float64(heldDelta)/(1<<20), float64(int64(n)*bodyBytes)/(1<<20), before, after, touched)
	if heldDelta < int64(n)*bodyBytes*8/10 {
		t.Fatalf("the instrument is blind: %d live 4 MiB slices produced only %.1f MiB of HeapAlloc. "+
			"Fix the control before trusting phase 1.", n, float64(heldDelta)/(1<<20))
	}
	hold = nil

	// ---- fixture ---------------------------------------------------------
	const budget = zzMaxBody + 1
	release := make(chan struct{})
	var releaseOnce sync.Once
	stop := func() { releaseOnce.Do(func() { close(release) }) }
	var stalled int64
	up := zzUpstream(t, release, &stalled)
	t.Cleanup(stop)
	srv, token := dataAPI(t, dataConfig{Upstream: up.URL, MaxBufferedBytes: budget})
	path := "/v1/games/" + zzGame + "/sources/src/raw/big"

	// Control: one stalled read holds the whole budget, so a second concurrent
	// read is shed. Without this, "the budget is free" below could be a budget
	// that is not in force at all.
	stallDone := make(chan int, 1)
	go func() {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/games/"+zzGame+"/sources/src/raw/stall", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := srv.Client().Do(req)
		if err != nil {
			stallDone <- -1
			return
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		stallDone <- resp.StatusCode
	}()
	waitUntil(t, 3*time.Second, func() bool { return atomic.LoadInt64(&stalled) >= 1 })
	time.Sleep(150 * time.Millisecond)
	code, _, _ := getAuth(t, srv.Client(), srv.URL+"/v1/games/"+zzGame+"/sources/src/raw/stall", token)
	t.Logf("control: one stalled read outstanding; a second concurrent read = %d (want 503)", code)
	if code != http.StatusServiceUnavailable {
		t.Fatalf("the control did not hold: a second read was admitted (%d) although the budget is one reservation", code)
	}
	stop()
	select {
	case got := <-stallDone:
		t.Logf("note: the parked read finished as %d", got)
	case <-time.After(3 * time.Second):
	}
	time.Sleep(150 * time.Millisecond)

	// ---- phase 1: the measurement ----------------------------------------
	// A budget that admits all n readers, so that on a host where the socket writes
	// really block (Linux) every reader can park: the point of the phase is that
	// once they are parked the budget reports itself SPENT, so a further full-cap
	// read is shed. With the one-reservation budget of the control above, the
	// second reader would be shed before it could park.
	phaseBudget := n * (zzMaxBody + 1)
	bigSrv, bigToken := dataAPI(t, dataConfig{Upstream: up.URL, MaxBufferedBytes: phaseBudget})
	addr := bigSrv.Listener.Addr().String()

	// The access log is written when (and only when) a handler returns, so
	// counting the completed /raw/big lines at measurement time says exactly how
	// many handlers are still parked and holding their body.
	logs := &captureHandler{}
	prevLog := slog.Default()
	slog.SetDefault(slog.New(logs))
	defer slog.SetDefault(prevLog)
	completed := func() int { return strings.Count(logs.String(), "path=/v1/games/phigros/sources/src/raw/big") }

	before = liveHeapAfterGC()

	conns := make([]net.Conn, 0, n)
	defer func() {
		for _, c := range conns {
			_ = c.Close()
		}
	}()
	for i := 0; i < n; i++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("dial %s: %v", addr, err)
		}
		if tcp, ok := c.(*net.TCPConn); ok {
			// A small receive buffer means the server's 4 MiB write cannot be
			// absorbed by this host's socket buffering.
			if err := tcp.SetReadBuffer(4096); err != nil {
				t.Logf("SetReadBuffer: %v", err)
			}
		}
		req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: probe\r\nAuthorization: Bearer %s\r\nConnection: close\r\n\r\n", path, bigToken)
		if _, err := c.Write([]byte(req)); err != nil {
			t.Fatalf("write request %d: %v", i, err)
		}
		head := readHeaders(t, c)
		if !strings.HasPrefix(head, "HTTP/1.1 200") {
			t.Fatalf("request %d answered %q, want 200 (budget %d admits all %d readers before any body is written)",
				i, strings.SplitN(head, "\r\n", 2)[0], phaseBudget, n)
		}
		conns = append(conns, c)
	}
	time.Sleep(400 * time.Millisecond)
	// Independent of the heap: the access log names the handlers that already
	// returned, and the goroutine dump names the ones still parked.
	done := completed()
	stack := make([]byte, 4<<20)
	stack = stack[:runtime.Stack(stack, true)]
	blocked := bytes.Count(stack, []byte("internal/poll.(*FD).Write")) +
		bytes.Count(stack, []byte("net.(*conn).Write")) +
		bytes.Count(stack, []byte("net.(*netFD).Write"))
	t.Logf("at measurement time: %d of %d raw handlers have returned (access log), %d goroutines exist, "+
		"%d stack frames are parked in a socket write", done, n, runtime.NumGoroutine(), blocked)
	after = liveHeapAfterGC()
	delta := int64(after) - int64(before)
	t.Logf("%d slow readers (4 KiB receive buffer) each own a parsed 200 head; after a forced GC HeapAlloc moved "+
		"by %.1f MiB; %d held %d-byte bodies would be %.1f MiB",
		n, float64(delta)/(1<<20), n, bodyBytes, float64(int64(n)*bodyBytes)/(1<<20))
	t.Logf("live 4 MiB bodies attributable to the delta: ~%d of %d", delta/bodyBytes, n)

	liveBodies := delta / bodyBytes
	parked := int64(n - done)
	t.Logf("live 4 MiB bodies attributable to the delta: ~%d; handlers parked at measurement: %d", liveBodies, parked)
	if parked == 0 {
		// Z11-2 verification note: this is a property of the HOST, not of the code.
		// Whether a socket write blocks depends on the kernel buffers, and this host
		// absorbs a 4 MiB response into them. The deterministic probe
		// (heldbody_deterministic_test.go) parks the same write IN PROCESS and is the
		// platform-independent confirmation; this probe stays as the Linux
		// confirmation, where a socket write really does block.
		t.Skipf("all %d handlers returned before the measurement: on this host the kernel absorbed every 4 MiB "+
			"response without a blocking write, so a held-body WRITE window cannot be exhibited here. "+
			"heldbody_deterministic_test.go covers the same window without a socket.", n)
	}
	if liveBodies < parked*3/4 {
		t.Errorf("~%d bodies are live in the heap while %d handlers are parked (the access log shows only %d of %d "+
			"returned), yet the instrument control above sees deliberately-held bodies: the held-body premise is "+
			"not established on this host", liveBodies, parked, done, n)
	}

	// INVERTED for the fix (Z11-2, docs/issues/P2-medium.md): with the reservation
	// transferred to the body, parked writers keep the budget spent, so a further
	// full-cap read must be SHED. Before the fix this same read completed, because
	// rawFetch released on return.
	extraCode, _, body := getAuth(t, bigSrv.Client(), bigSrv.URL+path, bigToken)
	t.Logf("with %d parked handlers holding %d-byte bodies and a %d-byte budget, one more full-cap read = %d (%d bytes)",
		parked, bodyBytes, phaseBudget, extraCode, len(body))
	if extraCode != http.StatusServiceUnavailable {
		t.Errorf("the extra read was ADMITTED (%d) while %d handlers are parked holding %d-byte bodies: the "+
			"reservation did not travel with the body (Z11-2)", extraCode, parked, bodyBytes)
	}
	if liveBodies >= parked*3/4 {
		t.Logf("held-body premise CONFIRMED on this host: ~%d parked handlers account for ~%d live 4 MiB bodies",
			parked, liveBodies)
	}
}
