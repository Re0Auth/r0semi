//go:build audit7

// Z11-5: the in-flight cap has no per-client share, and the per-address rate
// limit does not bound the concurrency one address can hold.
package zzprobe_z11resiliencedos

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/internal/ratelimit"
)

// TestZ11OneAddressCanHoldEveryInFlightSlot is red while the in-flight cap is
// process-wide and probes stay green.
func TestZ11OneAddressCanHoldEveryInFlightSlot(t *testing.T) {
	const slots = 2
	var inBody int64
	var slow http.HandlerFunc = func(w http.ResponseWriter, r *http.Request) {
		atomicAdd(&inBody, 1)
		_, _ = io.Copy(io.Discard, r.Body)
		atomicAdd(&inBody, -1)
		w.WriteHeader(http.StatusOK)
	}
	srv := miniAPI(t, miniConfig{
		MaxInFlight: slots,
		OIDC:        slow,
		Limiter:     ratelimit.New(50, 100),
	})

	if code, _, _ := get(t, srv.URL+"/nowhere"); code != http.StatusNotFound {
		t.Fatalf("an ordinary request answered %d before any slot was held: re-derive the probe", code)
	}

	// One address (the loopback peer), `slots` sockets, headers + one body byte,
	// then nothing. The declared length is the form-body cap
	// (oauth.MaxFormBytes = 64 KiB), so withBodyLimit accepts the request and the
	// handler blocks inside the body read; a larger declared length is refused 413
	// before a slot is spent. ReadTimeout is what would end this in the real
	// process; under httptest there is none, which only makes the probe's window
	// longer than a deployment's.
	addr := srv.Listener.Addr().String()
	conns := make([]net.Conn, 0, slots)
	defer func() {
		for _, c := range conns {
			_ = c.Close()
		}
	}()
	for i := 0; i < slots; i++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("dial %s: %v", addr, err)
		}
		conns = append(conns, c)
		if _, err := fmt.Fprintf(c, "POST /oauth/token HTTP/1.1\r\nHost: probe\r\n"+
			"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 65536\r\n\r\nx"); err != nil {
			t.Fatalf("write request %d: %v", i, err)
		}
	}
	waitUntil(t, 3*time.Second, func() bool { return atomicLoad(&inBody) == slots })
	if got := atomicLoad(&inBody); got != slots {
		t.Fatalf("only %d of %d requests reached the body read: the slots are not all held", got, slots)
	}
	t.Logf("%d slots held by %d sockets from ONE address (127.0.0.1), limiter budget spent: %d of its 100 burst tokens",
		slots, len(conns), len(conns))

	other, ok := clientFrom(t, "127.0.0.2")
	if !ok {
		t.Fatalf("could not send from a second source address: the probe cannot show that ANOTHER client is refused")
	}
	code, _, body := getVia(t, other, srv.URL+"/nowhere")
	t.Logf("another client (source 127.0.0.2, its own limiter bucket) now gets %d: %s", code, string(body))
	if code != http.StatusServiceUnavailable {
		t.Errorf("the other client was answered %d although every in-flight slot was held: re-derive the probe", code)
		return
	}

	health, _, hbody := getVia(t, other, srv.URL+"/healthz")
	ready, _, _ := getVia(t, other, srv.URL+"/readyz")
	t.Logf("while every slot is held: /healthz = %d (%s), /readyz = %d", health, string(hbody), ready)
	if health != http.StatusOK || ready != http.StatusOK {
		t.Errorf("/healthz = %d, /readyz = %d while the cap is saturated: the probes DID notice the load", health, ready)
	}

	t.Errorf("one address held all %d in-flight slots with %d sockets and %d of its 100 burst tokens, and every "+
		"other client was answered 503 temporarily_unavailable while /healthz and /readyz stayed 200. The cap is "+
		"process-wide with no per-client share, and the per-address limiter bounds rate, not admitted concurrency: "+
		"at the shipped configuration (50/s, ReadTimeout 30s, max_in_flight 128) one address can sustain the "+
		"saturation with ~5 requests/s and the orchestrator keeps routing to the instance.",
		slots, len(conns), len(conns))
}

// clientFrom returns an HTTP client whose connections originate from `ip`, so a
// probe can send from a second address on the loopback /8.
func clientFrom(t *testing.T, ip string) (*http.Client, bool) {
	t.Helper()
	parsed := net.ParseIP(ip)
	if parsed == nil {
		t.Fatalf("clientFrom(%q): not an IP", ip)
	}
	ln, err := net.Listen("tcp", ip+":0")
	if err != nil {
		t.Logf("cannot bind source address %s on this host: %v", ip, err)
		return nil, false
	}
	_ = ln.Close()
	c := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{LocalAddr: &net.TCPAddr{IP: parsed}}
			return d.DialContext(ctx, network, address)
		},
	}}
	return c, true
}

// getVia is get with a caller-supplied client.
func getVia(t *testing.T, c *http.Client, url string) (int, http.Header, []byte) {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", url, err)
	}
	return resp.StatusCode, resp.Header, body
}
