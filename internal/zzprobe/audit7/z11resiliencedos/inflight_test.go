//go:build audit7

// Z11-5 regression guard: the in-flight cap is shared per (plane, client), with a
// global remainder, so one source address cannot hold every slot.
//
// The defect made the cap process-wide: one address could hold every in-flight slot
// with a handful of slow-body sockets, and every other client got 503
// temporarily_unavailable while /healthz and /readyz stayed 200 — a denial of
// service indistinguishable from load, with the orchestrator still routing to the
// instance. The fix gives each (plane, client) key at most half the cap
// (internal/httpapi/middleware.go: withInFlightLimit), leaving the other half as
// headroom every other client draws from. This guard was formerly
// TestZ11OneAddressCanHoldEveryInFlightSlot, a finding-confirmation oracle.
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

// TestZ11OneAddressCannotHoldEveryInFlightSlot is green only while the in-flight
// cap has a per-(plane, client) share: with max_in_flight=2 source A may hold at
// most one slot, a second concurrent request from A is refused, and a request from
// a different source address B is still served.
func TestZ11OneAddressCannotHoldEveryInFlightSlot(t *testing.T) {
	const slots = 2
	const perClient = slots / 2 // the share the fix grants one (plane, client)
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
		t.Fatalf("an ordinary request answered %d before any slot was held: re-derive the guard", code)
	}

	// One address (the loopback peer), sockets that send headers + one body byte,
	// then nothing. The declared length is the form-body cap
	// (oauth.MaxFormBytes = 64 KiB), so withBodyLimit accepts the request and the
	// handler blocks inside the body read. ReadTimeout is what would end this in the
	// real process; under httptest there is none, which only makes the window
	// longer than a deployment's.
	addr := srv.Listener.Addr().String()
	conns := make([]net.Conn, 0, 3)
	defer func() {
		for _, c := range conns {
			_ = c.Close()
		}
	}()
	dialSlow := func(i int) net.Conn {
		t.Helper()
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("dial %s: %v", addr, err)
		}
		conns = append(conns, c)
		if _, err := fmt.Fprintf(c, "POST /oauth/token HTTP/1.1\r\nHost: probe\r\n"+
			"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 65536\r\n\r\nx"); err != nil {
			t.Fatalf("write request %d: %v", i, err)
		}
		return c
	}

	// A's first request takes A's whole share and blocks in the body read.
	_ = dialSlow(0)
	waitUntil(t, 3*time.Second, func() bool { return atomicLoad(&inBody) >= perClient })
	if got := atomicLoad(&inBody); got != perClient {
		t.Fatalf("A's first request did not reach the body read: inBody=%d want %d", got, perClient)
	}
	t.Logf("source A (loopback peer) holds %d of %d slots (its per-client share)", perClient, slots)

	// A's SECOND concurrent request is beyond A's share and must be refused, even
	// though the global cap has room. A process-wide cap would admit it. It stays on
	// the protocol plane, so it is the same (plane, client) key as A's first request,
	// and it is a plain GET, so the refusal is reached before any body is read.
	if code, _, _ := get(t, srv.URL+"/oauth/token"); code != http.StatusServiceUnavailable {
		t.Errorf("source A's second concurrent request was answered %d although its share is %d of %d: the "+
			"cap is process-wide again, so one address can hold every slot", code, perClient, slots)
	}
	if got := atomicLoad(&inBody); got != perClient {
		t.Errorf("source A held %d concurrent body reads although its share is %d: the per-client share is gone",
			got, perClient)
	}

	// A DIFFERENT source address is still served: the share leaves room.
	other, ok := clientFrom(t, "127.0.0.2")
	if !ok {
		t.Fatalf("could not send from a second source address: the guard cannot show that ANOTHER client is served")
	}
	code, _, body := getVia(t, other, srv.URL+"/nowhere")
	t.Logf("another client (source 127.0.0.2, its own bucket) gets %d: %s", code, string(body))
	if code == http.StatusServiceUnavailable {
		t.Errorf("the other client was answered %d while source A held only its share: the per-client share does "+
			"not leave room for everyone else", code)
	}

	health, _, hbody := getVia(t, other, srv.URL+"/healthz")
	ready, _, _ := getVia(t, other, srv.URL+"/readyz")
	t.Logf("while a slot is held: /healthz = %d (%s), /readyz = %d", health, string(hbody), ready)
	if health != http.StatusOK || ready != http.StatusOK {
		t.Errorf("/healthz = %d, /readyz = %d while the cap is saturated: the probes DID notice the load", health, ready)
	}
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
