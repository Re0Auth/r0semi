package httpapi

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/Re0Auth/r0semi/internal/ratelimit"
)

func prefixes(t *testing.T, cidrs ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			t.Fatalf("parse %q: %v", c, err)
		}
		out = append(out, p)
	}
	return out
}

func addrRequest(remoteAddr string, xff ...string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = remoteAddr
	for _, v := range xff {
		req.Header.Add("X-Forwarded-For", v)
	}
	return req
}

// The header is only read when the deployment declares it. A trust list alone is
// not a statement that the header is trustworthy: a proxy that forwards the
// caller's own X-Forwarded-For verbatim leaves every entry caller-written, and
// nothing in a request can tell that apart from a rewritten one.
func TestClientAddrReadsNoHeaderWithoutADeclaration(t *testing.T) {
	req := addrRequest("10.1.2.3:5555", "198.51.100.9")

	// Declared mode, trusted peer: the header is read.
	if got := clientAddr(req, prefixes(t, "10.0.0.0/8"), ClientAddrXForwardedFor); got != "198.51.100.9" {
		t.Fatalf("clientAddr = %q, want the forwarded client", got)
	}
	// The default mode (and an explicit "none"), with the same trusted peer: the
	// peer is the client.
	if got := clientAddr(req, prefixes(t, "10.0.0.0/8"), ClientAddrPeer); got != "10.1.2.3" {
		t.Fatalf("clientAddr with no declared header = %q, want the peer", got)
	}
}

// Without a trust list the header is noise even when it is declared: the peer is
// the client. This is what stops a caller from choosing its own rate-limit bucket
// by sending a fabricated X-Forwarded-For.
func TestClientAddrIgnoresForwardedForFromUntrustedPeer(t *testing.T) {
	req := addrRequest("203.0.113.7:5555", "198.51.100.9")

	for _, mode := range []ClientAddrHeader{ClientAddrPeer, ClientAddrXForwardedFor} {
		if got := clientAddr(req, nil, mode); got != "203.0.113.7" {
			t.Fatalf("clientAddr with no trust list, mode %v = %q, want the peer", mode, got)
		}
		// A trust list that does not cover the peer is the same as none.
		if got := clientAddr(req, prefixes(t, "10.0.0.0/8"), mode); got != "203.0.113.7" {
			t.Fatalf("clientAddr from an untrusted peer, mode %v = %q, want the peer", mode, got)
		}
	}
}

// A peer inside the trust list may speak for the client through the header, and
// only through the RIGHTMOST entry: everything to its left is what our proxy was
// told, which is the caller's own text.
func TestClientAddrUsesTheRightmostHopFromATrustedPeer(t *testing.T) {
	// A client that prepends its own entry cannot displace the one our nearest
	// proxy appended.
	req := addrRequest("10.1.2.3:5555", "1.2.3.4, 203.0.113.7")
	if got := clientAddr(req, prefixes(t, "10.0.0.0/8"), ClientAddrXForwardedFor); got != "203.0.113.7" {
		t.Fatalf("clientAddr = %q, want the address the nearest proxy appended", got)
	}
}

// The hop the nearest proxy appended may itself be inside the trust list — a node
// address after SNAT, a service mesh, an internal load balancer. Walking left past
// it reached an address the caller had written; the answer is the peer, which is
// coarser but real.
func TestClientAddrRefusesAHopInsideTheTrustList(t *testing.T) {
	req := addrRequest("10.1.2.3:5555", "198.51.100.9, 10.9.9.9")
	if got := clientAddr(req, prefixes(t, "10.0.0.0/8"), ClientAddrXForwardedFor); got != "10.1.2.3" {
		t.Fatalf("clientAddr = %q, want the peer when the appended hop is one of ours", got)
	}
}

// When every hop is one of ours the client is not in the chain at all. The
// leftmost entry is caller-written by construction, so it must never be the key.
func TestClientAddrAllHopsTrustedFallsBackToThePeer(t *testing.T) {
	req := addrRequest("10.1.2.3:5555", "10.9.9.9, 10.8.8.8")
	if got := clientAddr(req, prefixes(t, "10.0.0.0/8"), ClientAddrXForwardedFor); got != "10.1.2.3" {
		t.Fatalf("clientAddr = %q, want the peer, never a caller-written hop", got)
	}
}

// A hop we cannot parse makes the value unverifiable, so the header is not trusted
// at all rather than partially.
func TestClientAddrMalformedForwardedForFallsBackToPeer(t *testing.T) {
	req := addrRequest("10.1.2.3:5555", "198.51.100.9, not-an-ip")
	if got := clientAddr(req, prefixes(t, "10.0.0.0/8"), ClientAddrXForwardedFor); got != "10.1.2.3" {
		t.Fatalf("clientAddr = %q, want the peer when the value is unreadable", got)
	}
}

func TestClientAddrWithoutHeaderUsesPeer(t *testing.T) {
	req := addrRequest("10.1.2.3:5555")
	if got := clientAddr(req, prefixes(t, "10.0.0.0/8"), ClientAddrXForwardedFor); got != "10.1.2.3" {
		t.Fatalf("clientAddr = %q, want the peer", got)
	}
}

// Repeated header lines are read as one list, rightmost first — which is what
// net/http does for the rest of the service.
func TestClientAddrJoinsRepeatedHeaders(t *testing.T) {
	// A public address last: it is the nearest proxy's entry.
	req := addrRequest("10.1.2.3:5555", "10.9.9.9", "203.0.113.7")
	if got := clientAddr(req, prefixes(t, "10.0.0.0/8"), ClientAddrXForwardedFor); got != "203.0.113.7" {
		t.Fatalf("clientAddr = %q, want the last line's last entry", got)
	}
	// A trusted address last: the peer, not the caller-written first line.
	req = addrRequest("10.1.2.3:5555", "198.51.100.9", "10.9.9.9")
	if got := clientAddr(req, prefixes(t, "10.0.0.0/8"), ClientAddrXForwardedFor); got != "10.1.2.3" {
		t.Fatalf("clientAddr = %q, want the peer", got)
	}
}

func TestClientAddrHandlesIPv6(t *testing.T) {
	req := addrRequest("[::1]:5555", "2001:db8::5")
	if got := clientAddr(req, prefixes(t, "::1/128"), ClientAddrXForwardedFor); got != "2001:db8::5" {
		t.Fatalf("clientAddr = %q", got)
	}
}

// A RemoteAddr with no port still resolves.
func TestClientAddrWithoutPort(t *testing.T) {
	req := addrRequest("203.0.113.7")
	if got := clientAddr(req, nil, ClientAddrPeer); got != "203.0.113.7" {
		t.Fatalf("clientAddr = %q", got)
	}
}

// Through a proxy that declares its header, two clients behind it get their own
// buckets.
func TestTrustedProxyGivesEachClientItsOwnBucket(t *testing.T) {
	cfg := newFullConfig(t)
	cfg.Limiter = ratelimit.New(0.001, 1) // one token, effectively no refill
	cfg.TrustedProxies = prefixes(t, "10.0.0.0/8")
	cfg.ClientAddrHeader = ClientAddrXForwardedFor
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	handler := srv.Handler()

	call := func(client string) int {
		req := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
		req.RemoteAddr = "10.1.2.3:5555" // the proxy
		req.Header.Set("X-Forwarded-For", client)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}

	if got := call("198.51.100.1"); got != http.StatusUnauthorized {
		t.Fatalf("first call = %d, want 401", got)
	}
	if got := call("198.51.100.1"); got != http.StatusTooManyRequests {
		t.Fatalf("same client again = %d, want 429", got)
	}
	// A different client has its own bucket and is unaffected.
	if got := call("198.51.100.2"); got != http.StatusUnauthorized {
		t.Fatalf("second client = %d, want 401 (its own bucket)", got)
	}
}

// The same deployment WITHOUT the declaration: every client behind the proxy
// shares the proxy's bucket. That is the documented cost of the default, and it is
// the direction to fail in — a shared budget is an availability problem, a
// caller-chosen key is not a rate limit at all.
func TestUndeclaredHeaderCollapsesClientsIntoTheProxy(t *testing.T) {
	cfg := newFullConfig(t)
	cfg.Limiter = ratelimit.New(0.001, 1)
	cfg.TrustedProxies = prefixes(t, "10.0.0.0/8")
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	handler := srv.Handler()

	call := func(client string) int {
		req := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
		req.RemoteAddr = "10.1.2.3:5555" // the proxy
		req.Header.Set("X-Forwarded-For", client)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}

	if got := call("198.51.100.1"); got != http.StatusUnauthorized {
		t.Fatalf("first call = %d, want 401", got)
	}
	if got := call("198.51.100.2"); got != http.StatusTooManyRequests {
		t.Fatalf("a second client got its own bucket without the header being declared: %d, want 429", got)
	}
}

// Without a trust list, varying the header does not escape the peer's bucket:
// the caller cannot pick its own limit.
func TestUntrustedPeerCannotChooseItsOwnBucket(t *testing.T) {
	for _, mode := range []ClientAddrHeader{ClientAddrPeer, ClientAddrXForwardedFor} {
		cfg := newFullConfig(t)
		cfg.Limiter = ratelimit.New(0.001, 1)
		cfg.ClientAddrHeader = mode
		srv, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		handler := srv.Handler()

		call := func(client string) int {
			req := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
			req.RemoteAddr = "203.0.113.7:5555"
			req.Header.Set("X-Forwarded-For", client)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			return rec.Code
		}

		if got := call("198.51.100.1"); got != http.StatusUnauthorized {
			t.Fatalf("mode %v: first call = %d, want 401", mode, got)
		}
		// A different claimed client is still the same peer, so the same bucket.
		if got := call("198.51.100.2"); got != http.StatusTooManyRequests {
			t.Fatalf("mode %v: spoofed header escaped the bucket: %d, want 429", mode, got)
		}
	}
}

func TestParseClientAddrHeader(t *testing.T) {
	for _, tc := range []struct {
		in      string
		want    ClientAddrHeader
		wantErr bool
	}{
		{"", ClientAddrPeer, false},
		{"none", ClientAddrPeer, false},
		{"NONE", ClientAddrPeer, false},
		{" x-forwarded-for ", ClientAddrXForwardedFor, false},
		{"X-Forwarded-For", ClientAddrXForwardedFor, false},
		{"x-real-ip", ClientAddrPeer, true},
		{"forwarded", ClientAddrPeer, true},
	} {
		got, err := ParseClientAddrHeader(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParseClientAddrHeader(%q) = %v, want an error", tc.in, got)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("ParseClientAddrHeader(%q) = %v, %v; want %v", tc.in, got, err, tc.want)
		}
	}
}
