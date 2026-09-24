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

// Without a trust list the header is noise: the peer is the client. This is the
// default, and it is what stops a caller from choosing its own rate-limit bucket
// by sending a fabricated X-Forwarded-For.
func TestClientAddrIgnoresForwardedForFromUntrustedPeer(t *testing.T) {
	req := addrRequest("203.0.113.7:5555", "198.51.100.9")

	if got := clientAddr(req, nil); got != "203.0.113.7" {
		t.Fatalf("clientAddr with no trust list = %q, want the peer", got)
	}
	// A trust list that does not cover the peer is the same as none.
	if got := clientAddr(req, prefixes(t, "10.0.0.0/8")); got != "203.0.113.7" {
		t.Fatalf("clientAddr from an untrusted peer = %q, want the peer", got)
	}
}

// A peer inside the trust list may speak for the client through the header.
func TestClientAddrUsesForwardedForFromTrustedPeer(t *testing.T) {
	req := addrRequest("10.1.2.3:5555", "198.51.100.9")
	if got := clientAddr(req, prefixes(t, "10.0.0.0/8")); got != "198.51.100.9" {
		t.Fatalf("clientAddr = %q, want the forwarded client", got)
	}
}

// The chain is read from the right, past our own proxies, to the first address we
// do not trust.
func TestClientAddrSkipsTrustedHopsFromTheRight(t *testing.T) {
	req := addrRequest("10.1.2.3:5555", "198.51.100.9, 10.9.9.9")
	if got := clientAddr(req, prefixes(t, "10.0.0.0/8")); got != "198.51.100.9" {
		t.Fatalf("clientAddr = %q, want the client behind the trusted hop", got)
	}
}

// A client that prepends its own entry cannot displace the one our nearest proxy
// appended: the rightmost untrusted address is what that proxy actually saw.
func TestClientAddrIgnoresClientSuppliedEntries(t *testing.T) {
	req := addrRequest("10.1.2.3:5555", "1.2.3.4, 203.0.113.7")
	if got := clientAddr(req, prefixes(t, "10.0.0.0/8")); got != "203.0.113.7" {
		t.Fatalf("clientAddr = %q, want the address the nearest proxy appended", got)
	}
}

// When every hop is one of ours the client is not in the chain, so the leftmost
// entry is the closest thing to an origin.
func TestClientAddrAllHopsTrustedFallsBackToLeftmost(t *testing.T) {
	req := addrRequest("10.1.2.3:5555", "10.9.9.9, 10.8.8.8")
	if got := clientAddr(req, prefixes(t, "10.0.0.0/8")); got != "10.9.9.9" {
		t.Fatalf("clientAddr = %q, want the leftmost hop", got)
	}
}

// A hop we cannot parse makes the rest of the chain unverifiable, so the header
// is not trusted at all rather than partially.
func TestClientAddrMalformedForwardedForFallsBackToPeer(t *testing.T) {
	req := addrRequest("10.1.2.3:5555", "198.51.100.9, not-an-ip")
	if got := clientAddr(req, prefixes(t, "10.0.0.0/8")); got != "10.1.2.3" {
		t.Fatalf("clientAddr = %q, want the peer when the chain is unreadable", got)
	}
}

func TestClientAddrWithoutHeaderUsesPeer(t *testing.T) {
	req := addrRequest("10.1.2.3:5555")
	if got := clientAddr(req, prefixes(t, "10.0.0.0/8")); got != "10.1.2.3" {
		t.Fatalf("clientAddr = %q, want the peer", got)
	}
}

// Repeated headers are joined in order, which is what net/http does for the rest
// of the service.
func TestClientAddrJoinsRepeatedHeaders(t *testing.T) {
	req := addrRequest("10.1.2.3:5555", "198.51.100.9", "10.9.9.9")
	if got := clientAddr(req, prefixes(t, "10.0.0.0/8")); got != "198.51.100.9" {
		t.Fatalf("clientAddr = %q", got)
	}
}

func TestClientAddrHandlesIPv6(t *testing.T) {
	req := addrRequest("[::1]:5555", "2001:db8::5")
	if got := clientAddr(req, prefixes(t, "::1/128")); got != "2001:db8::5" {
		t.Fatalf("clientAddr = %q", got)
	}
}

// A RemoteAddr with no port still resolves.
func TestClientAddrWithoutPort(t *testing.T) {
	req := addrRequest("203.0.113.7")
	if got := clientAddr(req, nil); got != "203.0.113.7" {
		t.Fatalf("clientAddr = %q", got)
	}
}

// Through a trusted proxy, two clients behind it get their own buckets.
func TestTrustedProxyGivesEachClientItsOwnBucket(t *testing.T) {
	cfg := newFullConfig(t)
	cfg.Limiter = ratelimit.New(0.001, 1) // one token, effectively no refill
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
	if got := call("198.51.100.1"); got != http.StatusTooManyRequests {
		t.Fatalf("same client again = %d, want 429", got)
	}
	// A different client has its own bucket and is unaffected.
	if got := call("198.51.100.2"); got != http.StatusUnauthorized {
		t.Fatalf("second client = %d, want 401 (its own bucket)", got)
	}
}

// Without a trust list, varying the header does not escape the peer's bucket:
// the caller cannot pick its own limit.
func TestUntrustedPeerCannotChooseItsOwnBucket(t *testing.T) {
	cfg := newFullConfig(t)
	cfg.Limiter = ratelimit.New(0.001, 1)
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
		t.Fatalf("first call = %d, want 401", got)
	}
	// A different claimed client is still the same peer, so the same bucket.
	if got := call("198.51.100.2"); got != http.StatusTooManyRequests {
		t.Fatalf("spoofed header escaped the bucket: %d, want 429", got)
	}
}
