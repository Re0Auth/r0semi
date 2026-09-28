//go:build audit5

package verifyhttpedge

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Re0Auth/r0semi/internal/httpapi"
)

// zzCallHandler is the raw form: one request, one peer, one header chain.
func zzCallHandler(t *testing.T, h http.Handler, peer, method, target string, xff ...string) int {
	t.Helper()
	req := httptest.NewRequest(method, target, nil)
	req.RemoteAddr = peer
	for _, v := range xff {
		req.Header.Add("X-Forwarded-For", v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

// TestV_XFFChainShapeDecidesTheKey answers the only question that decides HE-1's
// severity: under which shapes of the received X-Forwarded-For is the rate-limit
// bucket key chosen by the caller?
//
// The walk in clientaddr.go used to go from the right and return the first hop that
// was NOT in trusted_proxies, so a caller picked the key exactly when every hop a
// trusted proxy appended was itself inside trusted_proxies (or nothing was
// appended). After P0-4 the answer is structural rather than shape-dependent:
//
//   - with no declared header, the header is not read at all — no shape matters;
//   - with the header declared, only the RIGHTMOST entry is read, so a chain whose
//     last entry is one of ours yields the peer, never a caller-written hop.
//
// The remaining case that a caller can still choose is a declared header in front
// of a proxy that forwards the caller's own value verbatim; it is asserted as such,
// because the setting is a statement about a proxy that nothing in a request can
// verify.
//
// The limiter is one token with no refill, so an admission count above the control
// means distinct bucket keys.
func TestV_XFFChainShapeDecidesTheKey(t *testing.T) {
	const spin = 20

	// run rotates the address a caller claims through one TCP peer and reports how
	// many of spin+1 requests the limiter admitted, plus whether the one-key
	// control behaved (an identical chain twice must shed load on the second
	// request, or the header is not being consulted and the count means nothing).
	run := func(t *testing.T, h http.Handler, peer string, mk func(i int) []string) (int, bool) {
		t.Helper()
		call := func(xff ...string) int { return zzCallHandler(t, h, peer, http.MethodGet, "/v1/me", xff...) }
		first, second := call(mk(0)...), call(mk(0)...)
		if first == http.StatusTooManyRequests {
			t.Fatalf("control: the very first request was refused (%d); the limiter is not wired", first)
		}
		control := second == http.StatusTooManyRequests
		admitted := 0
		for i := 1; i <= spin; i++ {
			if zzAdmitted(call(mk(i)...)) {
				admitted++
			}
		}
		return admitted, control
	}

	t.Run("no trust list: rotating the header buys nothing", func(t *testing.T) {
		h := zzServer(t).Handler()
		admitted, control := run(t, h, "203.0.113.77:4444", func(i int) []string {
			return []string{fmt.Sprintf("198.51.100.%d", i+1)}
		})
		t.Logf("untrusted peer, rotating XFF: admitted=%d/%d controlSecondRequest429=%v", admitted, spin, control)
		if !control {
			t.Fatalf("the header is not being read at all here, so this case proves nothing")
		}
		if admitted != 0 {
			t.Errorf("an untrusted peer varied X-Forwarded-For and got %d further requests", admitted)
		}
	})

	t.Run("trusted peer, NO declared header: rotating the header buys nothing", func(t *testing.T) {
		// The trust list alone is not a statement that the header is trustworthy,
		// so the peer is the key and every rotation lands in one bucket.
		h := zzServer(t, "10.0.0.0/8").Handler()
		admitted, control := run(t, h, "10.1.2.3:5555", func(i int) []string {
			return []string{fmt.Sprintf("198.51.100.%d", i+1)}
		})
		t.Logf("trusted peer, no declared header, rotating XFF: admitted=%d/%d controlSecondRequest429=%v",
			admitted, spin, control)
		if !control {
			t.Fatalf("control failed: the same header value was not a single bucket")
		}
		if admitted != 0 {
			t.Errorf("rotating X-Forwarded-For bought %d requests without the header being declared: "+
				"the bucket key is caller-chosen", admitted)
		}
	})

	t.Run("trusted peer, declared header, proxy APPENDED the public client (the safe shape)", func(t *testing.T) {
		srv := zzServerMode(t, httpapi.ClientAddrXForwardedFor, "10.0.0.0/8")
		h := srv.Handler()
		admitted, control := run(t, h, "10.1.2.3:5555", func(i int) []string {
			return []string{fmt.Sprintf("198.51.100.%d, 203.0.113.9", i+1)}
		})
		t.Logf("trusted peer, appended public client: admitted=%d/%d controlSecondRequest429=%v", admitted, spin, control)
		if !control {
			t.Fatalf("control failed: an identical chain was not a single bucket")
		}
		if admitted != 0 {
			t.Errorf("the forged leftmost entry displaced the appended real client: %d admissions", admitted)
		}
		// And the appended address is the key: a second real client gets its own bucket.
		other := zzCallHandler(t, h, "10.1.2.3:5555", http.MethodGet, "/v1/me",
			"198.51.100.1, 203.0.113.10")
		if !zzAdmitted(other) {
			t.Errorf("a second real client behind the same proxy was refused (%d): the key is not the appended address", other)
		}
	})

	t.Run("trusted peer, declared header, proxy APPENDED a hop inside the trust list", func(t *testing.T) {
		h := zzServerMode(t, httpapi.ClientAddrXForwardedFor, "10.0.0.0/8").Handler()
		// What a chain looks like when the address the last proxy appended is one
		// of our own networks: a k8s Service with externalTrafficPolicy=Cluster
		// SNATs the client to the node IP, a service mesh or internal LB appends
		// itself; both are inside 10.0.0.0/8.
		admitted, control := run(t, h, "10.1.2.3:5555", func(i int) []string {
			return []string{fmt.Sprintf("198.51.100.%d, 10.0.0.5", i+1)}
		})
		t.Logf("trusted peer, appended trusted hop: admitted=%d/%d controlSecondRequest429=%v", admitted, spin, control)
		if !control {
			t.Fatalf("control failed: an identical chain was not a single bucket")
		}
		if admitted != 0 {
			t.Errorf("the walk stepped past our own proxy's entry to a caller-written one: %d admissions", admitted)
		}
	})

	t.Run("trusted peer, declared header, VERBATIM forwarding (the operator's residual)", func(t *testing.T) {
		// The declared setting asserts the nearest proxy rewrites or appends the
		// header. When it instead forwards the caller's own value verbatim — nginx
		// redefines only Host and Connection by default — the rightmost entry IS
		// the caller's text, and rotating it buys a bucket per request. Nothing in
		// a request can detect that, which is why the default reads no header:
		// this case asserts the residual rather than denying it.
		h := zzServerMode(t, httpapi.ClientAddrXForwardedFor, "10.0.0.0/8").Handler()
		admitted, control := run(t, h, "10.1.2.3:5555", func(i int) []string {
			return []string{fmt.Sprintf("198.51.100.%d", i+1)}
		})
		t.Logf("trusted peer, verbatim forwarding, rotating XFF: admitted=%d/%d controlSecondRequest429=%v",
			admitted, spin, control)
		if !control {
			t.Fatalf("control failed: the same header value was not a single bucket")
		}
		if admitted != spin {
			t.Errorf("expected the residual to admit every rotation (%d), got %d: the probe no longer "+
				"demonstrates what the default protects against", spin, admitted)
		}
	})
}

// TestV_PeerAddressAloneIsAKeySpaceOfItsOwn checks the half of HE-1 that needs no
// configuration at all: when the peer is not a trusted proxy the key IS the peer
// address, so a caller that can present many source addresses gets one full burst
// per address. The limiter caps how many keys it TRACKS; it cannot cap how many an
// attacker can present.
func TestV_PeerAddressAloneIsAKeySpaceOfItsOwn(t *testing.T) {
	h := zzServer(t).Handler()
	admitted := 0
	for i := 0; i < 50; i++ {
		peer := fmt.Sprintf("203.0.113.%d:4444", i+1)
		if zzAdmitted(zzCallHandler(t, h, peer, http.MethodGet, "/v1/me")) {
			admitted++
		}
	}
	t.Logf("no trust list, 50 distinct source addresses, one shared limiter: admitted=%d/50", admitted)
	if admitted != 50 {
		t.Errorf("expected one full burst per source address, got %d/50", admitted)
	}
}
