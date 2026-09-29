//go:build audit7

// Z11-4 verification from the HTTP side: the reviewed probe drives
// ratelimit.Limiter.Check directly, which is the same call the middleware makes
// (middleware.go:357) but not the same entry point. This probe mounts the real
// middleware chain with TrustedProxies + X-Forwarded-For, so the bucket keys are
// the ones production derives from the header rather than keys handed straight to
// the limiter. The guard is that one delegated IPv6 /64 consumes ONE bucket and
// cannot spend, or drain, any other client's budget.
package zzprobe_z11verify

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/Re0Auth/r0semi/internal/httpapi"
	"github.com/Re0Auth/r0semi/internal/ratelimit"
)

// z11vProxyAPI mounts the real API with the two deployment settings that make
// X-Forwarded-For the source of the bucket key: the test peer is declared a
// trusted proxy and the header is declared to carry the client address.
func z11vProxyAPI(t *testing.T, l *ratelimit.Limiter) *httptest.Server {
	t.Helper()
	api, err := httpapi.New(httpapi.Config{
		Issuer:            "https://re0auth.test",
		OIDC:              stubOIDC,
		TokenIntrospector: stubIntrospector{},
		GrantStore:        stubGrants{},
		DeviceStore:       stubDevices{},
		Limiter:           l,
		// httptest's peer is 127.0.0.1, so trusting 127.0.0.0/8 makes the
		// rightmost X-Forwarded-For hop the client the limiter keys on.
		TrustedProxies:   []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
		ClientAddrHeader: httpapi.ClientAddrXForwardedFor,
	})
	if err != nil {
		t.Fatalf("httpapi.New: %v", err)
	}
	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)
	return srv
}

// z11vGet sends the request production derives a bucket key from: a GET with the
// client address in X-Forwarded-For, through the real chain.
func z11vGet(t *testing.T, url, client string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("X-Forwarded-For", client)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode
}

// z11vAddrIn returns the i'th distinct /128 inside p. The first eight bytes stay
// p's network address, so every address it returns is provably inside p's /64.
func z11vAddrIn(p netip.Prefix, i int) netip.Addr {
	b := p.Masked().Addr().As16()
	b[14] = byte(i >> 8)
	b[15] = byte(i)
	return netip.AddrFrom16(b)
}

// TestZ11VOneIPv6Slash64CannotStarveUnrelatedClients is red if aggregateClientKey
// stops coarsening an IPv6 client key to its /64: many distinct /128s inside one
// /64 would then become many buckets, spend many budgets, and the table size
// assertion (want exactly 1) fails — while the deployed limiter was fillable from
// a single delegated prefix.
func TestZ11VOneIPv6Slash64CannotStarveUnrelatedClients(t *testing.T) {
	const rate = 1e-6 // one token per ~11.6 days: no refill during the probe
	const distinct = 200

	one := netip.MustParsePrefix("2001:db8:ff::/64")
	other := netip.MustParsePrefix("2001:db8:fe::/64")
	unrelatedV4 := netip.MustParseAddr("203.0.113.7")

	// Positive control: on an unsaturated limiter the request shape used below is
	// not a 429 (it is the business plane's 401), so a 429 below is attributable
	// to the table, not the request.
	fresh := z11vProxyAPI(t, ratelimit.New(rate, 2))
	freshCode := z11vGet(t, fresh.URL+"/v1/me", z11vAddrIn(one, 0).String())
	t.Logf("positive control (unsaturated limiter, X-Forwarded-For /128): /v1/me = %d", freshCode)
	if freshCode != http.StatusUnauthorized {
		t.Fatalf("the control answered %d, want 401: the probe cannot attribute a 429 below to the table", freshCode)
	}

	l := ratelimit.New(rate, 2)
	srv := z11vProxyAPI(t, l)

	// Drive the REAL chain from many DISTINCT /128s that all share one /64.
	admitted := 0
	for i := 0; i < distinct; i++ {
		if code := z11vGet(t, srv.URL+"/v1/me", z11vAddrIn(one, i).String()); code != http.StatusTooManyRequests {
			admitted++
		}
	}
	if got := l.Size(); got != 1 {
		t.Errorf("bucket table holds %d keys after %d distinct /128s inside one /64, want exactly 1: "+
			"aggregateClientKey is not coarsening IPv6 to /64, so one delegated prefix can fill all %d buckets "+
			"and starve unrelated clients", got, distinct, l.MaxKeys())
	}
	if admitted != 2 {
		t.Errorf("%d of %d requests from one /64 were admitted, want exactly the shared burst of 2: the /64 did "+
			"not consume one budget", admitted, distinct)
	}

	// The /64's shared budget is exhausted: a further, never-seen /128 in the same
	// prefix must not be treated as a fresh client. This also fails under a revert,
	// where each /128 is its own full bucket.
	if code := z11vGet(t, srv.URL+"/v1/me", z11vAddrIn(one, 100_000).String()); code != http.StatusTooManyRequests {
		t.Errorf("a fresh /128 inside the saturated /64 was answered %d, want 429: the /64 did not consume one "+
			"shared budget", code)
	}

	// Starvation is not transferred: an unrelated client the table has never seen
	// still draws from its own bucket.
	if code := z11vGet(t, srv.URL+"/v1/me", z11vAddrIn(other, 0).String()); code != http.StatusUnauthorized {
		t.Errorf("an unrelated IPv6 /64 was answered %d after one /64 exhausted its own budget, want 401 (admitted): "+
			"the starvation spread to a different prefix", code)
	}
	if code := z11vGet(t, srv.URL+"/v1/me", unrelatedV4.String()); code != http.StatusUnauthorized {
		t.Errorf("an unrelated IPv4 client was answered %d after one /64 exhausted its own budget, want 401 "+
			"(admitted): the starvation spread across address families", code)
	}
}
