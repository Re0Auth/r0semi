//go:build audit7

// Z11-4 regression guard: IPv6 client keys are aggregated to their /64 for
// rate-limit buckets, so a single delegated /64 cannot fill the bucket table and
// starve unrelated clients.
//
// The defect keyed every /128 separately. One host with one /64 therefore had
// 2^64 key spaces, filled every shard from that single prefix, and from then on
// EVERY caller the limiter had not already seen shared a drained overflow bucket —
// anonymous denial of service against unrelated clients, silent because the probes
// stayed green.
//
// The fix lives in the HTTP layer, not in the transport-agnostic limiter:
// `bucketKey` calls `aggregateClientKey` (internal/httpapi/middleware.go), which
// coarsens an IPv6 client key to its /64. This guard therefore drives the REAL
// middleware chain — with the deployment's trusted-proxy + X-Forwarded-For
// attribution, which is the configuration in which the bucket key is exercised for
// an arbitrary address — and varies only the /128 inside one /64. It was formerly
// TestZ11OneIPv6Slash64DeniesEveryNewClient, which drove ratelimit.Check with raw
// /128 strings and bypassed the layer the fix lives at.
package zzprobe_z11resiliencedos

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/Re0Auth/r0semi/internal/httpapi"
	"github.com/Re0Auth/r0semi/internal/ratelimit"
)

// z11FillPrefix is one IPv6 /64. Every address this guard creates is inside it, so
// the whole subject is available to a single host with a single delegated prefix.
const z11FillPrefix = "2001:db8:ff::/64"

func z11Key(i int, plane string) string {
	return plane + "|" + fmt.Sprintf("2001:db8:ff::%x", i)
}

// z11ForwardingAPI mounts the real httpapi chain with X-Forwarded-For attribution,
// which is the only configuration in which the middleware's own bucketKey (and
// therefore its /64 aggregation) is driven for a caller-chosen address. The
// loopback peer is declared a trusted proxy so the header is read.
func z11ForwardingAPI(t *testing.T, l *ratelimit.Limiter) *httptest.Server {
	t.Helper()
	api, err := httpapi.New(httpapi.Config{
		Issuer:            "https://re0auth.test",
		OIDC:              stubOIDC,
		TokenIntrospector: stubIntrospector{},
		GrantStore:        stubGrants{},
		DeviceStore:       stubDevices{},
		Limiter:           l,
		TrustedProxies:    []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
		ClientAddrHeader:  httpapi.ClientAddrXForwardedFor,
	})
	if err != nil {
		t.Fatalf("httpapi.New: %v", err)
	}
	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)
	return srv
}

// z11StatusXFF performs one business-plane request attributed to xff and returns
// the status. On this plane an admitted request is the business 401 (no bearer),
// and a rate-limited one is 429.
func z11StatusXFF(t *testing.T, base, xff string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, base+"/v1/me", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Forwarded-For", xff)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /v1/me as %s: %v", xff, err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

// TestZ11OneIPv6Slash64CannotFillTheBucketTable is green only while the
// middleware's bucket key aggregates IPv6 to /64: many distinct /128 addresses in
// one /64 share one bucket (so they cannot fill the table), and an unrelated client
// is still served.
func TestZ11OneIPv6Slash64CannotFillTheBucketTable(t *testing.T) {
	// Cache-only limiter (1e-6/s): a spent bucket does not refill during the probe.
	const (
		probeRate  = 1e-6
		probeBurst = 2
	)
	l := ratelimit.New(probeRate, probeBurst)

	// Positive control: on an unsaturated limiter the request shape is the business
	// plane's 401, not a 429, so a 429 below is the shared bucket and not a broken
	// chain.
	fresh := z11ForwardingAPI(t, ratelimit.New(probeRate, probeBurst))
	if code := z11StatusXFF(t, fresh.URL, "198.51.100.7"); code != http.StatusUnauthorized {
		t.Fatalf("control: an unsaturated limiter answered %d, want 401: re-derive the guard", code)
	}

	srv := z11ForwardingAPI(t, l)

	// Many DISTINCT /128 addresses inside ONE /64. With the /64 aggregation they
	// are one bucket: exactly the first `probeBurst` are admitted and every later
	// one shares its drained budget.
	const distinct = 200
	prefix := netip.MustParsePrefix(z11FillPrefix)
	admitted, denied := 0, 0
	for i := 1; i <= distinct; i++ {
		addr := fmt.Sprintf("2001:db8:ff::%x", i)
		if a, err := netip.ParseAddr(addr); err != nil || !prefix.Contains(a) {
			t.Fatalf("probe built an address outside its own /64: %q (err=%v)", addr, err)
		}
		switch code := z11StatusXFF(t, srv.URL, addr); code {
		case http.StatusUnauthorized:
			admitted++
		case http.StatusTooManyRequests:
			denied++
		default:
			t.Fatalf("GET /v1/me as %s = %d: unexpected status", addr, code)
		}
	}
	if got := l.Size(); got != 1 {
		t.Errorf("one /64 created %d tracked buckets after %d distinct /128 addresses (want 1): the "+
			"middleware's bucket key no longer aggregates IPv6 to /64, so one prefix has 2^64 key spaces and "+
			"can fill all %d buckets", got, distinct, l.MaxKeys())
	}
	if admitted != probeBurst {
		t.Errorf("%d of %d distinct /128 addresses inside one /64 were admitted, want exactly the %d-token "+
			"burst: they are not sharing one bucket", admitted, distinct, probeBurst)
	}
	if denied != distinct-probeBurst {
		t.Errorf("%d of %d distinct /128 addresses inside one /64 were denied, want %d: they are not sharing "+
			"one bucket", denied, distinct, distinct-probeBurst)
	}

	// An unrelated new client — a different /64 and two IPv4 addresses — is still
	// served: the /64 filled 1 of MaxKeys buckets, so no shard is full and no
	// overflow bucket is in use.
	for _, xff := range []string{"2001:db8:1::5", "198.51.100.7", "203.0.113.99"} {
		if code := z11StatusXFF(t, srv.URL, xff); code != http.StatusUnauthorized {
			t.Errorf("an unrelated new client (%s) was answered %d after one /64 filled only 1 of %d buckets: "+
				"the /64 is starving clients it has never seen", xff, code, l.MaxKeys())
		} else {
			t.Logf("unrelated client %s still served (%d)", xff, code)
		}
	}
	t.Logf("one /64 contributed 1 tracked bucket of %d after %d distinct /128 addresses: %d admitted (burst %d), "+
		"%d rate-limited from the same shared bucket", l.MaxKeys(), distinct, admitted, probeBurst, denied)
}

// TestZ11AtCapacityTheTableStaysBounded is the green half: the spray really does
// not grow the table and really does not refund anyone's quota, which is what
// Z11-4 must not be read as contradicting.
func TestZ11AtCapacityTheTableStaysBounded(t *testing.T) {
	l := ratelimit.New(1e-6, 1, ratelimit.WithMaxKeys(16)) // one slot per shard
	for i := 1; i <= 5000; i++ {
		l.Allow(z11Key(i, "business"))
	}
	if got := l.Size(); got != 16 {
		t.Errorf("Size()=%d after 5000 distinct keys from one /64: the table is not bounded", got)
	}
}
