//go:build audit5

package verifyhttpedge

import (
	"fmt"
	"net/http"
	"net/netip"
	"testing"

	"github.com/Re0Auth/r0semi/internal/httpapi"
	"github.com/Re0Auth/r0semi/internal/ratelimit"
)

// The dedicated guard for P0-4, on the real HTTP plane: a rate-limit bucket key
// must not be something the caller writes, and a bucket that still holds quota must
// never be discarded.
//
// The finding: with `trusted_proxies` configured, the key came from a
// right-to-left walk of X-Forwarded-For that stopped at the first hop outside the
// trust list — which is a value the caller can write whenever the proxy forwards
// the caller's own header verbatim (nginx's default) or the appended hop is itself
// inside the trust list (SNAT, a mesh, an internal LB). "Every hop is trusted" was
// worse: it returned the LEFTMOST entry. On top of that, an insertion at the
// bucket-table cap evicted a LIVE bucket and re-created it with a full burst, so a
// caller with a controllable key space got a fresh quota per request — measured at
// `rate=0.001/s`: 20000 distinct values, 20000 admissions, 0 refusals.
//
// Both halves are asserted here. Part A is the key derivation, with a control
// showing the header still works when the deployment declares a proxy that appends.
// Part B is the capacity behaviour, driven end to end, with the limiter's own size
// observable to prove nothing was dropped for the newcomer.
func TestZZProbeRateLimitKeyCannotBeChosen(t *testing.T) {
	const peer = "10.1.2.3:5555" // our own proxy
	const trusted = "10.0.0.0/8"

	// admitted rotates one claimed address through one TCP peer and reports how many
	// requests the limiter let through beyond the first, plus whether the one-key
	// control held (the same value twice must be refused, or the header is not being
	// read and the count means nothing).
	admitted := func(t *testing.T, mode httpapi.ClientAddrHeader, mk func(i int) []string) (int, bool) {
		t.Helper()
		h := zzServerMode(t, mode, trusted).Handler()
		call := func(i int) int {
			return zzCallHandler(t, h, peer, http.MethodGet, "/v1/me", mk(i)...)
		}
		if first := call(0); first == http.StatusTooManyRequests {
			t.Fatalf("control: the first request was refused (%d); the limiter is not wired", first)
		}
		control := call(0) == http.StatusTooManyRequests
		n := 0
		for i := 1; i <= 20; i++ {
			if zzAdmitted(call(i)) {
				n++
			}
		}
		return n, control
	}

	t.Run("A1 no declaration: rotating the header buys nothing", func(t *testing.T) {
		n, control := admitted(t, httpapi.ClientAddrPeer, func(i int) []string {
			return []string{fmt.Sprintf("198.51.100.%d", i+1)}
		})
		if !control {
			t.Fatalf("control failed: an identical value was not one bucket")
		}
		if n != 0 {
			t.Errorf("rotating X-Forwarded-For bought %d requests without the header being declared: "+
				"the bucket key is caller-chosen", n)
		}
		t.Logf("no declaration: admitted=%d/20", n)
	})

	t.Run("A2 declared header, appending proxy: the left of our own entry is the caller's", func(t *testing.T) {
		n, control := admitted(t, httpapi.ClientAddrXForwardedFor, func(i int) []string {
			return []string{fmt.Sprintf("198.51.100.%d, 203.0.113.9", i+1)}
		})
		if !control {
			t.Fatalf("control failed: an identical chain was not one bucket")
		}
		if n != 0 {
			t.Errorf("the forged leftmost entry displaced the appended real client: %d admissions", n)
		}
		t.Logf("declared header, appending proxy: admitted=%d/20", n)
	})

	t.Run("A3 declared header, appended hop inside the trust list: the peer, not the caller's entry", func(t *testing.T) {
		n, control := admitted(t, httpapi.ClientAddrXForwardedFor, func(i int) []string {
			return []string{fmt.Sprintf("198.51.100.%d, 10.9.9.9", i+1)}
		})
		if !control {
			t.Fatalf("control failed: an identical chain was not one bucket")
		}
		if n != 0 {
			t.Errorf("the walk stepped past our own proxy's entry to a caller-written one: %d admissions", n)
		}
		t.Logf("declared header, appended trusted hop: admitted=%d/20", n)
	})

	t.Run("A4 control: two real clients behind an appending proxy keep their own buckets", func(t *testing.T) {
		h := zzServerMode(t, httpapi.ClientAddrXForwardedFor, trusted).Handler()
		first := zzCallHandler(t, h, peer, http.MethodGet, "/v1/me", "198.51.100.1, 203.0.113.9")
		second := zzCallHandler(t, h, peer, http.MethodGet, "/v1/me", "198.51.100.2, 203.0.113.10")
		again := zzCallHandler(t, h, peer, http.MethodGet, "/v1/me", "198.51.100.1, 203.0.113.9")
		if !zzAdmitted(first) || !zzAdmitted(second) {
			t.Errorf("two distinct real clients were refused (%d, %d): the declaration broke attribution", first, second)
		}
		if zzAdmitted(again) {
			t.Errorf("the first client was admitted twice with a burst of 1: its bucket did not follow it")
		}
	})

	// --- Part B: a bucket that still holds quota is never discarded -------------

	t.Run("B1 a spray cannot refund an exhausted key", func(t *testing.T) {
		// One slot per shard, so a handful of keys reach the cap.
		lim := ratelimit.New(zzNoRefill, 1, ratelimit.WithMaxKeys(16))
		srv := zzNewWithLimiter(t, lim, httpapi.ClientAddrXForwardedFor)
		h := srv.Handler()

		const victim = "203.0.113.20"
		if got := zzCallHandler(t, h, peer, http.MethodGet, "/v1/me", victim); !zzAdmitted(got) {
			t.Fatalf("the victim's first request was refused (%d)", got)
		}
		if got := zzCallHandler(t, h, peer, http.MethodGet, "/v1/me", victim); zzAdmitted(got) {
			t.Fatalf("the victim was admitted twice with a burst of 1 (%d)", got)
		}
		sizeBefore := lim.Size()

		// Fill the victim's shard with keys of the caller's choosing, then ask as the
		// victim again. Under the old code the insertion at capacity dropped the
		// victim's bucket and served it as if it had spent nothing.
		for _, k := range zzKeysInVictimShard(victim, 64) {
			zzCallHandler(t, h, peer, http.MethodGet, "/v1/me", k)
		}
		if got := zzCallHandler(t, h, peer, http.MethodGet, "/v1/me", victim); zzAdmitted(got) {
			t.Errorf("a key spray refunded the victim's spent budget: its request answered %d, want 429", got)
		}
		if got := lim.Size(); got != sizeBefore {
			t.Errorf("tracked keys = %d after the spray, want %d: a live bucket was dropped for the newcomer",
				got, sizeBefore)
		}
		t.Logf("victim stays exhausted after a 64-key spray in its own shard; tracked keys %d", lim.Size())
	})

	t.Run("B2 the table stays bounded and the surplus shares one bucket", func(t *testing.T) {
		lim := ratelimit.New(zzNoRefill, 1, ratelimit.WithMaxKeys(16))
		srv := zzNewWithLimiter(t, lim, httpapi.ClientAddrXForwardedFor)
		h := srv.Handler()

		// 2000 distinct claimed clients: far more than the 16-key cap.
		for i := 0; i < 2000; i++ {
			zzCallHandler(t, h, peer, http.MethodGet, "/v1/me", zzRotatingAddr(i))
		}
		if got := lim.Size(); got > 16 {
			t.Errorf("tracked keys = %d, want at most 16: the table grew past its cap", got)
		}
		if lim.Size() == 0 {
			t.Fatal("nothing was tracked; the probe is vacuous")
		}
		t.Logf("2000 rotating clients against a 16-key cap: tracked keys %d", lim.Size())
	})
}

// zzKeysInVictimShard returns n claimed addresses whose limiter key lands in the
// same shard as the victim's. The key is plane|address, so the shard is computed on
// the whole string — the same input shardFor sees.
func zzKeysInVictimShard(victim string, n int) []string {
	want := shardOf("business|" + victim)
	out := make([]string, 0, n)
	for i := 0; len(out) < n && i < 5_000_000; i++ {
		k := zzRotatingAddr(i)
		if k == victim {
			continue
		}
		if shardOf("business|"+k) == want {
			out = append(out, k)
		}
	}
	return out
}

// zzRotatingAddr is one of many distinct, readable, public addresses a caller can
// claim when the deployment reads the header.
func zzRotatingAddr(i int) string {
	return fmt.Sprintf("198.18.%d.%d", i/250, i%250+1)
}

// zzNewWithLimiter is zzNew with the limiter passed in, so the probe can read the
// table's size after a spray.
func zzNewWithLimiter(t *testing.T, lim *ratelimit.Limiter, mode httpapi.ClientAddrHeader) *httpapi.Server {
	t.Helper()
	srv, err := httpapi.New(httpapi.Config{
		Issuer:            "https://op.verify.test",
		OIDC:              http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }),
		TokenIntrospector: stubIntrospector{},
		GrantStore:        stubGrants{},
		DeviceStore:       stubDevices{},
		TrustedProxies:    []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		ClientAddrHeader:  mode,
		Limiter:           lim,
	})
	if err != nil {
		t.Fatalf("httpapi.New: %v", err)
	}
	return srv
}
