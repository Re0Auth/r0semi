//go:build audit7

// Z11-4: the fail-closed overflow bucket is not per client. A single IPv6 /64
// fills every shard, and from then on EVERY caller whose key is not already in
// the table shares one bucket per shard with all the others — so one host denies
// login to every client it has not already seen, while tracked clients keep
// their own budget.
//
// The documented half (docs/operations-decision.md:49): "桶表满时不淘汰活桶：
// 新键共用一个兜底桶". What is not documented is WHO ends up in it and that the
// table can be held full by one machine: the key is `planeOf(path)|addr`
// (internal/httpapi/middleware.go:349) and addr is a single /128
// (internal/httpapi/clientaddr.go:70-82), so a /64 is 2^64 key spaces. Round 5's
// recheck recorded that amplification (CM-V1) but its fix direction was "the
// spray must buy no quota" — which the overflow bucket achieves, by converting
// the spray into collateral starvation of unrelated clients.
//
// The probe runs at the SHIPPED defaults (10000 keys, 16 shards, 625/shard) and
// uses only addresses inside one /64, so it is the production shape rather than a
// scaled-down model of it.
package zzprobe_z11resiliencedos

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/internal/ratelimit"
)

// z11FillPrefix is one IPv6 /64. Every key this probe creates is inside it, so
// the whole attack is available to a single host with a single delegated prefix.
const z11FillPrefix = "2001:db8:ff::/64"

func z11Key(i int, plane string) string {
	return plane + "|" + fmt.Sprintf("2001:db8:ff::%x", i)
}

// TestZ11OneIPv6Slash64DeniesEveryNewClient is red while the table can be filled
// by one prefix and the overflow buckets are shared.
func TestZ11OneIPv6Slash64DeniesEveryNewClient(t *testing.T) {
	// Production values: the shipped limiter is ratelimit.New(50, 100) with the
	// default 10_000-key cap (cmd/re0auth/main.go:224-229, internal/ratelimit).
	// The rate is pinched so that a spent bucket does not refill during the
	// probe; what the rate changes in production is only how often the attacker
	// must come back (50/s per draining address).
	const (
		probeRate  = 1e-6 // ~1e6 s to refill one token
		probeBurst = 2
	)
	l := ratelimit.New(probeRate, probeBurst)

	// Positive control: a fresh client on a fresh limiter is admitted, so a
	// denial below is the table being full and not the limiter being broken.
	control := ratelimit.New(probeRate, probeBurst)
	if v := control.Check("business|198.51.100.7"); !v.Allowed {
		t.Fatalf("the positive control was denied on an empty limiter (%+v): re-derive the probe", v)
	}

	// ---- one /64 fills every shard ---------------------------------------
	prefix := netip.MustParsePrefix(z11FillPrefix)
	tracked := make([]string, 0, l.MaxKeys())
	for i := 1; i <= 400_000 && l.Size() < l.MaxKeys(); i++ {
		k := z11Key(i, "business")
		before := l.Size()
		l.Allow(k)
		if now := l.Size(); now > before {
			tracked = append(tracked, k)
		}
	}
	if got := l.Size(); got != l.MaxKeys() {
		t.Fatalf("could not fill the bucket table from one /64: Size=%d want %d", got, l.MaxKeys())
	}
	for _, k := range tracked {
		addr := strings.TrimPrefix(k, "business|")
		a, err := netip.ParseAddr(addr)
		if err != nil {
			t.Fatalf("probe built an unparseable address %q: %v", addr, err)
		}
		if !prefix.Contains(a) {
			t.Fatalf("probe escaped its own /64 with %q", addr)
		}
	}
	t.Logf("%d tracked keys (the whole table) created from one /64 %s", len(tracked), z11FillPrefix)

	// ---- keep every shard's overflow bucket drained ----------------------
	// These are fresh keys: the table is full, so each one lands on the overflow
	// bucket of its shard instead of being tracked. Production needs 16 such
	// addresses at 50 req/s each; the probe only needs one pass because the rate
	// is pinched.
	for i := 400_001; i <= 900_000; i++ {
		l.Allow(z11Key(i, "business"))
	}

	// ---- what an unrelated new client gets, on every plane ---------------
	// Different address family, different prefix, every plane: all denied,
	// because the shard is chosen by hash and every shard is full.
	victims := []string{
		"business|198.51.100.7",
		"protocol|198.51.100.7",
		"browser|198.51.100.7",
		"business|2001:db8:1::5", // an unrelated IPv6 client
		"protocol|203.0.113.99",  // a different IPv4
	}
	denied, shared := 0, 0
	for _, k := range victims {
		v := l.Check(k)
		t.Logf("%-22s allowed=%-5v shared=%-5v remaining=%d", k, v.Allowed, v.Shared, v.Remaining)
		if !v.Allowed {
			denied++
		}
		if v.Shared {
			shared++
		}
	}
	if denied != len(victims) {
		t.Errorf("%d of %d brand-new clients were still admitted after one /64 filled the table: "+
			"re-derive the probe", len(victims)-denied, len(victims))
		return
	}
	if shared != len(victims) {
		t.Errorf("a new client was denied from its OWN bucket rather than the shared overflow bucket "+
			"(%d of %d shared): the mechanism is not the one this probe describes", shared, len(victims))
	}

	// ---- and a client that was already tracked keeps its own budget ------
	// This is the asymmetry that makes it a denial rather than a global outage
	// for everybody: the attacker's own keys are the ones that survive.
	if v := l.Check(tracked[0]); !v.Allowed || v.Shared {
		t.Errorf("an address the attacker tracked is not exempt from the starvation (allowed=%v shared=%v): "+
			"the probe's model of the sharing is wrong", v.Allowed, v.Shared)
	} else {
		t.Logf("tracked key %s still served from its own bucket (shared=%v)", tracked[0], v.Shared)
	}

	t.Errorf("one host with one IPv6 /64 filled all %d tracked buckets and kept every shard's overflow bucket "+
		"empty; every new client on every plane is then answered 429 (%d/%d denied, all shared). The fail-closed "+
		"answer to the key spray is one shared bucket PER SHARD with no per-client share, so the spray does not "+
		"buy quota — it buys denial of service against everyone the attacker has not already seen. Production "+
		"sustains it with 16 addresses at 50 req/s (one per shard) while 10000 one-request-per-10-min refreshes "+
		"hold the table full.", l.MaxKeys(), denied, len(victims))
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
