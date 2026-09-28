//go:build audit5

package verifyhttpedge

import (
	"fmt"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/internal/ratelimit"
)

// shardOf replicates Limiter.shardFor (FNV-1a, 32-bit, modulo 16) so the probe can
// aim its traffic at one shard instead of hoping. It is a copy of the ALGORITHM,
// not a shortcut around the assertion: every check below is on the observed effect
// (a bucket that was exhausted answers again), so a wrong copy makes this probe
// fail, not pass quietly.
func shardOf(key string) int {
	const (
		offset32 = 2166136261
		prime32  = 16777619
	)
	h := uint32(offset32)
	for i := 0; i < len(key); i++ {
		h ^= uint32(key[i])
		h *= prime32
	}
	return int(h % 16)
}

// keysInShard returns n distinct keys that all land in the given shard.
func keysInShard(shard, n int, tag string) []string {
	out := make([]string, 0, n)
	for i := 0; len(out) < n; i++ {
		k := fmt.Sprintf("%s-%d", tag, i)
		if shardOf(k) == shard {
			out = append(out, k)
		}
		if i > 5_000_000 {
			panic("keysInShard: no keys found")
		}
	}
	return out
}

// TestV_CapacityDoesNotDiscardALiveBucket is the deterministic form of HE-1's
// second half, asserted as the property that must hold. With WithMaxKeys(16) each
// shard holds one key, so a second key in the same shard cannot be tracked — the
// old code dropped the first one and re-created it full on its next request.
//
// The fix is fail-closed: the intruder shares the shard's overflow bucket, the
// victim's spent budget is untouched, and the table does not grow.
//
// (The audited probe proves the same mechanism at the SHIPPED capacity, 625 per
// shard, where it was probabilistic. This is the same code path with the
// probability removed.)
func TestV_CapacityDoesNotDiscardALiveBucket(t *testing.T) {
	l := ratelimit.New(0.001, 1, ratelimit.WithMaxKeys(16))
	keys := keysInShard(0, 2, "evict")
	victim, intruder := keys[0], keys[1]

	if !l.Allow(victim) {
		t.Fatalf("fresh limiter refused the first key; the probe did not start clean")
	}
	if l.Allow(victim) {
		t.Fatalf("the victim's bucket was not exhausted by its second request; nothing below is measurable")
	}
	if got := l.Size(); got != 1 {
		t.Fatalf("tracked keys = %d, want 1", got)
	}

	intrusion := l.Check(intruder)
	if !intrusion.Shared {
		t.Errorf("the intruder was given a bucket of its own at capacity: %+v", intrusion)
	}

	again := l.Allow(victim)
	t.Logf("maxKeys=16 (1 per shard): victim exhausted, then an unrelated key inserted, then victim again -> admitted=%v", again)
	if again {
		t.Errorf("the victim's spent bucket was discarded by an insertion at capacity: its budget was refunded")
	}
	if got := l.Size(); got != 1 {
		t.Errorf("tracked keys = %d, want 1: a live bucket was dropped for the intruder", got)
	}
}

// TestV_ReclaimOnlyDropsBucketsThatLoseNothing pins the condition the rewrite
// introduced, at both ends: a bucket may be reclaimed only when its owner's next
// request would be admitted with a full bucket either way.
//
//   - Fast refill (100/s with burst 1: an empty bucket is full again in 10 ms) and
//     a 50 ms TTL: an idle key is reclaimable, so the map still self-cleans.
//   - Slow refill (0.001/s: 1000 s to refill) with the same TTL: nothing is
//     reclaimable — a bucket idle for 80 ms still holds 0.08 of the token its owner
//     is owed — so the newcomer shares the overflow bucket and nobody is refunded.
func TestV_ReclaimOnlyDropsBucketsThatLoseNothing(t *testing.T) {
	t.Run("fast refill: an idle bucket is reclaimed, and its owner loses nothing", func(t *testing.T) {
		// WithMaxKeys(16): ONE slot per shard, so the newcomer can only be tracked by
		// reclaiming the idle one.
		l := ratelimit.New(100, 1, ratelimit.WithMaxKeys(16), ratelimit.WithTTL(50*time.Millisecond))
		keys := keysInShard(0, 2, "idle")
		idle, newcomer := keys[0], keys[1]

		if !l.Allow(idle) {
			t.Fatalf("first key refused")
		}
		time.Sleep(80 * time.Millisecond) // past both the TTL and the refill window
		if !l.Allow(newcomer) {
			t.Fatalf("the newcomer was refused at capacity")
		}
		if got := l.Size(); got != 1 {
			t.Errorf("tracked keys = %d, want 1: the reclaimable idle bucket was not reclaimed", got)
		}
		if !l.Allow(idle) {
			t.Errorf("the reclaimed key was refused: reclaiming it refunded nothing, so it must be admitted")
		}
	})

	t.Run("slow refill: nothing is reclaimable, so a live bucket survives", func(t *testing.T) {
		l := ratelimit.New(0.001, 1, ratelimit.WithMaxKeys(32), ratelimit.WithTTL(50*time.Millisecond))
		keys := keysInShard(0, 3, "slow")
		idle, live, newcomer := keys[0], keys[1], keys[2]

		if !l.Allow(idle) {
			t.Fatalf("first key refused")
		}
		time.Sleep(80 * time.Millisecond) // past the TTL, but nowhere near a refill
		if !l.Allow(live) || l.Allow(live) {
			t.Fatalf("the live key could not be exhausted")
		}
		if !l.Allow(newcomer) {
			t.Fatalf("the newcomer was refused at capacity")
		}
		if l.Allow(live) {
			t.Errorf("the live, exhausted bucket was discarded: its owner's spent budget came back")
		}
		if got := l.Size(); got != 2 {
			t.Errorf("tracked keys = %d, want 2: an unreclaimable bucket was dropped", got)
		}
	})
}

// TestV_WithNoReclaimableBucketTheArrivalIsShared is the branch that replaced the
// live-bucket deletion: when nothing in the scanned sample may be dropped, the
// newcomer shares its shard's overflow bucket — so TWO exhausted keys stay
// exhausted, and the arrival is served from a bucket that is not theirs.
func TestV_WithNoReclaimableBucketTheArrivalIsShared(t *testing.T) {
	l := ratelimit.New(0.001, 1, ratelimit.WithMaxKeys(32))
	keys := keysInShard(0, 3, "fallback")
	a, b, c := keys[0], keys[1], keys[2]

	for _, k := range []string{a, b} {
		if !l.Allow(k) {
			t.Fatalf("%q refused on its first request", k)
		}
		if l.Allow(k) {
			t.Fatalf("%q was not exhausted", k)
		}
	}
	if !l.Check(c).Shared {
		t.Errorf("the third key was tracked even though the shard is full and nothing is reclaimable")
	}
	revived := 0
	for _, k := range []string{a, b} {
		if l.Allow(k) {
			revived++
		}
	}
	t.Logf("no reclaimable candidate: %d of 2 exhausted buckets came back to life", revived)
	if revived != 0 {
		t.Errorf("expected no live bucket to be discarded, got %d revived", revived)
	}
	if got := l.Size(); got != 2 {
		t.Errorf("tracked keys = %d, want 2", got)
	}
}
