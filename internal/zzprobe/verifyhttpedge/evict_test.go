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

// TestV_CapacityEvictionDiscardsALiveBucket is the deterministic form of HE-1's
// second half. With WithMaxKeys(16) each shard holds one key, so inserting a
// second key in the same shard MUST evict the first — there is nowhere else to
// put it. The question is what happens to a bucket whose caller has just spent its
// last token: this probe shows it is dropped and re-created full.
//
// (The audited probe proves the same mechanism at the SHIPPED capacity, 625 per
// shard, where it is probabilistic. This is the same code path with the
// probability removed.)
func TestV_CapacityEvictionDiscardsALiveBucket(t *testing.T) {
	l := ratelimit.New(0.001, 1, ratelimit.WithMaxKeys(16))
	keys := keysInShard(0, 2, "evict")
	victim, intruder := keys[0], keys[1]

	if !l.Allow(victim) {
		t.Fatalf("fresh limiter refused the first key; the probe did not start clean")
	}
	if l.Allow(victim) {
		t.Fatalf("the victim's bucket was not exhausted by its second request; nothing below is measurable")
	}
	if !l.Allow(intruder) {
		t.Fatalf("the second key in the shard was refused on its first request")
	}
	again := l.Allow(victim)
	t.Logf("maxKeys=16 (1 per shard): victim exhausted, then an unrelated key inserted, then victim again -> admitted=%v", again)
	if !again {
		t.Errorf("the victim's spent bucket survived an insertion at capacity; the eviction path changed")
	}
}

// TestV_EvictionPrefersAnIdleBucketToALiveOne checks the direction the report
// describes but does not test: at capacity, the scan prefers a bucket past its TTL,
// so a LIVE bucket is only discarded when no idle one is in the sample.
func TestV_EvictionPrefersAnIdleBucketToALiveOne(t *testing.T) {
	l := ratelimit.New(0.001, 1, ratelimit.WithMaxKeys(32), ratelimit.WithTTL(50*time.Millisecond))
	keys := keysInShard(0, 3, "idle")
	idle, live, newcomer := keys[0], keys[1], keys[2]

	if !l.Allow(idle) {
		t.Fatalf("first key refused")
	}
	time.Sleep(80 * time.Millisecond) // the idle key is now past the TTL
	if !l.Allow(live) || l.Allow(live) {
		t.Fatalf("the live key could not be exhausted")
	}
	if !l.Allow(newcomer) {
		t.Fatalf("the newcomer was refused at capacity")
	}
	if l.Allow(live) {
		t.Errorf("an IDLE bucket was available but the live, exhausted bucket was discarded instead")
	}
	if !l.Allow(idle) {
		t.Errorf("the idle bucket was not the one discarded (it still answers): the scan did not prefer it")
	}
	t.Logf("at capacity with one idle and one live bucket: the idle one was discarded, the exhausted one stayed exhausted")
}

// TestV_WithNoIdleBucketALiveOneIsDeleted is the fallback branch: when none of the
// scanned entries is past its TTL, one live bucket is deleted anyway. Exactly one
// of two exhausted keys therefore comes back to life — and nothing in the limiter
// reports it.
func TestV_WithNoIdleBucketALiveOneIsDeleted(t *testing.T) {
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
	if !l.Allow(c) {
		t.Fatalf("the third key was refused at capacity")
	}
	revived := 0
	for _, k := range []string{a, b} {
		if l.Allow(k) {
			revived++
		}
	}
	t.Logf("no idle candidate: %d of 2 exhausted buckets were silently replaced by full ones", revived)
	if revived != 1 {
		t.Errorf("expected exactly one live bucket to be discarded, got %d", revived)
	}
}
