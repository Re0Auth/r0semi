//go:build audit5

package ratelimit

import (
	"testing"
	"time"
)

// --- Finding CM-5: eviction at capacity dropped a *live* bucket ---
//
// evictLocked preferred a bucket idle past the TTL, and fell back to an arbitrary
// scanned entry when it found none. Every bucket in a busy shard is live, so the
// fallback was the common case: an insertion at capacity deleted someone else's
// bucket, and that someone's next request was admitted with a full burst — the
// accumulated state that was rate-limiting them was gone. A caller who could vary
// its key therefore had an unlimited budget: every request arrived as a new key and
// every request reset somebody.
//
// These probes assert the safe property — "one caller's arrival must not reset
// another key's budget" — which is what the fail-closed rewrite now provides: a key
// that cannot be tracked shares its shard's overflow bucket (Verdict.Shared) and a
// bucket is reclaimed only when its owner provably loses nothing.

// twoKeysInOneShard finds two distinct keys that hash to the same shard, so the
// probes can force two keys to compete for one shard's capacity.
func twoKeysInOneShard(t *testing.T, l *Limiter) (string, string) {
	t.Helper()
	first := ""
	for i := 0; i < 100000; i++ {
		k := "key-" + string(rune('a'+i%26)) + "-" + itoa(i)
		if first == "" {
			first = k
			continue
		}
		if l.shardFor(k) == l.shardFor(first) {
			return first, k
		}
	}
	t.Fatal("no two keys collided in a shard; the probe could not set up")
	return "", ""
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

// With one slot per shard the mechanism is naked: key A spends its whole budget,
// an unrelated key B arrives, and A must NOT be admitted again.
func TestAnArrivalAtCapacityResetsAnotherKeysBudget(t *testing.T) {
	l := New(0.001, 1, WithMaxKeys(shardCount)) // perShard() == 1
	keyA, keyB := twoKeysInOneShard(t, l)

	if !l.Allow(keyA) {
		t.Fatal("the first request for keyA was refused; the probe did not start clean")
	}
	if l.Allow(keyA) {
		t.Fatal("keyA was admitted twice with a burst of 1; the probe measured nothing")
	}
	if got := l.Size(); got != 1 {
		t.Fatalf("tracked keys = %d, want 1", got)
	}

	// An unrelated key arrives. It cannot be tracked — the shard is full and keyA
	// is live — so it shares the overflow bucket.
	unrelated := l.Check(keyB)
	if !unrelated.Shared {
		t.Errorf("the unrelated key was given a bucket of its own; the shard is full and keyA is live: %+v", unrelated)
	}

	if l.Allow(keyA) {
		t.Error("an unrelated key's request reset keyA's spent budget: the rate limit is per arrival, not per key")
	}
	if got := l.Size(); got != 1 {
		t.Errorf("tracked keys = %d after the arrival, want 1: a live bucket was dropped", got)
	}
}

// The same at a realistic-looking shard size, where the reclaim scan has four live
// candidates and must not drop any of them.
func TestEvictionAtCapacityRefundsExhaustedKeys(t *testing.T) {
	const perShard = 4
	l := New(0.001, 1, WithMaxKeys(shardCount*perShard))

	// Fill one shard with keys that are all live (lastSeen = now).
	shardKeys := make([]string, 0, perShard)
	var shard *shard
	for i := 0; i < 200000 && len(shardKeys) < perShard; i++ {
		k := itoa(i) + "-fill"
		s := l.shardFor(k)
		if shard == nil {
			shard = s
		}
		if s != shard {
			continue
		}
		shardKeys = append(shardKeys, k)
	}
	if len(shardKeys) != perShard {
		t.Fatal("could not fill one shard; the probe measured nothing")
	}
	for _, k := range shardKeys {
		if !l.Allow(k) {
			t.Fatalf("key %q was refused while filling the shard", k)
		}
	}
	// Every one of them is now exhausted.
	for _, k := range shardKeys {
		if l.Allow(k) {
			t.Fatalf("key %q was admitted twice with a burst of 1", k)
		}
	}

	// One more arrival in the same shard, from a key that is not any of them.
	var outsider string
	for i := 0; i < 200000; i++ {
		k := itoa(i) + "-outsider"
		if l.shardFor(k) == shard && !contains(shardKeys, k) {
			outsider = k
			break
		}
	}
	if outsider == "" {
		t.Fatal("could not find an outsider key in the same shard")
	}
	if !l.Check(outsider).Shared {
		t.Error("the outsider did not share the overflow bucket: it displaced a live bucket instead")
	}
	if got := l.Size(); got != perShard {
		t.Errorf("tracked keys = %d, want %d: a live bucket was dropped for an outsider", got, perShard)
	}

	refunded := 0
	for _, k := range shardKeys {
		if l.Allow(k) {
			refunded++
		}
	}
	if refunded != 0 {
		t.Errorf("%d exhausted keys were handed a fresh burst by one unrelated arrival; want 0", refunded)
	}
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

// The cap itself is honoured, so unbounded growth is not the defect here — what
// eviction does to a *live* bucket was.
func TestCapacityStaysBounded(t *testing.T) {
	l := New(1, 1, WithMaxKeys(64))
	for i := 0; i < 5000; i++ {
		l.Allow("k" + itoa(i))
	}
	// perShard rounds up, so the total may exceed maxKeys by at most shardCount-1.
	if got := l.Size(); got > 64+shardCount {
		t.Errorf("tracked keys = %d, want at most %d", got, 64+shardCount)
	}
	// Anti-vacuity: the limiter was really used, and the keys past the cap are the
	// ones sharing the overflow bucket.
	if l.Size() == 0 {
		t.Fatal("nothing was tracked; the probe measured nothing")
	}
	if !l.Check("k4999").Shared {
		t.Error("the last key was tracked in a full table; the overflow path was not exercised")
	}
	_ = time.Now
}

// A bucket IS reclaimed when doing so is provably free: a key idle for longer than
// the reclaim window would be admitted with a full bucket either way, so dropping
// its bucket refunds nothing. That is what keeps the map self-cleaning in the
// common (non-adversarial) case, and it is the whole of what the old eviction was
// trying to do — the difference is that "idle past the TTL" was never the same
// property.
func TestAnIdleBucketIsReclaimedWhenNothingIsRefunded(t *testing.T) {
	// rate 100/s with burst 1: an empty bucket is full again in 10 ms, so the
	// reclaim window is 10 ms rather than the 1000 s the same burst would need at
	// the 0.001/s rate the probes above use.
	ttl := 10 * time.Millisecond
	l := New(100, 1, WithMaxKeys(shardCount), WithTTL(ttl))
	keyA, keyB := twoKeysInOneShard(t, l)

	l.Allow(keyA) // A is now in the shard with a fresh lastSeen, and is empty
	time.Sleep(ttl + 20*time.Millisecond)
	l.Allow(keyB) // inserting B reclaims A: it has been idle past the window
	if got := l.Size(); got != 1 {
		t.Errorf("tracked keys = %d, want 1: the idle bucket was not reclaimed", got)
	}
	if !l.Allow(keyA) {
		// A's bucket is new again, which is correct and free: it would have been
		// full at this moment anyway.
		t.Error("the reclaimed key was refused: reclaiming it refunded nothing, so it must be admitted")
	}
}
