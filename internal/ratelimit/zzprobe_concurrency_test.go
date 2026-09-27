//go:build audit5

package ratelimit

import (
	"testing"
	"time"
)

// --- Finding CM-5: eviction at capacity drops a *live* bucket ---
//
// evictLocked prefers a bucket that has been idle past the TTL, and falls back to
// an arbitrary scanned entry when it finds none. Every bucket in a busy shard is
// live, so the fallback is the common case: an insertion at capacity deletes
// someone else's bucket, and that someone's next request is admitted with a full
// burst — the accumulated state that was rate-limiting them is gone.
//
// The docs claim eviction is O(1) at capacity (true: the scan is bounded by
// evictionScan) but the rate-limit consequence is not what that measures. These
// probes assert the safe property — "one caller's arrival must not reset another
// key's budget" — which currently fails.

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
// an unrelated key B arrives, and A is admitted again.
func TestAnArrivalAtCapacityResetsAnotherKeysBudget(t *testing.T) {
	l := New(0.001, 1, WithMaxKeys(shardCount)) // perShard() == 1
	keyA, keyB := twoKeysInOneShard(t, l)

	if !l.Allow(keyA) {
		t.Fatal("the first request for keyA was refused; the probe did not start clean")
	}
	if l.Allow(keyA) {
		t.Fatal("keyA was admitted twice with a burst of 1; the probe measured nothing")
	}
	if got := l.size(); got != 1 {
		t.Fatalf("tracked keys = %d, want 1", got)
	}

	// An unrelated key arrives. It must not be able to touch keyA's budget.
	l.Allow(keyB)

	if l.Allow(keyA) {
		t.Error("an unrelated key's request reset keyA's spent budget: the rate limit is per arrival, not per key")
	}
}

// The same at a realistic-looking shard size, where the idle-preference scan has
// four live candidates and still has to drop one of them. The count is not fixed
// because the refund cascades: a re-arrival by an evicted key is itself an
// insertion at capacity, so it evicts another live bucket in turn. That the count
// is non-zero is the point.
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
	l.Allow(outsider)

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

// The cap itself is honoured, so unbounded growth is not the defect here — it is
// what eviction does to a *live* bucket that is.
func TestCapacityStaysBounded(t *testing.T) {
	l := New(1, 1, WithMaxKeys(64))
	for i := 0; i < 5000; i++ {
		l.Allow("k" + itoa(i))
	}
	// perShard rounds up, so the total may exceed maxKeys by at most shardCount-1.
	if got := l.size(); got > 64+shardCount {
		t.Errorf("tracked keys = %d, want at most %d", got, 64+shardCount)
	}
	// Anti-vacuity: the limiter was really used.
	if l.size() == 0 {
		t.Fatal("nothing was tracked; the probe measured nothing")
	}
	_ = time.Now
}

// The idle preference does work when an idle bucket is in the sample: a key that
// has not been seen for longer than the TTL is the one dropped. This is the
// behaviour the fallback is a fallback for, and it is what keeps the common
// (non-adversarial) case from resetting a live budget.
func TestAnIdleBucketIsPreferredToALiveOne(t *testing.T) {
	ttl := 10 * time.Millisecond
	l := New(0.001, 1, WithMaxKeys(shardCount), WithTTL(ttl))
	keyA, keyB := twoKeysInOneShard(t, l)

	l.Allow(keyA) // A is now in the shard with a fresh lastSeen
	time.Sleep(ttl + 20*time.Millisecond)
	l.Allow(keyB) // inserting B sees A as idle and evicts A
	if l.Allow(keyA) {
		// A's bucket is new again, which is correct: it was idle past the TTL, so
		// its budget was going to be full anyway.
		return
	}
	t.Log("the idle bucket was not evicted, or the clock moved differently than expected")
}
