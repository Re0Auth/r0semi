//go:build audit5

package verifycm

import (
	"testing"

	"github.com/Re0Auth/r0semi/internal/ratelimit"
)

// CM-5 quantification. The audited probe proves the mechanism with
// WithMaxKeys(shardCount), i.e. ONE slot per shard — a configuration no deployment
// has. This asks the question that decides the severity: with the shipped default
// (maxKeys = 10_000, i.e. 625 keys per shard), how many distinct keys must an
// attacker create before anybody's budget can be reset, and how many victims does
// one forced insertion take?
//
// evictLocked's logic does not consult the rate or the burst at all, so the probe
// uses burst 1 / rate ~0 to make "exhausted" deterministic and cheap; only maxKeys
// (the default) is under test.

const (
	shardCount     = 16
	defaultMaxKeys = 10_000
	perShard       = defaultMaxKeys / shardCount // 625, what Limiter.perShard computes
)

// shardOf replicates Limiter.shardFor (FNV-1a, 32-bit, modulo shardCount).
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
	return int(h % shardCount)
}

// keysInShard returns n distinct keys that all land in the given shard.
func keysInShard(shard, n int, tag string) []string {
	out := make([]string, 0, n)
	for i := 0; len(out) < n; i++ {
		k := tag + "-" + itoa(i)
		if shardOf(k) == shard {
			out = append(out, k)
		}
		if i > 10_000_000 {
			panic("no keys found for shard")
		}
	}
	return out
}

func exhaustAll(t *testing.T, l *ratelimit.Limiter, keys []string) {
	t.Helper()
	for _, k := range keys {
		if !l.Allow(k) {
			t.Fatalf("key %q was refused on its first request; the probe did not start clean", k)
		}
		if l.Allow(k) {
			t.Fatalf("key %q was admitted twice with a burst of 1", k)
		}
	}
}

func refunded(t *testing.T, l *ratelimit.Limiter, keys []string) []string {
	t.Helper()
	var out []string
	for _, k := range keys {
		if l.Allow(k) {
			out = append(out, k)
		}
	}
	return out
}

func TestCM5AtTheShippedCapEvictionNeedsHundredsOfKeysInOneShard(t *testing.T) {
	l := ratelimit.New(0.001, 1) // burst 1: "exhausted" is one extra call; maxKeys is the default

	// exactly perShard keys in one shard, plus one more to force the eviction
	keys := keysInShard(0, perShard+1, "fill")
	full, outsider := keys[:perShard], keys[perShard]

	// Below capacity nothing can be evicted: fill perShard-1 and spend them.
	exhaustAll(t, l, full[:perShard-1])
	last := full[perShard-1]
	if !l.Allow(last) {
		t.Fatal("the last slot was refused; the shard was not filled as intended")
	}
	if l.Allow(last) {
		t.Fatal("the last key was admitted twice with burst 1")
	}
	if got := refunded(t, l, full[:perShard-1]); len(got) != 0 {
		t.Errorf("%d keys below the cap were refunded by an insertion that did not need to evict: %v", len(got), got)
	}

	// At capacity: every bucket in the shard is live (lastSeen = now), so
	// evictLocked has no idle bucket to prefer and deletes one of them.
	l.Allow(outsider)

	victims := refunded(t, l, full)
	t.Logf("with the shipped default cap (%d keys/shard) one insertion at capacity reset the budget of %d of the %d "+
		"previously-exhausted keys in that shard; the victim is the first entry of a random %d-entry sample, so "+
		"which key is a lottery. Anyone has to hold %d live keys in ONE shard (out of %d tracked keys) before any "+
		"of this can happen, and the count above exceeds 1 only because re-admitting an evicted key is itself an "+
		"insertion at capacity, which evicts the next victim in turn",
		perShard, len(victims), len(full), 64, perShard, defaultMaxKeys)
	if len(victims) == 0 {
		t.Errorf("no key was refunded by an insertion at capacity: the probe did not reach evictLocked")
	}
	// The point of the cap: a handful of keys are affected, not the shard.
	if len(victims) > perShard/10 {
		t.Errorf("one insertion at capacity refunded %d of %d keys; that is not the bounded cascade the cap implies",
			len(victims), perShard)
	}
}

// The direction of the defect, which decides whether it is a security finding: a
// bucket is a *limit*, never a grant. Deleting one can only hand its owner a fresh
// burst — it can never deny anybody anything. So eviction loosens the limiter for a
// victim; it does not help an attacker, who needs no eviction at all: a per-key
// limiter is bypassed by using fresh keys, which is true at any capacity.
func TestCM5EvictionCanOnlyLoosenAndKeyRotationNeedsNoEviction(t *testing.T) {
	l := ratelimit.New(50, 100) // the shipped default

	// A caller that varies its key is never rate-limited by a per-key limiter,
	// whether or not eviction ever runs: 1000 fresh keys are 1000 full bursts well
	// below the 10 000-key cap, so no eviction is involved at all.
	const n = 1_000
	admitted := 0
	for i := 0; i < n; i++ {
		if l.Allow("rotating-" + itoa(i)) {
			admitted++
		}
	}
	if admitted != n {
		t.Errorf("only %d of %d fresh keys were admitted; the probe's premise is wrong", admitted, n)
	}
	t.Logf("%d/%d fresh keys admitted with the shipped default limiter and no eviction involved: "+
		"key rotation bypasses a per-key limiter on its own, so eviction is not what weakens it", admitted, n)
}
