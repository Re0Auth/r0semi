//go:build audit5

package verifycm

import (
	"testing"

	"github.com/Re0Auth/r0semi/internal/ratelimit"
)

// CM-5 quantification, asserted as the property the rewrite provides. The audited
// probe proves the old mechanism with WithMaxKeys(shardCount), i.e. ONE slot per
// shard — a configuration no deployment has. This asks the question that decides
// the severity: with the shipped default (maxKeys = 10_000, i.e. 625 keys per
// shard), how many distinct keys must a caller create before anybody's budget can
// be reset?
//
// The answer is now "none, ever": an insertion at capacity that cannot reclaim a
// bucket the caller provably loses nothing by drops NOTHING, and the newcomer
// shares the shard's overflow bucket. The rate and the burst are irrelevant to
// that decision, so the probe uses burst 1 / rate ~0 to make "exhausted"
// deterministic and cheap; only maxKeys (the default) is under test.

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

func TestCM5AtTheShippedCapNoInsertionCanResetAnotherKeysBudget(t *testing.T) {
	l := ratelimit.New(0.001, 1) // burst 1: "exhausted" is one extra call; maxKeys is the default

	// exactly perShard keys in one shard, plus one more to force the insertion at
	// capacity
	keys := keysInShard(0, perShard+1, "fill")
	full, outsider := keys[:perShard], keys[perShard]

	// Below capacity nothing can be reclaimed: fill perShard-1 and spend them.
	exhaustAll(t, l, full[:perShard-1])
	last := full[perShard-1]
	if !l.Allow(last) {
		t.Fatal("the last slot was refused; the shard was not filled as intended")
	}
	if l.Allow(last) {
		t.Fatal("the last key was admitted twice with burst 1")
	}
	if got := refunded(t, l, full[:perShard-1]); len(got) != 0 {
		t.Errorf("%d keys below the cap were refunded by an insertion that did not need to reclaim: %v", len(got), got)
	}

	// At capacity: every bucket in the shard is live (lastSeen = now) and, at this
	// rate, none of them is reclaimable — so the outsider must share the overflow
	// bucket rather than displace anyone.
	if !l.Check(outsider).Shared {
		t.Errorf("the outsider was tracked at capacity: the overflow path is gone")
	}

	victims := refunded(t, l, full)
	t.Logf("with the shipped default cap (%d keys/shard) one insertion at capacity reset the budget of %d of the %d "+
		"previously-exhausted keys in that shard; the newcomer now shares the shard's overflow bucket instead, so the "+
		"count is zero at every capacity and no key spray can refund anybody",
		perShard, len(victims), len(full))
	if len(victims) != 0 {
		t.Errorf("%d keys were refunded by an insertion at capacity: a key spray still resets budgets", len(victims))
	}
	if got := l.Size(); got != perShard {
		t.Errorf("tracked keys = %d, want %d: the table grew at its cap", got, perShard)
	}
}

// The direction of the old defect, which decided its severity: a bucket is a
// *limit*, never a grant. Deleting one could only hand its owner a fresh burst — it
// could never deny anybody anything. The caller who varies its key never needed
// eviction at all: a per-key limiter is bypassed by using fresh keys, which is true
// at any capacity, and that is what the HTTP layer's key derivation now prevents
// (see the P0-4 probes in internal/httpapi and internal/zzprobe/verifyhttpedge).
//
// This case pins the boundary: below the table's cap, fresh keys are still admitted
// (the limiter is a limiter, not a whitelist); once a shard is full, every further
// key shares ONE bucket, so the spray is bounded by that bucket's burst instead of
// by one burst per invented key.
func TestCM5KeyRotationPaysOnlyUntilTheTableIsFull(t *testing.T) {
	l := ratelimit.New(50, 100) // the shipped default

	// 1000 fresh keys are 1000 full bursts well below the 10 000-key cap.
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
	t.Logf("%d/%d fresh keys admitted with the shipped default limiter, well below the %d-key cap",
		admitted, n, defaultMaxKeys)

	// One shard, filled to its cap: WithMaxKeys(shardCount) puts one slot in it.
	const burst = 100
	small := ratelimit.New(0.001, burst, ratelimit.WithMaxKeys(shardCount))
	slot := keysInShard(0, 1, "slot")[0]
	if !small.Allow(slot) {
		t.Fatal("the shard's single slot was refused")
	}
	spray := keysInShard(0, 500, "rot")
	fromShared, shared := 0, true
	for _, k := range spray {
		v := small.Check(k)
		if v.Allowed {
			fromShared++
		}
		if !v.Shared {
			shared = false
		}
	}
	if !shared {
		t.Errorf("a fresh key was tracked in a full shard: an insertion at capacity created a bucket again")
	}
	t.Logf("one shard at its cap: %d of %d rotated keys admitted, all from ONE shared bucket of burst %d",
		fromShared, len(spray), burst)
	if fromShared == 0 {
		t.Error("the shared bucket admitted nothing; the probe is vacuous")
	}
	if fromShared > burst {
		t.Errorf("the rotation was admitted %d times against one shared burst of %d: each key still buys its own budget",
			fromShared, burst)
	}
}
