package ratelimit

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAllowEnforcesBurstThenRefills(t *testing.T) {
	l := New(100, 2) // 100 events/second, burst 2

	if !l.Allow("a") {
		t.Fatal("the first burst token was refused")
	}
	if !l.Allow("a") {
		t.Fatal("the second burst token was refused")
	}
	if l.Allow("a") {
		t.Fatal("allowed beyond the burst")
	}
	// The refusal has to carry the wait, because the verdict is where the HTTP
	// layer's Retry-After comes from.
	if after := l.Check("a").Reset; after <= 0 || after > 100*time.Millisecond {
		t.Fatalf("Reset = %v, want (0, 100ms]", after)
	}

	// 50ms at 100/s is five tokens, comfortably more than the one needed.
	time.Sleep(50 * time.Millisecond)
	if !l.Allow("a") {
		t.Fatal("did not refill after the interval")
	}
}

func TestKeysAreIndependent(t *testing.T) {
	l := New(0.001, 1) // effectively no refill during the test
	if !l.Allow("a") {
		t.Fatal("first request for a was refused")
	}
	if l.Allow("a") {
		t.Fatal("second request for a was allowed")
	}
	if !l.Allow("b") {
		t.Fatal("b was throttled by a's bucket")
	}
}

// A key nobody has seen is admitted with a full bucket; the verdict reports the
// budget left after this request and, once the bucket is empty, the wait that the
// Retry-After header is made from. All of it comes out of one call, which is what
// lets the HTTP layer fill its headers and its decision from one read.
func TestCheckReportsTheBudgetAndTheWait(t *testing.T) {
	l := New(0.001, 2) // two tokens, effectively no refill during the test

	first := l.Check("brand-new")
	if !first.Allowed || first.Limit != 2 || first.Remaining != 1 || first.Reset != 0 {
		t.Fatalf("first = %+v, want allowed, limit 2, one token left and no wait", first)
	}

	// The last token goes out, so this response already carries the wait — that is
	// what lets a client back off before it is refused rather than after.
	second := l.Check("brand-new")
	if !second.Allowed || second.Remaining != 0 || second.Reset <= 0 {
		t.Fatalf("second = %+v, want allowed with an empty bucket and a positive wait", second)
	}

	third := l.Check("brand-new")
	if third.Allowed {
		t.Fatal("the third request was allowed")
	}
	if third.Reset <= 0 {
		t.Fatalf("Reset = %v, want a positive wait", third.Reset)
	}
}

// A caller that varies its key must not be able to grow the map without bound.
func TestEvictionCapsTrackedKeys(t *testing.T) {
	l := New(1, 1, WithMaxKeys(64), WithTTL(time.Minute))

	for i := 0; i < 500; i++ {
		l.Allow(string(rune('A' + i%26)))
		if size := l.size(); size > 64 {
			t.Fatalf("tracked %d keys, cap is 64", size)
		}
	}
}

// Sharding must not change a key's budget: the shard is chosen from the key, so
// every request for one key meets the same bucket and the same lock.
func TestAKeyKeepsItsBudgetAcrossShards(t *testing.T) {
	l := New(0.0001, 2) // two tokens, effectively no refill during the test

	for _, key := range []string{"a", "b", "plane|10.0.0.1", "another-key", strings.Repeat("long", 40)} {
		if !l.Check(key).Allowed {
			t.Fatalf("%q: the first token was refused", key)
		}
		second := l.Check(key)
		if !second.Allowed || second.Remaining != 0 {
			t.Fatalf("%q: second = %+v, want allowed with an empty bucket", key, second)
		}
		if l.Check(key).Allowed {
			t.Fatalf("%q: the bucket refilled past its burst", key)
		}
	}
}

// Keys that hash to different shards do not contend, so the limiter's cost stays
// flat as concurrency rises. The serial benchmark beside this one is the same
// work without the parallelism; before sharding, this one was the slower of the
// two.
func BenchmarkCheckDistinctKeysParallel(b *testing.B) {
	l := New(1e9, 1e9)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		var i int
		for pb.Next() {
			i++
			l.Check("key-" + strconv.Itoa(i%1024))
		}
	})
}

func TestAllowN(t *testing.T) {
	l := New(1, 5)
	if !l.AllowN("a", 4) {
		t.Fatal("4 of 5 tokens was refused")
	}
	if l.AllowN("a", 2) {
		t.Fatal("6 of 5 tokens was allowed")
	}
}

func TestConcurrentUseIsSafe(t *testing.T) {
	l := New(1000, 1000)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				l.Allow("shared")
				l.Check("shared")
			}
		}(i)
	}
	wg.Wait()
}

// The cost of admitting a new key must not grow with the number of tracked keys.
//
// It used to: at the cap, every insertion walked the whole map twice to find an
// idle bucket, which measured 102µs per new key at ten thousand buckets — against
// 43ns for a key that already had one — and the walk happened under the lock every
// other request needs. The bound is now a fixed sample; this reports it so a
// regression shows up as a number rather than as a latency incident.
func BenchmarkCheckAtCapacity(b *testing.B) {
	for _, maxKeys := range []int{1_000, 10_000} {
		b.Run(fmt.Sprintf("maxkeys=%d", maxKeys), func(b *testing.B) {
			l := New(1e9, 1e9, WithMaxKeys(maxKeys))
			for i := 0; i < maxKeys; i++ {
				l.Allow("seed-" + strconv.Itoa(i))
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				l.Check("new-" + strconv.Itoa(i))
			}
		})
	}
}

// The common path: a key that exists. This is what every request pays.
func BenchmarkCheckExistingKey(b *testing.B) {
	l := New(1e9, 1e9)
	l.Allow("hot")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l.Check("hot")
	}
}
