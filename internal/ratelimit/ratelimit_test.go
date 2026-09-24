package ratelimit

import (
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
	if after := l.RetryAfter("a"); after <= 0 || after > 100*time.Millisecond {
		t.Fatalf("RetryAfter = %v, want (0, 100ms]", after)
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

func TestUnknownKeyHasNoRetryAfter(t *testing.T) {
	l := New(1, 1)
	if got := l.RetryAfter("never-seen"); got != 0 {
		t.Fatalf("RetryAfter = %v, want 0", got)
	}
}

// A caller that varies its key must not be able to grow the map without bound.
func TestEvictionCapsTrackedKeys(t *testing.T) {
	l := New(1, 1, WithMaxKeys(64), WithTTL(time.Minute))

	for i := 0; i < 500; i++ {
		l.Allow(string(rune('A' + i%26)))
		l.mu.Lock()
		size := len(l.buckets)
		l.mu.Unlock()
		if size > 64 {
			t.Fatalf("tracked %d keys, cap is 64", size)
		}
	}
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
				l.RetryAfter("shared")
			}
		}(i)
	}
	wg.Wait()
}
