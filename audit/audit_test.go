package audit

import (
	"context"
	"testing"
)

func actions(events []Event) []string {
	out := make([]string, len(events))
	for i, e := range events {
		out[i] = e.Action
	}
	return out
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Below capacity, nothing is dropped and order is insertion order.
func TestMemoryLoggerKeepsEverythingBelowCapacity(t *testing.T) {
	l := NewMemoryLoggerWithCapacity(10)
	ctx := context.Background()
	for _, action := range []string{"a", "b", "c"} {
		if err := l.Record(ctx, Event{Action: action}); err != nil {
			t.Fatal(err)
		}
	}
	if got := actions(l.Events()); !equal(got, []string{"a", "b", "c"}) {
		t.Fatalf("events = %v", got)
	}
}

// Past capacity, the oldest go first and the retained window stays in
// chronological order. This is the property the ring buffer exists for: a
// process that runs for weeks must not grow an audit log without bound.
func TestMemoryLoggerEvictsOldestFirst(t *testing.T) {
	l := NewMemoryLoggerWithCapacity(3)
	ctx := context.Background()
	for _, action := range []string{"a", "b", "c", "d", "e"} {
		if err := l.Record(ctx, Event{Action: action}); err != nil {
			t.Fatal(err)
		}
	}
	if got := actions(l.Events()); !equal(got, []string{"c", "d", "e"}) {
		t.Fatalf("events = %v, want the three most recent in order", got)
	}
}

// Recording exactly to the bound, then one more, must not corrupt the window.
func TestMemoryLoggerAtExactlyCapacity(t *testing.T) {
	l := NewMemoryLoggerWithCapacity(2)
	ctx := context.Background()
	for _, action := range []string{"a", "b"} {
		_ = l.Record(ctx, Event{Action: action})
	}
	if got := actions(l.Events()); !equal(got, []string{"a", "b"}) {
		t.Fatalf("events = %v", got)
	}
	_ = l.Record(ctx, Event{Action: "c"})
	if got := actions(l.Events()); !equal(got, []string{"b", "c"}) {
		t.Fatalf("events = %v, want the window to slide", got)
	}
}

func TestMemoryLoggerCapacityOfOne(t *testing.T) {
	l := NewMemoryLoggerWithCapacity(1)
	ctx := context.Background()
	for _, action := range []string{"a", "b", "c"} {
		_ = l.Record(ctx, Event{Action: action})
	}
	if got := actions(l.Events()); !equal(got, []string{"c"}) {
		t.Fatalf("events = %v, want only the newest", got)
	}
}

// A non-positive capacity falls back to the default rather than silently
// disabling the bound.
func TestMemoryLoggerDefaultAndNonPositiveCapacity(t *testing.T) {
	if got := NewMemoryLogger().max; got != DefaultMaxEvents {
		t.Fatalf("default capacity = %d, want %d", got, DefaultMaxEvents)
	}
	if got := NewMemoryLoggerWithCapacity(0).max; got != DefaultMaxEvents {
		t.Fatalf("zero capacity = %d, want %d", got, DefaultMaxEvents)
	}
	if got := NewMemoryLoggerWithCapacity(-5).max; got != DefaultMaxEvents {
		t.Fatalf("negative capacity = %d, want %d", got, DefaultMaxEvents)
	}
}

// Events returns a copy: a caller ranging over it must not be able to reach into
// the ring, and recording after a read must not disturb the slice already handed
// out.
func TestMemoryLoggerEventsIsACopy(t *testing.T) {
	l := NewMemoryLoggerWithCapacity(4)
	ctx := context.Background()
	_ = l.Record(ctx, Event{Action: "a"})
	snapshot := l.Events()
	_ = l.Record(ctx, Event{Action: "b"})
	if len(snapshot) != 1 || snapshot[0].Action != "a" {
		t.Fatalf("snapshot changed after a later Record: %v", actions(snapshot))
	}
}

func BenchmarkMemoryLoggerRecord(b *testing.B) {
	l := NewMemoryLogger()
	ctx := context.Background()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = l.Record(ctx, Event{Action: "oidc.token", Outcome: OutcomeOK})
		}
	})
}
