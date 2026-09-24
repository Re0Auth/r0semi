// Package audit defines the audit-log capability: the durable record of who
// accessed what, and when.
//
// Record is synchronous by contract. Callers rely on that to withhold an
// irreversible emission -- a cross-boundary operation such as calling an
// upstream API with a decrypted credential -- until the event describing it is
// persisted (invariant I3).
package audit

import (
	"context"
	"sync"
	"time"
)

// Outcomes for Event.Outcome.
const (
	OutcomeOK     = "ok"
	OutcomeDenied = "denied"
	OutcomeError  = "error"
)

// Event is one audit record. Fields are intentionally flat and string-typed so
// that any backend (SQL, append-only log, external SIEM) can store them without
// coupling to component internals.
type Event struct {
	Time     time.Time
	Action   string
	Subject  string
	Provider string
	Outcome  string
	Detail   map[string]string
}

// Logger is the audit-log capability. Implementations must not return until the
// event is durably persisted; returning nil means "safe to proceed".
type Logger interface {
	Record(ctx context.Context, e Event) error
}

// DefaultMaxEvents bounds how many events a MemoryLogger retains.
const DefaultMaxEvents = 10_000

// MemoryLogger is a non-durable, bounded Logger for development and tests. It is
// safe for concurrent use.
//
// It keeps at most a fixed number of the most recent events and drops the oldest
// once that is exceeded. An in-memory log that grew without bound would turn a
// long-running process into a slow leak, and this is the logger a deployment
// gets when it has no DATABASE_URL — the case where nothing else is watching.
// Bounded and honest beats complete and fatal; durability is what the Postgres
// sink is for, and a deployment that needs every record must use it.
type MemoryLogger struct {
	mu sync.Mutex
	// buf is a ring: once count reaches max, buf is full and next indexes the
	// oldest slot, which the following Record overwrites.
	max   int
	buf   []Event
	next  int
	count int
}

// NewMemoryLogger returns an empty in-memory audit log bounded to
// DefaultMaxEvents.
func NewMemoryLogger() *MemoryLogger { return NewMemoryLoggerWithCapacity(DefaultMaxEvents) }

// NewMemoryLoggerWithCapacity returns an in-memory audit log that retains at
// most max recent events, discarding the oldest first. A non-positive max uses
// DefaultMaxEvents.
func NewMemoryLoggerWithCapacity(max int) *MemoryLogger {
	if max <= 0 {
		max = DefaultMaxEvents
	}
	// Preallocate only a little: a capacity of max events would reserve the full
	// bound up front, and tests build many loggers.
	initial := max
	if initial > 64 {
		initial = 64
	}
	return &MemoryLogger{max: max, buf: make([]Event, 0, initial)}
}

// Record implements Logger.
func (l *MemoryLogger) Record(_ context.Context, e Event) error {
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.count < l.max {
		l.buf = append(l.buf, e)
		l.count++
		return nil
	}
	l.buf[l.next] = e
	l.next = (l.next + 1) % l.max
	return nil
}

// Events returns the retained events oldest first. The result is a copy, so a
// caller may range over it while recording continues.
func (l *MemoryLogger) Events() []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.count < l.max {
		return append([]Event(nil), l.buf...)
	}
	// The ring wrapped: the oldest event sits at next, and the newest just before
	// it. Splicing there restores chronological order.
	out := make([]Event, 0, l.max)
	out = append(out, l.buf[l.next:]...)
	out = append(out, l.buf[:l.next]...)
	return out
}
