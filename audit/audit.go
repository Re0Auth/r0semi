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

// MemoryLogger is a non-durable Logger for development and tests. It is safe
// for concurrent use.
type MemoryLogger struct {
	mu     sync.Mutex
	events []Event
}

// NewMemoryLogger returns an empty in-memory audit log.
func NewMemoryLogger() *MemoryLogger { return &MemoryLogger{} }

// Record implements Logger.
func (l *MemoryLogger) Record(_ context.Context, e Event) error {
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	l.mu.Lock()
	l.events = append(l.events, e)
	l.mu.Unlock()
	return nil
}

// Events returns a copy of the recorded events in order.
func (l *MemoryLogger) Events() []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]Event(nil), l.events...)
}
