package postgres

import (
	"context"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Re0Auth/r0semi/audit"
)

// AuditLogger implements audit.Logger on Postgres.
//
// Records are append-only and durable. Record returns only after the INSERT is
// acknowledged, because callers such as vault.Use rely on that contract to
// withhold a plaintext secret until the access has been recorded (invariant I3,
// fail-closed). It deliberately does not batch or buffer.
//
// Every record is also chained to the one before it and signed with a key held
// outside the database, so a row cannot be edited, deleted or reordered without
// the change being detectable (see auditchain.go). The subject is stored as a
// keyed pseudonym rather than an account id, so erasing an account can unlink its
// history without rewriting the log (see auditpseudo.go).
type AuditLogger struct {
	pool *pgxpool.Pool
	key  []byte
	// mu guards cache, which maps a subject to its per-subject key. It is a cache,
	// not a source of truth: losing it costs one query.
	mu    sync.Mutex
	cache map[string][]byte
	// observe reports how long one chained append took, wait for the chain-head
	// lock included. It is a function rather than a metrics handle so this package
	// keeps no dependency on the instrumentation — the composition root injects it
	// (WithAuditObserver), which is also what keeps metric names in one place.
	observe func(time.Duration)
}

// Record implements audit.Logger.
func (l *AuditLogger) Record(ctx context.Context, e audit.Event) error {
	when := e.Time
	if when.IsZero() {
		when = time.Now().UTC()
	}
	// Truncated to the precision timestamptz stores. Hashing a nanosecond value
	// the database will round would produce a row that fails its own verification
	// the moment it is read back.
	when = when.UTC().Truncate(time.Microsecond)

	detail := e.Detail
	if detail == nil {
		detail = map[string]string{}
	}

	// The log stores a pseudonym, never the account id. A failure here fails the
	// record, which is what keeps the vault's fail-closed guarantee intact: an
	// event that cannot be written safely must not let its action proceed.
	subject, err := l.pseudonymize(ctx, e.Subject)
	if err != nil {
		return err
	}

	return l.appendChained(ctx, auditRow{
		OccurredAt: when,
		Action:     e.Action,
		Subject:    subject,
		Provider:   e.Provider,
		Outcome:    e.Outcome,
		Detail:     detail,
	})
}
