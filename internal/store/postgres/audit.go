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
// Records are append-only and durable. Record returns only after the batch
// containing the row is committed, because callers such as vault.Use rely on that
// contract to withhold a plaintext secret until the access has been recorded
// (invariant I3, fail-closed). Concurrent records are coalesced into one
// transaction by the batcher (see auditbatch.go): the row is still committed
// before its caller is answered, but the chain-head lock and the round trips are
// paid once per batch instead of once per row.
//
// Every record is also chained to the one before it and signed with a key held
// outside the database, so a row cannot be edited, deleted or reordered without
// the change being detectable (see auditchain.go). The subject is stored as a
// keyed pseudonym rather than an account id, so erasing an account can unlink its
// history without rewriting the log (see auditpseudo.go).
type AuditLogger struct {
	pool *pgxpool.Pool
	key  []byte
	// batch coalesces concurrent appends. It is created with the logger and
	// stopped by Close.
	batch *auditBatcher
	// mu guards cache, which maps a subject to its per-subject key AND to the
	// answer "this subject has no key", and tombstones, the local mirror of
	// audit_subject_tombstones. Neither is a source of truth: losing them costs
	// one query.
	mu    sync.Mutex
	cache map[string]cachedSubjectKey
	// tombstones mirrors the shared erasure facts another replica wrote. It is
	// consulted before the cache answers, and refreshed from the database on a
	// short interval so the check itself does not become a query per audit event
	// (see syncTombstones, Z10-1).
	tombstones map[string]struct{}
	// tombstoneSeq is the highest tombstones.seq this process has loaded, and
	// tombstoneSyncedAt is when it last tried. Together they make the refresh
	// incremental and rate-limited.
	tombstoneSeq          int64
	tombstoneSyncedAt     time.Time
	tombstoneSyncInterval time.Duration
	// now is the clock the cache's entries are aged with. It is the handle's clock
	// (see DB.now) so the TTL obeys the same single-clock policy as every other
	// deadline this package writes; set by DB.Audit, never nil.
	now func() time.Time
	// observe reports how long one chained append took, wait for the chain-head
	// lock included. It is a function rather than a metrics handle so this package
	// keeps no dependency on the instrumentation — the composition root injects it
	// (WithAuditObserver), which is also what keeps metric names in one place.
	observe func(time.Duration)
}

// Close stops the append writer once everything queued has been written. It is
// called by DB.Close, after the background loops have been joined, so no caller
// can still be enqueueing.
func (l *AuditLogger) Close() {
	if l.batch != nil {
		l.batch.Close()
	}
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

	return l.batch.enqueue(ctx, auditRow{
		OccurredAt: when,
		Action:     e.Action,
		Subject:    subject,
		Provider:   e.Provider,
		Outcome:    e.Outcome,
		Detail:     detail,
	})
}
