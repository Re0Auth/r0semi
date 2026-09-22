package postgres

import (
	"context"
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
type AuditLogger struct{ pool *pgxpool.Pool }

// Record implements audit.Logger.
func (l *AuditLogger) Record(ctx context.Context, e audit.Event) error {
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	detail := e.Detail
	if detail == nil {
		detail = map[string]string{}
	}
	_, err := l.pool.Exec(ctx, `
		INSERT INTO audit_events (occurred_at, action, subject, provider, outcome, detail)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		e.Time, e.Action, e.Subject, e.Provider, e.Outcome, detail)
	return err
}
