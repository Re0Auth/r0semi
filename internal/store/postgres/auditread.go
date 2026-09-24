package postgres

import (
	"context"
	"fmt"
	"strings"

	"github.com/Re0Auth/r0semi/audit"
)

// Page-size bounds for the operator read path. The default is small because an
// audit page is read by a person; the ceiling exists so one request cannot ask the
// database for the whole log.
const (
	defaultAuditPage = 100
	maxAuditPage     = 1000
)

// Query implements the operator read path over the audit log.
//
// It is a keyset scan ordered by id descending — newest first by insertion, not by
// the caller-supplied timestamp — and it asks for one row more than the page so it
// can say whether another page exists without a second count.
//
// The filters line up with the two indexes migration 0007 created for exactly this
// query ("everything about one subject" and "every occurrence of one action"),
// which until now nothing read.
func (l *AuditLogger) Query(ctx context.Context, q audit.Query) (audit.Page, error) {
	limit := q.Limit
	switch {
	case limit <= 0:
		limit = defaultAuditPage
	case limit > maxAuditPage:
		limit = maxAuditPage
	}

	var (
		where []string
		args  []any
	)
	add := func(column, op string, value any) {
		args = append(args, value)
		where = append(where, fmt.Sprintf("%s %s $%d", column, op, len(args)))
	}

	if q.Subject != "" {
		// The stored column holds a pseudonym, so the filter has to be translated.
		// A subject with no key left — one that has been erased — resolves to
		// nothing, and an empty page is the truthful answer: those rows still exist
		// but nothing connects them to this account any more.
		key, err := l.loadKey(ctx, q.Subject)
		if err != nil {
			return audit.Page{}, err
		}
		if key == nil {
			// An empty page — but carrying the limit the server applied, not a zero
			// value. A zero here would make "no pseudonym key exists" (never seen, or
			// erased) distinguishable from "the key exists but the filters matched
			// nothing", a one-bit account-existence oracle about an arbitrary
			// subject; and it would echo a page size the API never applies, so a
			// client feeding it back would be refused.
			return audit.Page{Entries: []audit.Entry{}, Limit: limit}, nil
		}
		add("subject", "=", pseudonymOf(key, q.Subject))
	}
	if q.Action != "" {
		add("action", "=", q.Action)
	}
	if !q.Since.IsZero() {
		add("occurred_at", ">=", q.Since)
	}
	if !q.Until.IsZero() {
		add("occurred_at", "<", q.Until)
	}
	if q.Before > 0 {
		add("id", "<", q.Before)
	}

	query := `SELECT id, occurred_at, action, subject, provider, outcome, detail FROM audit_events`
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	args = append(args, limit+1)
	query += fmt.Sprintf(" ORDER BY id DESC LIMIT $%d", len(args))

	rows, err := l.pool.Query(ctx, query, args...)
	if err != nil {
		return audit.Page{}, fmt.Errorf("postgres: audit: query: %w", err)
	}
	defer rows.Close()

	page := audit.Page{Entries: make([]audit.Entry, 0, limit), Limit: limit}
	for rows.Next() {
		var e audit.Entry
		if err := rows.Scan(&e.ID, &e.Time, &e.Action, &e.Subject, &e.Provider,
			&e.Outcome, &e.Detail); err != nil {
			return audit.Page{}, fmt.Errorf("postgres: audit: query scan: %w", err)
		}
		page.Entries = append(page.Entries, e)
	}
	if err := rows.Err(); err != nil {
		return audit.Page{}, fmt.Errorf("postgres: audit: query iterate: %w", err)
	}

	// The extra row is the probe, not part of the page.
	if len(page.Entries) > limit {
		page.Entries = page.Entries[:limit]
		page.NextBefore = page.Entries[len(page.Entries)-1].ID
	}
	return page, nil
}
