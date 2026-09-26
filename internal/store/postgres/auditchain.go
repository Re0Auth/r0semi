package postgres

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Re0Auth/r0semi/audit"
)

// auditChainKeySize is the HMAC key length, in bytes.
const auditChainKeySize = 32

// auditGenesis is the predecessor of the first chained row. The chain head row is
// seeded with it by migration 0013.
var auditGenesis = []byte{}

// auditRow is one event in the form it is stored and hashed. It is separate from
// audit.Event so the hash input is a value this package controls completely: if
// the hash were computed over the caller's struct, adding a field to it would
// silently change what every future row commits to.
type auditRow struct {
	OccurredAt time.Time
	Action     string
	Subject    string
	Provider   string
	Outcome    string
	Detail     map[string]string
}

// canonical returns the deterministic byte string this row is hashed over.
//
// Determinism is the whole requirement, and it is easy to lose: a map ranged in
// Go's random order, or a timestamp formatted differently on the way in and the
// way out, produces a row that fails its own verification. So the detail keys are
// sorted here, and the timestamp is reduced to the microsecond precision
// timestamptz actually stores.
//
// The leading domain tag keeps these hashes from ever colliding with a hash
// computed for a different purpose over the same fields.
func (r auditRow) canonical() []byte {
	var b bytes.Buffer
	writeLenPrefixed(&b, "re0auth.audit.row/1")
	writeLenPrefixed(&b, strconv.FormatInt(r.OccurredAt.UTC().UnixMicro(), 10))
	writeLenPrefixed(&b, r.Action)
	writeLenPrefixed(&b, r.Subject)
	writeLenPrefixed(&b, r.Provider)
	writeLenPrefixed(&b, r.Outcome)

	keys := make([]string, 0, len(r.Detail))
	for k := range r.Detail {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	writeLenPrefixed(&b, strconv.Itoa(len(keys)))
	for _, k := range keys {
		writeLenPrefixed(&b, k)
		writeLenPrefixed(&b, r.Detail[k])
	}
	return b.Bytes()
}

// writeLenPrefixed appends a length-prefixed string, so concatenation is
// unambiguous: without the length, ("ab","c") and ("a","bc") would hash the same.
func writeLenPrefixed(b *bytes.Buffer, s string) {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(s)))
	b.Write(n[:])
	b.WriteString(s)
}

// chainHash links a row to its predecessor.
func chainHash(prev, canonical []byte) []byte {
	h := sha256.New()
	h.Write(prev)
	h.Write(canonical)
	return h.Sum(nil)
}

// sign authenticates a row hash. The key lives in the environment, never in the
// database, which is what makes a rewritten chain unforgeable rather than merely
// inconsistent.
//
// The label is a domain separator: the same key also derives subject indexes and
// pseudonyms, and without it a value from one of those uses would be a valid input
// to another.
func (l *AuditLogger) sign(rowHash []byte) []byte {
	return l.mac(auditSignatureLabel, rowHash)
}

// appendChained writes one event and extends the chain.
//
// The head row is locked for the whole transaction. That serialisation is not an
// optimisation detail: two concurrent inserts that each read the same predecessor
// would produce two rows claiming the same place, and the chain would fork. The
// lock is held only for the length of one insert, and audit writes are not a hot
// path.
func (l *AuditLogger) appendChained(ctx context.Context, r auditRow) error {
	tx, err := l.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: audit: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var prev []byte
	if err := tx.QueryRow(ctx,
		`SELECT head_hash FROM audit_chain WHERE only_row FOR UPDATE`).Scan(&prev); err != nil {
		return fmt.Errorf("postgres: audit: lock chain head: %w", err)
	}
	if prev == nil {
		prev = auditGenesis
	}

	rowHash := chainHash(prev, r.canonical())
	sig := l.sign(rowHash)

	if _, err := tx.Exec(ctx, `
		INSERT INTO audit_events
			(occurred_at, action, subject, provider, outcome, detail, prev_hash, row_hash, signature)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		r.OccurredAt, r.Action, r.Subject, r.Provider, r.Outcome, r.Detail,
		prev, rowHash, sig); err != nil {
		return fmt.Errorf("postgres: audit: insert: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`UPDATE audit_chain SET head_hash = $1 WHERE only_row`, rowHash); err != nil {
		return fmt.Errorf("postgres: audit: advance chain head: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: audit: commit: %w", err)
	}
	return nil
}

// verifyStatementTimeout bounds the chain walk inside Verify.
//
// The pool's own statement_timeout (30s by default) is sized for a request. A
// Verify walks every chained row, so inheriting that bound makes S5 — a hard
// target — go blind as the log grows: the walk is cancelled, the endpoint answers
// 500, and nothing was learned about the chain. This bound is deliberately still
// bounded, and still under the HTTP server's writeTimeout (60s in cmd/re0auth):
// the walk is served by a request, and a bound above that would be cut at the
// socket instead, which is a worse failure because it looks like a network
// problem.
const verifyStatementTimeout = 45 * time.Second

// AuditVerification is an alias kept for readability inside this package; the
// type itself lives in the public audit package so the operator API can consume it
// without importing a database adapter.
type AuditVerification = audit.Verification

// Verify walks the chain from the beginning and reports the first row that does
// not hold up.
//
// It recomputes each row's hash from the row's own stored fields, checks the
// linkage to the previous row, and checks the signature. All three are needed:
// the recomputation catches an edited field, the linkage catches a deletion or a
// reorder, and the signature catches an attacker who rewrote the whole chain
// (who can recompute every hash but cannot forge the MAC).
//
// The walk runs in a transaction of its own, so it can raise statement_timeout
// for the length of the scan (see verifyStatementTimeout) and have the change
// revert automatically when the transaction ends. A bare SET would leak the
// longer bound into every later request on that pooled connection — the hazard
// postgres.go's migration note spells out.
func (l *AuditLogger) Verify(ctx context.Context) (audit.Verification, error) {
	tx, err := l.pool.Begin(ctx)
	if err != nil {
		return audit.Verification{}, fmt.Errorf("postgres: audit: verify begin: %w", err)
	}
	// Read-only: rollback is the honest end, and it is what puts the session's
	// statement_timeout back the moment this returns.
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx,
		`SET LOCAL statement_timeout = `+strconv.FormatInt(verifyStatementTimeout.Milliseconds(), 10)); err != nil {
		return audit.Verification{}, fmt.Errorf("postgres: audit: verify timeout: %w", err)
	}

	// The chain head is read first as a witness that rows were chained at all.
	// Without it, clearing the chain columns off every row (row_hash = NULL) makes
	// each row look pre-chain and the walk reports the log intact while a caller
	// with DB write access rewrote it freely.
	var head []byte
	if err := tx.QueryRow(ctx, `SELECT head_hash FROM audit_chain WHERE only_row`).Scan(&head); err != nil {
		return audit.Verification{}, fmt.Errorf("postgres: audit: verify head: %w", err)
	}

	rows, err := tx.Query(ctx, `
		SELECT id, occurred_at, action, subject, provider, outcome, detail,
		       prev_hash, row_hash, signature
		  FROM audit_events
		 ORDER BY id`)
	if err != nil {
		return audit.Verification{}, fmt.Errorf("postgres: audit: verify query: %w", err)
	}
	defer rows.Close()

	var (
		v       audit.Verification
		prev    []byte
		started bool
	)
	for rows.Next() {
		var (
			id       int64
			r        auditRow
			prevHash []byte
			rowHash  []byte
			sig      []byte
		)
		if err := rows.Scan(&id, &r.OccurredAt, &r.Action, &r.Subject, &r.Provider,
			&r.Outcome, &r.Detail, &prevHash, &rowHash, &sig); err != nil {
			return AuditVerification{}, fmt.Errorf("postgres: audit: verify scan: %w", err)
		}
		if rowHash == nil {
			// A pre-chain row. It must not appear after the chain has started: a
			// chained row whose hash was cleared would otherwise be silently
			// downgraded to "legacy" and skipped.
			if started {
				v.OK = false
				v.FirstBadID = id
				v.Reason = "unchained row appears after the chain began"
				return v, nil
			}
			v.Legacy++
			continue
		}

		if !started {
			started = true
			if len(prevHash) != 0 {
				v.OK = false
				v.FirstBadID = id
				v.Reason = "first chained row does not point at the genesis hash"
				return v, nil
			}
		} else if !bytes.Equal(prevHash, prev) {
			v.OK = false
			v.FirstBadID = id
			v.Reason = "prev_hash does not match the preceding row's hash"
			return v, nil
		}

		if !bytes.Equal(chainHash(prevHash, r.canonical()), rowHash) {
			v.OK = false
			v.FirstBadID = id
			v.Reason = "row contents do not match row_hash"
			return v, nil
		}
		if !hmac.Equal(l.sign(rowHash), sig) {
			v.OK = false
			v.FirstBadID = id
			v.Reason = "signature does not verify"
			return v, nil
		}

		v.Chained++
		prev = rowHash
	}
	if err := rows.Err(); err != nil {
		return AuditVerification{}, fmt.Errorf("postgres: audit: verify iterate: %w", err)
	}
	if v.Chained == 0 && len(head) != 0 {
		// The head advanced, so rows were chained, yet none of them read as
		// chained. That is exactly what clearing the chain columns produces, and
		// reporting it intact is the failure this check exists to prevent. (An
		// attacker who also resets the head to the genesis is indistinguishable from
		// a genuinely pre-chain log without an external anchor — the documented
		// boundary, not this one.)
		v.OK = false
		v.Reason = "the chain head has advanced but no chained row was found: the chain metadata was cleared"
		return v, nil
	}
	v.OK = true
	return v, nil
}

// Head returns the chain's current head hash. It is the value an external anchor
// publishes: handed to a system outside this database, it makes a truncated tail
// detectable — the one thing Verify cannot see on its own (see the note in
// migration 0013). A log whose head is still the genesis returns an empty slice.
func (l *AuditLogger) Head(ctx context.Context) ([]byte, error) {
	var head []byte
	if err := l.pool.QueryRow(ctx, `SELECT head_hash FROM audit_chain WHERE only_row`).Scan(&head); err != nil {
		return nil, fmt.Errorf("postgres: audit: head: %w", err)
	}
	return head, nil
}

// newAuditLogger validates the key and returns the sink.
func newAuditLogger(pool *pgxpool.Pool, key []byte) (*AuditLogger, error) {
	switch {
	case pool == nil:
		return nil, errors.New("postgres: audit: pool is required")
	case len(key) != auditChainKeySize:
		return nil, fmt.Errorf("postgres: audit: the chain key must be %d bytes, got %d",
			auditChainKeySize, len(key))
	}
	return &AuditLogger{
		pool:  pool,
		key:   append([]byte(nil), key...),
		cache: make(map[string][]byte, 64),
	}, nil
}
