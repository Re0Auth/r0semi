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

	"github.com/jackc/pgx/v5"
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
//
// It is called before appendChained takes the chain-head lock, so the buffer
// growth, the key sort and the strconv work do not sit in the one critical section
// every audit write serialises on. Grow is set from the fields because the buffer
// otherwise reallocates its way up on every call.
func (r auditRow) canonical() []byte {
	size := 64 + len(r.Action) + len(r.Subject) + len(r.Provider) + len(r.Outcome)
	for k, v := range r.Detail {
		size += 8 + len(k) + len(v)
	}
	var b bytes.Buffer
	b.Grow(size)

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

// auditVerifyRow is one audit_events row in the shape Verify walks it: the row's
// own fields plus the linkage, hash and signature columns the walk checks. The db
// tags name the columns, so a projection change is a mapping error rather than a
// silently shifted field.
type auditVerifyRow struct {
	ID         int64             `db:"id"`
	OccurredAt time.Time         `db:"occurred_at"`
	Action     string            `db:"action"`
	Subject    string            `db:"subject"`
	Provider   string            `db:"provider"`
	Outcome    string            `db:"outcome"`
	Detail     map[string]string `db:"detail"`
	PrevHash   []byte            `db:"prev_hash"`
	RowHash    []byte            `db:"row_hash"`
	Signature  []byte            `db:"signature"`
}

// writeLenPrefixed appends a length-prefixed string, so concatenation is
// unambiguous: without the length, ("ab","c") and ("a","bc") would hash the same.
func writeLenPrefixed(b *bytes.Buffer, s string) {
	var n [4]byte
	// The prefix is uint32 by the chain's own wire format, and every field fed
	// here is a bounded column value, so the truncation G115 warns about is not
	// reachable. The function has no error return to carry a length check, so
	// the conversion is annotated rather than made fallible.
	binary.BigEndian.PutUint32(n[:], uint32(len(s))) //nolint:gosec // G115: 4 GiB audit field is not a stored shape
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

// appendBatch writes a batch of rows as one extension of the chain.
//
// The head row is locked for the whole transaction, and the batch is written in
// one. That serialisation is not an optimisation detail: two concurrent inserts
// that each read the same predecessor would produce two rows claiming the same
// place, and the chain would fork. It is also why batching is worth having: the
// lock and the round trips are paid once for a batch instead of once per row. The
// rows are written in the order given, so each one's predecessor is the row
// before it — see auditbatch.go for the queue that preserves that order.
func (l *AuditLogger) appendBatch(ctx context.Context, rows []auditRow) error {
	if len(rows) == 0 {
		return nil
	}
	// The whole chained write is timed, wait for the lock included: that wait is
	// the number that decides whether the serialisation has become the ceiling
	// (see Metrics.ObserveAuditAppend). Timed even on failure, because a run of
	// slow failures is exactly what an operator needs to see.
	start := time.Now()
	defer func() {
		if l.observe != nil {
			l.observe(time.Since(start))
		}
	}()

	// Encoded before the transaction: the buffer, the sort and the strconv work are
	// a function of these rows alone, and they used to run between taking the
	// chain-head lock and releasing it — inside the one critical section every audit
	// write in the process serialises on.
	canonicals := make([][]byte, len(rows))
	for i, r := range rows {
		canonicals[i] = r.canonical()
	}

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

	batch := &pgx.Batch{}
	for i, r := range rows {
		rowHash := chainHash(prev, canonicals[i])
		sig := l.sign(rowHash)
		batch.Queue(`
			INSERT INTO audit_events
				(occurred_at, action, subject, provider, outcome, detail, prev_hash, row_hash, signature)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			r.OccurredAt, r.Action, r.Subject, r.Provider, r.Outcome, r.Detail,
			prev, rowHash, sig)
		prev = rowHash
	}
	// One round trip for the inserts, and the first statement's error is the
	// batch's: a failure here aborts the transaction and the rollback below
	// discards the whole batch, so no caller is told a row is durable unless every
	// row in it is.
	if err := tx.SendBatch(ctx, batch).Close(); err != nil {
		return fmt.Errorf("postgres: audit: insert: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`UPDATE audit_chain SET head_hash = $1 WHERE only_row`, prev); err != nil {
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
// postgres.go's migration note spells out. The transaction is also REPEATABLE READ
// so the chain head and the rows it is compared against come from one snapshot: a
// concurrent append must not look like a truncated tail (see the comparison
// below).
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

	// One snapshot for the head and the walk. Under READ COMMITTED each statement
	// gets a fresh snapshot, so an append that commits between the head read and
	// the row scan makes the head point at the appended row while the walk (which
	// started earlier) stops at the row before it — which the tail comparison
	// below would report as a truncated chain. The walk is read-only, so
	// REPEATABLE READ costs nothing and cannot raise a serialization failure.
	if _, err := tx.Exec(ctx,
		`SET LOCAL TRANSACTION ISOLATION LEVEL REPEATABLE READ`); err != nil {
		return audit.Verification{}, fmt.Errorf("postgres: audit: verify isolation: %w", err)
	}

	// The chain head and the legacy ceiling are read first, as witnesses. The
	// head is compared against the last chained row the walk finds, which is what
	// makes a deleted tail detectable (S09-6 / Z10-9); without the comparison,
	// clearing the chain columns off every row made each row look pre-chain and
	// the walk reported the log intact while a caller with DB write access rewrote
	// it freely. The ceiling bounds which NULL-hash rows may be called legacy
	// (Z10-2): a row with no hash and an id past the ceiling was inserted after
	// the seal and is not a migration-era row.
	var (
		head          []byte
		legacyCeiling int64
	)
	if err := tx.QueryRow(ctx,
		`SELECT head_hash, legacy_ceiling_id FROM audit_chain WHERE only_row`).
		Scan(&head, &legacyCeiling); err != nil {
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
		// RowToStructByName is applied per row rather than through CollectRows:
		// the walk stops at the first bad row, and buffering the whole log to
		// find it would turn a flat-memory streaming check into one that holds
		// every chained row at once. The mapping is still by column name.
		scanned, err := pgx.RowToStructByName[auditVerifyRow](rows)
		if err != nil {
			return AuditVerification{}, fmt.Errorf("postgres: audit: verify scan: %w", err)
		}
		id := scanned.ID
		r := auditRow{
			OccurredAt: scanned.OccurredAt,
			Action:     scanned.Action,
			Subject:    scanned.Subject,
			Provider:   scanned.Provider,
			Outcome:    scanned.Outcome,
			Detail:     scanned.Detail,
		}
		prevHash, rowHash, sig := scanned.PrevHash, scanned.RowHash, scanned.Signature
		if rowHash == nil {
			// A pre-chain row. It must not appear after the chain has started: a
			// chained row whose hash was cleared would otherwise be silently
			// downgraded to "legacy" and skipped. It must also not sit past the
			// ceiling migration 0030 sealed: the serial cannot reuse an id, so a
			// NULL-hash row with a higher id was inserted after the seal — it is a
			// forged row, not a migration-era one (Z10-2).
			//
			// legacyCeiling == 0 means no row was ever sealed as pre-chain, so
			// there is no id a NULL-hash row may legitimately carry. The id
			// comparison alone missed exactly that case: a row planted at id 0
			// with OVERRIDING SYSTEM VALUE made `id > 0` false and, while the
			// chain had not started, the walk accepted it as legacy. A genuine
			// migration-era row always has id >= 1 (the identity starts there)
			// AND was present when 0030 sealed the ceiling, so it cannot be
			// reached with legacyCeiling == 0.
			if legacyCeiling == 0 || id > legacyCeiling {
				v.OK = false
				v.FirstBadID = id
				v.Reason = "unchained row appears past the legacy ceiling recorded when the chain was sealed"
				return v, nil
			}
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
	// The head is the hash of the last chained row. The walk holds that row's
	// hash in prev, and it used to throw the comparison away: rows deleted from
	// the end of the chain left the head pointing at a hash no surviving row
	// carries, and the walk still answered ok (S09-6 / Z10-9). Comparing the two
	// costs nothing and is the strongest check available without an external
	// anchor. An attacker who can also rewrite head_hash is the documented
	// unanchored boundary, unchanged.
	if v.Chained > 0 && !bytes.Equal(prev, head) {
		v.OK = false
		v.Reason = "the chain head does not match the last chained row: rows were removed from the end of the chain"
		return v, nil
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
// detectable even against an attacker who rewrites head_hash as well — the one
// thing Verify cannot see on its own (see the note in migration 0013). A log whose
// head is still the genesis returns an empty slice.
func (l *AuditLogger) Head(ctx context.Context) ([]byte, error) {
	var head []byte
	if err := l.pool.QueryRow(ctx, `SELECT head_hash FROM audit_chain WHERE only_row`).Scan(&head); err != nil {
		return nil, fmt.Errorf("postgres: audit: head: %w", err)
	}
	return head, nil
}

// newAuditLogger validates the key and returns the sink.
//
// The append writer starts here and runs until Close. observe is deliberately not
// captured: DB.Audit sets it after construction, and appendBatch reads it at each
// call, so a logger built before the observer is wired still reports.
func newAuditLogger(pool *pgxpool.Pool, key []byte) (*AuditLogger, error) {
	switch {
	case pool == nil:
		return nil, errors.New("postgres: audit: pool is required")
	case len(key) != auditChainKeySize:
		return nil, fmt.Errorf("postgres: audit: the chain key must be %d bytes, got %d",
			auditChainKeySize, len(key))
	}
	l := &AuditLogger{
		pool:  pool,
		key:   append([]byte(nil), key...),
		now:   time.Now,
		cache: make(map[string]cachedSubjectKey, 64),
	}
	l.batch = newAuditBatcher(l.appendBatch)
	return l, nil
}
