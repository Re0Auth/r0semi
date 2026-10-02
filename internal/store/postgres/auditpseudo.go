package postgres

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Domain-separation labels. One key performs several HMACs, and without distinct
// labels a value computed for one purpose could be replayed as another.
const (
	auditSubjectIndexLabel = "re0auth.audit.subject-index/1"
	auditPseudonymLabel    = "re0auth.audit.pseudonym/1"
	auditSignatureLabel    = "re0auth.audit.signature/1"
)

// pseudonymBytes is how much of the HMAC output a pseudonym keeps: 128 bits, far
// beyond what a collision search could reach, and short enough to read.
const pseudonymBytes = 16

// pseudoCacheMax bounds the in-process subject→key cache. Audit writes sit on the
// vault's fail-closed path, so a database round trip per event is worth avoiding;
// but an unbounded map keyed by account id is a leak.
//
// Past the bound the cache is TRIMMED rather than dropped wholesale (S09-9): a
// wholesale reset made every subject in the following burst a miss, so a busy
// instance paid one to three extra queries per distinct subject exactly when it
// could least afford them. Expired entries go first, and a quarter of what is
// left only if the bound is still reached.
const pseudoCacheMax = 4096

// pseudoCacheTTL ages every entry, including a cached miss. It is the FALLBACK,
// not the mechanism: the tombstone mirror (see syncTombstones) is what closes the
// cross-instance erasure window, and this TTL only bounds the residue when a
// replica cannot reach the tombstone table at all. Two things depend on it:
//
//   - If a tombstone refresh fails, this process cannot know an erasure happened
//     elsewhere, so with no TTL a key it cached before the erasure would keep
//     pseudonymising the erased subject forever — the steady-state failure of
//     erasure Z10-1 records.
//   - A cached miss (subject has no key) cannot outlive a key another instance
//     minted, by more than this.
const pseudoCacheTTL = 30 * time.Second

// tombstoneSyncInterval bounds how stale the local tombstone mirror may be before
// it is refreshed from audit_subject_tombstones. The mirror is checked before the
// cache answers, so an erasure another replica commits becomes effective here
// within this interval rather than at the next TTL expiry. Keeping the refresh on
// an interval rather than per lookup is deliberate: a query per audit event would
// undo the cache S09-9 exists for, while every tombstone is a permanent local
// fact once loaded (removal is a re-read, not a re-query).
const tombstoneSyncInterval = time.Second

// cachedSubjectKey is one cache entry. A nil key is a cached MISS: the subject had
// no row, which is cached so the negative lookup is not repeated per request and
// so a subject with a key and one without are not distinguishable by a database
// round trip on every call (S11-7).
type cachedSubjectKey struct {
	key     []byte
	expires time.Time
}

// auditSubjectKeySize is the per-subject pseudonym key's length, in bytes. It is
// the same 32 bytes the chain key uses, and it is enforced on every read for the
// same reason: a key this package did not mint must not compute pseudonyms.
const auditSubjectKeySize = 32

// mac computes a domain-separated HMAC under the audit key.
func (l *AuditLogger) mac(label string, msg []byte) []byte {
	m := hmac.New(sha256.New, l.key)
	m.Write([]byte(label))
	m.Write(msg)
	return m.Sum(nil)
}

// subjectIndex is the table row a subject's key lives in.
//
// It is a keyed hash rather than the subject so that this table is not a second
// copy of the account list: a database dump does not contain the ids here, and
// without the environment key nobody can compute the index for a candidate
// subject to look one up.
func (l *AuditLogger) subjectIndex(subject string) string {
	sum := l.mac(auditSubjectIndexLabel, []byte(subject))
	return base64.RawURLEncoding.EncodeToString(sum[:18])
}

// pseudonymOf derives the handle the log stores for a subject.
func pseudonymOf(key []byte, subject string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(auditPseudonymLabel))
	m.Write([]byte(subject))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil)[:pseudonymBytes])
}

// loadKey returns the stored key for a subject, or nil when there is none. It
// never creates one: minting a key is a write, and a read path that creates state
// would make "show me this account's history" have a side effect.
//
// A miss is cached too (as a nil key, with the same TTL). Without it a subject
// that has been erased — or never pseudonymised — cost a database lookup on every
// call while a subject with a key was answered from memory, which is both the
// per-request query S11-7 reports and the timing difference it leaks.
func (l *AuditLogger) loadKey(ctx context.Context, subject string) ([]byte, error) {
	// The tombstone check comes first, and it applies to warm hits too: an
	// erasure performed by another replica must invalidate THIS process's cache
	// entry, not merely the row it no longer sees (Z10-1).
	key, ok, err := l.cachedAnswer(ctx, subject)
	if err != nil {
		return nil, err
	}
	if ok {
		return key, nil
	}

	var stored []byte
	err = l.pool.QueryRow(ctx,
		`SELECT key FROM audit_subject_keys WHERE idx = $1`, l.subjectIndex(subject)).Scan(&stored)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		l.remember(subject, nil)
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("postgres: audit: look up subject key: %w", err)
	}
	if err := checkSubjectKey(stored); err != nil {
		return nil, err
	}
	l.remember(subject, stored)
	return stored, nil
}

// cachedAnswer returns a warm cache value only when no tombstone invalidates it.
// A tombstone drops the entry and reports "not cached", so the caller re-reads
// the row — which, after the erasure, no longer exists.
func (l *AuditLogger) cachedAnswer(ctx context.Context, subject string) ([]byte, bool, error) {
	tombstoned, err := l.tombstoned(ctx, subject)
	if err != nil {
		return nil, false, err
	}
	if tombstoned {
		l.forget(subject)
		return nil, false, nil
	}
	key, ok := l.cached(subject)
	return key, ok, nil
}

// cached returns a live entry. The second result distinguishes "cached miss"
// (nil, true) from "not cached" (nil, false).
func (l *AuditLogger) cached(subject string) ([]byte, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	entry, ok := l.cache[subject]
	if !ok || !l.now().Before(entry.expires) {
		return nil, false
	}
	return entry.key, true
}

// forget drops one cache entry, so the next read rebuilds it from the database.
func (l *AuditLogger) forget(subject string) {
	l.mu.Lock()
	delete(l.cache, subject)
	l.mu.Unlock()
}

// tombstoned reports whether an erasure for the subject has been committed by any
// replica. It refreshes the local mirror first (rate-limited), so a warm cache is
// never trusted over a fact the database holds.
func (l *AuditLogger) tombstoned(ctx context.Context, subject string) (bool, error) {
	if err := l.syncTombstones(ctx); err != nil {
		return false, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, ok := l.tombstones[l.subjectIndex(subject)]
	return ok, nil
}

// syncTombstones loads every tombstone committed since the last refresh. The
// refresh is incremental (seq > watermark) and rate-limited to
// tombstoneSyncInterval; a failure leaves the watermark untouched, so the next
// call retries immediately rather than serving a stale mirror.
//
// A failure is returned rather than swallowed: this sits on the vault's
// fail-closed audit path, and answering "not tombstoned" from a mirror that could
// not be refreshed would resurrect an erased subject — exactly the failure the
// table exists to prevent.
func (l *AuditLogger) syncTombstones(ctx context.Context) error {
	if l.pool == nil {
		// A logger built without a pool (source guards, unit fixtures) has no
		// shared tombstone state to read.
		return nil
	}

	l.mu.Lock()
	interval := l.tombstoneSyncInterval
	if interval <= 0 {
		interval = tombstoneSyncInterval
	}
	if !l.tombstoneSyncedAt.IsZero() && l.now().Before(l.tombstoneSyncedAt.Add(interval)) {
		l.mu.Unlock()
		return nil
	}
	since := l.tombstoneSeq
	l.mu.Unlock()

	rows, err := l.pool.Query(ctx,
		`SELECT seq, idx FROM audit_subject_tombstones WHERE seq > $1`, since)
	if err != nil {
		return fmt.Errorf("postgres: audit: read subject tombstones: %w", err)
	}
	loaded := make(map[string]struct{})
	high := since
	for rows.Next() {
		var seq int64
		var idx string
		if err := rows.Scan(&seq, &idx); err != nil {
			rows.Close()
			return fmt.Errorf("postgres: audit: read subject tombstones: %w", err)
		}
		loaded[idx] = struct{}{}
		if seq > high {
			high = seq
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("postgres: audit: read subject tombstones: %w", err)
	}
	rows.Close()

	l.mu.Lock()
	if l.tombstones == nil {
		l.tombstones = make(map[string]struct{}, len(loaded))
	}
	for idx := range loaded {
		l.tombstones[idx] = struct{}{}
	}
	if high > l.tombstoneSeq {
		l.tombstoneSeq = high
	}
	l.tombstoneSyncedAt = l.now()
	l.mu.Unlock()
	return nil
}

// checkSubjectKey refuses a stored key whose length this package never writes.
//
// The read path treats "no row" as "no key yet" and mints one, so a wrong-length
// row must not be reported that way: minting a second key for a subject that
// already has one would split its history across two pseudonyms, and using the
// short key would compute them under an empty HMAC key. The chain key is held to
// the same standard (newAuditLogger) — a row this package did not write is a
// failure to report, not a state to paper over.
func checkSubjectKey(key []byte) error {
	if len(key) != auditSubjectKeySize {
		return fmt.Errorf("postgres: audit: the subject key must be %d bytes, got %d",
			auditSubjectKeySize, len(key))
	}
	return nil
}

// subjectKey returns the per-subject key, creating it on first use.
//
// The insert is ON CONFLICT DO NOTHING followed by a re-read, so two processes
// racing to pseudonymise the same subject agree on one key. Picking our own key
// after losing that race would give the same account two pseudonyms and split its
// history in two.
func (l *AuditLogger) subjectKey(ctx context.Context, subject string) ([]byte, error) {
	key, err := l.loadKey(ctx, subject)
	if err != nil || key != nil {
		return key, err
	}

	idx := l.subjectIndex(subject)
	fresh := make([]byte, auditSubjectKeySize)
	if _, err := rand.Read(fresh); err != nil {
		return nil, fmt.Errorf("postgres: audit: generate subject key: %w", err)
	}
	if _, err := l.pool.Exec(ctx, `
		INSERT INTO audit_subject_keys (idx, key) VALUES ($1, $2)
		ON CONFLICT (idx) DO NOTHING`, idx, fresh); err != nil {
		return nil, fmt.Errorf("postgres: audit: store subject key: %w", err)
	}
	// Re-read: another process may have won the insert, and its key is the one
	// that counts.
	if err := l.pool.QueryRow(ctx,
		`SELECT key FROM audit_subject_keys WHERE idx = $1`, idx).Scan(&key); err != nil {
		return nil, fmt.Errorf("postgres: audit: read subject key: %w", err)
	}
	if err := checkSubjectKey(key); err != nil {
		return nil, err
	}
	l.remember(subject, key)
	return key, nil
}

// remember stores one entry, trimming the cache first when it is at its bound.
//
// Trimming, not resetting: the entries that are already expired go first, and
// only then a fraction of the live ones, so the burst that follows a full cache
// still finds most of its subjects warm (S09-9). Correctness never depends on the
// cache being warm — a miss is one query — so the eviction policy is chosen for
// cost, and it is deliberately partial rather than clever.
func (l *AuditLogger) remember(subject string, key []byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.trimLocked()
	l.cache[subject] = cachedSubjectKey{key: key, expires: l.now().Add(pseudoCacheTTL)}
}

// trimLocked makes room if the cache is full. Called with mu held.
func (l *AuditLogger) trimLocked() {
	if len(l.cache) < pseudoCacheMax {
		return
	}
	now := l.now()
	for subject, entry := range l.cache {
		if !now.Before(entry.expires) {
			delete(l.cache, subject)
		}
	}
	if len(l.cache) < pseudoCacheMax {
		return
	}
	// Still full: drop a quarter of the live entries. Go's map iteration order is
	// unspecified, so this is an arbitrary quarter rather than an LRU — the point
	// is that it is a quarter and not everything.
	for drop := len(l.cache) / 4; drop > 0; drop-- {
		for subject := range l.cache {
			delete(l.cache, subject)
			break
		}
	}
}

// pseudonymize maps a subject to what the log stores. An empty subject is left
// alone: some events (an RFC 7009 revocation) are about no account at all, and
// minting a key for "" would be inventing one.
func (l *AuditLogger) pseudonymize(ctx context.Context, subject string) (string, error) {
	if subject == "" {
		return "", nil
	}
	key, err := l.subjectKey(ctx, subject)
	if err != nil {
		return "", err
	}
	return pseudonymOf(key, subject), nil
}

// Destroy removes the key that makes one account's pseudonym computable, which is
// what erases the link between that account and its audit history. The audit rows
// are left exactly as they are — the chain stays valid — but nobody, including
// this service, can recompute which account they describe.
//
// The deletion and a tombstone row commit together (Z10-1). The tombstone is what
// tells every other replica — which cannot be reached from here — that its warm
// cache entry is no longer justified; without it an erasure only became effective
// elsewhere after the 30s TTL. Deleting is idempotent: a second call removes
// nothing, rewrites the same tombstone row and reports no error.
func (l *AuditLogger) Destroy(ctx context.Context, subject string) error {
	if subject == "" {
		return errors.New("postgres: audit: subject is required")
	}
	idx := l.subjectIndex(subject)

	tx, err := l.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: audit: destroy subject key: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx,
		`DELETE FROM audit_subject_keys WHERE idx = $1`, idx); err != nil {
		return fmt.Errorf("postgres: audit: destroy subject key: %w", err)
	}
	// The tombstone is written in the SAME transaction as the deletion: a replica
	// must never be able to observe the tombstone while the key row still exists,
	// or it would drop its cache and immediately re-read the key it is meant to
	// stop using. The timestamp comes from the store clock, like every other time
	// this package writes, and is informational: the sync watermark is `seq`, so
	// two replicas with skewed clocks still agree on ordering.
	if _, err := tx.Exec(ctx, `
		INSERT INTO audit_subject_tombstones (idx, tombstoned_at) VALUES ($1, $2)
		ON CONFLICT (idx) DO NOTHING`, idx, l.now()); err != nil {
		return fmt.Errorf("postgres: audit: record subject tombstone: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: audit: destroy subject key: %w", err)
	}

	// Drop the cached copy too: a warm cache would keep pseudonymising the subject
	// after the row that justifies it is gone.
	l.forget(subject)
	// Remember the tombstone locally as well, so even this process re-reads the
	// (absent) key rather than caching a newly minted one without a check.
	l.mu.Lock()
	if l.tombstones == nil {
		l.tombstones = make(map[string]struct{}, 1)
	}
	l.tombstones[idx] = struct{}{}
	l.mu.Unlock()
	return nil
}
