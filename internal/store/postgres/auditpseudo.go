package postgres

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"

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
// but an unbounded map keyed by account id is a leak. Past the bound the cache is
// dropped wholesale — crude, but the cost of a miss is one query, and correctness
// never depends on the cache being warm.
const pseudoCacheMax = 4096

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
func (l *AuditLogger) loadKey(ctx context.Context, subject string) ([]byte, error) {
	l.mu.Lock()
	cached, ok := l.cache[subject]
	l.mu.Unlock()
	if ok {
		return cached, nil
	}

	var key []byte
	err := l.pool.QueryRow(ctx,
		`SELECT key FROM audit_subject_keys WHERE idx = $1`, l.subjectIndex(subject)).Scan(&key)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("postgres: audit: look up subject key: %w", err)
	}
	if err := checkSubjectKey(key); err != nil {
		return nil, err
	}
	l.remember(subject, key)
	return key, nil
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

func (l *AuditLogger) remember(subject string, key []byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.cache) >= pseudoCacheMax {
		l.cache = make(map[string][]byte, 64)
	}
	l.cache[subject] = key
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
// Deleting is idempotent: a second call removes nothing and reports no error.
func (l *AuditLogger) Destroy(ctx context.Context, subject string) error {
	if subject == "" {
		return errors.New("postgres: audit: subject is required")
	}
	if _, err := l.pool.Exec(ctx,
		`DELETE FROM audit_subject_keys WHERE idx = $1`, l.subjectIndex(subject)); err != nil {
		return fmt.Errorf("postgres: audit: destroy subject key: %w", err)
	}
	// Drop the cached copy too: a warm cache would keep pseudonymising the subject
	// after the row that justifies it is gone.
	l.mu.Lock()
	delete(l.cache, subject)
	l.mu.Unlock()
	return nil
}
