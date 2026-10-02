package postgres

// audit_tombstone_guard_test.go is the database-free half of Z10-1=A.
//
// Z10-1: Destroy deletes the per-subject key and this process's cache entry, but
// another replica cannot be told about the erasure: it keeps pseudonymising the
// erased subject from its warm cache. The 30s TTL only shortens that failure to a
// window; it never closes it. The fix is a tombstone row written in the same
// transaction as the key deletion, consulted before the cache answers.
//
// This guard reads the shipped adapter source. The behavioral cross-replica
// proof needs a live Postgres and lives with the CI integration tests; the
// database-free half pins the statements and the call order they depend on.

import (
	"context"
	"strings"
	"testing"
)

func TestDestroyWritesATombstoneAndTheCacheConsultsIt(t *testing.T) {
	body := sourceOf(t, "auditpseudo.go")

	destroy := receiverMethod(t, body, "auditpseudo.go", "Destroy")
	if !strings.Contains(destroy, "audit_subject_tombstones") {
		t.Error("Destroy does not write an audit_subject_tombstones row: an erasure stays invisible to " +
			"every other replica's warm cache, and only the 30s TTL limits the failure (Z10-1)")
	}
	if !strings.Contains(destroy, "DELETE FROM audit_subject_keys") {
		t.Error("Destroy no longer deletes the subject key; the guard is reading the wrong method")
	}

	// The cache read must consult the tombstone set before it answers, and the
	// set is kept in step with the database by a SELECT over the table.
	load := receiverMethod(t, body, "auditpseudo.go", "loadKey")
	if !strings.Contains(load, "cachedAnswer(") {
		t.Error("loadKey answers from the warm cache without going through the tombstone check; an " +
			"erasure performed by another replica would never invalidate it (Z10-1)")
	}
	answer := receiverMethod(t, body, "auditpseudo.go", "cachedAnswer")
	if !strings.Contains(answer, "tombstoned(") || !strings.Contains(answer, "forget(") {
		t.Error("cachedAnswer does not consult the tombstone set and drop the invalidated entry")
	}
	if !strings.Contains(body, "SELECT") || !strings.Contains(body, "FROM audit_subject_tombstones") {
		t.Error("no statement reads audit_subject_tombstones, so the tombstone set can never be refreshed")
	}
	if !strings.Contains(body, "FROM audit_subject_keys WHERE idx = $1") {
		t.Error("the cache read path no longer re-reads audit_subject_keys; the guard is reading the wrong text")
	}

	// TTL is the fallback, not the mechanism: the cache must still age its
	// entries so a logger that cannot reach the tombstone table does not keep an
	// erased subject alive forever.
	if !strings.Contains(body, "expires: l.now().Add(pseudoCacheTTL)") {
		t.Error("cache entries no longer carry a TTL: with the tombstone as the only mechanism, a " +
			"replica that cannot refresh it keeps resolving the erased subject forever")
	}
}

// TestATombstoneInvalidatesAWarmCache is the runtime half that needs no database:
// a warm entry for a subject whose erasure this process has learned about must not
// be answered from cache.
func TestATombstoneInvalidatesAWarmCache(t *testing.T) {
	l := keyWith(0x5a)
	const subject = "usr_erased"
	l.remember(subject, []byte("a-warm-key-that-must-not-be-used"))
	if _, ok := l.cached(subject); !ok {
		t.Fatal("fixture failed: the entry is not warm, so the probe would prove nothing")
	}

	l.mu.Lock()
	l.tombstones[l.subjectIndex(subject)] = struct{}{}
	l.mu.Unlock()

	key, ok, err := l.cachedAnswer(context.Background(), subject)
	if err != nil {
		t.Fatalf("cachedAnswer: %v", err)
	}
	if ok {
		t.Fatalf("a tombstoned subject was answered from the warm cache (%d-byte key); the erasure "+
			"would not propagate to this replica (Z10-1)", len(key))
	}
	l.mu.Lock()
	_, stillCached := l.cache[subject]
	l.mu.Unlock()
	if stillCached {
		t.Fatal("the invalidated cache entry was not dropped, so the next read could still answer from it")
	}

	// And the mirror really is keyed by the hashed subject index, not the raw
	// subject: a tombstone lookup must be independent of the account bytes.
	other := keyWith(0x5a)
	if tombstoned, err := other.tombstoned(context.Background(), subject); err != nil || tombstoned {
		t.Fatalf("a fresh logger reported tombstoned=%v err=%v for a subject it never learned about",
			tombstoned, err)
	}
}
