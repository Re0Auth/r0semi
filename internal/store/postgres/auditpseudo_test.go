package postgres

import (
	"bytes"
	"context"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/audit"
)

func keyWith(fill byte) *AuditLogger {
	return &AuditLogger{
		key:        bytes.Repeat([]byte{fill}, 32),
		now:        time.Now,
		cache:      map[string]cachedSubjectKey{},
		tombstones: map[string]struct{}{},
	}
}

// A stored key that is not the length this package mints must fail the read rather
// than be used or treated as absent. Using it would compute pseudonyms under a
// short (or empty) HMAC key; treating it as absent would mint a second key for a
// subject that already has one and split its history across two pseudonyms. The
// chain key has always been checked this way — this is the missing half.
func TestSubjectKeyLengthIsChecked(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  []byte
	}{
		{"absent", nil},
		{"empty", []byte{}},
		{"short", bytes.Repeat([]byte{0x01}, 31)},
		{"long", bytes.Repeat([]byte{0x01}, 33)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := checkSubjectKey(tc.key); err == nil {
				t.Fatalf("a %d-byte subject key was accepted", len(tc.key))
			}
		})
	}
	if err := checkSubjectKey(bytes.Repeat([]byte{0x01}, 32)); err != nil {
		t.Fatalf("a key this package mints was refused: %v", err)
	}
}

// And the check sits on the read path, not only in a helper: a key row written by
// something other than this package — a hand edit, a restore that truncated a
// value — must fail the write instead of pseudonymising the subject under it.
func TestAuditRefusesAKeyRowItDidNotMint(t *testing.T) {
	db := openTestDB(t)
	logger := openAudit(t, db)
	ctx := context.Background()

	if _, err := db.pool.Exec(ctx,
		`INSERT INTO audit_subject_keys (idx, key) VALUES ($1, $2)`,
		logger.subjectIndex("usr_short_key"), []byte{}); err != nil {
		t.Fatal(err)
	}
	err := logger.Record(ctx, audit.Event{
		Action: "vault.use", Subject: "usr_short_key", Provider: "phigros.taptap", Outcome: audit.OutcomeOK,
	})
	if err == nil {
		t.Fatal("an empty key row was used to pseudonymise a subject")
	}
}

// TestPseudonymIsStableForOneKey: the same account must get the same handle every
// time, or its history would be scattered across unrelated pseudonyms.
func TestPseudonymIsStableForOneKey(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, 32)
	first := pseudonymOf(key, "usr_abc")
	for i := 0; i < 10; i++ {
		if got := pseudonymOf(key, "usr_abc"); got != first {
			t.Fatalf("pseudonym changed between calls: %q then %q", first, got)
		}
	}
	if pseudonymOf(key, "usr_other") == first {
		t.Fatal("two different subjects share a pseudonym")
	}
}

// TestPseudonymDependsOnThePerSubjectKey: this is what makes erasure work. With a
// different key the same subject produces a different handle, so destroying the
// key removes the only way to connect the two.
func TestPseudonymDependsOnThePerSubjectKey(t *testing.T) {
	a := pseudonymOf(bytes.Repeat([]byte{0x01}, 32), "usr_abc")
	b := pseudonymOf(bytes.Repeat([]byte{0x02}, 32), "usr_abc")
	if a == b {
		t.Fatal("the pseudonym does not depend on the per-subject key")
	}
}

// TestAuditHashesAreDomainSeparated: one key drives three HMACs, so the same input
// must not produce the same output in two of those uses — otherwise a value from
// one could be replayed as another.
func TestAuditHashesAreDomainSeparated(t *testing.T) {
	l := keyWith(0x5a)
	msg := []byte("the-same-input")

	index := l.mac(auditSubjectIndexLabel, msg)
	pseudo := l.mac(auditPseudonymLabel, msg)
	sig := l.mac(auditSignatureLabel, msg)
	if bytes.Equal(index, pseudo) || bytes.Equal(index, sig) || bytes.Equal(pseudo, sig) {
		t.Fatal("two HMAC uses share an output for the same input: the labels are not separating them")
	}
	// And the label really is in the input: dropping it would collide with a bare HMAC.
	bare := l.mac("", msg)
	if bytes.Equal(bare, index) {
		t.Fatal("an empty label matches the index label")
	}
}

// TestSubjectIndexDependsOnTheAuditKey: the index is how a key row is found, and
// it must not be computable from the database alone. If it were a plain hash of the
// subject, a dump would let anyone resolve a pseudonym back to an account.
func TestSubjectIndexDependsOnTheAuditKey(t *testing.T) {
	one := keyWith(0x01).subjectIndex("usr_abc")
	two := keyWith(0x02).subjectIndex("usr_abc")
	if one == two {
		t.Fatal("the subject index does not depend on the audit key")
	}
	if keyWith(0x01).subjectIndex("usr_abc") != one {
		t.Fatal("the subject index is not stable for one key")
	}
	// It must not contain the subject either.
	if bytes.Contains([]byte(one), []byte("usr_abc")) {
		t.Fatal("the subject index contains the subject")
	}
}

// TestPseudonymCacheIsBounded: the cache is an optimisation, and an unbounded map
// keyed by account id would be a leak in a long-running process.
func TestPseudonymCacheIsBounded(t *testing.T) {
	l := keyWith(0x5a)
	for i := 0; i < pseudoCacheMax+50; i++ {
		l.remember("usr_"+strconv.Itoa(i), bytes.Repeat([]byte{1}, 32))
	}
	l.mu.Lock()
	size, usable := len(l.cache), l.cache != nil
	l.mu.Unlock()
	if size > pseudoCacheMax {
		t.Fatalf("cache grew to %d entries, past the %d bound", size, pseudoCacheMax)
	}
	if !usable {
		t.Fatal("dropping the cache left it unusable")
	}
	// A hit after the trim still works: correctness never depends on warmth.
	l.remember("usr_x", bytes.Repeat([]byte{2}, 32))
	l.mu.Lock()
	cached, ok := l.cache["usr_x"]
	l.mu.Unlock()
	if !ok || cached.key == nil {
		t.Fatal("the cache does not return what was just stored")
	}
}

// TestPseudonymCacheTrimsRatherThanResets: at the bound the cache must lose a
// fraction, not everything. A wholesale reset made every subject in the next
// burst a miss, which is one to three extra queries each on the vault's
// fail-closed path (S09-9).
func TestPseudonymCacheTrimsRatherThanResets(t *testing.T) {
	l := keyWith(0x5a)
	for i := 0; i < pseudoCacheMax; i++ {
		l.remember("usr_"+strconv.Itoa(i), bytes.Repeat([]byte{1}, 32))
	}
	l.remember("usr_new", bytes.Repeat([]byte{2}, 32))

	l.mu.Lock()
	size := len(l.cache)
	l.mu.Unlock()
	// The previous behaviour left exactly one entry; a quarter-eviction leaves
	// roughly three quarters. Any floor well above 1 distinguishes them.
	if size < pseudoCacheMax/2 {
		t.Fatalf("the cache held %d entries after trimming at the %d bound: it was reset, not trimmed",
			size, pseudoCacheMax)
	}
	if size > pseudoCacheMax {
		t.Fatalf("the cache held %d entries, past the %d bound", size, pseudoCacheMax)
	}
}

// TestPseudonymCacheEntriesExpire: a TTL is what bounds how long a replica that
// was NOT told about an erasure keeps resolving the erased subject. Without it the
// stale key is permanent — a steady-state failure of erasure, not a window (Z10-1).
//
// The TTL is measured on the logger's injected clock (l.now), never on the wall
// clock: nothing here sleeps or races real time. The clock value is read and
// advanced under a mutex so the test stays correct (and race-clean) even if a
// future caller lets the logger's clock be read from another goroutine.
func TestPseudonymCacheEntriesExpire(t *testing.T) {
	l := keyWith(0x5a)
	var (
		mu      sync.Mutex
		current = time.Unix(1_700_000_000, 0)
	)
	l.now = func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return current
	}
	advance := func(d time.Duration) {
		mu.Lock()
		current = current.Add(d)
		mu.Unlock()
	}

	l.remember("usr_a", bytes.Repeat([]byte{1}, 32))
	if _, ok := l.cached("usr_a"); !ok {
		t.Fatal("a fresh entry is not cached")
	}

	// Just inside the TTL: still warm.
	advance(pseudoCacheTTL - time.Second)
	if _, ok := l.cached("usr_a"); !ok {
		t.Fatal("an entry inside its TTL is not cached")
	}

	// Past the TTL: dead, with no wall-clock time having passed.
	advance(2 * time.Second)
	if _, ok := l.cached("usr_a"); ok {
		t.Fatal("a cache entry outlived its TTL: an erasure on another replica would never be observed")
	}
}

// TestPseudonymCacheCachesAMiss: the negative answer is cached too, so a subject
// with no key row is not a database round trip on every call — which is both the
// per-request query and the "has a pseudonym key" timing difference S11-7 reports.
func TestPseudonymCacheCachesAMiss(t *testing.T) {
	l := keyWith(0x5a)
	l.remember("usr_absent", nil)

	key, ok := l.cached("usr_absent")
	if !ok {
		t.Fatal("a cached miss is not reported as cached")
	}
	if key != nil {
		t.Fatalf("a cached miss returned a %d-byte key", len(key))
	}
}

func TestDestroyRejectsAnEmptySubject(t *testing.T) {
	l := keyWith(0x5a)
	if err := l.Destroy(context.Background(), ""); err == nil {
		t.Fatal("an empty subject should be rejected")
	}
}

// TestAuditPseudonymisesSubjectAndUnlinksOnDestroy is the end-to-end property:
// the log never stores the account id, the pseudonym is stable, destroying the key
// leaves the chain valid, and a later write cannot reuse the destroyed link.
func TestAuditPseudonymisesSubjectAndUnlinksOnDestroy(t *testing.T) {
	db := openTestDB(t)
	logger := openAudit(t, db)
	ctx := context.Background()
	const subject = "usr_secret"

	for i := 0; i < 2; i++ {
		if err := logger.Record(ctx, audit.Event{
			Action: "vault.use", Subject: subject, Provider: "phigros.taptap", Outcome: audit.OutcomeOK,
		}); err != nil {
			t.Fatal(err)
		}
	}

	// The stored subject is a pseudonym, and it is the same for both rows.
	var stored []string
	rows, err := db.pool.Query(ctx, `SELECT subject FROM audit_events ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		stored = append(stored, s)
	}
	rows.Close()
	if len(stored) != 2 {
		t.Fatalf("stored %d rows, want 2", len(stored))
	}
	if stored[0] == subject || stored[1] == subject {
		t.Fatal("the raw account id was stored in the audit log")
	}
	if stored[0] != stored[1] {
		t.Fatalf("the same account got two pseudonyms: %q and %q", stored[0], stored[1])
	}
	firstHandle := stored[0]

	// A live subject resolves back: the key row exists.
	var keys int
	if err := db.pool.QueryRow(ctx, `SELECT count(*) FROM audit_subject_keys`).Scan(&keys); err != nil {
		t.Fatal(err)
	}
	if keys != 1 {
		t.Fatalf("subject keys = %d, want 1", keys)
	}

	if err := logger.Destroy(ctx, subject); err != nil {
		t.Fatal(err)
	}

	// The chain is untouched: erasure detaches, it does not rewrite history.
	v, err := logger.Verify(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !v.OK || v.Chained != 2 {
		t.Fatalf("verification after destroy = %+v, want the chain intact", v)
	}

	// The key is gone, so nothing can resolve those rows any more.
	if err := db.pool.QueryRow(ctx, `SELECT count(*) FROM audit_subject_keys`).Scan(&keys); err != nil {
		t.Fatal(err)
	}
	if keys != 0 {
		t.Fatalf("subject keys = %d after destroy, want 0", keys)
	}

	// A later write for the same subject cannot resurrect the link: it mints a new
	// key, so it lands under a different pseudonym and the old rows stay detached.
	if err := logger.Record(ctx, audit.Event{Action: "late.event", Subject: subject, Outcome: audit.OutcomeOK}); err != nil {
		t.Fatal(err)
	}
	var after string
	if err := db.pool.QueryRow(ctx,
		`SELECT subject FROM audit_events ORDER BY id DESC LIMIT 1`).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after == firstHandle {
		t.Fatal("a write after the destroy reused the destroyed pseudonym, re-linking the history")
	}
}

// TestAuditLeavesAnEmptySubjectEmpty: some events belong to no account, and
// minting a key for "" would be inventing one.
func TestAuditLeavesAnEmptySubjectEmpty(t *testing.T) {
	db := openTestDB(t)
	logger := openAudit(t, db)
	ctx := context.Background()

	if err := logger.Record(ctx, audit.Event{
		Action: "oauth.revoke", Subject: "", Provider: "oauth", Outcome: audit.OutcomeOK,
	}); err != nil {
		t.Fatal(err)
	}
	var subject string
	if err := db.pool.QueryRow(ctx, `SELECT subject FROM audit_events`).Scan(&subject); err != nil {
		t.Fatal(err)
	}
	if subject != "" {
		t.Fatalf("subject = %q, want empty", subject)
	}
	var keys int
	if err := db.pool.QueryRow(ctx, `SELECT count(*) FROM audit_subject_keys`).Scan(&keys); err != nil {
		t.Fatal(err)
	}
	if keys != 0 {
		t.Fatalf("a key was minted for the empty subject (%d rows)", keys)
	}
}
