package postgres

import (
	"os"
	"strings"
	"testing"
)

// TestMigrationLockIsGoosesBoundedSessionLocker pins the migration lock to
// goose's Postgres session locker rather than the blocking `pg_advisory_lock`
// this package used to issue by hand.
//
// The finding it guards is a startup that never answers: the old call blocked
// forever behind a peer that never finished migrating. goose's locker probes with
// `pg_try_advisory_lock` in a bounded retry loop, so waiting has an end. A revert
// to a blocking advisory lock, or to an unbounded locker, has to fail here rather
// than be discovered as a hung rollout.
//
// It reads the production source from disk, the same way this package's other
// source-level guards do, because the property is "which call is issued" and no
// unit test can express that without a database.
func TestMigrationLockIsGoosesBoundedSessionLocker(t *testing.T) {
	body, err := os.ReadFile("postgres.go")
	if err != nil {
		t.Fatalf("cannot read the adapter source: %v", err)
	}
	src := string(body)

	if strings.Contains(src, "SELECT pg_advisory_lock(") {
		t.Error("postgres.go issues a blocking pg_advisory_lock; the migration lock must be goose's session locker, whose wait is bounded")
	}
	for _, want := range []string{
		"lock.NewPostgresSessionLocker(",
		"lock.WithLockID(migrationLockKey)",
		"lock.WithLockTimeout(migrationLockPeriod, migrationLockAttempts)",
		"locker.SessionLock(ctx, conn)",
		"locker.SessionUnlock(context.WithoutCancel(ctx), conn)",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("the migration lock is no longer wired through %q", want)
		}
	}

	// The wait must stay bounded. A zero period or threshold would make the
	// locker either invalid or unbounded, which is the failure mode this guard
	// exists to prevent.
	if migrationLockPeriod < 1 || migrationLockAttempts < 1 {
		t.Errorf("migration lock bound is not positive: period=%d attempts=%d (the wait would be unbounded or invalid)",
			migrationLockPeriod, migrationLockAttempts)
	}
}
