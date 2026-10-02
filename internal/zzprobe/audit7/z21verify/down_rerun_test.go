//go:build audit7

package z21verify

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// This probe re-checks Z21-1's claimed failure mode.
//
// The reviewed report says an unguarded `DROP COLUMN status` (0010) / `DROP TABLE
// session_subjects` (0011) makes "a second `-migrate-down` step" fail with
// `does not exist`. That is only true if a Down section can be *re-run against the
// state it already produced*. The goose source says it cannot:
//
//   provider.go:308-328   Down(ctx) = down(ctx, true, 0)
//   provider.go:454-465   down() builds the apply list, then runMigrations(... byOne=true)
//   provider_run.go:119-122  byOne => apply = migrations[:1]   (exactly one per invocation)
//   provider_run.go:203-219  the DDL and the version-table delete run in ONE tx
//   provider_run.go:243-257  maybeInsertOrDelete(Delete) is inside that same tx
//
// So a successful Down decrements the version atomically: the next invocation runs
// the *next* migration's Down, never the same one. The two IF EXISTS omissions are
// still an inconsistency, but the concrete error path in the report does not exist.

// TestGooseDownCannotRerunTheSameSection pins the goose properties Z21-1's claim
// depends on. It works from the module source and skips (loudly, with a reason)
// only when the module cache is not present.
func TestGooseDownCannotRerunTheSameSection(t *testing.T) {
	dir := modCacheDir("github.com/pressly/goose/v3", "v3.28.0")
	if dir == "" {
		t.Skip("goose v3.28.0 is not in the module cache here; run `go mod download github.com/pressly/goose/v3` and re-run")
	}
	provider, err := os.ReadFile(filepath.Join(dir, "provider.go"))
	if err != nil {
		t.Fatalf("read goose provider.go: %v", err)
	}
	run, err := os.ReadFile(filepath.Join(dir, "provider_run.go"))
	if err != nil {
		t.Fatalf("read goose provider_run.go: %v", err)
	}
	p, r := string(provider), string(run)

	// Premise 1: Down() is down(byOne=true, version=0).
	if !strings.Contains(p, "res, err := p.down(ctx, true, 0)") {
		t.Fatalf("premise changed: goose's Provider.Down no longer calls down(ctx, true, 0)")
	}
	// Premise 2: byOne truncates the apply list to one migration.
	if !strings.Contains(r, "apply = migrations[:1]") {
		t.Fatalf("premise changed: goose's byOne no longer applies exactly one migration per call")
	}
	// Premise 3: DDL + version delete are one transaction (so the version cannot
	// stay "applied" after the DROP committed).
	if !strings.Contains(r, "return p.maybeInsertOrDelete(ctx, tx, m.Version, direction)") {
		t.Fatalf("premise changed: goose no longer deletes the version row inside the migration's transaction")
	}
	if !strings.Contains(r, "if useTx && !p.cfg.isolateDDL {") {
		t.Fatalf("premise changed: goose's transactional path no longer guards on useTx/isolateDDL")
	}
	// No migration opts out of the transaction, so premise 3 applies to all of them.
	for _, name := range []string{"0010_client_status.sql", "0011_session_subjects.sql"} {
		body := migrationText(t, name)
		if strings.Contains(strings.ToUpper(body), "GOOSE NO TRANSACTION") {
			t.Fatalf("%s now declares NO TRANSACTION; the single-transaction argument does not apply to it", name)
		}
	}
}

// TestTheTwoUnguardedDownsAreStillThere is the regression guard for Z21-1 after
// the fix. The name is kept for the round-9 coverage matrix; the assertion now
// pins the re-runnable shape rather than the old omission, so un-guarding any of
// the three Downs makes it fail again.
func TestTheTwoUnguardedDownsAreStillThere(t *testing.T) {
	ten := migrationText(t, "0010_client_status.sql")
	eleven := migrationText(t, "0011_session_subjects.sql")
	twentySeven := migrationText(t, "0027_client_allow_missing_pkce.sql")

	_, downTen := splitDirection(ten)
	if !strings.Contains(strings.ToUpper(downTen), "DROP COLUMN IF EXISTS") {
		t.Fatalf("0010's Down is not re-runnable: %q", downTen)
	}
	_, downEleven := splitDirection(eleven)
	if !strings.Contains(strings.ToUpper(downEleven), "DROP TABLE IF EXISTS") {
		t.Fatalf("0011's Down is not re-runnable: %q", downEleven)
	}
	_, down27 := splitDirection(twentySeven)
	if !strings.Contains(strings.ToUpper(down27), "DROP COLUMN IF EXISTS") {
		t.Fatalf("0027's Down is not re-runnable: %q", down27)
	}
	// Positive control for the reader: 0009's Down is the house style these three
	// now match, so the assertion is about this project's convention rather than
	// a string that happens to be present.
	nine := migrationText(t, "0009_oidc_token_issued_at.sql")
	_, down := splitDirection(nine)
	if !strings.Contains(strings.ToUpper(down), "DROP COLUMN IF EXISTS") {
		t.Fatalf("control failed: 0009's Down is not the IF EXISTS shape, so the comparison is vacuous")
	}
	t.Log("0010/0011/0027 Downs are re-runnable, matching 0009")
}
