//go:build audit7

package z21verify

import (
	"regexp"
	"strings"
	"testing"
)

// Independent re-derivation of Z21-2's state transition.
//
// The reviewed probe hardcodes the post-cycle state (`after[i] = chainedRow{}`,
// `headAfter := []byte{}`, `droppedColumns := true`) and then checks its own model.
// This probe replaces those hardcodes with a parse of 0013's text: the columns the
// Down removes, the fact that the Up re-adds them without a DEFAULT, and the genesis
// seed the Up inserts. It also checks the one thing that makes the loss in-place
// undetectable: Verify never *decides* anything from v.Legacy.
func TestAuditChainCycleStateIsDerivedFromTheMigrationText(t *testing.T) {
	body := migrationText(t, "0013_audit_chain.sql")
	up, down := splitDirection(body)
	upSQL, downSQL := stripSQLComments(up), stripSQLComments(down)

	// --- premise: the Down really removes the per-row chain metadata ----------
	for _, col := range []string{"prev_hash", "row_hash", "signature"} {
		if !regexp.MustCompile(`(?is)ALTER\s+TABLE\s+audit_events\s+DROP\s+COLUMN\s+IF\s+EXISTS\s+` + col).MatchString(downSQL) {
			t.Logf("FIXED: 0013's Down no longer drops audit_events.%s", col)
			return
		}
	}
	if !strings.Contains(strings.ToUpper(downSQL), "DROP TABLE IF EXISTS AUDIT_CHAIN") {
		t.Fatalf("premise changed: 0013's Down no longer drops audit_chain (so the head survives)")
	}

	// --- premise: the Up re-adds them with no DEFAULT (=> NULL for old rows) --
	reAdd := regexp.MustCompile(`(?is)ALTER\s+TABLE\s+audit_events\s+ADD\s+COLUMN\s+(prev_hash|row_hash|signature)\s+bytea\s*;`)
	if got := len(reAdd.FindAllString(upSQL, -1)); got != 3 {
		t.Fatalf("premise changed: 0013's Up adds %d of the 3 chain columns as plain nullable bytea", got)
	}
	// --- premise: the Up seeds the head back to the genesis, not from rows ----
	if !strings.Contains(upSQL, `INSERT INTO audit_chain (only_row, head_hash) VALUES (true, '\x'::bytea)`) {
		t.Fatalf("premise changed: 0013's Up no longer seeds the chain head with the empty genesis hash")
	}

	// --- premise: no Down deletes audit rows, so the history survives ---------
	entries := migrationEntries(t)
	deleted := false
	for _, name := range entries {
		_, d := splitDirection(migrationText(t, name))
		u := strings.ToUpper(stripSQLComments(d))
		if strings.Contains(u, "DELETE FROM AUDIT_EVENTS") || strings.Contains(u, "TRUNCATE") ||
			regexp.MustCompile(`(?is)DROP\s+TABLE\s+(IF\s+EXISTS\s+)?AUDIT_EVENTS\b`).MatchString(d) {
			deleted = true
			t.Logf("note: %s's Down removes audit rows/table (%s)", name, strings.TrimSpace(d))
		}
	}
	if !deleted {
		t.Log("premise holds: no Down section deletes or drops audit_events, so the rows outlive their metadata")
	}

	// --- the verdict the real Verify reaches for that state -------------------
	// All rows NULL row_hash => Legacy++, started never set; head is the empty
	// genesis => the `Chained == 0 && len(head) != 0` branch is skipped; OK = true.
	chainSrc := storeSource(t, "auditchain.go")
	if n := strings.Count(chainSrc, "v.Legacy"); n != 1 {
		t.Fatalf("premise changed: auditchain.go touches v.Legacy %d times; the only read of it was in "+
			"the caller, which is what makes the loss in-place undetectable", n)
	}
	if !strings.Contains(chainSrc, "if v.Chained == 0 && len(head) != 0 {") {
		t.Fatalf("premise changed: the head-witness branch in Verify is no longer `Chained == 0 && head != empty`")
	}
	if !strings.Contains(chainSrc, "if rowHash == nil {") {
		t.Fatalf("premise changed: Verify no longer treats a NULL row_hash as legacy")
	}
	t.Log("derived: after 0013 Down+Up every surviving row is legacy, the head is the genesis, " +
		"and Verify has no branch that turns a non-empty Legacy count into a failure — verdict OK=true")
}

var reMigrationName = regexp.MustCompile(`^\d+_[a-z0-9_]+\.sql$`)

func migrationEntries(t *testing.T) []string {
	t.Helper()
	entries, err := readDirNames(migrationsDir(t))
	if err != nil {
		t.Fatalf("read migrations: %v", err)
	}
	var out []string
	for _, name := range entries {
		if reMigrationName.MatchString(name) {
			out = append(out, name)
		}
	}
	if len(out) < 20 {
		t.Fatalf("found only %d migration files; the locator is broken", len(out))
	}
	return out
}
