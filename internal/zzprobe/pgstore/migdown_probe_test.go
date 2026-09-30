//go:build audit5

// Package pgstore holds schema-level probes for the Postgres storage adapter.
//
// They are kept in a package of their own (the project's convention for probe
// packages, see docs/audit-5/BRIEF.md §4) so they can read the migration SQL
// on disk without joining internal/store/postgres's test binary, and without
// modifying anything inside it. See helpers_test.go for how the files are
// located — they are read from `internal/store/postgres/migrations/*.sql`
// through a relative path, so the probes cannot describe a schema the repository
// does not have.
package pgstore

import (
	"regexp"
	"sort"
	"strings"
	"testing"
)

// --- parser -----------------------------------------------------------------

// splitGoose divides a migration file into its Up and Down halves. Everything
// before the Up annotation is a header comment; anything after "Down" is the
// down section. A file with no Down section yields down == "" (not "missing"),
// so the caller has to say which it means.
func splitGoose(text string) (up, down string) {
	upAt := strings.Index(text, "-- +goose Up")
	downAt := strings.Index(text, "-- +goose Down")
	body := text
	if upAt >= 0 {
		body = text[upAt+len("-- +goose Up"):]
	}
	if downAt < 0 {
		return body, ""
	}
	return text[upAt+len("-- +goose Up") : downAt], text[downAt+len("-- +goose Down"):]
}

// stripLineComments removes `-- ...` comments so a name mentioned in prose is
// never mistaken for executed SQL. Without it, migration 0018's comment ("add a
// migration like 0018_oidc_refresh_tokens_id_hash_idx.sql") or 0012's header
// would be parsed as DDL.
func stripLineComments(sql string) string {
	var out []string
	for _, line := range strings.Split(sql, "\n") {
		if i := strings.Index(line, "--"); i >= 0 {
			line = line[:i]
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

// These patterns are intentionally independent of the ones inside the postgres
// package: a probe that reused the production regex could only ever confirm the
// production regex agrees with itself.
var (
	ddlCreateIndexRE = regexp.MustCompile(`(?is)\bCREATE\s+(?:UNIQUE\s+)?INDEX\s+(?:CONCURRENTLY\s+)?(?:IF\s+NOT\s+EXISTS\s+)?("[A-Za-z0-9_]+"|[A-Za-z0-9_]+)`)
	ddlCreateTableRE = regexp.MustCompile(`(?is)\bCREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?("[A-Za-z0-9_]+"|[A-Za-z0-9_]+)`)
	ddlDropIndexRE   = regexp.MustCompile(`(?is)\bDROP\s+INDEX\s+(?:CONCURRENTLY\s+)?(?:IF\s+EXISTS\s+)?("[A-Za-z0-9_]+"|[A-Za-z0-9_]+)(?:\s*,\s*(?:IF\s+EXISTS\s+)?("[A-Za-z0-9_]+"|[A-Za-z0-9_]+))*`)
	ddlDropTableRE   = regexp.MustCompile(`(?is)\bDROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?("[A-Za-z0-9_]+"|[A-Za-z0-9_]+)(?:\s*,\s*(?:IF\s+EXISTS\s+)?("[A-Za-z0-9_]+"|[A-Za-z0-9_]+))*`)
	identRE          = regexp.MustCompile(`"[A-Za-z0-9_]+"|[A-Za-z0-9_]+`)
)

func unquote(s string) string { return strings.Trim(s, `"`) }

// objectsCreatedIn returns the index and table names a migration's Up section
// creates.
func objectsCreatedIn(sql string) (indexes, tables []string) {
	clean := stripLineComments(sql)
	for _, m := range ddlCreateIndexRE.FindAllStringSubmatch(clean, -1) {
		indexes = append(indexes, unquote(m[1]))
	}
	for _, m := range ddlCreateTableRE.FindAllStringSubmatch(clean, -1) {
		tables = append(tables, unquote(m[1]))
	}
	return indexes, tables
}

// objectsDroppedIn returns every name a migration's Down section drops, from
// both DROP INDEX (including the comma-separated form) and DROP TABLE.
func objectsDroppedIn(sql string) map[string]bool {
	clean := stripLineComments(sql)
	dropped := make(map[string]bool)
	for _, m := range ddlDropIndexRE.FindAllStringSubmatch(clean, -1) {
		for _, g := range m[1:] {
			if g != "" {
				dropped[unquote(identRE.FindString(g))] = true
			}
		}
	}
	for _, m := range ddlDropTableRE.FindAllStringSubmatch(clean, -1) {
		for _, g := range m[1:] {
			if g != "" {
				dropped[unquote(identRE.FindString(g))] = true
			}
		}
	}
	return dropped
}

// --- the probes -------------------------------------------------------------
//
// The interesting question about a Down section is NOT "does it name every
// index its Up created". A `DROP TABLE` removes a table's indexes with it, so an
// index left unnamed in a Down whose table is also dropped is correct 鈥?and the
// first version of this probe asserted the stricter property, reported 15
// offenders, and was wrong. The two probes below are the versions that hold:
//
//  1. per migration: does any index survive a Down *whose table also survives*?
//     That is the only shape that can break the next `goose up`.
//  2. across the whole history: after every Down has run in reverse order, does
//     any index survive? That is what repeated `-migrate-down` (or `goose down-to
//     0`) would leave behind.
//
// Both pass on the shipped schema, which is the useful result: the Down sections
// are self-consistent, and the repository has a check it did not have before.
//
// The one class of object they do NOT require a Down to remove is the
// non-rollbackable audit-integrity set declared above (ADR-0008 §5): 0013's and
// 0014's Downs are comment-only no-ops on purpose, so audit_chain,
// audit_subject_keys and audit_events_row_hash_idx are meant to survive. Each
// exemption is a named entry with the migration that justifies it, and every
// probe re-proves the justification from the shipped SQL, so the set cannot grow
// without a matching migration change.

// --- the non-rollbackable audit-integrity objects ---------------------------
//
// 0013_audit_chain.sql and 0014_audit_pseudonyms.sql are the two migrations whose
// Down sections execute NOTHING on purpose, because rolling them back destroys
// tamper-evidence rather than undoing a schema change (docs/migration-decision.md,
// ADR-0008 §5):
//
//   - 0013's old Down dropped audit_chain, dropped audit_events_row_hash_idx and
//     dropped prev_hash/row_hash/signature from audit_events; its Up re-added the
//     columns (NULL for every surviving row) and re-seeded the head to genesis, so
//     after one Down/Up cycle every historical row read back as Legacy while
//     Verify still returned OK=true.
//   - 0014's old Down dropped audit_subject_keys, the only copy of every
//     per-subject pseudonym key, splitting every live subject's pseudonym history.
//
// The two probes below assert that every CREATE TABLE / CREATE INDEX in the
// repository is undone by its own Down "or is one of these, declared here with a
// reason". The declaration is deliberately a pair (object -> the migration that
// creates it), and each probe re-proves the declaration from the shipped SQL — so
// the exemption cannot be widened by adding a name here without also changing the
// migration that justifies it, and cannot be left behind when the migration is
// fixed. An unreasoned exemption is exactly how this guard would quietly become a
// hole for every future migration.
var (
	// nonRollbackableTables maps a table the full Down sequence leaves behind on
	// purpose to the migration that creates it.
	nonRollbackableTables = map[string]string{
		"audit_chain":        "0013_audit_chain.sql",
		"audit_subject_keys": "0014_audit_pseudonyms.sql",
	}
	// nonRollbackableIndexes maps an index the full Down sequence may leave
	// behind on purpose to the migration that creates it. The 0013 index is
	// listed because its Down is a no-op too; today no Down removes it either by
	// name or by dropping its table, because 0007's Down drops audit_events and
	// takes the index with it. The declaration therefore changes nothing today:
	// it is here so the probe keeps passing on the ADR-0008 grounds if 0007 ever
	// stops dropping the table, instead of reporting a false defect.
	nonRollbackableIndexes = map[string]string{
		"audit_events_row_hash_idx": "0013_audit_chain.sql",
	}
)

// downExecutesNothing reports whether a migration's Down section is a
// comment-only no-op, re-read from disk rather than assumed.
func downExecutesNothing(t *testing.T, name string) bool {
	t.Helper()
	_, down := splitGoose(readMigration(t, name))
	return strings.TrimSpace(stripLineComments(down)) == ""
}

// TestLeakedIndexesSitOnTablesThatSurviveTheDown is the per-migration form.
//
// An index whose own name is dropped is fine. An index whose TABLE is dropped is
// fine, because the DROP TABLE takes it. The defect is the third case: an index
// that no Down names and whose table no Down drops survives the rollback, and the
// next `goose up` runs the same CREATE INDEX against a name that still exists 鈥?// `relation "oauth_device_user_code_idx" already exists`, the migration aborts,
// and the advisory lock is held until an operator intervenes.
//
// It is database-free on purpose: "CREATE INDEX <name> where <name> exists" is a
// conflict Postgres reports deterministically, so no server is needed to decide
// it. The report labels every Postgres-path claim 璇伙紱鏃?DB 鎵ц accordingly.
func TestLeakedIndexesSitOnTablesThatSurviveTheDown(t *testing.T) {
	var breaking []string
	// spared records the declared non-rollbackable indexes skipped below, so the
	// exemption is reported rather than silent.
	spared := map[string]string{}
	checked := 0
	for _, name := range migrationFiles(t) {
		up, down := splitGoose(readMigration(t, name))
		if strings.TrimSpace(down) == "" {
			t.Errorf("%s has no Down section at all", name)
			continue
		}
		created, _ := objectsCreatedIn(up)
		if len(created) == 0 {
			continue
		}
		checked++
		dropped := objectsDroppedIn(down)
		targets := indexTargets(up)
		for _, idx := range created {
			if dropped[idx] {
				continue // a Down removes it by name
			}
			tbl, known := targets[idx]
			if !known {
				t.Errorf("%s: parsed index %q but not the table it is on; the probe cannot classify it", name, idx)
				continue
			}
			if dropped[tbl] {
				continue // its table goes, and takes it along
			}
			// ADR-0008 §5: a declared non-rollbackable index is meant to survive
			// its migration's Down, because that Down is a comment-only no-op.
			if owner, declared := nonRollbackableIndexes[idx]; declared {
				if owner != name {
					t.Errorf("%s creates %q but the non-rollbackable declaration credits %s; "+
						"a stale declaration is how the exemption list quietly becomes wrong",
						name, idx, owner)
					continue
				}
				spared[idx] = name
				continue
			}
			breaking = append(breaking, name+" -> "+idx+" (table "+tbl+" survives)")
		}
	}
	// Anti-vacuous: the "ON <table>" parse must have worked; otherwise every
	// index would be reported unclassifiable above and this count would be zero.
	if checked < 5 {
		t.Fatalf("only %d migrations were classified; the probe is not reading the files", checked)
	}
	for idx := range spared {
		if _, ok := nonRollbackableIndexes[idx]; !ok {
			t.Errorf("index %q was spared without a declaration; the exemption set must not be "+
				"widened to cover another migration's leak", idx)
		}
	}
	// Here the 0013 index IS at risk (its table survives 0013's Down), so the
	// exemption must be exactly the declared set: a declared entry that was not
	// spared means its Down now removes it, and the entry should be deleted
	// rather than left behind as a blanket exemption.
	if len(spared) != len(nonRollbackableIndexes) {
		t.Errorf("the probe spared %d index(es) (%v) but %d are declared (%v); the exemption set "+
			"has drifted", len(spared), spared, len(nonRollbackableIndexes), nonRollbackableIndexes)
	}
	for idx := range nonRollbackableIndexes {
		if _, ok := spared[idx]; !ok {
			t.Errorf("declared non-rollbackable index %q was not spared: its Down now removes it "+
				"by name or by dropping its table, so the declaration is inert and should be removed", idx)
		}
	}
	// The exemption set is pinned by name: adding an entry is a change to the
	// guard, and it needs the ADR-0008 §5 justification this probe re-checks.
	for idx, owner := range nonRollbackableIndexes {
		if !downExecutesNothing(t, owner) {
			t.Errorf("declared non-rollbackable index %q: %s's Down executes SQL; ADR-0008 §5 "+
				"requires a comment-only no-op, so the exemption is no longer justified", idx, owner)
		}
	}
	for _, b := range breaking {
		t.Logf("BREAKS RE-APPLY: %s", b)
	}
	if len(breaking) > 0 {
		t.Errorf("%d index(es) survive a Down whose table also survives, so re-applying that migration "+
			"fails with `relation already exists` (see the BREAKS RE-APPLY lines)", len(breaking))
	}
}

// TestCreatedTablesSurviveTheirDown checks the coarser half of the same story,
// and it is the half that makes the index probe's exemptions sound: an index may
// be left unnamed in a Down only because its table is dropped there. If a table
// created by an Up were not dropped by its Down, every index on it would leak,
// and the exemption the index probe grants would be granting a defect.
//
// It is also the guard for a real regression mode: a `CREATE TABLE` added to an
// Up with no matching `DROP TABLE` in its Down leaves the table (and its data)
// behind after a rollback, and the next Up fails on the table name.
func TestCreatedTablesSurviveTheirDown(t *testing.T) {
	var offenders []string
	var checked, exemplars int
	// exempted records the tables this probe spared, so the exemption can be
	// asserted to be exactly the declared one instead of accepting whatever the
	// probe happened to skip.
	exempted := map[string]string{}
	for _, name := range migrationFiles(t) {
		up, down := splitGoose(readMigration(t, name))
		_, created := objectsCreatedIn(up)
		if len(created) == 0 {
			continue
		}
		checked++
		if strings.TrimSpace(down) == "" {
			offenders = append(offenders, name+" creates tables but has no Down section")
			continue
		}
		dropped := objectsDroppedIn(down)
		missing, exemptHere := 0, 0
		for _, tbl := range created {
			if !dropped[tbl] {
				owner, declared := nonRollbackableTables[tbl]
				if declared {
					if owner != name {
						t.Errorf("%s creates %q but the non-rollbackable declaration credits %s; "+
							"a stale declaration is how the exemption list quietly becomes wrong",
							name, tbl, owner)
						continue
					}
					// ADR-0008 §5: the Down is a comment-only no-op, so this is a
					// deliberate survivor. Re-prove it from the SQL, not the map.
					if !downExecutesNothing(t, name) {
						t.Errorf("%s is declared non-rollbackable but its Down executes SQL; "+
							"ADR-0008 §5 requires a comment-only no-op", name)
					}
					exempted[tbl] = name
					exemptHere++
					continue
				}
				missing++
				offenders = append(offenders, name+" leaves table "+tbl+" behind")
			}
		}
		if missing == 0 && exemptHere == 0 {
			exemplars++
		}
	}
	if checked < 5 {
		t.Fatalf("only %d migrations create a table; the parser is broken", checked)
	}
	// Anti-vacuous: at least one migration must drop everything it creates, or
	// this check could not pass and would prove nothing about the others.
	if exemplars == 0 {
		t.Fatalf("no migration drops every table it creates; the check cannot pass")
	}
	// The exemption is exactly the declared set, no more and no less: a declared
	// table that is no longer spared means its Down now drops something ADR-0008
	// §5 forbids dropping, and an unlisted table that was spared would mean the
	// guard had been loosened without an entry here.
	if len(exempted) != len(nonRollbackableTables) {
		t.Errorf("the probe spared %d table(s) (%v) but %d are declared (%v); the exemption "+
			"set has drifted", len(exempted), exempted, len(nonRollbackableTables), nonRollbackableTables)
	}
	for tbl, owner := range nonRollbackableTables {
		if got, ok := exempted[tbl]; !ok {
			t.Errorf("declared non-rollbackable table %q (%s) was not spared: its Down now "+
				"removes it, which is the defect ADR-0008 §5 exists to prevent", tbl, owner)
		} else if got != owner {
			t.Errorf("non-rollbackable table %q was spared under %s, want %s", tbl, got, owner)
		}
	}
	for _, o := range offenders {
		t.Logf("OFFENDER: %s", o)
	}
	if len(offenders) > 0 {
		t.Errorf("%d table definition(s) survive their own Down section", len(offenders))
	}
}

// indexOnRE captures an index's target table. It is separate from
// ddlCreateIndexRE because the "ON <table>" clause can be several lines below
// the index name, which the single-regex form cannot span reliably.
var indexOnRE = regexp.MustCompile(`(?is)CREATE\s+(?:UNIQUE\s+)?INDEX\s+(?:CONCURRENTLY\s+)?(?:IF\s+NOT\s+EXISTS\s+)?("[A-Za-z0-9_]+"|[A-Za-z0-9_]+)\s+ON\s+("[A-Za-z0-9_]+"|[A-Za-z0-9_]+)`)

// indexTargets maps index name -> table name for every CREATE INDEX in a
// migration's Up section.
func indexTargets(up string) map[string]string {
	out := make(map[string]string)
	for _, m := range indexOnRE.FindAllStringSubmatch(stripLineComments(up), -1) {
		out[unquote(m[1])] = unquote(m[2])
	}
	return out
}

// TestNoIndexSurvivesTheFullDownSequence tests the documented operator story in
// docs/migration-decision.md (ADR-0008 搂1 and 搂4: migrations roll back under
// `-migrate-down`, one step per invocation, and the rollback story is
// restore-from-backup) against the strongest reading of it: if every migration's
// Down is run in reverse order 鈥?which is what repeated `-migrate-down`, or a
// single goose `down-to 0`, does 鈥?is the schema actually back at zero?
//
// The property that decides it is cheap and database-free. An index survives the
// whole sequence iff no Down in the repository names it AND no Down drops the
// table it is on. If any index survives, then re-applying the Up that created it
// runs `CREATE INDEX <name>` against an object that still exists, and Postgres
// answers `relation "<name>" already exists` 鈥?the migration aborts mid-run and
// the advisory lock is held until the operator intervenes.
//
// Only indexes created by a migration that also *drops its table* in Down are
// exempt: DROP TABLE removes dependent indexes with it, which is why the
// per-migration form of this check (the two probes above) passes while this one
// can still fail. This is the version of the question that matters, and nothing
// in the repository asks it: migrate_down_test.go rolls back exactly one step
// from the head, and migrations_test.go only asserts each file has a Down section.
func TestNoIndexSurvivesTheFullDownSequence(t *testing.T) {
	type origin struct{ file, table string }

	created := map[string]origin{}
	droppedByName := map[string]bool{}
	tablesDropped := map[string]bool{}

	for _, name := range migrationFiles(t) {
		up, down := splitGoose(readMigration(t, name))
		targets := indexTargets(up)
		createdIdx, _ := objectsCreatedIn(up)
		for _, idx := range createdIdx {
			tbl, ok := targets[idx]
			if !ok {
				t.Fatalf("%s: index %q has no parsed ON clause; the probe cannot attribute it", name, idx)
			}
			created[idx] = origin{file: name, table: tbl}
		}
		for obj := range objectsDroppedIn(down) {
			droppedByName[obj] = true
		}
		for _, m := range ddlDropTableRE.FindAllStringSubmatch(stripLineComments(down), -1) {
			for _, g := range m[1:] {
				if g != "" {
					tablesDropped[unquote(identRE.FindString(g))] = true
				}
			}
		}
	}
	if len(created) < 20 {
		t.Fatalf("parsed only %d CREATE INDEX statements; the parser is broken", len(created))
	}
	if len(tablesDropped) < 5 {
		t.Fatalf("parsed only %d DROP TABLE statements; the Down parser is broken", len(tablesDropped))
	}

	var survivors []string
	// spared records the declared non-rollbackable indexes that would otherwise
	// have been reported, so the exemption can be asserted instead of assumed.
	spared := map[string]string{}
	for idx, o := range created {
		if droppedByName[idx] {
			continue // some Down removes it by name
		}
		if tablesDropped[o.table] {
			continue // a Down drops its table, which drops the index with it
		}
		if owner, declared := nonRollbackableIndexes[idx]; declared {
			if owner != o.file {
				t.Errorf("index %q is declared non-rollbackable under %s but is created by %s; "+
					"a stale declaration is how the exemption list quietly becomes wrong",
					idx, owner, o.file)
				continue
			}
			spared[idx] = owner
			continue
		}
		survivors = append(survivors, idx+" (created by "+o.file+", table "+o.table+")")
	}
	// Every declared non-rollbackable index must still be created by the migration
	// the declaration names, and that migration's Down must execute nothing
	// (ADR-0008 §5). This is what stops the exemption from being an unreasoned
	// list: the declaration is re-proved from the shipped SQL on every run.
	for idx, owner := range nonRollbackableIndexes {
		o, ok := created[idx]
		if !ok {
			t.Errorf("declared non-rollbackable index %q is created by no migration's Up; "+
				"remove the declaration", idx)
			continue
		}
		if o.file != owner {
			t.Errorf("declared non-rollbackable index %q is created by %s, not %s", idx, o.file, owner)
		}
		if !downExecutesNothing(t, owner) {
			t.Errorf("declared non-rollbackable index %q: %s's Down executes SQL; ADR-0008 §5 "+
				"requires a comment-only no-op, so the exemption is no longer justified", idx, owner)
		}
		if _, atRisk := spared[idx]; !atRisk {
			// Not a failure: the object is removed anyway (0007's Down drops
			// audit_events), which is a stronger control. Log it so the reader
			// knows the declaration is currently inert rather than load-bearing.
			t.Logf("declared non-rollbackable index %q needs no exemption: a Down removes it "+
				"anyway (by name or by dropping its table)", idx)
		}
	}
	sort.Strings(survivors)
	for _, s := range survivors {
		t.Logf("SURVIVES THE DOWN SEQUENCE: %s", s)
	}
	if len(survivors) > 0 {
		t.Errorf("%d index(es) are removed by no Down in the repository and sit on a table no Down drops, "+
			"so a full rollback leaves them behind and the re-apply fails with `relation already exists` "+
			"(see the SURVIVES THE DOWN SEQUENCE lines)", len(survivors))
	}
}

// probe above, and the one that states the defect precisely.
