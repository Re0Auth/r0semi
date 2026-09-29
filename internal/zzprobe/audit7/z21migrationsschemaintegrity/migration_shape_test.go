//go:build audit7

package z21migrationsschemaintegrity

import (
	"regexp"
	"sort"
	"strings"
	"testing"
)

var reGooseVersion = regexp.MustCompile(`^(\d+)_`)

var (
	reDropTable *regexp.Regexp
	reDropIndex *regexp.Regexp
	reDropCol   *regexp.Regexp
)

func init() {
	reDropTable = regexp.MustCompile(`(?is)DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?("?[A-Za-z_]\w*"?)`)
	reDropIndex = regexp.MustCompile(`(?is)DROP\s+INDEX\s+(?:IF\s+EXISTS\s+)?("?[A-Za-z_]\w*"?)`)
	reDropCol = regexp.MustCompile(`(?is)DROP\s+COLUMN\s+(?:IF\s+EXISTS\s+)?("?[A-Za-z_]\w*"?)`)
}

// versionOf returns the goose numeric version of a migration filename.
func versionOf(name string) (int64, bool) {
	m := reGooseVersion.FindStringSubmatch(name)
	if m == nil {
		return 0, false
	}
	var v int64
	for _, ch := range m[1] {
		v = v*10 + int64(ch-'0')
	}
	return v, true
}

// knownMissingVersions are versions this repository applied to real databases at
// some point and whose files are no longer in the embedded set. 0005_authz.sql
// (dropped by 87f4ad9) created authz_requests; any database that ran it still has
// a row for version 5 in its version table.
var knownMissingVersions = map[int64]string{
	5: "0005_authz.sql, dropped by 87f4ad9 (pre-goose authz_requests)",
}

// TestVersionSequenceHasNoUnexplainedGap carries the guard round 5's PG-002
// asked for: a gap in the version sequence is only allowed if it is named in the
// known-stops list above. The old guard (TestMigrationFilesAreGooseShaped)
// asserts the versions are strictly increasing, which a deletion satisfies.
func TestVersionSequenceHasNoUnexplainedGap(t *testing.T) {
	files := migrationFiles(t)
	byVersion := make(map[int64]string, len(files))
	var max int64
	for _, path := range files {
		name := baseName(path)
		v, ok := versionOf(name)
		if !ok {
			t.Errorf("migration %q has no numeric version prefix", name)
			continue
		}
		if prev, dup := byVersion[v]; dup {
			t.Errorf("version %d is used by both %s and %s", v, prev, name)
		}
		byVersion[v] = name
		if v > max {
			max = v
		}
	}
	if len(byVersion) < 20 {
		t.Fatalf("parsed only %d versions; the locator is broken", len(byVersion))
	}
	for v := int64(1); v <= max; v++ {
		if _, ok := byVersion[v]; ok {
			continue
		}
		if reason, known := knownMissingVersions[v]; known {
			t.Logf("known stop in the version sequence: %d (%s)", v, reason)
			continue
		}
		t.Errorf("MIGRATION GAP: version %d has no file and is not in the known-stops list; "+
			"a database that applied it cannot run provider.Down at all (goose builds the whole "+
			"apply list with getMigration before running any of it)", v)
	}
}

func baseName(path string) string {
	if i := strings.LastIndexAny(path, `\/`); i >= 0 {
		return path[i+1:]
	}
	return path
}

// TestEveryDownIsSafeOnRerun pins the two things a down section has to be for
// `-migrate-down` to be repeatable and explainable: DROPs are guarded with IF
// EXISTS, and a DROP only ever names an object that some migration's Up created.
//
// The second half is the interesting one: a Down whose DROP names nothing
// (0019's `DROP INDEX session_subjects_created_at_idx` when 0019's own Up is the
// only creator, say) is fine, but a Down that drops an object another migration
// created is a cross-migration coupling that turns "undo my step" into "undo
// someone else's".
func TestEveryDownIsSafeOnRerun(t *testing.T) {
	files := migrationFiles(t)
	raw := readAll(t, files)
	created := make(map[string]bool)
	for _, body := range raw {
		up, _ := splitDirection(body)
		for _, m := range reCreateTable.FindAllStringSubmatch(up, -1) {
			created[strings.ToLower(unquote(m[1]))] = true
		}
		for _, m := range reIndex.FindAllStringSubmatch(up, -1) {
			created["index "+strings.ToLower(unquote(m[1]))] = true
		}
	}
	if len(created) < 25 {
		t.Fatalf("recovered only %d created objects; the extractor is broken", len(created))
	}

	reDropTable = regexp.MustCompile(`(?is)DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?("?[A-Za-z_]\w*"?)`)
	reDropIndex = regexp.MustCompile(`(?is)DROP\s+INDEX\s+(?:IF\s+EXISTS\s+)?("?[A-Za-z_]\w*"?)`)
	reDropCol = regexp.MustCompile(`(?is)DROP\s+COLUMN\s+(?:IF\s+EXISTS\s+)?("?[A-Za-z_]\w*"?)`)

	reDropTable = regexp.MustCompile(`(?is)DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?("?[A-Za-z_]\w*"?)`)
	reDropIndex = regexp.MustCompile(`(?is)DROP\s+INDEX\s+(?:IF\s+EXISTS\s+)?("?[A-Za-z_]\w*"?)`)
	reDropCol = regexp.MustCompile(`(?is)DROP\s+COLUMN\s+(?:IF\s+EXISTS\s+)?("?[A-Za-z_]\w*"?)`)

	names := make([]string, 0, len(raw))
	for n := range raw {
		names = append(names, n)
	}
	sort.Strings(names)

	unguarded := 0
	for _, name := range names {
		_, down := splitDirection(raw[name])
		if down == "" {
			t.Errorf("%s: no -- +goose Down section", name)
			continue
		}
		for _, re := range []*regexp.Regexp{reDropTable, reDropIndex} {
			for _, m := range re.FindAllStringSubmatch(down, -1) {
				whole := m[0]
				if !strings.Contains(strings.ToUpper(whole), "IF EXISTS") {
					t.Errorf("DOWN NOT RERUN-SAFE: %s has an unguarded %q; a second -migrate-down "+
						"step fails with 'does not exist'", name, strings.TrimSpace(whole))
					unguarded++
				}
			}
		}
		for _, m := range reDropCol.FindAllStringSubmatch(down, -1) {
			if !strings.Contains(strings.ToUpper(m[0]), "IF EXISTS") {
				t.Errorf("DOWN NOT RERUN-SAFE: %s has an unguarded %q", name, strings.TrimSpace(m[0]))
				unguarded++
			}
		}
		// A DROP must be of something a migration created.
		for _, m := range reDropTable.FindAllStringSubmatch(down, -1) {
			obj := strings.ToLower(unquote(m[1]))
			if !created[obj] {
				t.Errorf("DOWN DROPS AN UNKNOWN OBJECT: %s drops table %q, which no migration's Up creates",
					name, obj)
			}
		}
		for _, m := range reDropIndex.FindAllStringSubmatch(down, -1) {
			obj := "index " + strings.ToLower(unquote(m[1]))
			if !created[obj] {
				t.Errorf("DOWN DROPS AN UNKNOWN OBJECT: %s drops %q, which no migration's Up creates",
					name, obj)
			}
		}
	}
	if unguarded == 0 {
		t.Log("every DROP in every Down section is IF EXISTS-guarded")
	}
}
