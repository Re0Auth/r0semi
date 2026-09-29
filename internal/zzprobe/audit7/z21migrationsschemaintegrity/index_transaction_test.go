//go:build audit7

package z21migrationsschemaintegrity

import (
	"sort"
	"strings"
	"testing"
)

// TestIndexMigrationsAreNonConcurrentInOneTransaction extends round 6's 04-7
// from migration 0022 to the whole family, and pins the two facts the write
// freeze follows from:
//
//  1. No migration declares `-- +goose NO TRANSACTION`, so goose wraps each
//     file's Up in ONE transaction (goose v3.28.0 provider.go:468-530 ->
//     runMigrations). Every CREATE INDEX in that file therefore runs before the
//     commit that drops the SHARE lock.
//  2. No migration uses CREATE INDEX CONCURRENTLY, so each one takes ACCESS
//     EXCLUSIVE at creation and SHARE while it builds, and SHARE conflicts with
//     ROW EXCLUSIVE — i.e. with INSERT/UPDATE/DELETE.
//
// The freeze is per migration, not one long freeze across all of them: goose
// commits after each file. It is therefore the *largest single file's* index
// build that bounds the window, which is why the multi-index files here are
// worth naming.
func TestIndexMigrationsAreNonConcurrentInOneTransaction(t *testing.T) {
	raw := readAll(t, migrationFiles(t))
	names := make([]string, 0, len(raw))
	for n := range raw {
		names = append(names, n)
	}
	sort.Strings(names)

	noTransaction := 0
	concurrent := 0
	type entry struct {
		name string
		n    int
	}
	var multi []entry
	total := 0

	for _, name := range names {
		up, _ := splitDirection(raw[name])
		upper := strings.ToUpper(up)
		if strings.Contains(upper, "GOOSE NO TRANSACTION") {
			noTransaction++
		}
		if strings.Contains(upper, "CONCURRENTLY") {
			concurrent++
		}
		n := len(reIndex.FindAllStringSubmatch(up, -1))
		total += n
		if n > 1 {
			multi = append(multi, entry{name, n})
		}
	}
	if total < 20 {
		t.Fatalf("found only %d CREATE INDEX statements; the extractor is broken", total)
	}
	t.Logf("%d CREATE INDEX statements across %d migrations; %d declare NO TRANSACTION; %d use CONCURRENTLY",
		total, len(names), noTransaction, concurrent)
	for _, m := range multi {
		t.Logf("write-freeze window: %s builds %d indexes in one transaction, none concurrently", m.name, m.n)
	}

	if noTransaction != 0 || concurrent != 0 {
		t.Fatalf("the premise changed: noTransaction=%d concurrent=%d — re-read this probe against the migrations",
			noTransaction, concurrent)
	}
	if len(multi) < 3 {
		t.Fatalf("only %d migrations build several indexes; the family shrank, re-check 04-7", len(multi))
	}
}
