//go:build audit7

package z21migrationsschemaintegrity

import (
	"sort"
	"strings"
	"testing"
)

// TestParserInventory is a diagnostic, not a finding: it prints the tables and
// indexes the parser recovered, so a reader can see the anti-vacuous premise
// behind the two guards.
func TestParserInventory(t *testing.T) {
	s := parseSchema(t, readAll(t, migrationFiles(t)))
	var tables []string
	for table := range s.columns {
		tables = append(tables, table)
	}
	sort.Strings(tables)
	t.Logf("tables: %s", strings.Join(tables, ", "))
	for _, table := range tables {
		var lists []string
		for _, cols := range s.indexes[table] {
			lists = append(lists, strings.Join(cols, ","))
		}
		t.Logf("  %s (%d cols) indexes: %s", table, len(s.columns[table]), strings.Join(lists, " | "))
	}
}
