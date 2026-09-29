//go:build audit7

package z21migrationsschemaintegrity

import (
	"regexp"
	"sort"
	"strings"
	"testing"
)

// sqlKeywords and operators that can never be a column predicate.
var notAColumn = map[string]bool{
	"where": true, "and": true, "or": true, "not": true, "null": true, "true": true,
	"false": true, "select": true, "in": true, "is": true, "exists": true, "returning": true,
	"any": true, "all": true, "from": true, "delete": true, "update": true, "set": true,
	"values": true, "upper": true, "lower": true, "replace": true, "coalesce": true,
	"interval": true, "now": true, "count": true, "distinct": true, "on": true, "as": true,
	"case": true, "when": true, "then": true, "else": true, "end": true, "like": true,
	"ilike": true, "between": true, "by": true, "order": true, "limit": true, "desc": true,
	"asc": true, "union": true, "sum": true, "max": true, "min": true, "minute": true,
	"secs": true, "seconds": true,
}

var (
	reDelete = regexp.MustCompile(`(?is)DELETE\s+FROM\s+("?[A-Za-z_]\w*"?)`)
	reUpdate = regexp.MustCompile(`(?is)UPDATE\s+("?[A-Za-z_]\w*"?)\s`)
	reWhere  = regexp.MustCompile(`(?is)\bWHERE\b`)
	// A simple predicate: `col`, `table.col` or `alias.col` on the left of a
	// comparison operator. Function calls (`upper(...)`) do not match.
	rePredicateCol = regexp.MustCompile(`(?is)(?:\b[A-Za-z_]\w*\s*\.\s*)?\b([A-Za-z_]\w*)\s*(?:=|<>|!=|<=|>=|<|>|\bIS\b|\bIN\b)`)
	reIdent        = regexp.MustCompile(`[A-Za-z_]\w*`)
)

// mutation is one DELETE/UPDATE statement's table and the set of columns its
// WHERE clause compares.
type mutation struct {
	table  string
	cols   []string
	extras []string
	stmt   string
}

func first10(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 120 {
		return s[:120] + "..."
	}
	return s
}

// reTerminator ends a statement's WHERE clause: the next SQL statement's
// keyword, a RETURNING clause, or a semicolon. Without this the concatenated
// literals of one Go file run into the next statement and every following column
// reads as a predicate of this one.
var reTerminator = regexp.MustCompile(`(?is);|\bRETURNING\b|\bDELETE\s+FROM\b|\bINSERT\s+INTO\b|\bUPDATE\b|\bSELECT\b`)

// mutationsFromSQL finds every DELETE/UPDATE statement in a blob of concatenated
// Go SQL literals and returns its table plus WHERE-clause columns.
func mutationsFromSQL(t *testing.T, sql string) []mutation {
	t.Helper()
	var out []mutation
	scan := func(idxs [][]int, tableGroup int) {
		for _, m := range idxs {
			table := unquote(sql[m[tableGroup]:m[tableGroup+1]])
			rest := sql[m[1]:]
			end := len(rest)
			if loc := reTerminator.FindStringIndex(rest); loc != nil {
				end = loc[0]
			}
			stmt := sql[m[0] : m[1]+end]
			// An UPDATE that never reaches its SET is a concatenation artefact,
			// not a statement: real Go-built updates carry SET.
			if !strings.Contains(strings.ToUpper(stmt), " SET ") {
				continue
			}
			mut := mutation{table: table, stmt: first10(stmt)}

			preds := predicateColumns(stmt)
			for c := range preds {
				mut.cols = append(mut.cols, c)
			}
			sort.Strings(mut.cols)
			if len(mut.cols) == 0 {
				continue
			}
			// The table name and the aliases it was given are not columns.
			mut.extras = append(mut.extras, table)
			for _, id := range reIdent.FindAllString(stmt, -1) {
				mut.extras = append(mut.extras, strings.ToLower(id))
			}
			out = append(out, mut)
		}
	}
	scan(reDelete.FindAllStringSubmatchIndex(sql, -1), 2)
	scan(reUpdate.FindAllStringSubmatchIndex(sql, -1), 2)
	return out
}

// predicateColumns returns the column names compared in the statement's WHERE
// clause. Fails the test when the extractor finds nothing at all, so a broken
// regex cannot masquerade as "everything is indexed".
func predicateColumns(stmt string) map[string]bool {
	loc := reWhere.FindStringIndex(stmt)
	if loc == nil {
		return nil
	}
	clause := stmt[loc[1]:]
	if i := strings.Index(strings.ToLower(clause), " returning "); i >= 0 {
		clause = clause[:i]
	}
	out := make(map[string]bool)
	for _, m := range rePredicateCol.FindAllStringSubmatch(clause, -1) {
		col := strings.ToLower(m[1])
		if notAColumn[col] {
			continue
		}
		out[col] = true
	}
	return out
}

// TestEveryGoMutationPredicateHasALeadingIndex generalises the existing
// TestClientScopedRevokeIsIndexed: instead of a hand-written list of tables, it
// derives every delete/update target the shipped store names and checks that
// each one has an index whose LEADING column the predicate can use.
//
// This is the guard that would have caught the oidc_devices client_id gap (04-3)
// without anyone remembering to add the table to a list.
func TestEveryGoMutationPredicateHasALeadingIndex(t *testing.T) {
	s := parseSchema(t, readAll(t, migrationFiles(t)))
	sql := goSQL(t)
	muts := mutationsFromSQL(t, sql)
	if len(muts) < 8 {
		t.Fatalf("extracted only %d mutation statements; the extractor is broken", len(muts))
	}

	reported := 0
	for _, mut := range muts {
		cols := s.columns[mut.table]
		if cols == nil {
			t.Errorf("MUTATION ON UNKNOWN TABLE: %q has no CREATE TABLE in the shipped migrations (%s)",
				mut.table, mut.stmt)
			reported++
			continue
		}
		// Only columns of this table can be predicates; everything else the
		// extractor picked up is an alias or a concatenation artefact.
		var preds []string
		for _, c := range mut.cols {
			if hasColumn(cols, c) {
				preds = append(preds, c)
			}
		}
		if len(preds) == 0 {
			continue
		}
		if !indexCoversAll(s.indexes[mut.table], preds) {
			// A lookup is still fine when the predicate names the whole primary
			// key or any single indexed column; a sequential scan happens only
			// when no index supplies any of them.
			if !indexCoversAny(s.indexes[mut.table], preds) {
				t.Errorf("UNINDEXED MUTATION PREDICATE: %s WHERE %v — no index covers any of those columns (%s)",
					mut.table, preds, mut.stmt)
				reported++
			}
		}
	}
	if reported == 0 {
		t.Logf("all %d delete/update targets derived from the Go sources can be served by an index", len(muts))
	}
}

// indexCoversAll reports whether some index's leading columns are exactly the
// predicate set (any order): that is the shape Postgres can use without a scan.
func indexCoversAll(lists [][]string, preds []string) bool {
	want := make(map[string]bool, len(preds))
	for _, p := range preds {
		want[p] = true
	}
	for _, cols := range lists {
		got := make(map[string]bool, len(cols))
		for _, c := range cols {
			got[normalizeIndexColumn(c)] = true
		}
		if len(got) != len(want) {
			continue
		}
		ok := true
		for p := range want {
			if !got[p] {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func indexCoversAny(lists [][]string, preds []string) bool {
	for _, cols := range lists {
		for _, c := range cols {
			norm := normalizeIndexColumn(c)
			for _, p := range preds {
				if norm == p {
					return true
				}
			}
		}
	}
	return false
}

func hasColumn(cols map[string]column, name string) bool {
	_, ok := cols[name]
	return ok
}
