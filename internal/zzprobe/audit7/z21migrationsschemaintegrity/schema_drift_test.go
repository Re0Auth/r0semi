//go:build audit7

package z21migrationsschemaintegrity

import (
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Go-side view: every SQL string literal the shipped store builds
// ---------------------------------------------------------------------------

// goSQL returns the concatenation of every string literal that appears as a
// function argument in the shipped store sources. Adjacent literals of an
// implicit concatenation arrive as separate BasicLit nodes in the same
// BinaryExpr, so collecting all BasicLits and joining them recovers the same
// text the database sees (including `SELECT `+deviceCols+` FROM ...`, whose
// column names are then present as one token list).
func goSQL(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	fset := token.NewFileSet()
	for _, path := range storeFiles(t) {
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			v := lit.Value
			if len(v) >= 2 && (v[0] == '`' || v[0] == '"') {
				v = unquoteGoLiteral(v)
			}
			b.WriteString(v)
			b.WriteByte('\n')
			return true
		})
	}
	out := b.String()
	if len(out) < 5000 {
		t.Fatalf("collected only %d bytes of string literals; the extractor is broken", len(out))
	}
	return out
}

func unquoteGoLiteral(v string) string {
	switch v[0] {
	case '`':
		return strings.Trim(v, "`")
	case '"':
		return strings.Trim(v, `"`)
	}
	return v
}

// identifiers returns every identifier-like token in a blob of text, lowercased.
func identifiers(text string) map[string]bool {
	out := make(map[string]bool)
	for _, m := range regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*`).FindAllString(text, -1) {
		out[strings.ToLower(m)] = true
	}
	return out
}

// ---------------------------------------------------------------------------
// Z21-1  schema columns the shipped Go never names
// ---------------------------------------------------------------------------

// TestEverySchemaColumnIsNamedByTheStore is the guard the existing
// credential_columns_test.go does not provide: that one only looks at columns
// whose NAME looks credential-shaped. This one asks the wider question — is
// there a column in the shipped schema that the shipped store never mentions,
// i.e. drift between the migration set and the Go contract.
//
// A column that fails here is not automatically a bug: a primary key, a
// constraint-only column or a column the database defaults can legitimately be
// absent from the Go text. It is a finding when the column is NOT NULL with no
// default (an INSERT that omits it would fail) or when it is meant to carry
// security-relevant state the code silently drops.
func TestEverySchemaColumnIsNamedByTheStore(t *testing.T) {
	s := parseSchema(t, readAll(t, migrationFiles(t)))
	// Anti-vacuous: the parser has to have found the columns this report talks
	// about, or "no orphans" would mean "no columns".
	var total int
	for _, cols := range s.columns {
		total += len(cols)
	}
	if total < 100 {
		t.Fatalf("parsed only %d columns; the parser is broken", total)
	}
	t.Logf("parsed %d tables / %d columns from the migration set", len(s.columns), total)
	sql := strings.ToLower(goSQL(t))
	ids := identifiers(sql)

	type orphan struct {
		table, column string
		c             column
	}
	var orphans []orphan
	for table, cols := range s.columns {
		for name, c := range cols {
			if ids[strings.ToLower(name)] {
				continue
			}
			orphans = append(orphans, orphan{table, name, c})
		}
	}
	sort.Slice(orphans, func(i, j int) bool {
		if orphans[i].table != orphans[j].table {
			return orphans[i].table < orphans[j].table
		}
		return orphans[i].column < orphans[j].column
	})
	for _, o := range orphans {
		t.Errorf("SCHEMA DRIFT: %s.%s is in the shipped schema but no shipped store source names it "+
			"(notNull=%v hasDefault=%v)", o.table, o.column, o.c.notNull, o.c.hasDef)
	}
	if len(orphans) == 0 {
		t.Logf("every column of %d tables is named by the shipped store", len(s.columns))
	}
}

// TestNoRequiredColumnIsInvisibleToTheStore is the sharp subset of the above:
// a NOT NULL column with no DEFAULT that the Go text never names is a write that
// fails at runtime on every INSERT that omits it — the failure mode is a 500,
// not a silent one, so this is a guard rather than a finding today.
func TestNoRequiredColumnIsInvisibleToTheStore(t *testing.T) {
	s := parseSchema(t, readAll(t, migrationFiles(t)))
	ids := identifiers(strings.ToLower(goSQL(t)))
	for table, cols := range s.columns {
		for name, c := range cols {
			if c.notNull && !c.hasDef && !ids[strings.ToLower(name)] {
				t.Errorf("REQUIRED COLUMN NOT REFERENCED: %s.%s is NOT NULL with no DEFAULT and the store "+
					"never names it; every INSERT omitting it will fail unless the caller always supplies it",
					table, name)
			}
		}
	}
}
