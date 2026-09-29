//go:build audit7

package z21migrationsschemaintegrity

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Locating the tree
// ---------------------------------------------------------------------------

// repoRoot walks up from the test's working directory until it finds go.mod.
// The probe reads the migrations and the package under audit as data; it never
// writes anything.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 12; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("no go.mod found above %s", dir)
	return ""
}

func migrationsDir(t *testing.T) string {
	t.Helper()
	return filepath.Join(repoRoot(t), "internal", "store", "postgres", "migrations")
}

func storeFiles(t *testing.T) []string {
	t.Helper()
	dir := filepath.Join(repoRoot(t), "internal", "store", "postgres")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		out = append(out, filepath.Join(dir, name))
	}
	sort.Strings(out)
	if len(out) < 10 {
		t.Fatalf("found only %d store source files; the locator is broken", len(out))
	}
	return out
}

func migrationFiles(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(migrationsDir(t))
	if err != nil {
		t.Fatalf("read migrations: %v", err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		out = append(out, filepath.Join(migrationsDir(t), e.Name()))
	}
	sort.Strings(out)
	if len(out) < 20 {
		t.Fatalf("found only %d migration files; the locator is broken", len(out))
	}
	return out
}

func readAll(t *testing.T, paths []string) map[string]string {
	t.Helper()
	out := make(map[string]string, len(paths))
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		out[filepath.Base(p)] = string(b)
	}
	return out
}

func readFileString(root string, parts ...string) (string, error) {
	b, err := os.ReadFile(filepath.Join(append([]string{root}, parts...)...))
	return string(b), err
}

// ---------------------------------------------------------------------------
// Schema model, parsed from the migration SQL
// ---------------------------------------------------------------------------

type column struct {
	notNull bool
	hasDef  bool
	unique  bool
	fk      bool
}

type schema struct {
	// columns[table][column]
	columns map[string]map[string]column
	// indexes[table] = each index's column list, first column first.
	indexes map[string][][]string
	// createdBy[object] = the migration file that created it.
	createdBy map[string]string
}

func flattenSQL(body string) string {
	r := strings.NewReplacer("\r\n", " ", "\n", " ", "\t", " ")
	return r.Replace(body)
}

// splitDirection separates a migration file's Up section from its Down section.
// Parsing the whole file means the Down section's DROP statements (and the
// objects they name) land in the "created" set, which is how a schema parser
// quietly invents objects that no Up section creates.
func splitDirection(body string) (up, down string) {
	if i := strings.Index(body, "-- +goose Down"); i >= 0 {
		return body[:i], body[i:]
	}
	return body, ""
}

// stripSQLComments removes `-- ...` line comments. The migrations document every
// column inline, and those comments contain commas and words that a purely
// lexical column parser would otherwise read as column definitions.
func stripSQLComments(body string) string {
	out := make([]string, 0, 64)
	for _, line := range strings.Split(body, "\n") {
		if i := strings.Index(line, "--"); i >= 0 {
			line = line[:i]
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

var (
	reCreateTable = regexp.MustCompile(`(?is)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?("?[A-Za-z_][A-Za-z0-9_]*"?)`)
	// The index column list is read by matchClosingParen, not by the regex, so a
	// parenthesised expression index does not truncate it. Group 1 is the index
	// name, group 2 the table.
	reIndex     = regexp.MustCompile(`(?is)CREATE\s+(?:UNIQUE\s+)?INDEX\s+(?:CONCURRENTLY\s+)?(?:IF\s+NOT\s+EXISTS\s+)?("?[A-Za-z_][A-Za-z0-9_]*"?)\s+ON\s+("?[A-Za-z_][A-Za-z0-9_]*"?)\s*\(`)
	reAddCol    = regexp.MustCompile(`(?is)ALTER\s+TABLE\s+("?[A-Za-z_][A-Za-z0-9_]*"?)\s+ADD\s+COLUMN\s+(?:IF\s+NOT\s+EXISTS\s+)("?[A-Za-z_][A-Za-z0-9_]*"?)([^;]*)`)
	reCreateSeq = regexp.MustCompile(`(?is)CREATE\s+SEQUENCE\s+(?:IF\s+NOT\s+EXISTS\s+)("?[A-Za-z_][A-Za-z0-9_]*"?)`)
	rePrimary   = regexp.MustCompile(`(?is)PRIMARY\s+KEY\s*\(`)
	// A table-level UNIQUE constraint is backed by an index too.
	reUnique = regexp.MustCompile(`(?is)(?:^|\s)UNIQUE\s*\(`)
)

func unquote(s string) string { return strings.Trim(s, `"`) }

// tableConstraintKeywords are the words that begin a table-level constraint
// rather than a column definition.
var tableConstraintKeywords = map[string]bool{
	"constraint": true, "primary": true, "unique": true, "check": true,
	"foreign": true, "exclude": true, "like": true,
}

func classify(def string) column {
	l := strings.ToLower(def)
	return column{
		notNull: strings.Contains(l, "not null"),
		hasDef:  strings.Contains(l, "default"),
		unique:  strings.Contains(l, "unique"),
		fk:      strings.Contains(l, "references"),
	}
}

// splitTopLevel cuts a parenthesised body at depth-0 commas outside quoted
// strings, so a definition containing `'(a,b)'` or `(a, b)` stays in one piece.
// Splitting lexically instead is exactly how a parser starts attributing the
// next table's columns to this one.
func splitTopLevel(s string) []string {
	var out []string
	depth, start := 0, 0
	quote := byte(0)
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case quote != 0:
			if ch == quote {
				quote = 0
			}
		case ch == '\'' || ch == '"':
			quote = ch
		case ch == '(':
			depth++
		case ch == ')':
			depth--
		case ch == ',' && depth == 0:
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if tail := strings.TrimSpace(s[start:]); tail != "" {
		out = append(out, tail)
	}
	return out
}

// columnName returns the leading identifier of a column definition and the rest
// of the definition, or ("", "") when the fragment is a table-level constraint.
func columnName(def string) (string, string) {
	def = strings.TrimSpace(def)
	if def == "" {
		return "", ""
	}
	i := 0
	for i < len(def) && (def[i] == '_' || def[i] == '-' ||
		(def[i] >= 'a' && def[i] <= 'z') || (def[i] >= 'A' && def[i] <= 'Z') ||
		(def[i] >= '0' && def[i] <= '9')) {
		i++
	}
	if i == 0 {
		return "", ""
	}
	name := def[:i]
	if tableConstraintKeywords[strings.ToLower(name)] {
		return "", ""
	}
	return name, def[i:]
}

// parseSchema builds the schema from the migration text: everything the embedded
// migration set creates, which is exactly what a deployment applies.
func parseSchema(t *testing.T, migrations map[string]string) schema {
	t.Helper()
	s := schema{
		columns:   make(map[string]map[string]column),
		indexes:   make(map[string][][]string),
		createdBy: make(map[string]string),
	}
	names := make([]string, 0, len(migrations))
	for n := range migrations {
		names = append(names, n)
	}
	sort.Strings(names)

	for _, name := range names {
		migrationUp, _ := splitDirection(migrations[name])
		body := flattenSQL(stripSQLComments(migrationUp))
		for _, m := range reCreateTable.FindAllStringSubmatchIndex(body, -1) {
			table := unquote(body[m[2]:m[3]])
			open := strings.IndexByte(body[m[1]:], '(')
			if open < 0 {
				continue
			}
			start := m[1] + open
			end := matchClosingParen(body, start)
			if end < 0 {
				continue
			}
			defs := body[start+1 : end]

			cols := s.columns[table]
			if cols == nil {
				cols = make(map[string]column)
				s.columns[table] = cols
			}
			for _, def := range splitTopLevel(defs) {
				colName, tail := columnName(def)
				if colName == "" {
					continue
				}
				cols[colName] = classify(tail)
				if strings.Contains(strings.ToLower(tail), "primary key") {
					s.indexes[table] = append(s.indexes[table], []string{colName})
				}
			}
			// A table-level PRIMARY KEY creates an index of its own; without
			// registering it, a lookup by the primary key reads as unindexed.
			if loc := rePrimary.FindStringIndex(defs); loc != nil {
				if close := matchClosingParen(defs, loc[1]-1); close > 0 {
					pkCols := splitIndexColumns(defs[loc[1]:close])
					s.indexes[table] = append(s.indexes[table], pkCols)
					s.createdBy["primary:"+table] = name
				}
			}
			s.createdBy["table:"+table] = name
		}
		for _, m := range reCreateTable.FindAllStringSubmatchIndex(body, -1) {
			table := unquote(body[m[2]:m[3]])
			open := strings.IndexByte(body[m[1]:], '(')
			if open < 0 {
				continue
			}
			start := m[1] + open
			end := matchClosingParen(body, start)
			if end < 0 {
				continue
			}
			defs := body[start+1 : end]
			for _, loc := range reUnique.FindAllStringIndex(defs, -1) {
				if close := matchClosingParen(defs, loc[1]-1); close > 0 {
					s.indexes[table] = append(s.indexes[table], splitIndexColumns(defs[loc[1]:close]))
				}
			}
		}
		for _, m := range reAddCol.FindAllStringSubmatch(body, -1) {
			table := unquote(m[1])
			cols := s.columns[table]
			if cols == nil {
				cols = make(map[string]column)
				s.columns[table] = cols
			}
			cols[unquote(m[2])] = classify(m[3])
		}
		for _, m := range reCreateSeq.FindAllStringSubmatch(body, -1) {
			s.createdBy["sequence:"+unquote(m[1])] = name
		}
		for _, m := range reIndex.FindAllStringSubmatchIndex(body, -1) {
			indexName := unquote(body[m[2]:m[3]])
			table := unquote(body[m[4]:m[5]])
			open := strings.IndexByte(body[m[5]:], '(')
			if open < 0 {
				continue
			}
			start := m[5] + open
			end := matchClosingParen(body, start)
			if end < 0 {
				continue
			}
			cols := splitIndexColumns(body[start+1 : end])
			s.indexes[table] = append(s.indexes[table], cols)
			s.createdBy["index:"+indexName] = name
		}
	}
	if len(s.columns) < 18 {
		var got []string
		for table := range s.columns {
			got = append(got, table)
		}
		sort.Strings(got)
		t.Fatalf("parsed only %d tables from the migrations (%v); the parser is broken",
			len(s.columns), got)
	}
	var idx int
	for _, v := range s.indexes {
		idx += len(v)
	}
	if idx < 30 {
		t.Fatalf("parsed only %d indexes; the parser is broken", idx)
	}
	return s
}

// matchClosingParen returns the index of the ')' matching the '(' at open. An
// empty body returns open, which is what a `CHECK ()`-shaped zero-column
// constraint needs; a genuinely unbalanced body returns -1.
func matchClosingParen(s string, open int) int {
	if open >= len(s) || s[open] != '(' {
		return -1
	}
	depth := 0
	inQuote := byte(0)
	for i := open; i < len(s); i++ {
		ch := s[i]
		switch {
		case inQuote != 0:
			if ch == inQuote {
				inQuote = 0
			}
		case ch == '\'' || ch == '"':
			inQuote = ch
		case ch == '(':
			depth++
		case ch == ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// splitIndexColumns normalises an index column list: `subject`, `occurred_at
// DESC` and `upper(replace(user_code, '-', ”))` each become one entry.
func splitIndexColumns(spec string) []string {
	var out []string
	for _, raw := range splitTopLevel(spec) {
		if c := normalizeIndexColumn(raw); c != "" {
			out = append(out, c)
		}
	}
	return out
}

func normalizeIndexColumn(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "(")
	s = strings.TrimSuffix(s, ")")
	s = strings.TrimSpace(s)
	fields := strings.Fields(s)
	if len(fields) > 1 {
		switch strings.ToUpper(fields[len(fields)-1]) {
		case "ASC", "DESC":
			s = strings.Join(fields[:len(fields)-1], " ")
		case "NULLS":
			if len(fields) > 2 {
				s = strings.Join(fields[:len(fields)-2], " ")
			}
		}
	}
	if i := strings.Index(s, "::"); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}
