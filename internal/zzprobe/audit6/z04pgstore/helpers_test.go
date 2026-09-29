//go:build audit6

package z04pgstore

// Shared plumbing for the zone-04 probes: where the shipped sources live, and
// small parsers over the migration SQL and the Go adapter. The shape follows
// internal/zzprobe/pgstore/helpers_test.go from round 5 (read the live files
// from disk, never modify the tracked package), one directory deeper.

import (
	"crypto/rand"
	"crypto/rsa"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/internal/oidcstore"
)

// testSigner builds the signer both store constructors require. Nothing on the
// probed paths signs with it; it only has to exist.
func testSigner(t *testing.T) *oidcstore.Signer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	return oidcstore.NewSigner("probe-key", key)
}

const (
	// repoRoot is the workspace root, resolved from this package's test working
	// directory (go test runs tests with the package directory as cwd).
	repoRoot = "../../../.."
	// migrationsDir is the shipped schema, read from disk so the probes cannot
	// drift from what the migration runner would apply.
	migrationsDir = repoRoot + "/internal/store/postgres/migrations"
	// adapterDir is the Postgres adapter's own sources.
	adapterDir = repoRoot + "/internal/store/postgres"
	// memoryDir is the in-memory twin, the contract reference a database-free
	// probe can execute.
	memoryDir = repoRoot + "/internal/store/memory"
)

// readShipped returns a tracked file's bytes, failing loudly when the path does
// not resolve — a probe that reads nothing passes vacuously.
func readShipped(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.FromSlash(path))
	if err != nil {
		t.Fatalf("read %s: %v (path resolution broken; every assertion built on it is vacuous)", path, err)
	}
	if len(body) == 0 {
		t.Fatalf("%s is empty", path)
	}
	return string(body)
}

// stripGoComments removes // and /* */ comments so SQL fragments quoted in
// prose are never mistaken for executed code.
func stripGoComments(src string) string {
	out := regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(src, "")
	var lines []string
	for _, line := range strings.Split(out, "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

// methodBodyOf returns the source of one method, from its `func (…) name(` line
// to the next top-level func declaration.
func methodBodyOf(t *testing.T, code, name string) string {
	t.Helper()
	return funcBodyFrom(t, code, `(?m)^func \([^)]*\) `+regexp.QuoteMeta(name)+`\(`)
}

// topLevelFuncBodyOf returns the source of a package-level function, matching
// `func name(` with no receiver.
func topLevelFuncBodyOf(t *testing.T, code, name string) string {
	t.Helper()
	return funcBodyFrom(t, code, `(?m)^func `+regexp.QuoteMeta(name)+`\(`)
}

func funcBodyFrom(t *testing.T, code, startPattern string) string {
	t.Helper()
	re := regexp.MustCompile(startPattern)
	loc := re.FindStringIndex(code)
	if loc == nil {
		t.Fatalf("function matching %s not found; the probe is not reading the file (was it renamed?)", startPattern)
	}
	rest := code[loc[0]:]
	if next := regexp.MustCompile(`(?m)^func `).FindStringIndex(rest[1:]); next != nil {
		rest = rest[:next[0]+1]
	}
	if strings.TrimSpace(rest) == "" {
		t.Fatalf("function matching %s extracted as empty text", startPattern)
	}
	return rest
}

// leadingIndexCols returns table -> the set of columns that are the FIRST column
// of some index the shipped migrations create. It includes PRIMARY KEY and
// table-level UNIQUE leading columns, matching what a single-column predicate can
// actually use. This parser is written independently of the ones inside
// internal/store/postgres, so a probe can disagree with a production guard.
func leadingIndexCols(t *testing.T) map[string]map[string]bool {
	t.Helper()
	out := make(map[string]map[string]bool)
	add := func(table, col string) {
		if out[table] == nil {
			out[table] = make(map[string]bool)
		}
		out[table][col] = true
	}

	paths, err := filepath.Glob(filepath.FromSlash(migrationsDir + "/*.sql"))
	if err != nil {
		t.Fatalf("glob migrations: %v", err)
	}
	sort.Strings(paths)
	if len(paths) < 15 {
		t.Fatalf("found only %d .sql files under %s; the path is broken", len(paths), migrationsDir)
	}

	createIndexRE := regexp.MustCompile(`(?is)CREATE\s+(?:UNIQUE\s+)?INDEX\s+(?:CONCURRENTLY\s+)?(?:IF\s+NOT\s+EXISTS\s+)?\w+\s+ON\s+([A-Za-z0-9_]+)\s*\(([^)]*)\)`)
	tableBlockRE := regexp.MustCompile(`(?is)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([A-Za-z0-9_]+)\s*\((.*?)\s*\)\s*;`)
	bare := func(s string) string { return strings.Trim(strings.TrimSpace(s), `,;"'()`) }

	for _, p := range paths {
		body := stripLineComments(readShipped(t, filepath.ToSlash(p)))
		for _, m := range createIndexRE.FindAllStringSubmatch(body, -1) {
			first := strings.TrimSpace(strings.Split(m[2], ",")[0])
			if i := strings.Index(first, "("); i > 0 { // expression index
				first = strings.TrimSpace(first[:i])
			}
			if first != "" {
				add(m[1], first)
			}
		}
		for _, m := range tableBlockRE.FindAllStringSubmatch(body, -1) {
			for _, line := range strings.Split(m[2], "\n") {
				fields := strings.Fields(strings.TrimSpace(line))
				if len(fields) < 2 {
					continue
				}
				// Table-level `UNIQUE (a, b)`: every column, like the
				// round-5 parser; `PRIMARY KEY (a, b)`: leading only.
				if strings.EqualFold(fields[0], "unique") {
					inner := strings.Trim(strings.Join(fields[1:], " "), "()")
					for _, col := range strings.Split(inner, ",") {
						if c := bare(col); c != "" {
							add(m[1], c)
						}
					}
					continue
				}
				if strings.EqualFold(fields[0], "primary") && len(fields) > 1 && strings.EqualFold(bare(fields[1]), "KEY") {
					inner := strings.Trim(strings.Join(fields[2:], " "), "()")
					if c := bare(strings.Split(inner, ",")[0]); c != "" {
						add(m[1], c)
					}
					continue
				}
				for i := 1; i+1 < len(fields); i++ {
					if strings.EqualFold(bare(fields[i]), "PRIMARY") && strings.EqualFold(bare(fields[i+1]), "KEY") {
						add(m[1], strings.Trim(strings.ToLower(fields[0]), `" `))
					}
				}
			}
		}
	}
	seen := 0
	for _, cols := range out {
		seen += len(cols)
	}
	if seen < 25 {
		t.Fatalf("parsed only %d leading index columns; the parser is not reading the schema", seen)
	}
	return out
}

// stripLineComments removes `--` comments from SQL so commented-out indexes
// cannot be counted by the schema parsers.
func stripLineComments(sql string) string {
	var lines []string
	for _, line := range strings.Split(sql, "\n") {
		if i := strings.Index(line, "--"); i >= 0 {
			line = line[:i]
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}
