//go:build audit7

package z21verify

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// repoRoot walks up from the test's working directory until it finds go.mod.
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

// migrationText returns the text of one migration file.
func migrationText(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(migrationsDir(t), name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

// storeSource returns one shipped (non-test) source file of the postgres store.
func storeSource(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "internal", "store", "postgres", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

// splitDirection returns the Up and Down halves of a goose migration file.
func splitDirection(body string) (up, down string) {
	if i := strings.Index(body, "-- +goose Down"); i >= 0 {
		return body[:i], body[i:]
	}
	return body, ""
}

func stripSQLComments(body string) string {
	lines := strings.Split(body, "\n")
	for i, line := range lines {
		if j := strings.Index(line, "--"); j >= 0 {
			lines[i] = line[:j]
		}
	}
	return strings.Join(lines, "\n")
}

// goSourceFiles lists the shipped .go files of internal/store/postgres.
func goSourceFiles(t *testing.T) []string {
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
	if len(out) < 10 {
		t.Fatalf("found only %d shipped store sources; the locator is broken", len(out))
	}
	return out
}

// readPath reads an absolute path.
func readPath(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// readDirNames lists the entry names of a directory.
func readDirNames(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	return names, nil
}

// modCacheDir returns the extracted module directory of a dependency, or ""
// when it cannot be located (the caller then skips rather than passing).
func modCacheDir(module, version string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	candidates := []string{
		filepath.Join(home, "go", "pkg", "mod", filepath.FromSlash(module)+"@"+version),
	}
	if gp := os.Getenv("GOPATH"); gp != "" {
		candidates = append(candidates, filepath.Join(gp, "pkg", "mod", filepath.FromSlash(module)+"@"+version))
	}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && st.IsDir() {
			return c
		}
	}
	return ""
}
