//go:build audit7

// Helpers for the Z10 re-check. Nothing here needs a database: these probes read
// the product's own source text and assert the properties the zone-10 report
// claims, so a wrong claim fails here instead of being taken on trust.
package z10verify

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// repoFile reads one repository file, found by walking up to the module root.
func repoFile(t *testing.T, rel string) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("could not find the module root above %s", dir)
		}
		dir = parent
	}
	body, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(body)
}

// funcBody returns the source of one function, from its `func` line to the
// matching closing brace, found by brace counting over a copy of the text with
// string and comment literals blanked out. It fails loudly when the function
// cannot be found, so a rename makes the probe red rather than vacuous.
func funcBody(t *testing.T, rel, name string) string {
	t.Helper()
	return funcBodyIn(t, rel, name, scrubLiterals(t, rel, repoFile(t, rel)))
}

// funcBodyRaw is funcBody without the literal scrubbing, so a probe can assert
// on string literals (an SQL statement, a JSON key) as well as on structure.
func funcBodyRaw(t *testing.T, rel, name string) string {
	t.Helper()
	return funcBodyIn(t, rel, name, repoFile(t, rel))
}

func funcBodyIn(t *testing.T, rel, name, src string) string {
	t.Helper()
	re := regexp.MustCompile(`(?m)^func (?:\([^)]*\) )?` + regexp.QuoteMeta(name) + `\(`)
	loc := re.FindStringIndex(src)
	if loc == nil {
		t.Fatalf("%s no longer declares a method named %s; this probe would be vacuous", rel, name)
	}
	depth := 0
	seen := false
	for i := loc[0]; i < len(src); i++ {
		switch src[i] {
		case '{':
			depth++
			seen = true
		case '}':
			depth--
			if seen && depth == 0 {
				return src[loc[0] : i+1]
			}
		}
	}
	t.Fatalf("%s: %s's body never closed; the source is not what this probe expects", rel, name)
	return ""
}

// scrubLiterals blanks out string/rune literals and comments so brace counting
// and keyword searches are not fooled by text inside them.
func scrubLiterals(t *testing.T, rel, src string) string {
	t.Helper()
	out := []byte(src)
	i := 0
	for i < len(out) {
		switch {
		case out[i] == '"':
			j := i + 1
			for j < len(out) && out[j] != '"' {
				if out[j] == '\\' {
					j++
				}
				j++
			}
			for k := i; k <= j && k < len(out); k++ {
				out[k] = ' '
			}
			i = j + 1
		case out[i] == '`':
			j := i + 1
			for j < len(out) && out[j] != '`' {
				j++
			}
			for k := i; k <= j && k < len(out); k++ {
				out[k] = ' '
			}
			i = j + 1
		case out[i] == '/' && i+1 < len(out) && out[i+1] == '/':
			for i < len(out) && out[i] != '\n' {
				out[i] = ' '
				i++
			}
		case out[i] == '/' && i+1 < len(out) && out[i+1] == '*':
			out[i], out[i+1] = ' ', ' '
			i += 2
			for i < len(out) && !(out[i] == '*' && i+1 < len(out) && out[i+1] == '/') {
				i++
			}
			if i+1 < len(out) {
				out[i], out[i+1] = ' ', ' '
				i += 2
			}
		case out[i] == '\'':
			j := i + 1
			for j < len(out) && out[j] != '\'' {
				if out[j] == '\\' {
					j++
				}
				j++
			}
			for k := i; k <= j && k < len(out); k++ {
				out[k] = ' '
			}
			i = j + 1
		default:
			i++
		}
	}
	return string(out)
}
