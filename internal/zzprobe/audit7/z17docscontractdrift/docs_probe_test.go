//go:build audit7

// Zone 17 (round 7) probes: documentation / contract / config-sample drift.
//
// Every probe here is a NEGATIVE assertion about the repository's own
// documentation against its own code, so a green run means "no drift found" and
// a red run is the finding. Each one keeps a positive control, so a probe that
// silently stopped looking at anything cannot pass.
package z17docscontractdrift

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// repoRoot walks up from the test binary's working directory (this package's
// directory) until it finds go.mod.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("no go.mod above %s", dir)
		}
		dir = parent
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// loadYAML decodes a document, failing loudly rather than panicking.
func loadYAML(t *testing.T, path string) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(readFile(t, path)), &doc); err != nil {
		t.Fatalf("%s does not parse: %v", path, err)
	}
	return doc
}

func digMap(t *testing.T, node any, keys ...string) map[string]any {
	t.Helper()
	for _, key := range keys {
		m, ok := node.(map[string]any)
		if !ok {
			t.Fatalf("%v: parent is not a mapping", keys)
		}
		node, ok = m[key]
		if !ok {
			t.Fatalf("%v: %q is missing", keys, key)
		}
	}
	m, ok := node.(map[string]any)
	if !ok {
		t.Fatalf("%v: not a mapping", keys)
	}
	return m
}

// TestZ17OpenAPIBindingEnumAdmitsTheUnconfiguredBinding is Z17-4.
//
// The document gives Binding.token_class and Binding.status closed enums. The
// handler marshals both struct fields unconditionally (no `omitempty`), so the
// empty string is always representable on the wire; and for a binding whose
// source has left the configuration — the documented `configured: false` state,
// which CHANGELOG.md:126-130 requires the endpoint to keep listing — the fields
// are left at their zero value. A client generated from the spec therefore has
// to reject a response the server is documented to produce.
func TestZ17OpenAPIBindingEnumAdmitsTheUnconfiguredBinding(t *testing.T) {
	root := repoRoot(t)
	doc := loadYAML(t, filepath.Join(root, "docs", "openapi.yaml"))
	binding := digMap(t, doc, "components", "schemas", "Binding")
	props := digMap(t, binding, "properties")
	src := readFile(t, filepath.Join(root, "internal", "httpapi", "binding_routes.go"))

	checked := 0
	for _, field := range []string{"token_class", "status"} {
		prop, ok := props[field].(map[string]any)
		if !ok {
			t.Fatalf("openapi Binding.%s has no schema", field)
		}
		rawEnum, ok := prop["enum"].([]any)
		if !ok || len(rawEnum) == 0 {
			t.Fatalf("openapi Binding.%s has no enum; this probe would be vacuous", field)
		}
		enum := make([]string, 0, len(rawEnum))
		for _, v := range rawEnum {
			s, _ := v.(string)
			enum = append(enum, s)
		}

		// The Go field's json tag, and whether the zero value can be suppressed.
		tag := fmt.Sprintf("json:%q", field)
		at := strings.Index(src, tag)
		if at < 0 {
			t.Fatalf("no struct tag %s in binding_routes.go; this probe would be vacuous", tag)
		}
		lineEnd := strings.Index(src[at:], "\n")
		if lineEnd < 0 {
			lineEnd = len(src) - at
		}
		decl := src[at : at+lineEnd]
		if strings.Contains(decl, "omitempty") {
			continue
		}
		checked++
		if !containsString(enum, "") {
			t.Errorf("openapi Binding.%s documents enum %v, but the field is marshalled "+
				"unconditionally (binding_routes.go: %q, no omitempty) and is left empty for a binding "+
				"whose source has left the configuration (`configured: false`). The server can emit a "+
				"value the spec's closed enum forbids.", field, enum, strings.TrimSpace(decl))
		}
	}
	if checked == 0 {
		t.Fatal("no unconditional enum field was examined; the probe is vacuous")
	}
}

func containsString(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// envVarRe matches an environment variable name the composition root reads.
var envVarRe = regexp.MustCompile(`RE0AUTH_[A-Z0-9_]+`)

// TestZ17ConfigExampleDocumentsEveryImplementedOverride is Z17-5.
//
// README.md:42 sends the reader to config/re0auth.example.toml for the complete
// set of keys, defaults and explanations, and the sample itself notes an
// environment override beside almost every key. Several implemented overrides
// are named nowhere in the sample or in any document (the logging ones appear
// nowhere in the repository at all), so an operator following the documented
// reference cannot discover that they exist.
func TestZ17ConfigExampleDocumentsEveryImplementedOverride(t *testing.T) {
	root := repoRoot(t)

	// Implemented: every RE0AUTH_* literal in the composition root and the shared
	// config helpers. The logging variables are built from a prefix
	// (internal/config/logging.go:32, called as SetupLogging("RE0AUTH") at
	// cmd/re0auth/main.go:296), so they are added by hand.
	implemented := map[string]string{}
	sources := []string{}
	for _, dir := range []string{"cmd/re0auth", "internal/config"} {
		entries, err := os.ReadDir(filepath.Join(root, filepath.FromSlash(dir)))
		if err != nil {
			t.Fatalf("read %s: %v", dir, err)
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			path := filepath.Join(root, filepath.FromSlash(dir), e.Name())
			sources = append(sources, path)
			for _, name := range envVarRe.FindAllString(readFile(t, path), -1) {
				if _, ok := implemented[name]; !ok {
					implemented[name] = dir + "/" + e.Name()
				}
			}
		}
	}
	for _, name := range []string{"RE0AUTH_LOG_LEVEL", "RE0AUTH_LOG_FORMAT"} {
		implemented[name] = "internal/config/logging.go:32 (prefix \"RE0AUTH\" from cmd/re0auth/main.go:296)"
	}

	// Documented: the sample, the prose docs and the release notes.
	documented := readFile(t, filepath.Join(root, "config", "re0auth.example.toml"))
	docPaths := []string{"README.md", "SECURITY.md", "CHANGELOG.md", "CONTRIBUTING.md"}
	for _, d := range docPaths {
		documented += readFile(t, filepath.Join(root, d))
	}
	docs, err := os.ReadDir(filepath.Join(root, "docs"))
	if err != nil {
		t.Fatalf("read docs: %v", err)
	}
	for _, e := range docs {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
			continue
		}
		documented += readFile(t, filepath.Join(root, "docs", e.Name()))
	}
	if len(sources) == 0 || len(documented) < 1000 {
		t.Fatal("the scan read nothing; the probe would be vacuous")
	}

	// Positive control: two overrides that are both implemented and documented.
	for _, ok := range []string{"RE0AUTH_KEK", "RE0AUTH_MAX_IN_FLIGHT"} {
		if _, found := implemented[ok]; !found {
			t.Fatalf("positive control %s is not in the implemented set; the source scan is wrong", ok)
		}
		if !strings.Contains(documented, ok) {
			t.Fatalf("positive control %s is not in the documented text", ok)
		}
	}

	var missing []string
	for name, where := range implemented {
		if !strings.Contains(documented, name) {
			missing = append(missing, fmt.Sprintf("%s (implemented at %s)", name, where))
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("%d implemented environment override(s) are named in no document, while "+
			"README.md:42 points at config/re0auth.example.toml as the complete reference:\n  %s",
			len(missing), strings.Join(missing, "\n  "))
	}
}

var roundsRe = regexp.MustCompile(`(?i)\b(one|two|three|four|five|six|seven|eight|nine|ten|\d+)\s+rounds\b`)

var wordNumber = map[string]int{
	"one": 1, "two": 2, "three": 3, "four": 4, "five": 5,
	"six": 6, "seven": 7, "eight": 8, "nine": 9, "ten": 10,
}

var auditDocRe = regexp.MustCompile(`^security-audit-(\d+)\.md$`)

// TestZ17SecurityDocAuditRoundsAreNotStale is Z17-3.
//
// SECURITY.md's "Our own audits" section advertises how many rounds have been
// run and which write-ups are on disk. This is the file a reporter reads to
// decide what has already been covered, so a stale count is a contract about
// the project's own evidence, not a cosmetic line.
func TestZ17SecurityDocAuditRoundsAreNotStale(t *testing.T) {
	root := repoRoot(t)
	sec := readFile(t, filepath.Join(root, "SECURITY.md"))

	m := roundsRe.FindStringSubmatch(sec)
	if m == nil {
		t.Fatal("SECURITY.md no longer states a number of rounds; the probe would be vacuous")
	}
	claimed, ok := wordNumber[strings.ToLower(m[1])]
	if !ok {
		var err error
		claimed, err = strconv.Atoi(m[1])
		if err != nil {
			t.Fatalf("cannot read the claimed round count from %q", m[0])
		}
	}

	entries, err := os.ReadDir(filepath.Join(root, "docs"))
	if err != nil {
		t.Fatalf("read docs: %v", err)
	}
	found := 0
	for _, e := range entries {
		g := auditDocRe.FindStringSubmatch(e.Name())
		if g == nil {
			continue
		}
		found++
		round, _ := strconv.Atoi(g[1])
		if round > claimed {
			t.Errorf("SECURITY.md says %d rounds have been run, but docs/%s is on disk (round %d). "+
				"The audit-history section is stale.", claimed, e.Name(), round)
		}
		if !strings.Contains(sec, e.Name()) {
			t.Errorf("docs/%s exists but SECURITY.md's \"Our own audits\" section does not name it, "+
				"while it claims to list the write-ups that are on disk.", e.Name())
		}
	}
	if found == 0 || !strings.Contains(sec, "security-audit-") {
		t.Fatal("no audit write-up was found; the probe would be vacuous")
	}
}
