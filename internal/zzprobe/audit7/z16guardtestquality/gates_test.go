//go:build audit7

package z16guardtestquality

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// This file holds the two gate-quality probes of zone 16 that are not about the
// shape of a single test function:
//
//   - the security linter's rule set is narrowed by `.golangci.yml`'s
//     `gosec.includes`, so a rule the project cares about can be installed,
//     configured and still never run. The probe asserts the invariant that
//     matters: no rule that gosec's own default set finds on this tree may be
//     missing from the narrowed set;
//   - every test file behind a build tag is invisible to `go build`, `go vet`,
//     `go test ./...` and `golangci-lint run ./...` alike, so the audit corpus
//     can rot without a single gate noticing (supplement to N-04, which records
//     that the tagged probes do not *run*).

// gosecRule is one gosec finding parsed out of the linter's output.
var gosecRule = regexp.MustCompile(`\((gosec)\)`)

// ruleID matches the "GNNN:" prefix golangci-lint prints in front of a gosec
// diagnostic.
var ruleID = regexp.MustCompile(`\b(G\d{3}):`)

type linterConfig struct {
	Linters struct {
		Enable   []string `yaml:"enable"`
		Settings struct {
			Gosec struct {
				Includes []string `yaml:"includes"`
			} `yaml:"gosec"`
		} `yaml:"settings"`
	} `yaml:"linters"`
}

func readLinterConfig(t *testing.T, root string) linterConfig {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, ".golangci.yml"))
	if err != nil {
		t.Fatalf("read .golangci.yml: %v", err)
	}
	var cfg linterConfig
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("parse .golangci.yml: %v", err)
	}
	return cfg
}

// runLint invokes the pinned golangci-lint over the packages whose production
// code carries the rules under discussion, and returns its combined output.
// withRepoConfig selects the configuration CI runs.
func runLint(t *testing.T, root, lint string, withRepoConfig bool) string {
	t.Helper()
	args := []string{"run", "--timeout=3m"}
	if !withRepoConfig {
		args = append(args, "--no-config", "--default", "none", "--enable", "gosec")
	}
	args = append(args, "./cmd/re0auth/", "./cmd/referencesource/", "./cmd/perfreport/")
	cmd := exec.Command(lint, args...)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("golangci-lint: %v", err)
		}
	}
	return string(out)
}

// TestNarrowedGosecRuleSetHidesNoLiveFinding pins the invariant behind
// `.golangci.yml`'s curated gosec subset.
//
// The config comment explains the subset by naming the patterns the project uses
// on purpose (a MAC that really is HMAC-SHA1, a config path that really comes
// from a flag) and G101. What it does not say is that `includes` is a *filter*:
// the five ids listed there are the only gosec rules that run at all, so the
// server-hardening and overflow rules the service's own threat model names —
// G112 (no ReadHeaderTimeout), G114 (a serve function with no timeouts), G115
// (integer-overflow conversion) — are installed, configured and inert. The
// assertion is therefore not "the list must be long", it is: nothing gosec's own
// default set finds on this tree may be missing from the narrowed set.
func TestNarrowedGosecRuleSetHidesNoLiveFinding(t *testing.T) {
	root := repoRoot(t)
	cfg := readLinterConfig(t, root)
	includes := cfg.Linters.Settings.Gosec.Includes
	if !slices.Contains(cfg.Linters.Enable, "gosec") {
		t.Fatal("gosec is no longer enabled; this probe no longer measures the CI lint gate")
	}
	if len(includes) == 0 {
		t.Fatal("gosec has no `includes` list, so this probe's premise (a narrowed rule set) is gone")
	}
	t.Logf("repository gosec.includes = %v", includes)

	lint, err := exec.LookPath("golangci-lint")
	if err != nil {
		// The tool is what CI installs (v2.14.0, pinned in the lint job); without
		// it the dynamic half cannot run, so the static half is asserted instead.
		t.Logf("golangci-lint is not on PATH: %v; asserting the static shape only", err)
		for _, want := range []string{"G114", "G115"} {
			if !slices.Contains(includes, want) {
				t.Errorf("gosec.includes does not run %s; the repository has a live hit for it "+
					"(run `golangci-lint run --no-config --default none --enable gosec ./...` to see it)", want)
			}
		}
		return
	}

	wide := runLint(t, root, lint, false)
	narrow := runLint(t, root, lint, true)

	wideRules := reportedRules(wide)
	if len(wideRules) == 0 {
		t.Fatal("gosec's default rule set reported nothing at all: the positive control is empty, " +
			"so a green result here would mean the probe is broken rather than the gate sound")
	}
	var hidden []string
	for _, id := range wideRules {
		if !slices.Contains(includes, id) {
			hidden = append(hidden, id)
		}
	}
	sort.Strings(hidden)
	t.Logf("gosec default set reported %v; the repository config runs only %v", wideRules, includes)
	if len(hidden) > 0 {
		t.Errorf("the CI lint gate cannot see %v: `gosec.includes` is a filter, so a rule that is not "+
			"listed never runs. Live hits it hides (from the wide run):\n%s",
			hidden, firstLines(wide, 12))
	}
	// The control: with the repository config the same packages must report a
	// subset. If the two runs agree, `includes` did not narrow anything and this
	// probe is measuring the wrong thing.
	if strings.Contains(narrow, "G114:") || strings.Contains(narrow, "G115:") {
		t.Logf("the repository config reported a rule this probe expected it to drop: %s", firstLines(narrow, 6))
	}
}

// reportedRules returns the sorted, unique gosec rule ids in a lint output.
func reportedRules(out string) []string {
	seen := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		if !gosecRule.MatchString(line) {
			continue
		}
		m := ruleID.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		seen[m[1]] = true
	}
	var ids []string
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func firstLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}

// tagConstraint extracts the tag list from a `//go:build` line: `a && b` and
// `a || b` both name tags the file needs; `!x` is a negation, not a tag.
func tagConstraint(line string) []string {
	expr := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "//go:build"))
	var out []string
	for _, tok := range strings.FieldsFunc(expr, func(r rune) bool {
		return r == ' ' || r == '&' || r == '|' || r == '(' || r == ')' || r == '\t'
	}) {
		tok = strings.TrimPrefix(tok, "!")
		if tok == "" || tok == "true" || tok == "false" {
			continue
		}
		out = append(out, tok)
	}
	return out
}

// TestEveryTaggedTestFileIsReachableFromCI is the guard N-04 asks for, stated as
// an invariant rather than as a count: a test file behind a build tag must have
// some workflow that sets that tag, or the file is outside every gate the
// repository has.
//
// It is strictly stronger than "the probes do not run": because `go build`,
// `go vet`, `go test ./...` and `golangci-lint run ./...` all honour build
// constraints, a tagged file is not even *compiled* by them. A probe that stops
// compiling, or grows a lint error, is discovered by nobody — the corpus that
// audit documents cite as evidence can decay in silence. The demonstration is a
// one-liner: this repository's own probe files carry a staticcheck diagnostic that
// the CI lint step does not report (`golangci-lint run ./...` is clean) and that
// `golangci-lint run --build-tags audit7 ./...` does report.
func TestEveryTaggedTestFileIsReachableFromCI(t *testing.T) {
	root := repoRoot(t)

	// Tags any workflow sets.
	workflowTags := map[string]bool{}
	workflows, err := os.ReadDir(filepath.Join(root, ".github", "workflows"))
	if err != nil {
		t.Fatalf("read workflows: %v", err)
	}
	tagFlag := regexp.MustCompile(`-tags[= ]+("[^"]*"|'[^']*'|\S+)`)
	for _, e := range workflows {
		if e.IsDir() || (!strings.HasSuffix(e.Name(), ".yml") && !strings.HasSuffix(e.Name(), ".yaml")) {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(root, ".github", "workflows", e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		for _, m := range tagFlag.FindAllStringSubmatch(string(raw), -1) {
			for _, tag := range strings.FieldsFunc(strings.Trim(m[1], `"'`), func(r rune) bool {
				return r == ',' || r == ' '
			}) {
				if tag != "" {
					workflowTags[tag] = true
				}
			}
		}
	}
	t.Logf("workflows set these build tags: %v", sortedKeys(workflowTags))

	// Tracked test files and their constraints, via git so build outputs and
	// local scratch directories are not part of the question.
	cmd := exec.Command("git", "ls-files", "-z", "*_test.go")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git ls-files: %v", err)
	}
	tagged := map[string][]string{} // tag -> files
	total := 0
	for _, name := range strings.Split(string(out), "\x00") {
		if name == "" {
			continue
		}
		total++
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		for _, line := range strings.Split(string(raw), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "//go:build") {
				for _, tag := range tagConstraint(line) {
					tagged[tag] = append(tagged[tag], name)
				}
				break
			}
			trimmed := strings.TrimSpace(line)
			if trimmed != "" && !strings.HasPrefix(trimmed, "//") {
				break
			}
		}
	}
	if total < 200 {
		t.Fatalf("only %d tracked test files were listed; the walk is not reading the repository", total)
	}
	if len(tagged) == 0 {
		t.Fatal("no tagged test file was found, so this probe would pass vacuously")
	}

	var orphaned int
	reasons := []string{}
	for tag, files := range tagged {
		if workflowTags[tag] {
			continue
		}
		orphaned += len(files)
		reasons = append(reasons, tag+": "+strings.Join(files, ", "))
	}
	sort.Strings(reasons)
	t.Logf("%d of %d tracked test files are behind a tag no workflow sets", orphaned, total)
	if orphaned > 0 {
		t.Errorf("%d tracked test files (%d tags) are excluded from every CI gate: no workflow passes "+
			"-tags. They are not run by `go test ./...` and not even compiled by `go build`, `go vet` or "+
			"golangci-lint, so a probe that stops compiling or grows a lint error fails nothing.\n%s",
			orphaned, len(reasons), strings.Join(reasons, "\n"))
	}
}

func sortedKeys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
