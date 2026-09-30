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
//   - the security linter's rule set must stay default-on. `.golangci.yml` once
//     "curated" gosec through `gosec.includes`, which in golangci-lint v2 is a
//     `rules.NewRuleFilter(false, includes...)` *allowlist*: naming five rules
//     did not select them, it silently switched every other rule off, so G112,
//     G114 and G115 were installed, configured and inert. The probe asserts that
//     no allowlist has returned, and that any rule the config does decline is
//     declined by name — with a reason written next to it — rather than by a
//     filter that hides its own contents;
//   - every test file behind a build tag is invisible to `go build`, `go vet`,
//     `go test ./...` and `golangci-lint run ./...` alike, so the audit corpus
//     can rot without a single gate noticing (supplement to N-04, which records
//     that the tagged probes do not *run*).

// gosecRule is one gosec finding parsed out of the linter's output.
var gosecRule = regexp.MustCompile(`\((gosec)\)`)

// ruleID matches the "GNNN:" prefix golangci-lint prints in front of a gosec
// diagnostic.
var ruleID = regexp.MustCompile(`\b(G\d{3}):`)

// bareRuleID matches a rule id wherever it appears, such as the `text:` value of
// a linters.exclusions entry, which carries no trailing colon.
var bareRuleID = regexp.MustCompile(`\bG\d{3}\b`)

type linterConfig struct {
	Linters struct {
		Enable   []string `yaml:"enable"`
		Settings struct {
			Gosec struct {
				Includes []string `yaml:"includes"`
				Excludes []string `yaml:"excludes"`
			} `yaml:"gosec"`
		} `yaml:"settings"`
		Exclusions struct {
			Rules []struct {
				Path    string   `yaml:"path"`
				Linters []string `yaml:"linters"`
				Text    string   `yaml:"text"`
			} `yaml:"rules"`
		} `yaml:"exclusions"`
	} `yaml:"linters"`
}

// readLinterConfig parses `.golangci.yml` and also returns its comment lines, so
// "documented" can mean what it says: a rule id appearing in a `#` line next to
// the exclusion it explains.
func readLinterConfig(t *testing.T, root string) (linterConfig, []string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, ".golangci.yml"))
	if err != nil {
		t.Fatalf("read .golangci.yml: %v", err)
	}
	var cfg linterConfig
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("parse .golangci.yml: %v", err)
	}
	var comments []string
	for _, line := range strings.Split(string(raw), "\n") {
		if trimmed := strings.TrimSpace(line); strings.HasPrefix(trimmed, "#") {
			comments = append(comments, trimmed)
		}
	}
	return cfg, comments
}

// runLint invokes the pinned golangci-lint with gosec's own default rule set over
// the whole module. The repository config is deliberately not read, so the result
// is what gosec reports before any project-level exclusion is applied — the
// question this probe asks is what the exclusions are hiding.
func runLint(t *testing.T, root, lint string) string {
	t.Helper()
	cmd := exec.Command(lint, "run", "--timeout=3m", "--no-config", "--default", "none", "--enable", "gosec", "./...")
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
// `.golangci.yml`'s gosec settings: the rule set is default-on and the only
// rules that do not run are the ones the config declines *by name*, with a
// one-line reason.
//
// The name is kept from the probe's first version, when the config used
// `gosec.includes`. That was the bug: in golangci-lint v2 `includes` is a
// `rules.NewRuleFilter(false, includes...)` allowlist, so the five ids listed
// there were the only gosec rules that ran at all — the server-hardening and
// overflow rules the service's own threat model names (G112 no
// ReadHeaderTimeout, G114 a serve function with no timeouts, G115 an
// integer-overflow conversion) were installed, configured and inert. The probe
// now fails if an allowlist returns, fails on a path-only gosec exclusion (a
// blanket suppression in the same family), and checks the dynamic half: every
// rule gosec's own default set reports on this tree must either run under the
// repository config or be a declined rule whose id is written in the config's
// comments.
//
// (Z16-2, docs/issues/P2-medium.md)
func TestNarrowedGosecRuleSetHidesNoLiveFinding(t *testing.T) {
	root := repoRoot(t)
	cfg, comments := readLinterConfig(t, root)
	if !slices.Contains(cfg.Linters.Enable, "gosec") {
		t.Fatal("gosec is no longer enabled; this probe no longer measures the CI lint gate")
	}

	// (a) The allowlist must not come back. A non-empty `includes` is not a
	// selection of the rules named; it is the silent removal of every rule not
	// named, which is exactly what this probe exists to catch.
	if includes := cfg.Linters.Settings.Gosec.Includes; len(includes) > 0 {
		t.Fatalf("gosec.includes = %v is non-empty: in golangci-lint v2 it is an allowlist, so every rule "+
			"not named never runs. Decline a finding by naming it in gosec.excludes with a reason instead.", includes)
	}

	// The rules the config declines, and how. `gosec.excludes` is rule-level; a
	// `linters.exclusions.rules` entry that names gosec and carries a `text` is
	// rule-level on a path. An entry with no `text` hides every gosec rule on
	// that path — the allowlist failure wearing a path-shaped coat.
	declined := map[string]bool{}
	for _, id := range cfg.Linters.Settings.Gosec.Excludes {
		declined[id] = true
	}
	for _, rule := range cfg.Linters.Exclusions.Rules {
		if !slices.Contains(rule.Linters, "gosec") {
			continue
		}
		if strings.TrimSpace(rule.Text) == "" {
			t.Errorf("the gosec exclusion for path %q has no `text`: it hides every gosec rule on those files "+
				"rather than a named one. Name the rule in gosec.excludes, or give the entry a `text`.", rule.Path)
			continue
		}
		for _, id := range ruleIDsIn(rule.Text) {
			declined[id] = true
		}
	}

	lint, err := exec.LookPath("golangci-lint")
	if err != nil {
		// Without the tool CI pins the dynamic half cannot run; the static half —
		// no allowlist, no blanket exclusion — has already been asserted.
		t.Logf("golangci-lint is not on PATH: %v; asserting the static shape only", err)
		return
	}

	wide := runLint(t, root, lint)
	wideRules := reportedRules(wide)
	if len(wideRules) == 0 {
		t.Fatal("gosec's default rule set reported nothing at all: the positive control is empty, " +
			"so a green result here would mean the probe is broken rather than the gate sound")
	}

	var running, hidden []string
	for _, id := range wideRules {
		switch {
		case !declined[id]:
			// With no allowlist in force, a rule the config does not decline runs.
			running = append(running, id)
		case documentedRule(comments, id):
			// Declined on purpose, with the reason written beside it.
		default:
			hidden = append(hidden, id)
		}
	}
	sort.Strings(hidden)
	t.Logf("gosec's default set reported %v; running under the repository config: %v; declined by name: %v",
		wideRules, running, sortedKeys(declined))
	if len(hidden) > 0 {
		t.Errorf("the CI lint gate cannot see %v, and nothing in .golangci.yml says why. A rule may only be "+
			"declined by name — `gosec.excludes`, or a `_test\\.go` entry carrying a `text` — and its reason "+
			"must be written as a comment that names the rule. Live hits it hides (from the wide run):\n%s",
			hidden, firstLines(wide, 12))
	}
}

// documentedRule reports whether the config's comment lines name id, which is how
// every declined rule carries its one-line reason.
func documentedRule(comments []string, id string) bool {
	for _, c := range comments {
		if strings.Contains(c, id) {
			return true
		}
	}
	return false
}

// ruleIDsIn returns the GNNN ids in a linters.exclusions `text` value.
func ruleIDsIn(text string) []string {
	var ids []string
	for _, m := range bareRuleID.FindAllString(text, -1) {
		ids = append(ids, m)
	}
	return ids
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
