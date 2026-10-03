//go:build audit7

package z16guardtestquality

import (
	"errors"
	"fmt"
	"go/build/constraint"
	"os"
	"os/exec"
	"path"
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

// intentionalTag names a build tag that no workflow sets ON PURPOSE, with the
// document that made the call. A file reachable only through one of these is a
// reviewed decision rather than a CI gap.
//
// Z16's invariant is "a tagged test file must be reachable from some gate"; the
// gzhttp spike is the one file the repository deliberately keeps outside every
// gate, and it says so: `docs/dependencies.md:48-49` calls it "随取随用的判定记录，
// 不是一道门禁" and names the manual command that runs it.
var intentionalTag = map[string]string{
	"gzhttpspike": "docs/dependencies.md:48-49 — the gzhttp spike is a decision record run by hand " +
		"(`RE0AUTH_GZHTTP_SPIKE=1 go test -tags gzhttpspike -count=1 -v ./internal/compress/`), not a gate",
}

// taggedFile is one tracked test file with a `//go:build` constraint.
type taggedFile struct {
	name string
	expr constraint.Expr
}

// satisfiable reports whether some assignment drawn from tags satisfies the
// build expression. A file is reachable when the tags a workflow sets can
// compile it; `a || b` is reachable when EITHER tag is set, which is exactly the
// case the per-tag census used to get wrong (13 `audit || audit6` files were
// reported as orphaned although `-tags audit6` compiles them).
func satisfiable(e constraint.Expr, tags map[string]bool) bool {
	if e == nil {
		return true
	}
	return e.Eval(func(tag string) bool { return tags[tag] })
}

// newExprSet is satisfiable's tag-set argument.
func newExprSet(tags ...string) map[string]bool {
	set := make(map[string]bool, len(tags))
	for _, t := range tags {
		set[t] = true
	}
	return set
}

// TestEveryTaggedTestFileIsReachableFromCI is the guard N-04 asks for, stated as
// an invariant rather than as a count: a test file behind a build tag must have
// some workflow that can satisfy that tag constraint, or the file is outside
// every gate the repository has.
//
// It is strictly stronger than "the probes do not run": because `go build`,
// `go vet`, `go test ./...` and `golangci-lint run ./...` all honour build
// constraints, a tagged file is not even *compiled* by them. A probe that stops
// compiling, or grows a lint error, is discovered by nobody — the corpus that
// audit documents cite as evidence can decay in silence. The demonstration is a
// one-liner: this repository's own probe files carry a staticcheck diagnostic that
// the CI lint step does not report (`golangci-lint run ./...` is clean) and that
// `golangci-lint run --build-tags audit7 ./...` does report.
//
// The probe has two halves and neither alone is enough. The first is a census:
// every tracked test file is read, its constraint parsed (both the `//go:build` and
// the legacy `// +build` spelling, Z16V-2), and it is a finding when no CI tag set
// satisfies it. The second is the compile step: the files the census calls
// reachable are actually compiled with `go vet` under that tag set (Z16-1), so a
// file that is reachable on paper but no longer builds is a finding too. A text
// scan by itself is the shape of a fake guard; the toolchain is what closes it.
func TestEveryTaggedTestFileIsReachableFromCI(t *testing.T) {
	root := repoRoot(t)

	// The tag sets CI actually passes, one per `-tags` occurrence, plus the empty
	// set: the ordinary `go test ./...` / `go vet ./...` gates run with no tags,
	// and that is the invocation that compiles a `//go:build !x` file. A file is
	// reachable when some one of these sets satisfies its expression. (The old
	// census unioned every tag into one set and then looked at tags one at a time,
	// which both over-reported `a || b` files and could not express `!x`.)
	//
	// `-tags` is matched only as a Go flag: the previous pattern matched the
	// `-tags` inside git's `--no-tags --quiet` and recorded `--quiet` as a tag.
	tagSets := []map[string]bool{newExprSet()}
	workflowTags := map[string]bool{}
	workflows, err := os.ReadDir(filepath.Join(root, ".github", "workflows"))
	if err != nil {
		t.Fatalf("read workflows: %v", err)
	}
	tagFlag := regexp.MustCompile(`(?:^|\s)-tags[= ]+("[^"]*"|'[^']*'|\S+)`)
	for _, e := range workflows {
		if e.IsDir() || (!strings.HasSuffix(e.Name(), ".yml") && !strings.HasSuffix(e.Name(), ".yaml")) {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(root, ".github", "workflows", e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		for _, m := range tagFlag.FindAllStringSubmatch(string(raw), -1) {
			set := newExprSet()
			for _, tag := range strings.FieldsFunc(strings.Trim(m[1], `"'`), func(r rune) bool {
				return r == ',' || r == ' '
			}) {
				if tag != "" {
					set[tag] = true
					workflowTags[tag] = true
				}
			}
			tagSets = append(tagSets, set)
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
	var constrained []taggedFile
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
		expr, tagged, err := buildConstraintOf(raw)
		if err != nil {
			t.Fatalf("parse build constraint of %s: %v", name, err)
		}
		if tagged {
			constrained = append(constrained, taggedFile{name: name, expr: expr})
		}
	}
	if total < 200 {
		t.Fatalf("only %d tracked test files were listed; the walk is not reading the repository", total)
	}
	if len(constrained) == 0 {
		t.Fatal("no tagged test file was found, so this probe would pass vacuously")
	}

	// A file is reachable when one of CI's tag sets satisfies its expression. A
	// file that only an intentionally-manual tag reaches is a reviewed decision,
	// not a gap (the gzhttp spike, docs/dependencies.md:48-49).
	documentedSets := make([]map[string]bool, 0, len(tagSets))
	for _, set := range tagSets {
		with := newExprSet()
		for tag := range set {
			with[tag] = true
		}
		for tag := range intentionalTag {
			with[tag] = true
		}
		documentedSets = append(documentedSets, with)
	}
	reachableBy := func(expr constraint.Expr, sets []map[string]bool) bool {
		for _, set := range sets {
			if satisfiable(expr, set) {
				return true
			}
		}
		return false
	}

	var orphaned, documented []string
	for _, f := range constrained {
		if reachableBy(f.expr, tagSets) {
			continue
		}
		label := f.name + " (build constraint " + f.expr.String() + ")"
		if reachableBy(f.expr, documentedSets) {
			documented = append(documented, label)
			continue
		}
		orphaned = append(orphaned, label)
	}
	sort.Strings(orphaned)
	sort.Strings(documented)
	t.Logf("%d of %d tracked test files are behind a constraint no workflow can satisfy; %d are behind a "+
		"deliberately-manual tag", len(orphaned), total, len(documented))
	for _, d := range documented {
		t.Logf("  documented as not-a-gate: %s — %s", d, intentionalTag["gzhttpspike"])
	}

	// ---------------------------------------------------------------- real compile
	//
	// Everything above is a text scan, and a text scan is exactly the shape of a
	// fake guard: it can say a file is reachable while the file no longer builds.
	// So the reachable files are COMPILED, by the toolchain's own build-constraint
	// engine rather than by this probe's parse: for each constrained file, the
	// first CI tag set that satisfies its expression is the set the file's package
	// is vetted under (`go vet` compiles test files; `go build` does not).
	//
	// The work is grouped by tag set and deduplicated by directory, so a probe
	// with N tagged files in one package costs one package compilation, not N. The
	// common case is a single group — the repo-wide
	// `-tags audit5,audit6,audit7,conformance,audit,protocolaudit` set satisfies
	// almost every positive constraint — plus a small second group for the few
	// files a negation excludes from that set.
	compileDirs := map[string]map[string]bool{}
	compileFiles := make([]string, 0, len(constrained))
	for _, f := range constrained {
		set, ok := firstSatisfying(f.expr, tagSets)
		if !ok {
			// Unreachable from CI: the reachability half above reports it. There
			// is no CI tag set to compile it under.
			continue
		}
		key := strings.Join(sortedKeys(set), ",")
		if compileDirs[key] == nil {
			compileDirs[key] = map[string]bool{}
		}
		compileDirs[key]["./"+path.Dir(f.name)] = true
		compileFiles = append(compileFiles, f.name)
	}
	if len(compileFiles) == 0 && len(documented) == 0 {
		// Non-vacuous: if no reachable file was selected for compilation and
		// nothing was recorded as deliberately manual, the census itself is empty
		// and a green compile step would prove nothing.
		t.Fatal("the compile step selected no file and no file is documented as deliberately manual: " +
			"the reachability census is broken, so a green result here would be vacuous")
	}
	var compileKeys []string
	for key := range compileDirs {
		compileKeys = append(compileKeys, key)
	}
	sort.Strings(compileKeys)
	for _, key := range compileKeys {
		dirs := make([]string, 0, len(compileDirs[key]))
		for d := range compileDirs[key] {
			dirs = append(dirs, d)
		}
		sort.Strings(dirs)
		var tags []string
		if key != "" {
			tags = strings.Split(key, ",")
		}
		t.Logf("compiling %d package(s) under -tags=%q (%d tagged files in this group)",
			len(dirs), key, countTaggedInDirs(compileFiles, dirs))
		if err := vetTagSet(t, root, tags, dirs); err != nil {
			t.Errorf("COMPILE FAILURE: a tracked test file behind a build constraint CI sets does not "+
				"compile under that set. `go build`, `go test ./...` and golangci-lint all skip it, so "+
				"without this step a probe that stopped compiling would be discovered by nobody. %v", err)
		}
	}

	if len(orphaned) > 0 {
		t.Errorf("STILL-OPEN (CI configuration — this probe cannot fix itself): %d tracked test files are "+
			"behind a build constraint no workflow can satisfy. They are not run by `go test ./...` and not "+
			"even compiled by `go build`, `go vet` or golangci-lint, so a probe that stops compiling or grows "+
			"a lint error fails nothing.\n%s\n"+
			"Fix (Lead, in .github/workflows/ci.yml): add the missing tag to the repo-wide vet step's -tags "+
			"list (or add a `go vet -tags <missing> ./...` step), so the file is compiled by CI. This probe "+
			"stays red until that CI change lands.",
			len(orphaned), strings.Join(orphaned, "\n"))
	}
}

// buildConstraintOf returns the build constraint a Go source file's header
// declares, and whether it declares one.
//
// Both spellings are read. The first version of this walk matched only the
// `//go:build` prefix, so a file carrying the legacy `// +build` form was
// indistinguishable from an untagged file: it was never added to the census, so
// it was never checked for reachability and never compiled by this probe — the
// exact blind spot the probe exists to remove. `go/build/constraint.Parse` already
// understands both syntaxes; the bug was in the walk, not the parser.
//
// When both forms are present `//go:build` is authoritative (it is what the
// toolchain uses), and multiple legacy lines are ANDed, which is what the
// go/build rule for `// +build` says. The scan stops at the first non-comment,
// non-blank line — the package clause.
func buildConstraintOf(raw []byte) (constraint.Expr, bool, error) {
	var goBuild constraint.Expr
	var legacy []constraint.Expr
	finish := func() (constraint.Expr, bool, error) {
		if goBuild != nil {
			return goBuild, true, nil
		}
		if len(legacy) == 0 {
			return nil, false, nil
		}
		expr := legacy[0]
		for _, next := range legacy[1:] {
			expr = &constraint.AndExpr{X: expr, Y: next}
		}
		return expr, true, nil
	}
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "//go:build"):
			expr, err := constraint.Parse(trimmed)
			if err != nil {
				return nil, false, fmt.Errorf("%q: %w", trimmed, err)
			}
			if goBuild == nil {
				goBuild = expr
			}
		case strings.HasPrefix(trimmed, "// +build"):
			expr, err := constraint.Parse(trimmed)
			if err != nil {
				return nil, false, fmt.Errorf("%q: %w", trimmed, err)
			}
			legacy = append(legacy, expr)
		case trimmed == "" || strings.HasPrefix(trimmed, "//"):
			// A comment or a blank line: the header continues.
		default:
			// The package clause ends the build-constraint header.
			return finish()
		}
	}
	return finish()
}

// TestZ16BuildConstraintParserReadsBothSpellings is the anti-vacuity control for
// buildConstraintOf.
//
// The repository currently carries no `// +build`-only file, so the walk alone
// cannot prove that the legacy spelling is read at all: reverting the parser to
// its old `//go:build`-only shape would leave the main probe green. This table
// makes the difference observable — every legacy case below fails the moment the
// `// +build` branch is removed.
func TestZ16BuildConstraintParserReadsBothSpellings(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  string
		want string // the constraint's String(), or "" for "no constraint"
	}{
		{"go:build only", "//go:build audit7\n\npackage p\n", "audit7"},
		{"legacy +build only", "// +build audit7\n\npackage p\n", "audit7"},
		{"legacy conjunction", "// +build linux,amd64\n\npackage p\n", "linux && amd64"},
		{"legacy disjunction", "// +build linux darwin\n\npackage p\n", "linux || darwin"},
		{"legacy lines are ANDed", "// +build audit7\n// +build !conformance\n\npackage p\n", "audit7 && !conformance"},
		{"go:build wins over +build", "//go:build audit7\n// +build audit5\n\npackage p\n", "audit7"},
		{"after a licence comment", "// Copyright 2024\n//\n//go:build audit7\n\npackage p\n", "audit7"},
		{"no constraint", "package p\n", ""},
		{"comment that merely mentions a constraint", "// the constraint is //go:build audit7\n\npackage p\n", ""},
	} {
		expr, ok, err := buildConstraintOf([]byte(tc.src))
		if err != nil {
			t.Errorf("%s: buildConstraintOf: %v", tc.name, err)
			continue
		}
		if tc.want == "" {
			if ok {
				t.Errorf("%s: parsed constraint %q, want none", tc.name, expr.String())
			}
			continue
		}
		if !ok {
			t.Errorf("%s: buildConstraintOf found no constraint, want %q — a file behind `// +build` is "+
				"invisible to a walk that only looks for `//go:build`, which is how such a file escapes the "+
				"reachability census and this probe's compile step (Z16V-2)", tc.name, tc.want)
			continue
		}
		if got := expr.String(); got != tc.want {
			t.Errorf("%s: constraint = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// firstSatisfying returns the first tag set whose assignment satisfies expr, and
// false when none does (the file is unreachable from CI).
func firstSatisfying(expr constraint.Expr, sets []map[string]bool) (map[string]bool, bool) {
	for _, set := range sets {
		if satisfiable(expr, set) {
			return set, true
		}
	}
	return nil, false
}

// countTaggedInDirs counts the compileFiles (slash-separated, repo-relative) that
// live in one of dirs ("./x/y"), for the per-group log line.
func countTaggedInDirs(files, dirs []string) int {
	in := make(map[string]bool, len(dirs))
	for _, d := range dirs {
		in[strings.TrimPrefix(d, "./")] = true
	}
	n := 0
	for _, f := range files {
		if in[path.Dir(f)] {
			n++
		}
	}
	return n
}

// vetTagSet compiles the packages in dirs under tags and returns the toolchain's
// output on failure. `go vet` is the cheapest command that compiles a package's
// test files as well as its non-test files; `go build` ignores `_test.go`
// entirely, which is the hole this step closes.
func vetTagSet(t *testing.T, root string, tags, dirs []string) error {
	t.Helper()
	args := []string{"vet"}
	if len(tags) > 0 {
		args = append(args, "-tags="+strings.Join(tags, ","))
	}
	args = append(args, dirs...)
	cmd := exec.Command("go", args...)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	return fmt.Errorf("go vet -tags=%s: %v\n%s", strings.Join(tags, ","), err, firstLines(string(out), 20))
}

func sortedKeys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
