package archtest

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestCIFuzzTargetListCoversEveryFuzzTarget ties the hand-written FUZZ_TARGETS
// list in ci.yml's `fuzz` job to the `func Fuzz*` that actually exist in the
// module.
//
// The comment above that list states the rule -- "It lists every target rather
// than a sample", because "a target that only ever sees its seed corpus never
// explores anything" -- and a comment is not a gate: two targets were listed
// while eight others existed, and the job stayed green. The workflow now checks
// the list against the toolchain at run time (Z16-5); this is the
// repository-internal half, so `go test ./...` fails in the same commit that
// adds a Fuzz function without adding it to the list. A rename that leaves the
// list naming a target that no longer exists fails here too, which is the other
// direction the run-time `diff` cannot be trusted to catch on a laptop.
func TestCIFuzzTargetListCoversEveryFuzzTarget(t *testing.T) {
	if testing.Short() {
		t.Skip("this guard shells out to `go list`; skipped under -short")
	}
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}

	ci, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatalf("read ci.yml: %v", err)
	}
	declared, err := ciFuzzTargets(ci)
	if err != nil {
		t.Fatalf("cannot read FUZZ_TARGETS out of ci.yml: %v", err)
	}
	actual, err := moduleFuzzTargets(root)
	if err != nil {
		t.Fatalf("cannot enumerate the module's fuzz targets: %v", err)
	}

	// Anti-vacuous: every comparison below passes when either set is empty, which
	// is also what a parse that stopped reading looks like.
	if len(declared) == 0 {
		t.Fatal("FUZZ_TARGETS parsed as empty: the guard would compare nothing and pass; " +
			"either the list lost its entries or this parse no longer reads it")
	}
	if len(actual) < 5 {
		t.Fatalf("only %d fuzz targets were found in the module (the list declares %d); the "+
			"enumeration is not reading the tree", len(actual), len(declared))
	}

	unlisted, stale := fuzzTargetDrift(declared, actual)
	if len(unlisted) > 0 {
		t.Errorf("ci.yml's FUZZ_TARGETS omits %d fuzz target(s), so the `fuzz` job never runs them and "+
			"they only ever see their seed corpus:\n  %s", len(unlisted), strings.Join(unlisted, "\n  "))
	}
	if len(stale) > 0 {
		t.Errorf("ci.yml's FUZZ_TARGETS names %d target(s) that no `func Fuzz*` provides, so the job "+
			"runs a name that no longer builds:\n  %s", len(stale), strings.Join(stale, "\n  "))
	}
	if len(unlisted) == 0 && len(stale) == 0 {
		t.Logf("ci.yml's FUZZ_TARGETS names all %d fuzz targets in the module", len(actual))
	}
}

// TestZ16_5FuzzListGuardDetectsDrift proves the guard above is not a
// restatement of the tree. It drives the same parse and the same comparison on
// the mutation the finding describes: drop the five oidchttp targets from
// ci.yml and the guard must report exactly those five as unlisted, with nothing
// stale. A parse that silently returned every line, or a comparison that only
// checked one direction, would pass here.
func TestZ16_5FuzzListGuardDetectsDrift(t *testing.T) {
	if testing.Short() {
		t.Skip("this probe shells out to `go list`; skipped under -short")
	}
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	ci, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatalf("read ci.yml: %v", err)
	}
	actual, err := moduleFuzzTargets(root)
	if err != nil {
		t.Fatalf("cannot enumerate the module's fuzz targets: %v", err)
	}
	if len(actual) < 5 {
		t.Fatalf("only %d fuzz targets were found; the probe would compare nothing", len(actual))
	}

	// The mutation: the five oidchttp entries the workflow's own `diff` would
	// catch, removed from the raw text. The regex is anchored on the list's
	// `./pkg:Name` lines, so it cannot match the prose above them.
	drop := regexp.MustCompile(`(?m)^\s*\./internal/oidchttp:Fuzz\w+\s*$\n`)
	mutated := drop.ReplaceAll(ci, nil)
	if dropped := len(ci) - len(mutated); dropped == 0 {
		t.Fatalf("the ci.yml fuzz list no longer has the `./internal/oidchttp:Fuzz*` lines this probe " +
			"removes; update it to the mutation the finding describes")
	}
	declared, err := ciFuzzTargets(mutated)
	if err != nil {
		t.Fatalf("cannot read FUZZ_TARGETS out of the mutated ci.yml: %v", err)
	}
	if len(declared) == 0 || len(declared) >= len(actual) {
		t.Fatalf("dropping targets left %d declared entries against %d real ones; the mutation or the "+
			"parse is not reading the list", len(declared), len(actual))
	}

	unlisted, stale := fuzzTargetDrift(declared, actual)
	if len(stale) != 0 {
		t.Errorf("the mutation dropped entries that were never in the list, so nothing was removed: %v", stale)
	}
	if len(unlisted) != 5 {
		t.Fatalf("dropping the five oidchttp targets reported %d unlisted target(s) %v; the guard does "+
			"not notice the drift it exists for", len(unlisted), unlisted)
	}
	var oidchttp []string
	for _, target := range unlisted {
		if strings.HasPrefix(target, "./internal/oidchttp:") {
			oidchttp = append(oidchttp, target)
		}
	}
	if len(oidchttp) != 5 {
		t.Errorf("unlisted targets %v are not the five oidchttp entries the mutation removed", unlisted)
	}

	// The other direction, on the same comparison: a name the list keeps after
	// its function is renamed is stale, and must be reported as such.
	renamed := map[string]bool{"./internal/oidchttp:FuzzThisTargetWasRenamed": true}
	if _, stale := fuzzTargetDrift(renamed, actual); len(stale) != 1 || stale[0] != "./internal/oidchttp:FuzzThisTargetWasRenamed" {
		t.Errorf("a listed target with no `func Fuzz*` behind it was not reported as stale: %v", stale)
	}
}

// fuzzTargetDrift compares the declared list with the targets that exist, in
// both directions: unlisted is a target the gate never runs, stale is a name
// the gate runs that no longer builds. Each is sorted so a failure message is
// stable across runs.
func fuzzTargetDrift(declared, actual map[string]bool) (unlisted, stale []string) {
	for target := range actual {
		if !declared[target] {
			unlisted = append(unlisted, target)
		}
	}
	for target := range declared {
		if !actual[target] {
			stale = append(stale, target)
		}
	}
	sort.Strings(unlisted)
	sort.Strings(stale)
	return unlisted, stale
}

// ciFuzzTargets reads the FUZZ_TARGETS block out of ci.yml.
//
// It is parsed structurally rather than by a whole-file search, for the reason
// Z16-4 recorded for the Makefile guard: a `strings.Contains` over the file is
// satisfied by prose, and this block is described by four comment lines right
// above it that quote the very names the list carries. Only the value of an
// `env` entry named FUZZ_TARGETS is read, so the explanation cannot stand in
// for the list. The block may live at workflow or job level; a job rename is a
// move, not a reason for the guard to go blind.
func ciFuzzTargets(ci []byte) (map[string]bool, error) {
	var workflow struct {
		Env  map[string]any `yaml:"env"`
		Jobs map[string]struct {
			Env map[string]any `yaml:"env"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(ci, &workflow); err != nil {
		return nil, fmt.Errorf("parse ci.yml: %w", err)
	}

	var values []string
	collect := func(env map[string]any) error {
		raw, ok := env["FUZZ_TARGETS"]
		if !ok {
			return nil
		}
		value, ok := raw.(string)
		if !ok {
			return fmt.Errorf("FUZZ_TARGETS is a %T, not a string list", raw)
		}
		values = append(values, value)
		return nil
	}
	if err := collect(workflow.Env); err != nil {
		return nil, err
	}
	for _, job := range workflow.Jobs {
		if err := collect(job.Env); err != nil {
			return nil, err
		}
	}
	if len(values) == 0 {
		return nil, errors.New("no job in ci.yml sets FUZZ_TARGETS")
	}

	targets := map[string]bool{}
	for _, value := range values {
		for _, line := range strings.Split(value, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			targets[line] = true
		}
	}
	return targets, nil
}

// moduleFuzzTargets returns the `./pkg:Name` form of every fuzz target the
// default `go test` build can see. The file set comes from `go list`, and only
// the files it reports are parsed: a directory walk would read a
// `//go:build audit7` file whose Fuzz function no default gate compiles, and
// would then demand that ci.yml list a target the toolchain cannot run. The
// import-path form is the one ci.yml uses and the one the workflow's own
// `go test -list '^Fuzz'` step writes, so the two sides compare equal, not
// merely overlapping.
func moduleFuzzTargets(root string) (map[string]bool, error) {
	// No double quotes in the template: `go list -f` is invoked from several
	// shells in this repository, and a template that survives all of them is one
	// nobody has to re-quote.
	const tmpl = `{{.Dir}}|{{range .TestGoFiles}}{{.}} {{end}}|{{range .XTestGoFiles}}{{.}} {{end}}`
	cmd := exec.Command("go", "list", "-f", tmpl, "./...")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return nil, fmt.Errorf("go list ./...: %w: %s", err, strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, fmt.Errorf("go list ./...: %w", err)
	}

	fset := token.NewFileSet()
	targets := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "|", 3)
		if len(parts) != 3 {
			return nil, fmt.Errorf("unexpected `go list` line %q", line)
		}
		dir, files := parts[0], strings.Fields(parts[1]+" "+parts[2])
		if rel, err := filepath.Rel(root, dir); err == nil {
			pkg := "./" + filepath.ToSlash(rel)
			if rel == "." {
				pkg = "./"
			}
			for _, name := range files {
				path := filepath.Join(dir, name)
				f, err := parser.ParseFile(fset, path, nil, 0)
				if err != nil {
					return nil, fmt.Errorf("parse %s: %w", path, err)
				}
				for _, decl := range f.Decls {
					fn, ok := decl.(*ast.FuncDecl)
					if !ok || !isFuzzTarget(fn) {
						continue
					}
					targets[pkg+":"+fn.Name.Name] = true
				}
			}
		}
	}
	return targets, nil
}

// isFuzzTarget reports whether a declaration is a fuzz target as the testing
// package defines one: a top-level function named Fuzz*, taking exactly one
// *testing.F and returning nothing. A method or a `FuzzSomething` helper of
// another shape is not a target, and `go test -list '^Fuzz'` would not run it
// either.
func isFuzzTarget(fn *ast.FuncDecl) bool {
	if fn.Recv != nil || fn.Name == nil || !strings.HasPrefix(fn.Name.Name, "Fuzz") {
		return false
	}
	if fn.Type == nil || fn.Type.Params == nil || fn.Type.Results != nil {
		return false
	}
	params := fn.Type.Params.List
	if len(params) != 1 || len(params[0].Names) != 1 {
		return false
	}
	star, ok := params[0].Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	sel, ok := star.X.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	ident, ok := sel.X.(*ast.Ident)
	return ok && ident.Name == "testing" && sel.Sel.Name == "F"
}
