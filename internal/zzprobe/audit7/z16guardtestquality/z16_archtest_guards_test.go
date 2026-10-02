//go:build audit7

package z16guardtestquality

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// This file runs the repository's *real* archtest guards against a mutated copy
// of the two artifacts they read, so a "the guard did not fire" claim comes with
// a positive control (the same binary fails when the text it looks for is
// changed) and a negative control (it passes on the unmutated tree).
//
// The guards are compiled once with `go test -c`; the binary is then run in a
// temporary module root whose Makefile / .github/workflows are the only inputs
// the selected tests need.

// buildArchtest compiles the real internal/archtest package into a test binary.
func buildArchtest(t *testing.T, root string) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "archtest.test")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	cmd := exec.Command("go", "test", "-c", "-o", bin, "./internal/archtest/")
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go test -c ./internal/archtest: %v\n%s", err, out)
	}
	if _, err := os.Stat(bin); err != nil {
		t.Fatalf("the archtest binary was not produced: %v", err)
	}
	return bin
}

// runArchtest runs the binary in dir and reports whether the selected tests
// passed, plus its output.
func runArchtest(t *testing.T, bin, dir, run string) (bool, string) {
	t.Helper()
	cmd := exec.Command(bin, "-test.run", run, "-test.count=1", "-test.v")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err == nil {
		return true, string(out)
	}
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("run archtest: %v\n%s", err, out)
	}
	return false, string(out)
}

// archtestRoot lays out the files the selected guards read, applying the mutator
// to the Makefile (mutFile) or to ci.yml (mutCI) when given.
func archtestRoot(t *testing.T, repo string, mutFile, mutCI func(string) string) string {
	t.Helper()
	tmp := t.TempDir()
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}

	mk, err := os.ReadFile(filepath.Join(repo, "Makefile"))
	must(err)
	if mutFile != nil {
		mk = []byte(mutFile(string(mk)))
	}
	must(os.WriteFile(filepath.Join(tmp, "Makefile"), mk, 0o644))

	// TestReleaseShipsNpmAttribution reads the Dockerfile too (the runtime stage
	// must carry the npm attribution, Z13-3), so the temporary root has to contain
	// it or the guard fatals on the missing file rather than on the mutation.
	df, err := os.ReadFile(filepath.Join(repo, "Dockerfile"))
	must(err)
	must(os.WriteFile(filepath.Join(tmp, "Dockerfile"), df, 0o644))

	src := filepath.Join(repo, ".github", "workflows")
	dst := filepath.Join(tmp, ".github", "workflows")
	must(os.MkdirAll(dst, 0o755))
	entries, err := os.ReadDir(src)
	must(err)
	for _, e := range entries {
		raw, err := os.ReadFile(filepath.Join(src, e.Name()))
		must(err)
		if mutCI != nil && e.Name() == "ci.yml" {
			raw = []byte(mutCI(string(raw)))
		}
		must(os.WriteFile(filepath.Join(dst, e.Name()), raw, 0o644))
	}
	must(os.MkdirAll(filepath.Join(tmp, "internal", "archtest"), 0o755))
	return tmp
}

const (
	makefileGuard = "^TestReleaseShipsNpmAttribution$"
	workflowGuard = "^(TestWorkflowActionsArePinnedToFullSHAs|TestWorkflowsCacheOnlyWhatTheyCreate|" +
		"TestWorkflowsGrantWriteScopesOnlyToTheJobThatUsesThem)$"
)

// TestZ16ArchtestGuardsAreSatisfiedByComments was the "a guard that greps a whole
// file is satisfied by prose" finding (Z16-4) on the real guard. The Makefile
// guard now parses targets/prerequisites instead of searching the file, so the
// mutation below — commenting the `release:` rule out while leaving the same words
// in a comment — must FAIL the guard. This is the regression guard for that fix
// (the name is kept for the audit coverage matrix).
func TestZ16ArchtestGuardsAreSatisfiedByComments(t *testing.T) {
	repo := repoRoot(t)
	bin := buildArchtest(t, repo)

	// Positive control: the guard passes on the unmutated tree.
	tmp := archtestRoot(t, repo, nil, nil)
	if ok, out := runArchtest(t, bin, filepath.Join(tmp, "internal", "archtest"), makefileGuard); !ok {
		t.Fatalf("control: the guard fails on an unmutated Makefile:\n%s", out)
	}

	// Positive control 2: changing the text it looks for does make it fail, so the
	// mutation harness really reaches the guard.
	tmp2 := archtestRoot(t, repo, func(mk string) string {
		if !strings.Contains(mk, "npm-attribution:") {
			t.Fatal("the Makefile no longer contains `npm-attribution:`; the mutation harness is stale")
		}
		return strings.Replace(mk, "npm-attribution:", "npm-licences:", 1)
	}, nil)
	if ok, out := runArchtest(t, bin, filepath.Join(tmp2, "internal", "archtest"), makefileGuard); ok {
		t.Fatalf("control 2: renaming the target did not fail the guard, so the harness proves nothing:\n%s", out)
	}

	// The mutation: comment the `release:` rule out, leaving the same words in a
	// comment. A whole-file `strings.Contains` would still be satisfied; the
	// structural guard must not be, because `make release` then has no rule at all.
	const want = "\nrelease: dist sbom npm-attribution checksums\n"
	tmp3 := archtestRoot(t, repo, func(mk string) string {
		if !strings.Contains(mk, want) {
			t.Fatalf("the Makefile no longer has the release rule; update this probe")
		}
		return strings.Replace(mk, want, "\n# release: dist sbom npm-attribution checksums\n", 1)
	}, nil)
	ok, out := runArchtest(t, bin, filepath.Join(tmp3, "internal", "archtest"), makefileGuard)
	if ok {
		t.Errorf("TestReleaseShipsNpmAttribution passed with the `release:` rule commented out: it is a "+
			"whole-file `strings.Contains` again (Z16-4 regressed), so it says \"the SPA's npm licence "+
			"listing reaches a release\" while `make release` can exist only as a comment.\n%s", out)
	}
	if !strings.Contains(out, "release") {
		t.Errorf("the guard failed for a reason unrelated to the release rule; re-derive this probe:\n%s", out)
	}
}

// TestZ16NoGuardKeepsTheFuzzTargetListComplete: ci.yml hand-lists the fuzz
// targets and nothing ties that list to the `func Fuzz*` in the tree.
func TestZ16NoGuardKeepsTheFuzzTargetListComplete(t *testing.T) {
	repo := repoRoot(t)
	ci := readFile(t, filepath.Join(repo, ".github", "workflows", "ci.yml"))

	// The proposed guard, evaluated live: the list and the tree agree today.
	listed := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^\s*(\S+):(Fuzz\w+)\s*$`).FindAllStringSubmatch(ci, -1) {
		listed[m[1]+":"+m[2]] = true
	}
	if len(listed) < 5 {
		t.Fatalf("only %d fuzz targets parsed out of ci.yml; the parse is not reading the list", len(listed))
	}
	present := map[string]bool{}
	for _, pkgDir := range []string{"idp", "oauth", "internal/federation", "internal/oidchttp"} {
		for _, name := range fuzzFuncs(t, filepath.Join(repo, filepath.FromSlash(pkgDir))) {
			present["./"+pkgDir+":"+name] = true
		}
	}
	if len(present) < 5 {
		t.Fatalf("only %d fuzz functions found on disk; the walk is not reading the tree", len(present))
	}
	var missing []string
	for k := range present {
		if !listed[k] {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("a fuzz target exists that the CI list does not run: %v", missing)
	}

	// The demonstration: drop five targets from the list and run every archtest
	// guard that reads a workflow. They are all still green, so the mutation is
	// invisible to the package whose job is to make workflow rules checkable.
	drop := regexp.MustCompile(`(?m)^\s*\./internal/oidchttp:Fuzz\w+\s*$\n`)
	if !drop.MatchString(ci) {
		t.Fatalf("the ci.yml fuzz list no longer has the oidchttp entries; update this probe")
	}
	bin := buildArchtest(t, repo)
	tmp := archtestRoot(t, repo, nil, func(raw string) string { return drop.ReplaceAllString(raw, "") })
	ok, out := runArchtest(t, bin, filepath.Join(tmp, "internal", "archtest"), workflowGuard)
	if !ok {
		t.Fatalf("the harness is wrong: the workflow guards are expected to stay green on a truncated fuzz list:\n%s", out)
	}
	// And nothing in archtest even mentions fuzz targets.
	var mentions []string
	src := filepath.Join(repo, "internal", "archtest")
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".go") && strings.Contains(readFile(t, filepath.Join(src, e.Name())), "Fuzz") {
			mentions = append(mentions, e.Name())
		}
	}
	if len(mentions) > 0 {
		t.Logf("archtest now mentions fuzz targets in %v; re-check this finding", mentions)
		return
	}
	t.Errorf("the fuzz target list in ci.yml (ci.yml:467-478) is hand-maintained and no guard keeps it " +
		"complete: dropping five of the ten targets leaves every archtest guard green (proven above), and " +
		"no file in internal/archtest mentions `Fuzz`. The comment above the list states the rule — \"It " +
		"lists every target rather than a sample\", because \"a target that only ever sees its seed corpus " +
		"never explores anything\" — and that rule is exactly what regresses when a new `func Fuzz*` is " +
		"added without touching ci.yml. The fix is one archtest check: enumerate `func Fuzz` across the " +
		"module (go/ast or `go test -list '^Fuzz' ./...`) and assert the ci.yml list names every one.")
}

// fuzzFuncs returns the names of the `func Fuzz*` declarations in a directory.
func fuzzFuncs(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	re := regexp.MustCompile(`(?m)^func (Fuzz\w+)\(`)
	var names []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		for _, m := range re.FindAllStringSubmatch(readFile(t, filepath.Join(dir, e.Name())), -1) {
			names = append(names, m[1])
		}
	}
	return names
}
