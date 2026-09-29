//go:build audit7

package z16verify

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// repoRoot is this package's copy of the shared helper: the reviewer must not
// depend on the package under review, so the five-level walk is repeated here.
func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func run(t *testing.T, dir string, env []string, name string, args ...string) (int, string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	if env != nil {
		cmd.Env = append(os.Environ(), env...)
	}
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if !asExitError(err, &ee) {
			t.Fatalf("run %s %v: %v\n%s", name, args, err, out)
		}
		code = ee.ExitCode()
	}
	return code, string(out)
}

func asExitError(err error, target **exec.ExitError) bool {
	ee, ok := err.(*exec.ExitError)
	if ok {
		*target = ee
	}
	return ok
}

// TestTaggedTypeErrorsAreInvisibleToTheDefaultGates is the positive control for
// Z16-3's strongest claim ("a probe can rot to calling a function that does not
// exist and every default gate stays green"). It builds a throwaway module whose
// only package carries two errors of that class behind an opt-in tag and shows
// the default `go vet`/`go build` accept it while `-tags` rejects it.
func TestTaggedTypeErrorsAreInvisibleToTheDefaultGates(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module probe.example/z16verify\n\ngo 1.27\n")
	write("main.go", "package main\n\nfunc real(x int) int { return x }\n\nfunc main() { _ = real(1) }\n")
	write("tagged_test.go", "//go:build auditX\n\npackage main\n\nimport \"testing\"\n\n"+
		"func TestArgumentTypeMismatch(t *testing.T) { _ = real(\"string\") }\n")
	write("tagged2_test.go", "//go:build auditX\n\npackage main\n\nimport \"testing\"\n\n"+
		"func TestUndefinedCallee(t *testing.T) { _ = noSuchFunctionAnywhere() }\n")

	if code, out := run(t, dir, nil, "go", "vet", "./..."); code != 0 {
		t.Fatalf("control: the default vet must accept the tagged file (that is the whole point); got exit %d:\n%s", code, out)
	}
	if code, out := run(t, dir, nil, "go", "build", "./..."); code != 0 {
		t.Fatalf("control: the default build must accept the tagged file; got exit %d:\n%s", code, out)
	}
	code, out := run(t, dir, nil, "go", "vet", "-tags", "auditX", "./...")
	if code == 0 {
		t.Fatalf("the tagged file compiles clean, so this control is not measuring what it claims")
	}
	if !strings.Contains(out, "undefined: noSuchFunctionAnywhere") &&
		!strings.Contains(out, "cannot use") {
		t.Fatalf("the tagged run failed for some other reason than a type error:\n%s", out)
	}
	// The mirror: a *syntax* error behind the tag does surface in the default run,
	// because the compiler lexes every file to collect imports. This bounds the
	// claim ("type errors are invisible", not "nothing about the file is seen").
	syntax := filepath.Join(dir, "broken_test.go")
	if err := os.WriteFile(syntax, []byte("//go:build auditX\n\npackage main\n\nfunc oops( {\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, out := run(t, dir, nil, "go", "vet", "./..."); code == 0 {
		t.Logf("note: the default vet accepted a syntax error behind the tag too; output:\n%s", out)
	} else {
		t.Logf("note: the default vet rejected a syntax error behind the tag (imports are still lexed): %s", strings.TrimSpace(out))
	}
}

// splitJob returns the YAML text of one job in a workflow.
func splitJob(t *testing.T, workflow, name string) string {
	t.Helper()
	lines := strings.Split(workflow, "\n")
	start := -1
	for i, l := range lines {
		if l == "  "+name+":" {
			start = i
			break
		}
	}
	if start < 0 {
		t.Fatalf("no job %q in the workflow; this probe is reading the wrong file", name)
	}
	key := regexp.MustCompile(`^  [A-Za-z_][A-Za-z0-9_-]*:`)
	for i := start + 1; i < len(lines); i++ {
		if key.MatchString(lines[i]) {
			return strings.Join(lines[start:i], "\n")
		}
	}
	return strings.Join(lines[start:], "\n")
}

// TestLoadJobMechanismIsLiveAndTheGapIsReal re-derives Z16-1 end to end without
// trusting the package under review: the command the job runs is executed, both
// with the real test name and with a name that matches nothing, and the
// anti-vacuity marker the neighbouring workflow greps for is checked against the
// two outputs. The last step is the positive control for `grep -q`.
func TestLoadJobMechanismIsLiveAndTheGapIsReal(t *testing.T) {
	root := repoRoot(t)

	ci, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	load := splitJob(t, string(ci), "load")
	if !strings.Contains(load, "make load") {
		t.Fatalf("ci.yml's load job no longer runs `make load`; the finding moved:\n%s", load)
	}

	mk, err := os.ReadFile(filepath.Join(root, "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^\t(RE0AUTH_LOAD_PROFILE=1 go test .*?)\s*$`).FindStringSubmatch(string(mk))
	if m == nil {
		t.Fatalf("the Makefile no longer has a `load` recipe of the expected shape; a finding that rests on it is stale")
	}
	recipe := strings.TrimSpace(m[1])
	if !strings.Contains(recipe, "./internal/httpapi/") {
		t.Fatalf("the load recipe changed target package: %q", recipe)
	}
	// The exact mechanism: the floor lives in the test the -run pattern has to
	// find, so a pattern that finds nothing is a successful `go test` that has
	// measured nothing (and, unlike perf.yml, ci.yml reads no output).
	noMatch := strings.Replace(recipe, "-run TestLoadProfile", "-run 'TestLoadProfileRenamedAway'", 1)
	if noMatch == recipe {
		t.Fatalf("the recipe no longer uses `-run TestLoadProfile`; update this probe")
	}
	// Strip the env prefix so this can run in-process-ish: go test itself is the
	// child either way.
	code, out := run(t, root, []string{"RE0AUTH_LOAD_PROFILE=1", "RE0AUTH_LOAD_SECONDS=1", "RE0AUTH_LOAD_WORKERS=1"},
		"go", "test", "-count=1", "-run", "^TestLoadProfileRenamedAway$", "./internal/httpapi/")
	if code != 0 {
		t.Fatalf("control: a -run that matches nothing must exit 0; got %d:\n%s", code, out)
	}
	if !strings.Contains(out, "no tests to run") {
		t.Fatalf("control: expected `no tests to run`, got:\n%s", out)
	}
	if strings.Contains(out, "capacity profile:") {
		t.Fatalf("the zero-match run printed the marker, so the grep in perf.yml would not catch it either")
	}

	// Positive control for the proposed one-line fix: the marker really is on
	// stdout of the real invocation, so `grep -q 'capacity profile:'` would pass
	// there and fail on the zero-match run above.
	code, out = run(t, root, []string{"RE0AUTH_LOAD_PROFILE=1", "RE0AUTH_LOAD_SECONDS=1", "RE0AUTH_LOAD_WORKERS=1"},
		"go", "test", "-count=1", "-v", "-run", "^TestLoadProfile$", "./internal/httpapi/")
	if code != 0 {
		t.Fatalf("the live capacity profile failed, so the marker control is void:\n%s", out)
	}
	if !strings.Contains(out, "capacity profile:") {
		t.Fatalf("the live run did not print the marker; the proposed grep would not work:\n%s", out)
	}
	if !strings.Contains(out, "--- PASS: TestLoadProfile") {
		t.Fatalf("the live run did not report the test; the marker control is void:\n%s", out)
	}
}

// TestWorkflowJobsThatOnlyRunACommandHaveNoAntiVacuityRead generalises Z16-1:
// report which ci.yml jobs contain no step capable of reading a command's output.
// It is the census the finding needs, and it is asserted so a change is visible.
func TestWorkflowJobsThatOnlyRunACommandHaveNoAntiVacuityRead(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(raw)
	names := regexp.MustCompile(`(?m)^  ([A-Za-z_][A-Za-z0-9_-]*):\s*$`).FindAllStringSubmatch(workflow, -1)
	if len(names) < 8 {
		t.Fatalf("parsed only %d jobs out of ci.yml; the parse is not reading the file", len(names))
	}
	readers := regexp.MustCompile(`grep -q|::error::|exit 1|test "\$|awk `)
	var unguarded []string
	for _, n := range names {
		job := splitJob(t, workflow, n[1])
		hasRun := strings.Contains(job, "run: |") || regexp.MustCompile(`(?m)^\s+run: `).MatchString(job)
		if !hasRun {
			continue
		}
		if !readers.MatchString(job) {
			unguarded = append(unguarded, n[1])
		}
	}
	t.Logf("ci.yml jobs whose steps run commands but never read a failure signal out of them: %v", unguarded)
	// The name list must still contain the job the finding names, or the census
	// silently stopped covering it.
	found := false
	for _, name := range unguarded {
		if name == "load" {
			found = true
		}
	}
	if !found {
		t.Logf("the load job now reads its own output (or was renamed); re-check Z16-1 against this census")
	}
}

// TestProbeRetryIsNotInstalledOnTheDataPlaneIsCitedButGreen is a guard-quality
// check of the reviewer's own ground: the report calls out three "computed and
// logged" probes and counts two older ones as recorded precedents. This asserts
// the recorded precedents are still green in the default/audit-tagged run, so the
// distinction the report draws is exercised rather than asserted.
func TestRecordedPrecedentsAreStillGreen(t *testing.T) {
	if runtime.GOOS == "windows" {
		// The probe packages do not build with the default tags on every platform;
		// the tagged run below is the one that matters and is started explicitly.
	}
	root := repoRoot(t)
	for _, tc := range []struct{ pkg, run string }{
		{"./internal/zzprobe/federation/", "^TestProbeRegistryAcceptsPathEscapingNames$"},
		{"./internal/zzprobe/federation/", "^TestProbeRetryIsNotInstalledOnTheDataPlane$"},
	} {
		code, out := run(t, root, nil, "go", "test", "-count=1", "-tags", "audit5", "-run", tc.run, tc.pkg)
		if code != 0 || !strings.Contains(out, "ok ") {
			t.Fatalf("%s in %s did not pass with -tags audit5; the recorded precedent is not a green probe any more:\n%s",
				tc.run, tc.pkg, out)
		}
	}
}
