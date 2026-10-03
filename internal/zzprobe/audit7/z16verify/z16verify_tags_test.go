//go:build audit7

package z16verify

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// This file is the adversarial test of zone 16's own guard: the Z16 report
// proposes "a test file behind a build tag must be reachable from CI" and points
// at gates_test.go::TestEveryTaggedTestFileIsReachableFromCI as one of the
// probes for it. This package runs that guard, unmodified, against a controlled
// tree where a tagged test file does not compile, and asks whether the guard
// fires. It does not — the guard reads the file's *text*, never compiles it — so
// the invariant it names is not the invariant it checks.

// copyRepo copies the parts of the module the shipped guards read. It skips the
// trees that are not Go sources: the frontend's node_modules, the scratch pads,
// and the VCS database. The result carries no tag for any file under
// internal/zzprobe/audit6.
func copyRepo(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", ".svelte-kit", "scratchpad", "_audit",
				"test-results", "playwright-report":
				return filepath.SkipDir
			}
			if rel == "dist" || rel == "web" {
				// The built frontend is not needed; internal/webui/dist is,
				// because //go:embed all:dist makes the module uncompilable
				// without it.
				return filepath.SkipDir
			}
			if strings.HasPrefix(rel, "web"+string(filepath.Separator)) {
				return filepath.SkipDir
			}
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dst, rel)), 0o755); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), raw, 0o644)
	})
	if err != nil {
		t.Fatalf("copy repo: %v", err)
	}
}

// gitQuiet runs git in dir with an isolated identity so a temporary repository
// needs no global configuration.
func gitQuiet(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=z16verify", "GIT_AUTHOR_EMAIL=z16verify@example.invalid",
		"GIT_COMMITTER_NAME=z16verify", "GIT_COMMITTER_EMAIL=z16verify@example.invalid",
		"GIT_CONFIG_NOSYSTEM=1", "HOME="+dir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

// TestTaggedCorpusGuardCompilesWhatItAccepts is the regression control for Z16-1.
//
// The guard used to accept a tracked, tagged test file without ever compiling it,
// so a probe that stopped building stayed green: reachability was decided over file
// names and build comments, and the toolchain was never asked. The compile step
// landed (gates_test.go, "real compile"), so the same plant now makes the guard
// fail with COMPILE FAILURE. The orphan run still proves the planted file is in the
// corpus the guard enumerates, so the failure is caused by the body, not by the
// fixture being skipped.
func TestTaggedCorpusGuardCompilesWhatItAccepts(t *testing.T) {
	// The broken body, used verbatim in the isolated control and in the fixture
	// the guard reads. Only the build comment changes between the two guard runs.
	const body = "package z05memstore\n\nimport \"testing\"\n\n" +
		"func TestZ16VerifyBrokenProbe(t *testing.T) { _ = noSuchFunctionAnywhere() }\n"

	// Isolated control: the exact body behind the exact tag is excluded from the
	// default build (`go vet ./...` never looks inside it) and rejected once the
	// tag is set. Deterministic on purpose: it does not depend on a copy of the
	// whole repository, which a concurrent writer can leave torn mid-file.
	ctrl := t.TempDir()
	for _, f := range []struct{ name, text string }{
		{"go.mod", "module probe.example/z16verify\n\ngo 1.27\n"},
		{"unrelated.go", "package z05memstore\n\nfunc real() {}\n"},
		{"fixture_test.go", "//go:build audit6\n\n" + body},
	} {
		if err := os.WriteFile(filepath.Join(ctrl, f.name), []byte(f.text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if code, out := run(t, ctrl, nil, "go", "vet", "./..."); code != 0 {
		t.Fatalf("control: the default gates must exclude the tagged fixture (that is what makes it "+
			"invisible to `go test ./...` and `go vet ./...`); got exit %d:\n%s", code, out)
	}
	code, out := run(t, ctrl, nil, "go", "vet", "-tags", "audit6", "./...")
	if code == 0 {
		t.Fatalf("the fixture body compiles under the tag, so this probe would prove nothing")
	}
	if !strings.Contains(out, "noSuchFunctionAnywhere") {
		t.Fatalf("the tagged vet failed for a reason other than the fixture's undefined callee:\n%s", out)
	}
	t.Logf("isolated control: `go vet ./...` accepts the fixture, `go vet -tags audit6 ./...` rejects "+
		"it with %s", strings.TrimSpace(firstLine(out)))

	src := repoRoot(t)
	tmp := t.TempDir()
	copyRepo(t, src, tmp)

	// The fixture: a tracked file in the repository's own corpus is overwritten
	// with that same body. The guard enumerates it through `git ls-files`.
	broken := filepath.Join(tmp, "internal", "zzprobe", "audit6", "z05memstore", "alias_residual_test.go")
	writeFixture := func(tag string) {
		t.Helper()
		if err := os.WriteFile(broken, []byte("//go:build "+tag+"\n\n"+body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeFixture("audit6")

	gitQuiet(t, tmp, "init", "--quiet")
	gitQuiet(t, tmp, "add", "-A")
	gitQuiet(t, tmp, "commit", "--quiet", "-m", "verify fixture")

	guardRun := func() (int, string) {
		t.Helper()
		c, o := run(t, tmp, nil, "go", "test", "-tags", "audit7", "-count=1", "-v",
			"-run", "^TestEveryTaggedTestFileIsReachableFromCI$",
			"./internal/zzprobe/audit7/z16guardtestquality/")
		if !strings.Contains(o, "tracked test files are behind a constraint no workflow can satisfy") {
			t.Fatalf("the guard did not report a corpus at all, so it is not reading the tree:\n%s", o)
		}
		return c, o
	}

	// Run 1 (workflow-satisfiable tag): the planted file cannot compile, so the
	// guard's compile step must fail and name the planted defect. Before the
	// compile step landed this run was silent, which was the finding.
	code, out = guardRun()
	if code == 0 {
		t.Fatalf("the guard passed with a tracked, tagged file that does not compile, so the compile "+
			"step is not running:\n%s", out)
	}
	if !strings.Contains(out, "COMPILE FAILURE") || !strings.Contains(out, "alias_residual_test.go") {
		t.Fatalf("the guard failed without naming the compile failure of the planted file:\n%s", out)
	}
	if !strings.Contains(out, "noSuchFunctionAnywhere") {
		t.Fatalf("the guard's failure is not the planted undefined callee, so the fixture did not reach "+
			"the compiler:\n%s", out)
	}

	// Run 2 (orphan form): same tracked file, same broken body, a tag no workflow
	// sets. The guard must still name it in the orphan list — corpus membership is
	// unchanged, only satisfiability differs.
	writeFixture("z16orphanprobe")
	_, out = guardRun()
	const label = "alias_residual_test.go (build constraint z16orphanprobe)"
	if !strings.Contains(out, label) {
		t.Fatalf("the guard did not name the same broken file under an unsatisfiable tag, so the "+
			"file is not in the corpus run 1 read:\n%s", out)
	}
	t.Logf("the guard: refuses to pass when a workflow-satisfiable tagged file does not compile " +
		"(run 1, COMPILE FAILURE naming the planted file), and reports the same file as orphaned under " +
		"an unsatisfiable tag (run 2)")
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// TestTaggedCorpusGuardReadsTheLegacyBuildTag is the regression control for Z16V-2.
//
// The guard's walk once looked for `//go:build` alone, so the older `// +build`
// form — which Go still honours — was invisible: a legacy-tagged file was counted
// as a default-suite test, never checked for reachability and never compiled. The
// walk now parses both spellings (gates_test.go::buildConstraintOf), so the same
// legacy fixtures are corroborated here: a legacy tag the workflows set makes the
// guard's compile step fail, and a legacy-only orphan tag is named in the census.
func TestTaggedCorpusGuardReadsTheLegacyBuildTag(t *testing.T) {
	src := repoRoot(t)
	tmp := t.TempDir()
	copyRepo(t, src, tmp)

	legacy := filepath.Join(tmp, "internal", "zzprobe", "audit6", "z05memstore", "rev1_test.go")
	writeLegacy := func(tag string) {
		t.Helper()
		if err := os.WriteFile(legacy, []byte("// +build "+tag+"\n\npackage z05memstore\n\nimport \"testing\"\n\n"+
			"func TestZ16VerifyLegacyTagged(t *testing.T) { _ = noSuchFunctionAnywhere() }\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeLegacy("audit6")
	gitQuiet(t, tmp, "init", "--quiet")
	gitQuiet(t, tmp, "add", "-A")
	gitQuiet(t, tmp, "commit", "--quiet", "-m", "verify fixture")

	// Control: the toolchain really does exclude it by default and include it
	// under the tag, i.e. this IS a build-constrained file.
	if code, _ := run(t, tmp, nil, "go", "vet", "./internal/zzprobe/audit6/z05memstore/..."); code != 0 {
		t.Fatalf("control: a legacy-tagged file must be excluded from the default build")
	}
	if code, _ := run(t, tmp, nil, "go", "vet", "-tags", "audit6", "./internal/zzprobe/audit6/z05memstore/..."); code == 0 {
		t.Fatalf("control: with the tag set the file must be compiled (and fail)")
	}

	guardRun := func() (int, string) {
		t.Helper()
		c, o := run(t, tmp, nil, "go", "test", "-tags", "audit7", "-count=1", "-v",
			"-run", "^TestEveryTaggedTestFileIsReachableFromCI$",
			"./internal/zzprobe/audit7/z16guardtestquality/")
		if !strings.Contains(o, "tracked test files are behind a constraint no workflow can satisfy") {
			t.Fatalf("the guard did not run at all:\n%s", o)
		}
		return c, o
	}

	// (a) A legacy tag the workflows set: the file is in the census now, so the
	// compile step runs it and fails on the planted body.
	code, out := guardRun()
	if code == 0 {
		t.Fatalf("the guard passed with a broken legacy-tagged file, so the legacy form is still "+
			"invisible to the census:\n%s", out)
	}
	if !strings.Contains(out, "COMPILE FAILURE") || !strings.Contains(out, "noSuchFunctionAnywhere") {
		t.Fatalf("the guard failed without compiling the legacy-tagged fixture:\n%s", out)
	}

	// (b) A legacy-only orphan tag: the guard must now name it in the orphan list,
	// which the old `//go:build`-only walk could never do.
	writeLegacy("z16orphanprobe")
	_, out = guardRun()
	if !strings.Contains(out, "rev1_test.go (build constraint z16orphanprobe)") {
		t.Fatalf("a legacy-only orphan tag is still invisible to the guard's census:\n%s", out)
	}
	t.Logf("legacy-tagged fixture: excluded from the default build by the toolchain (control above), " +
		"compiled-and-failed by the guard when a workflow sets the tag (run a), named as orphaned when no " +
		"workflow does (run b)")
}

// TestLoadJobInspectionIfFixed keeps the one-line fix honest: the guard the Z16
// report proposed (read the step's output) must be able to distinguish the live
// run from the zero-measurement run. This is the same positive control as in the
// other file, asserted here as a named guard so a later edit cannot silently
// weaken it.
//
// 【原为发现演示，现为回归守卫】The fix landed (ci.yml:624-632), and this is now
// the control that says the job's grep would actually fire: the marker is present
// on the live run and absent on a `-run` that matches nothing. The live fixture
// uses loadLiveSeconds/loadLiveWorkers so it clears TestLoadProfile's own floor
// instead of tripping it (see that const's comment).
func TestLoadJobInspectionIfFixed(t *testing.T) {
	root := repoRoot(t)
	code, out := run(t, root, loadLiveEnv(),
		"go", "test", "-count=1", "-v", "-run", "^TestLoadProfile$", "./internal/httpapi/")
	if code != 0 || !strings.Contains(out, "capacity profile:") {
		t.Fatalf("the anti-vacuity marker is not produced by the live run:\n%s", out)
	}
	code, out = run(t, root, nil, "go", "test", "-count=1", "-run", "^TestLoadProfileRenamedAway$", "./internal/httpapi/")
	if code != 0 || strings.Contains(out, "capacity profile:") {
		t.Fatalf("the zero-match run is not distinguishable from the live one:\n%s", out)
	}
}
