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

// TestTaggedCorpusGuardIsBlindToWhetherItsFilesCompile runs the repository's own
// "a tagged test file must be reachable from CI" guard against a tree whose
// tracked, tagged test file cannot compile, holding the broken body fixed and
// moving only its build comment. Reachability is asserted over file names and
// build comments and never over the toolchain, so the guard is blind to whether
// a file it accepts actually compiles.
//
// N-04 landed: ci.yml:400 now vets with `-tags audit5,audit6,audit7,conformance,
// audit,protocolaudit`, so the guard's orphan list is empty and every
// workflow-satisfiable constraint is compiled by that one step. The guard itself
// still compiles nothing, and the two runs below separate the two facts:
//
//   - tagged `audit6` — a tag the workflows set, hence "reachable" — the guard is
//     silent: it reports the corpus, accepts the file's constraint as reachable
//     and never names it, while the tagged toolchain rejects it (control above).
//   - tagged `z16orphanprobe` — a tag no workflow sets — the guard names the very
//     same file. Corpus membership is therefore proved by run 2, and the only
//     difference between the runs is satisfiability, not the compile error.
//
// Compilation of these files is covered exclusively by the CI vet step's -tags
// list, so a file whose tag is absent from it can still decay in silence.
func TestTaggedCorpusGuardIsBlindToWhetherItsFilesCompile(t *testing.T) {
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

	// Corroboration in the copied tree: the fixture's own package must not vet
	// clean under its tag. Whether the compiler names our callee is only logged —
	// a copy taken while another process writes the repository can carry a torn
	// unrelated file, and the package is then skipped as a broken dependency. The
	// isolated control above is the normative proof of the fixture's breakage.
	code, out = run(t, tmp, nil, "go", "vet", "-tags", "audit6", "./internal/zzprobe/audit6/z05memstore/...")
	if code == 0 {
		t.Fatalf("the fixture's own package vets clean under -tags audit6, so the fixture is not the " +
			"broken sample this probe needs")
	}
	t.Logf("copied tree: `go vet -tags audit6 ./internal/zzprobe/audit6/z05memstore/...` exits %d (%s)",
		code, strings.TrimSpace(firstLine(out)))

	guardRun := func() string {
		t.Helper()
		_, out := run(t, tmp, nil, "go", "test", "-tags", "audit7", "-count=1", "-v",
			"-run", "^TestEveryTaggedTestFileIsReachableFromCI$",
			"./internal/zzprobe/audit7/z16guardtestquality/")
		if !strings.Contains(out, "tracked test files are behind a constraint no workflow can satisfy") {
			t.Fatalf("the guard did not report a corpus at all, so it is not reading the tree:\n%s", out)
		}
		return out
	}

	// Run 1 (reachable form): the fixture's tag is in ci.yml:400's list, and the
	// guard says nothing about the file. It is accepted as reachable without ever
	// being compiled — even though the isolated control shows it cannot compile.
	out = guardRun()
	if !strings.Contains(out, "audit6") {
		t.Fatalf("the guard no longer reports the fixture's tag among the workflow tags, so the "+
			"reachability half of this probe is void:\n%s", out)
	}
	if strings.Contains(out, "alias_residual_test.go") {
		t.Fatalf("the guard named a file whose tag the workflows set; that is a different guard "+
			"than the one under test:\n%s", out)
	}

	// Run 2 (orphan form): same tracked file, same broken body, a tag no workflow
	// sets. The guard must now name it — proving the file IS in the corpus it
	// enumerates, so run 1's silence was a satisfiability verdict and not a skip.
	writeFixture("z16orphanprobe")
	out = guardRun()
	const label = "alias_residual_test.go (//go:build z16orphanprobe)"
	if !strings.Contains(out, label) {
		t.Fatalf("the guard did not name the same broken file under an unsatisfiable tag, so the "+
			"file is not in the corpus it reads and run 1 proved nothing:\n%s", out)
	}
	// The guard named it without compiling it. The isolated control already proved
	// the same body cannot compile in either tag form, and the guard's report
	// contains no compilation step for anything it lists.
	t.Logf("the guard: names the fixture when its constraint is orphaned (run 2), accepts the same " +
		"broken file silently when ci.yml:400's tags satisfy it (run 1); the report itself compiles " +
		"nothing it lists")
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// TestTaggedCorpusGuardParsesOnlyGoBuildNotTheLegacyTag is the second half: the
// guard's tag extraction looks for `//go:build` alone, so the older
// `// +build` form — which Go still honours as a build constraint — is invisible
// to it. A file whose constraint is only the legacy comment is therefore counted
// as a default-suite test and never reported as orphaned.
func TestTaggedCorpusGuardParsesOnlyGoBuildNotTheLegacyTag(t *testing.T) {
	src := repoRoot(t)
	tmp := t.TempDir()
	copyRepo(t, src, tmp)

	legacy := filepath.Join(tmp, "internal", "zzprobe", "audit6", "z05memstore", "rev1_test.go")
	if err := os.WriteFile(legacy, []byte("// +build audit6\n\npackage z05memstore\n\nimport \"testing\"\n\n"+
		"func TestZ16VerifyLegacyTagged(t *testing.T) { _ = noSuchFunctionAnywhere() }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
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

	code, out := run(t, tmp, nil, "go", "test", "-tags", "audit7", "-count=1", "-v",
		"-run", "^TestEveryTaggedTestFileIsReachableFromCI$",
		"./internal/zzprobe/audit7/z16guardtestquality/")
	if !strings.Contains(out, "tracked test files are behind a constraint no workflow can satisfy") {
		t.Fatalf("the guard did not run at all:\n%s", out)
	}
	if strings.Contains(out, "rev1_test.go") {
		t.Fatalf("the guard named the legacy-tagged file, so it does understand the legacy form:\n%s", out)
	}
	t.Logf("legacy-tagged fixture: excluded from the default build by the toolchain (control above), "+
		"compiled under -tags audit6 (control above), and never named by the guard's report (exit %d)", code)
	// And the guard's own scanner sees the file as untagged, which is why it is
	// absent from the orphan list: `-tags audit6` runs it, `go test ./...` does
	// not, and the guard's two halves disagree about what "tagged" means.
	t.Log("legacy-tagged fixture: accounted as untagged by the guard, excluded from the default build by the toolchain")
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
