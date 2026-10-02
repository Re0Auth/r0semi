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
// "a tagged test file must be reachable from CI" guard against a tree where a
// tracked, tagged test file cannot compile. The guard lists it by name — reachable
// is exactly what it did not check — while the tagged build rejects it, because
// reachability is asserted over file names and build comments and never over the
// toolchain.
func TestTaggedCorpusGuardIsBlindToWhetherItsFilesCompile(t *testing.T) {
	src := repoRoot(t)
	tmp := t.TempDir()
	copyRepo(t, src, tmp)

	// A tracked, audit-tagged file in the repository's own corpus is overwritten
	// with a body that calls a function which does not exist. It is still tagged,
	// still tracked, and no workflow sets that tag (N-04 added audit5/audit6/
	// audit7, so `audit` is the tag that stays orphaned).
	broken := filepath.Join(tmp, "internal", "zzprobe", "audit6", "z05memstore", "alias_residual_test.go")
	if err := os.WriteFile(broken, []byte("//go:build audit\n\npackage z05memstore\n\n"+
		"import \"testing\"\n\nfunc TestZ16VerifyBrokenProbe(t *testing.T) { _ = noSuchFunctionAnywhere() }\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	gitQuiet(t, tmp, "init", "--quiet")
	gitQuiet(t, tmp, "add", "-A")
	gitQuiet(t, tmp, "commit", "--quiet", "-m", "verify fixture")

	// The premise: the file really does not compile once the tag it carries is
	// set. (This is the tagged vet of the whole package; the package's other
	// files are intact, so a failure here is the fixture's undefined callee.)
	code, out := run(t, tmp, nil, "go", "vet", "-tags", "audit", "./internal/zzprobe/audit6/z05memstore/...")
	if code == 0 {
		t.Fatalf("the fixture does not even look broken; the tagged vet accepted it")
	}
	if !strings.Contains(out, "noSuchFunctionAnywhere") {
		t.Logf("tagged vet output (kept for diagnosis):\n%s", out)
		t.Fatalf("the tagged vet failed for a reason other than the fixture's undefined callee")
	}
	t.Logf("tagged vet on the fixture's package: exit %d (%s)", code, strings.TrimSpace(firstLine(out)))

	// The fixture really is in the corpus the guard reads, and the guard really
	// runs — it reports the corpus size. Whether it names the fixture is not the
	// point here (the fixture's tag is a tag no workflow sets, so naming it is
	// what the guard is for); the blindness is that the report is purely textual:
	// it never asks whether a single file in it compiles.
	code, out = run(t, tmp, nil, "go", "test", "-tags", "audit7", "-count=1", "-v",
		"-run", "^TestEveryTaggedTestFileIsReachableFromCI$",
		"./internal/zzprobe/audit7/z16guardtestquality/")
	if !strings.Contains(out, "tracked test files") {
		t.Fatalf("the guard did not report a corpus at all, so it is not reading the tree:\n%s", out)
	}
	if !strings.Contains(out, "alias_residual_test.go") {
		t.Fatalf("the fixture is not in the corpus the guard read, so this probe proves nothing:\n%s", out)
	}
	t.Logf("the guard's report (exit %d) lists the fixture by name while the fixture cannot compile "+
		"(control above); the report contains no compilation step for any file it lists", code)
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
