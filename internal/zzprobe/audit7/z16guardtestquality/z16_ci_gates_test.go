//go:build audit7

package z16guardtestquality

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// repoRoot is declared in assertless_test.go, which owns the package's shared
// helper. This file only adds its own.

func readFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// jobBlock returns the YAML text of one job in a workflow: from `  <name>:` to
// the next two-space top-level key.
func jobBlock(t *testing.T, workflow, name string) string {
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

// TestZ16LoadJobIsGreenWithZeroMeasurement: the CI `load` job's only floor lives
// inside the test that its `-run` pattern has to find, and a pattern that matches
// nothing is a successful `go test`.
func TestZ16LoadJobIsGreenWithZeroMeasurement(t *testing.T) {
	root := repoRoot(t)

	// Positive control for the mechanism: `go test -run <no match>` exits 0. This
	// is the live fact the whole finding rests on.
	cmd := exec.Command("go", "test", "-count=1", "-run", "^TestZ16NoSuchTestExists$", "./internal/httpapi/")
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("control: a no-match -run must exit 0 (that is the mechanism), got %v:\n%s", err, out)
	}
	if !strings.Contains(string(out), "no tests to run") {
		t.Fatalf("control: expected `no tests to run`, got:\n%s", out)
	}

	ci := readFile(t, filepath.Join(root, ".github", "workflows", "ci.yml"))
	perf := readFile(t, filepath.Join(root, ".github", "workflows", "perf.yml"))
	load := jobBlock(t, ci, "load")

	if !strings.Contains(load, "make load") {
		t.Fatalf("the load job no longer runs `make load`; this probe is measuring the wrong thing:\n%s", load)
	}
	// Comments are not gates: strip them before asking whether any step can fail.
	var steps []string
	for _, l := range strings.Split(load, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(l), "#") {
			steps = append(steps, l)
		}
	}
	if regexp.MustCompile(`grep -q|::error::|exit 1`).MatchString(strings.Join(steps, "\n")) {
		t.Logf("the load job now inspects its own output; the finding is fixed:\n%s", load)
		return
	}
	if !strings.Contains(perf, "grep -q 'capacity profile:'") {
		t.Fatalf("perf.yml no longer greps for the profile output, so the contrast this finding rests on is gone")
	}

	t.Errorf("ci.yml's `load` job is green with zero measurement: it runs `make load`, which runs " +
		"`go test -count=1 -v -run TestLoadProfile ./internal/httpapi/` (Makefile:62-63). A -run " +
		"pattern that matches nothing is exit 0 with `no tests to run` (control above), and the job " +
		"reads no output: the `total < 100` floor lives inside TestLoadProfile (load_test.go:161), " +
		"which the pattern must find. Rename or move that test and the capacity gate stays green " +
		"having measured nothing — while perf.yml:97 pays the one line that catches exactly this " +
		"(`grep -q 'capacity profile:' load.txt`), and ci.yml's own neighbouring steps grep for " +
		"`--- PASS: TestOIDCWiringEndToEnd` for the same reason.")
}

// TestZ16AdversarialProbeCorpusIsInvisibleToCI: the recorded adversarial corpus
// (rounds 5 and 6, and its guards) is behind opt-in build tags that no CI job and
// no Makefile target ever passes.
func TestZ16AdversarialProbeCorpusIsInvisibleToCI(t *testing.T) {
	root := repoRoot(t)

	var files, funcs int
	var byTag = map[string]int{}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); name == ".git" || name == "node_modules" || name == ".svelte-kit" || name == "scratchpad" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		head := string(raw)
		if i := strings.Index(head, "\n\n"); i > 0 {
			head = head[:i]
		}
		m := regexp.MustCompile(`go:build[^\n]*audit\d`).FindString(head)
		if m == "" {
			return nil
		}
		tag := strings.TrimSpace(strings.TrimPrefix(m, "go:build"))
		byTag[tag]++
		// audit7 is this round's own scratch corpus; the finding is about the two
		// recorded rounds whose guards the audit documents cite as evidence.
		if tag == "audit7" {
			return nil
		}
		files++
		funcs += len(regexp.MustCompile(`(?m)^func Test`).FindAllString(string(raw), -1))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Anti-vacuous: the walk must really have found the corpus.
	if files < 50 {
		t.Fatalf("only %d tagged probe files found; the walk is not reading the tree", files)
	}

	// Live control: the tag is what exposes them, and nothing passes it by default.
	testFiles := func(tags ...string) int {
		args := []string{"list", "-f", "{{len .TestGoFiles}}"}
		for _, tag := range tags {
			args = append(args, "-tags", tag)
		}
		args = append(args, "./internal/zzprobe/federation/")
		c := exec.Command("go", args...)
		c.Dir = root
		out, err := c.Output()
		if err != nil {
			t.Fatalf("go list: %v", err)
		}
		n, err := strconv.Atoi(strings.TrimSpace(string(out)))
		if err != nil {
			t.Fatalf("go list output %q: %v", out, err)
		}
		return n
	}
	if got := testFiles(); got != 0 {
		t.Fatalf("control: without a tag the probe package reports %d test files; expected 0", got)
	}
	if got := testFiles("audit5"); got == 0 {
		t.Fatalf("control: with -tags audit5 the probe package reports 0 test files; the tag is not the mechanism")
	}

	for _, name := range []string{"Makefile"} {
		if strings.Contains(readFile(t, filepath.Join(root, name)), "-tags audit") {
			t.Logf("%s now runs the tagged corpus; the finding is fixed", name)
			return
		}
	}
	entries, err := os.ReadDir(filepath.Join(root, ".github", "workflows"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(readFile(t, filepath.Join(root, ".github", "workflows", e.Name())), "-tags audit") {
			t.Logf("%s now runs the tagged corpus; the finding is fixed", e.Name())
			return
		}
	}

	t.Errorf("%d probe files (%d test functions) behind opt-in `go:build audit*` tags (%v) are in no CI "+
		"job and no Makefile target: nothing ever passes one, so `go test ./...`, `go vet ./...` and "+
		"`golangci-lint run ./...` in the CI `test`/`windows-smoke`/`release` gates never even *compile* "+
		"them (control: the same package reports 0 test files untagged and >0 with -tags audit5). Every "+
		"guard recorded as evidence in docs/security-audit-5.md and scratchpad/audit6 is therefore "+
		"unverifiable by the repository itself — the rule docs/dependencies.md states and the reason "+
		"internal/archtest exists at all. (226 files including this round's own audit7 scratch: see "+
		"TestEveryTaggedTestFileIsReachableFromCI for the same invariant per tag.)", files, funcs, byTag)
}
