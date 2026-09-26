package archtest

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// noticeEntry matches a module bullet in NOTICE: two spaces, a dash, a space, then
// the module path and nothing else. The deeper-indented lines beneath an entry are
// attribution text, and this deliberately does not match them.
var noticeEntry = regexp.MustCompile(`(?m)^  - (\S+)$`)

// TestNoticeCoversTheBuildGraph is what keeps NOTICE from drifting behind go.mod.
//
// NOTICE is a licensing artifact: it tells a redistributor which third-party code
// is inside the released binary. It was maintained by hand, and the failure mode of
// a hand-maintained list is silence — a dependency is added, the attribution is
// not, and nothing says so until someone audits a release. The list is checked
// against `go list -deps ./...`: the production build graph, without -test, because
// that is the graph the release artifacts are built from. Test-only modules such as
// gopkg.in/yaml.v3 are therefore deliberately neither in that graph nor in NOTICE.
//
// The check is one-directional on purpose. A graph module missing from NOTICE is a
// compliance defect; a NOTICE entry whose module left the graph is over-attribution,
// which harms nobody and gives the list a little slack while dependencies move.
func TestNoticeCoversTheBuildGraph(t *testing.T) {
	if testing.Short() {
		t.Skip("architecture checks shell out to `go list`; skipped under -short")
	}
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}

	// The main module is the project itself — it is licensed by LICENSE, not
	// attributed in NOTICE — so it must not be required here.
	mainModule := strings.TrimSpace(goListOutput(t, root, "list", "-m"))

	out := goListOutput(t, root, "list", "-deps", "-f", `{{with .Module}}{{.Path}}{{end}}`, "./...")
	modules := make(map[string]bool)
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line == mainModule {
			continue
		}
		modules[line] = true
	}

	raw, err := os.ReadFile(filepath.Join(root, "NOTICE"))
	if err != nil {
		t.Fatal(err)
	}
	declared := make(map[string]bool)
	for _, m := range noticeEntry.FindAllSubmatch(raw, -1) {
		declared[string(m[1])] = true
	}

	// Floors, so a parse that silently stops matching fails here instead of passing
	// vacuously — the same reason the coverage floor and the alert-count floor exist.
	if len(modules) < 20 {
		t.Fatalf("only %d dependency modules were found; the build graph cannot be that small", len(modules))
	}
	if len(declared) < 20 {
		t.Fatalf("only %d modules were parsed out of NOTICE; the parser cannot be right", len(declared))
	}

	var missing []string
	for m := range modules {
		if !declared[m] {
			missing = append(missing, m)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Fatalf("NOTICE carries no attribution for %d module(s) in the build graph:\n  %s\n"+
			"Add each one under the section for its license.",
			len(missing), strings.Join(missing, "\n  "))
	}
}

// goListOutput runs a go command in the module root and returns its stdout. The
// stderr is folded into the failure, because "go list failed" without the reason
// is not actionable.
func goListOutput(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("go", args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			t.Fatalf("go %s: %v\n%s", strings.Join(args, " "), err, ee.Stderr)
		}
		t.Fatalf("go %s: %v", strings.Join(args, " "), err)
	}
	return string(out)
}
