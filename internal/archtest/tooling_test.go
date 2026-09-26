package archtest

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoTrackedFileNamesPrivateTooling: the repository has to stand on its own.
//
// A path under a private tooling directory is one no reader can open, so a document
// that cites one is a broken reference dressed up as provenance — and the same
// string in a commit message is the difference between "written by the maintainer"
// and "generated". The method is what belongs in the record ("a list of adversarial
// probes, grouped by invariant"), and that is what the audit documents now say.
//
// The two ignore files are the exception, and they are why the rule is shaped this
// way: they have to name the directory in order to keep it out of git and out of the
// Docker build context. The scan reads `git ls-files`, so it covers exactly what
// ships — an ignored local directory or a build output is not the repository.
func TestNoTrackedFileNamesPrivateTooling(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("git", "ls-files", "-z")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		// Failing loudly matters more than the check itself: a scan that could not
		// run and a scan that found nothing look identical in a green job.
		t.Fatalf("git ls-files: %v", err)
	}

	allowed := map[string]bool{".gitignore": true, ".dockerignore": true}
	// The directory, the identity it commits under, and the name of the audit
	// procedure it ships: three ways the same trace came in, and all three were
	// present when this check was written.
	needles := []string{".commandcode", "commandcodebot", "audit-authz"}

	for _, name := range strings.Split(string(out), "\x00") {
		if name == "" || allowed[name] {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		for i, line := range strings.Split(string(raw), "\n") {
			lower := strings.ToLower(line)
			for _, needle := range needles {
				if strings.Contains(lower, needle) {
					t.Errorf("%s:%d names %q; nothing outside this machine can resolve it, "+
						"so describe the method instead", name, i+1, needle)
				}
			}
		}
	}
}
