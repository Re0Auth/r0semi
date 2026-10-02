package archtest

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// commentOutRule turns the first line beginning with rule into a comment: the
// mutation Z16-4 says the old guard could not see.
func commentOutRule(t *testing.T, makefile []byte, rule string) []byte {
	t.Helper()
	lines := strings.Split(string(makefile), "\n")
	for i, line := range lines {
		if strings.HasPrefix(line, rule) {
			lines[i] = "# " + line
			return []byte(strings.Join(lines, "\n"))
		}
	}
	t.Fatalf("no Makefile line begins with %q", rule)
	return nil
}

// Z16-4 probe. The guard used to be four whole-file `strings.Contains` calls, so
// commenting the `release:` rule out left every needle in the text and the guard
// stayed green while `make release` had no rule at all.
//
// The probe drives the same helper the guard now uses, on the real Makefile and
// on one mutated byte-for-byte from it, so "the parse reads the rule" is shown
// rather than asserted.
func TestZ16_4TheMakefileGuardReadsTheReleaseRule(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	mk, err := os.ReadFile(filepath.Join(root, "Makefile"))
	if err != nil {
		t.Fatal(err)
	}

	prereqs, ok := makePrerequisites(mk, "release")
	if !ok {
		t.Fatal("the real Makefile has no `release:` rule")
	}
	for _, need := range []string{"dist", "sbom", "npm-attribution", "checksums"} {
		if !slices.Contains(prereqs, need) {
			t.Errorf("`release` prerequisites %v do not include %q", prereqs, need)
		}
	}
	if checks, ok := makePrerequisites(mk, "checksums"); !ok || !slices.Contains(checks, "npm-attribution") {
		t.Errorf("`checksums` prerequisites %v do not include npm-attribution", checks)
	}

	// The mutation: comment the rule line out. The text the old guard searched
	// for is still there, which is exactly why it passed.
	mutated := commentOutRule(t, mk, "release:")
	const needle = "release: dist sbom npm-attribution checksums"
	if !strings.Contains(string(mutated), needle) {
		t.Fatalf("the mutation removed %q, so it would not prove the old guard was blind", needle)
	}
	if _, ok := makePrerequisites(mutated, "release"); ok {
		t.Errorf("a commented-out `release:` line was still read as a rule: `make release` has no "+
			"rule and the guard would pass while the release chain does not exist (text %q is still "+
			"present, which is all the old strings.Contains saw)", needle)
	}

	// A target that is present but empty is the other half: the rule line has to
	// name its prerequisites, not merely exist.
	empty := []byte("release:\n\t@echo nothing\n")
	if got, ok := makePrerequisites(empty, "release"); !ok || len(got) != 0 {
		t.Errorf("an empty `release:` rule parsed as %v (ok=%v), want no prerequisites", got, ok)
	}
}

// Z13-5 probe. The guard read only workflow-level `permissions`, so a job that
// grants itself a write scope was invisible — and the repository already had one
// (codeql.yml's analyze needs security-events: write). The job-level check is
// driven by an allowlist constant, and this probe pins both directions: a known
// elevation stays explained, an unknown one is reported.
func TestZ13_5JobLevelWriteScopesAreFlaggedUnlessAllowlisted(t *testing.T) {
	// The real elevation must stay explained, or the guard would force the one
	// job that legitimately writes to be dismantled.
	real := map[string]any{"contents": "read", "security-events": "write", "actions": "read"}
	if got := unexplainedWriteScopes("codeql.yml", "analyze", real); len(got) != 0 {
		t.Errorf("codeql.yml/analyze's security-events: write is not explained by the allowlist: %v", got)
	}

	// The same grant on a job the allowlist does not name: the guard used to be
	// blind to this because it never looked at jobs at all.
	mutated := map[string]any{"contents": "read", "security-events": "write"}
	if got := unexplainedWriteScopes("ci.yml", "test", mutated); len(got) != 1 || got[0] != "security-events" {
		t.Errorf("a job-level `security-events: write` on ci.yml's test job was not flagged: %v", got)
	}

	// A whole-workflow shorthand at job level cannot be explained by any entry.
	if got := unexplainedWriteScopes("release.yml", "image", "write-all"); len(got) != 1 || got[0] != "*" {
		t.Errorf("a job-level `permissions: write-all` was not flagged: %v", got)
	}

	// The same elevation written as YAML, decoded through the exact struct the
	// guard uses: this is the mutation (a job adding security-events: write to
	// ci.yml) in the shape the guard consumes it.
	const mutatedWorkflow = `
name: ci
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps: []
`
	var decoded struct {
		Jobs map[string]struct {
			Permissions any `yaml:"permissions"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal([]byte(mutatedWorkflow), &decoded); err != nil {
		t.Fatal(err)
	}
	if got := unexplainedWriteScopes("ci.yml", "test", decoded.Jobs["test"].Permissions); len(got) != 1 || got[0] != "security-events" {
		t.Errorf("a job-level security-events: write in ci.yml was not reported after YAML decoding: %v", got)
	}

	// Read scopes are not writes, whatever the workflow.
	if got := writeScopes(map[string]any{"contents": "read", "actions": "read"}); len(got) != 0 {
		t.Errorf("read scopes were collected as writes: %v", got)
	}

	// Anti-vacuous, against the real files: the YAML has to decode into the shape
	// the guard walks, or every check above passes on an empty set.
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, ".github", "workflows")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	jobs, grants := 0, 0
	for _, entry := range entries {
		if entry.IsDir() || (!strings.HasSuffix(entry.Name(), ".yml") && !strings.HasSuffix(entry.Name(), ".yaml")) {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var workflow struct {
			Jobs map[string]struct {
				Permissions any `yaml:"permissions"`
			} `yaml:"jobs"`
		}
		if err := yaml.Unmarshal(raw, &workflow); err != nil {
			t.Fatalf("%s: %v", entry.Name(), err)
		}
		for _, spec := range workflow.Jobs {
			if spec.Permissions == nil {
				continue
			}
			jobs++
			if len(writeScopes(spec.Permissions)) > 0 {
				grants++
			}
		}
	}
	if jobs < 3 {
		t.Fatalf("only %d jobs with a permissions block were decoded; the job-level parse is not "+
			"reading the workflows", jobs)
	}
	if grants == 0 {
		t.Fatalf("no workflow job grants a write scope, but codeql.yml/analyze does: the parse is "+
			"not seeing job permissions")
	}
	t.Logf("job-level permissions: %d jobs declare them, %d grant a write", jobs, grants)
}
