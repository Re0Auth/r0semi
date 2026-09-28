package archtest

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// fullSHA matches the pin form a remote `uses:` must carry: a 40-hex commit.
var fullSHA = regexp.MustCompile(`^[0-9a-f]{40}$`)

// TestWorkflowActionsArePinnedToFullSHAs makes the SHA-pinning rule a check rather
// than a comment.
//
// Every remote `uses:` runs with this repository's token, inside a job that may
// hold the release secrets, so an unpinned `@v4` is somebody else's code that can
// change without a commit here. The rule was stated in a comment at the top of
// ci.yml and enforced by nobody, so a new step added with a floating tag was green
// until it was not. The base-image digest rule already has a guard
// (dockerfile_test.go); this is the action half. The tool-version half
// (`go install …@vX.Y.Z`) stays unguarded, and docs/dependencies.md §7 says so.
func TestWorkflowActionsArePinnedToFullSHAs(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, ".github", "workflows")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	pinned := 0
	for _, entry := range entries {
		if entry.IsDir() || (!strings.HasSuffix(entry.Name(), ".yml") && !strings.HasSuffix(entry.Name(), ".yaml")) {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimPrefix(strings.TrimSpace(line), "- ")
			if !strings.HasPrefix(line, "uses:") {
				continue
			}
			// Keep only the ref: drop a trailing `# vX` comment and any quotes.
			fields := strings.Fields(strings.TrimSpace(strings.TrimPrefix(line, "uses:")))
			if len(fields) == 0 {
				continue
			}
			value := strings.Trim(fields[0], `"'`)
			// A local reusable workflow is this repository's own code, reviewed
			// in the commit that changes it — not what this guard is about.
			if strings.HasPrefix(value, "./") || strings.HasPrefix(value, "docker://") {
				continue
			}
			pinned++
			at := strings.LastIndex(value, "@")
			if at < 0 {
				t.Errorf("%s:%d: %s has no @<ref>", entry.Name(), i+1, value)
				continue
			}
			if sha := value[at+1:]; !fullSHA.MatchString(sha) {
				t.Errorf("%s:%d: %s is not pinned to a full commit SHA; a tag can move under the build",
					entry.Name(), i+1, value)
			}
		}
	}

	// Anti-vacuous: the walk passes by finding nothing, which is also what a parse
	// that stopped reading the directory looks like.
	if pinned < 30 {
		t.Fatalf("only %d remote `uses:` were found; the parse is not reading the workflows", pinned)
	}
}

// TestWorkflowsCacheOnlyWhatTheyCreate: a Node cache in a workflow is only correct
// when the same job populates what it saves.
//
// `actions/setup-node` with `cache: pnpm` saves the pnpm store in its post step. A
// job that never installs never creates that store, and the post step fails with
// "Path Validation Error: Path(s) specified in the action for caching do(es) not
// exist" — which marks the JOB failed. That is not a hypothetical: it is how the
// `supply-chain` job went red while every real step in it passed, because a cache
// *hit* skips the save and the bug only surfaces on a cold cache (a fresh
// repository, or any change to the lockfile that moves the key). A security gate
// that reports a failure unrelated to the code it checks is a gate people delete.
//
// The second half is the ordering the workflows state in comments: the cache step
// finds the pnpm store through the pnpm binary, so `pnpm/action-setup` has to run
// before `actions/setup-node`, or the cache silently points nowhere.
func TestWorkflowsCacheOnlyWhatTheyCreate(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, ".github", "workflows")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	// Read too, because release.yml builds the frontend through `make web`: it is
	// the recipe there, not a `pnpm install` in the step, that creates the store.
	makefile, err := os.ReadFile(filepath.Join(root, "Makefile"))
	if err != nil {
		t.Fatal(err)
	}

	type step struct {
		Name string `yaml:"name"`
		Uses string `yaml:"uses"`
		Run  string `yaml:"run"`
		With struct {
			Cache string `yaml:"cache"`
		} `yaml:"with"`
	}
	var workflow struct {
		Jobs map[string]struct {
			Steps []step `yaml:"steps"`
		} `yaml:"jobs"`
	}

	cached := 0
	for _, entry := range entries {
		if entry.IsDir() || (!strings.HasSuffix(entry.Name(), ".yml") && !strings.HasSuffix(entry.Name(), ".yaml")) {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		workflow.Jobs = nil
		if err := yaml.Unmarshal(raw, &workflow); err != nil {
			t.Fatalf("%s: %v", entry.Name(), err)
		}

		for job, spec := range workflow.Jobs {
			nodeAt, pnpmAt, installs := -1, -1, false
			for i, s := range spec.Steps {
				switch {
				case strings.HasPrefix(s.Uses, "pnpm/action-setup@"):
					pnpmAt = i
				case strings.HasPrefix(s.Uses, "actions/setup-node@"):
					nodeAt = i
				}
				if installsPnpm(s.Run, makefile) {
					installs = true
				}
			}
			if nodeAt < 0 || spec.Steps[nodeAt].With.Cache != "pnpm" {
				continue
			}
			cached++

			if !installs {
				t.Errorf("%s: job %q caches the pnpm store but no step installs, "+
					"so the post step fails the job on a cold cache", entry.Name(), job)
			}
			if pnpmAt < 0 || pnpmAt > nodeAt {
				t.Errorf("%s: job %q asks setup-node to locate the pnpm store, "+
					"but pnpm/action-setup does not run first", entry.Name(), job)
			}
		}
	}

	// An anti-vacuous floor: three jobs cache pnpm today (the two frontend build
	// jobs and the baselines job). If the parse stops matching — a key renamed, the
	// workflows moved — every check above passes by finding nothing, which is the
	// failure mode this package exists to refuse. Removing a cache deliberately
	// lowers this number in the same commit; a drop nobody meant is the parse.
	if cached < 3 {
		t.Errorf("found only %d jobs caching pnpm; the parse is no longer reading the workflows", cached)
	}
}

// installsPnpm reports whether a step's script populates the pnpm store, either
// directly or through a Makefile target (`make web` is how release.yml builds the
// frontend, and its recipe is what runs `pnpm install`).
func installsPnpm(script string, makefile []byte) bool {
	if strings.Contains(script, "pnpm install") {
		return true
	}
	for _, line := range strings.Split(script, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || filepath.Base(fields[0]) != "make" {
			continue
		}
		if makeTargetInstallsPnpm(makefile, fields[1]) {
			return true
		}
	}
	return false
}

// makeTargetInstallsPnpm reads a target's recipe out of the Makefile and reports
// whether it installs. The recipe is the run of indented lines that follows the
// `target:` line; the first line with no indentation ends it.
func makeTargetInstallsPnpm(makefile []byte, target string) bool {
	inTarget := false
	for _, line := range strings.Split(string(makefile), "\n") {
		line = strings.TrimRight(line, "\r")
		if !inTarget {
			if strings.HasPrefix(line, target+":") {
				inTarget = true
			}
			continue
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		if line[0] != '\t' && line[0] != ' ' {
			return false
		}
		if strings.Contains(line, "pnpm install") {
			return true
		}
	}
	return false
}

// TestWorkflowsGrantWriteScopesOnlyToTheJobThatUsesThem pins githubactions:S8233.
//
// A `permissions` block at the top of a workflow arms every job that does not
// narrow itself. release.yml carried one — contents, packages and id-token all
// writable — so the reusable CI gate and the packaging job both ran holding a
// token that can publish a release, while all either needed was to read the
// repository. The block is gone and each job now states its own scopes; this
// keeps it that way, because putting it back is one convenient line and its cost
// is invisible until a step that should not have it spends the token.
//
// Read scopes may stay at workflow level. They widen nothing, and one honest line
// describes a whole file of jobs that only read.
func TestWorkflowsGrantWriteScopesOnlyToTheJobThatUsesThem(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, ".github", "workflows")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	// `permissions` is either a mapping of scope to level, or one of the two
	// shorthands (`read-all` / `write-all`), so it is decoded as it is written
	// rather than into a shape that would reject a valid workflow.
	var workflow struct {
		Permissions any `yaml:"permissions"`
	}

	checked := 0
	for _, entry := range entries {
		if entry.IsDir() || (!strings.HasSuffix(entry.Name(), ".yml") && !strings.HasSuffix(entry.Name(), ".yaml")) {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		workflow.Permissions = nil
		if err := yaml.Unmarshal(raw, &workflow); err != nil {
			t.Fatalf("%s: %v", entry.Name(), err)
		}
		checked++

		switch p := workflow.Permissions.(type) {
		case string:
			if p == "write-all" {
				t.Errorf("%s: workflow-level `permissions: write-all` arms every job "+
					"that does not narrow itself; scope it to the jobs that write", entry.Name())
			}
		case map[string]any:
			for scope, level := range p {
				if level == "write" {
					t.Errorf("%s: workflow-level `%s: write` arms every job that does "+
						"not narrow itself; move it to the job that uses it", entry.Name(), scope)
				}
			}
		}
	}

	// Anti-vacuous: every check above passes by finding nothing, which is also
	// what a parse that stopped reading the directory looks like.
	if checked == 0 {
		t.Fatal("no workflow was read, so this guard would pass vacuously")
	}
}
