package archtest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

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
