package archtest

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// fullSHA matches the pin form a remote `uses:` must carry: a 40-hex commit.
var fullSHA = regexp.MustCompile(`^[0-9a-f]{40}$`)

// TestReleaseShipsNpmAttribution keeps the Makefile wiring that carries the SPA's
// npm licence listing into every release. NOTICE covers the Go module graph only,
// and the Svelte/SvelteKit runtime ships inside the binary, so the listing is what
// satisfies those packages' MIT/ISC notice requirement. The file must be built by
// `release` and covered by `checksums`, or it is generated and then dropped.
//
// The guard reads the Makefile's structure rather than searching the whole file
// for the four lines it used to: a whole-file `strings.Contains` passed with the
// `release:` line commented out, because the text was still there while `make
// release` had no rule at all (Z16-4). What is asserted now is what make
// actually reads: the prerequisites of `release` and `checksums`, and the recipe
// of `npm-attribution`.
func TestReleaseShipsNpmAttribution(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	mk, err := os.ReadFile(filepath.Join(root, "Makefile"))
	if err != nil {
		t.Fatal(err)
	}

	releasePrereqs, ok := makePrerequisites(mk, "release")
	if !ok {
		t.Fatal("the Makefile has no `release:` target")
	}
	for _, need := range []string{"dist", "sbom", "npm-attribution", "checksums"} {
		if !slices.Contains(releasePrereqs, need) {
			t.Errorf("`release` does not depend on %q (prerequisites: %v): the SPA's npm licence "+
				"listing would not reach a release", need, releasePrereqs)
		}
	}

	checksumsPrereqs, ok := makePrerequisites(mk, "checksums")
	if !ok {
		t.Fatal("the Makefile has no `checksums:` target")
	}
	for _, need := range []string{"sbom", "npm-attribution"} {
		if !slices.Contains(checksumsPrereqs, need) {
			t.Errorf("`checksums` does not depend on %q (prerequisites: %v): the listing would be "+
				"built and then left out of SHA256SUMS", need, checksumsPrereqs)
		}
	}

	// The listing has to be generated somewhere in the chain `release` builds,
	// and the target the chain names for it has to name the same artifact. The
	// generator lives in `dist` (the archives that target seals have to carry the
	// listing) and `npm-attribution` re-asserts it; which of the two runs the
	// command is an implementation choice, so the guard accepts either — but not
	// neither, which is the edit that drops the listing.
	generated := false
	for _, target := range []string{"dist", "npm-attribution"} {
		recipe, ok := makeRecipe(mk, target)
		if !ok {
			continue
		}
		if slices.ContainsFunc(recipe, func(line string) bool { return strings.Contains(line, "pnpm licenses list --json") }) {
			generated = true
		}
	}
	if !generated {
		t.Errorf("neither `dist` nor `npm-attribution` runs `pnpm licenses list --json`: the npm " +
			"licence listing would be built into every binary without its attribution")
	}

	attributionRecipe, ok := makeRecipe(mk, "npm-attribution")
	if !ok {
		t.Fatal("the Makefile has no `npm-attribution:` target")
	}
	if !slices.ContainsFunc(attributionRecipe, func(line string) bool {
		return strings.Contains(line, "_npm-attribution.json")
	}) {
		t.Errorf("`npm-attribution` does not name the listing artifact (recipe: %v)", attributionRecipe)
	}

	// The image is the third shipping form of the same embedded SPA. This gate used
	// to read only the Makefile, so it stayed green while the runtime stage copied
	// LICENSE and NOTICE and nothing else — the archive had the listing and the
	// image did not (Z13-3). Reading the Dockerfile here is what makes the gap fail
	// at pull-request time; the audit5 canary for the same edit is
	// internal/zzprobe/deploy/artifacts_test.go's runtime-stage whitelist.
	df, err := os.ReadFile(filepath.Join(root, "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	runtime := string(df)
	if i := strings.LastIndex(runtime, "FROM scratch"); i >= 0 {
		runtime = runtime[i:]
	}
	if !strings.Contains(runtime, "npm-attribution") {
		t.Errorf("the runtime stage of the Dockerfile does not copy the npm attribution " +
			"listing the Makefile builds: the SPA is embedded in the same binary, so the " +
			"image has the same MIT/ISC notice obligation as the archives")
	}
}

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
// whether it installs.
func makeTargetInstallsPnpm(makefile []byte, target string) bool {
	recipe, _ := makeRecipe(makefile, target)
	return slices.ContainsFunc(recipe, func(line string) bool { return strings.Contains(line, "pnpm install") })
}

// makePrerequisites returns the prerequisites on a target's rule line, with any
// trailing comment removed.
//
// This is a structural read, not a whole-file search, and that is the point: a
// `strings.Contains` over the Makefile passed with the `release:` line commented
// out, because the text was still present while make had no such rule (Z16-4).
// The target name must therefore begin a line — a comment or a recipe line does
// not qualify — and only the text before `#` is read.
//
// A prerequisite list continued over several lines with a backslash is not
// parsed; the Makefile states these on one line, and a guard that silently
// accepted half of a list would be worse than one that reports the miss.
func makePrerequisites(makefile []byte, target string) ([]string, bool) {
	for _, line := range strings.Split(string(makefile), "\n") {
		line = strings.TrimRight(line, "\r")
		if !strings.HasPrefix(line, target+":") {
			continue
		}
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		return strings.Fields(strings.TrimPrefix(line, target+":")), true
	}
	return nil, false
}

// makeRecipe returns the trimmed recipe lines of a target: the run of indented
// lines that follows the `target:` line, ended by the first line with no
// indentation. A target that is absent reports ok=false.
func makeRecipe(makefile []byte, target string) ([]string, bool) {
	var recipe []string
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
			break
		}
		recipe = append(recipe, strings.TrimSpace(line))
	}
	return recipe, inTarget
}

// jobWriteScopeAllowlist names, per workflow file and job, the write scopes the
// job is known to need. It is the whole point of the job-level half of the guard
// below: the repository really does elevate one job
// (codeql.yml's `analyze` needs `security-events: write` to upload results), and
// a check without a list of known writers would either flag that job forever or
// — the shape this replaced — not look at job-level permissions at all.
//
// Adding a job here is a deliberate, reviewable edit; a job that grants itself a
// write scope without one is what the guard exists to catch.
var jobWriteScopeAllowlist = map[string]map[string][]string{
	"release.yml": {
		// packages: write is the GHCR push; id-token is what buildx exchanges
		// for provenance and keyless signing exchanges for a Fulcio certificate.
		"image": {"packages", "id-token"},
		// gh release create writes the release; cosign signs the checksums
		// keyless, which is the id-token.
		"release": {"contents", "id-token"},
	},
	"codeql.yml": {
		// github/codeql-action/analyze uploads its SARIF to code scanning.
		"analyze": {"security-events"},
	},
}

// writeScopes returns the scopes a permissions block grants write on. The
// `write-all` shorthand becomes "*", which no allowlist entry matches by
// accident.
func writeScopes(perms any) []string {
	switch p := perms.(type) {
	case string:
		if p == "write-all" {
			return []string{"*"}
		}
	case map[string]any:
		var out []string
		for scope, level := range p {
			if level == "write" {
				out = append(out, scope)
			}
		}
		slices.Sort(out)
		return out
	}
	return nil
}

// unexplainedWriteScopes returns the write scopes a single job holds that the
// allowlist does not name for it.
func unexplainedWriteScopes(file, job string, perms any) []string {
	allowed := jobWriteScopeAllowlist[file][job]
	var out []string
	for _, scope := range writeScopes(perms) {
		if !slices.Contains(allowed, scope) {
			out = append(out, scope)
		}
	}
	return out
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
// Job-level blocks are read too. The workflow-level check alone is blind to the
// other half of the finding: the repository already had a job that elevated
// itself — codeql.yml's `analyze` grants `security-events: write` — and nothing
// in this package could see it (Z13-5). Every job-level write scope must now be
// explained by jobWriteScopeAllowlist, so a new grant is a visible constant
// change rather than a silent one.
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
		Jobs        map[string]struct {
			Permissions any `yaml:"permissions"`
		} `yaml:"jobs"`
	}

	checked, jobsChecked := 0, 0
	for _, entry := range entries {
		if entry.IsDir() || (!strings.HasSuffix(entry.Name(), ".yml") && !strings.HasSuffix(entry.Name(), ".yaml")) {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		workflow.Permissions = nil
		workflow.Jobs = nil
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

		for job, spec := range workflow.Jobs {
			if spec.Permissions == nil {
				continue
			}
			jobsChecked++
			for _, scope := range unexplainedWriteScopes(entry.Name(), job, spec.Permissions) {
				t.Errorf("%s: job %q holds `%s: write`, which jobWriteScopeAllowlist does not name for it. "+
					"Either narrow the job or add the scope to the allowlist with the reason it must write.",
					entry.Name(), job, scope)
			}
		}
	}

	// Anti-vacuous: every check above passes by finding nothing, which is also
	// what a parse that stopped reading the directory looks like.
	if checked == 0 {
		t.Fatal("no workflow was read, so this guard would pass vacuously")
	}
	// And the job-level half only works if the YAML shape decoded as expected —
	// a `map[any]any`, or jobs looked up under the wrong key, would make the
	// loop above run zero times while the guard still reported PASS.
	if jobsChecked < 3 {
		t.Fatalf("only %d jobs with a permissions block were read; the job-level parse is not "+
			"reading the workflows", jobsChecked)
	}
}
