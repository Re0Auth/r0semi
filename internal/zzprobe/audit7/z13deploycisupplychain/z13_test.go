//go:build audit7

// Package z13deploycisupplychain holds the seventh round's red-first probes for
// the deployment / CI / supply-chain / release-artifact surface. Every test here
// states an invariant the repository claims in a comment or a doc, drives the
// real artifact (or the real gate that guards it), and fails when the claim does
// not hold. The positive controls are inside the same test: a probe that could
// not have failed for the right reason is reported as a harness failure, not as
// a finding.
package z13deploycisupplychain

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// repoRoot walks up from the test's working directory until it finds the module
// root, so the probe reads the checkout it was run from rather than a copy.
func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := wd
	for i := 0; i < 12; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("no go.mod above %s", wd)
	return ""
}

func readFile(t *testing.T, parts ...string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(parts...))
	if err != nil {
		t.Fatalf("read %s: %v", filepath.Join(parts...), err)
	}
	return string(raw)
}

func lineOf(t *testing.T, path, needle string) int {
	t.Helper()
	for i, line := range strings.Split(readFile(t, path), "\n") {
		if strings.Contains(line, needle) {
			return i + 1
		}
	}
	return -1
}

// runGit runs git in dir and returns stdout, stderr and the exit code. A
// non-zero exit is a normal result here (check-ignore uses it to mean "not
// ignored"), so it is not a test failure.
func runGit(t *testing.T, dir string, args ...string) (string, string, int) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	var out, errb strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	if err == nil {
		return out.String(), errb.String(), 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return out.String(), errb.String(), ee.ExitCode()
	}
	t.Fatalf("git %s: %v (%s)", strings.Join(args, " "), err, errb.String())
	return "", "", -1
}

// ---------------------------------------------------------------------------
// Z13-1: the default backup directory is inside the repository and is neither
// gitignored nor dockerignored, while every sibling secret path is.
// ---------------------------------------------------------------------------

func TestZ13BackupDefaultDirIsNotIgnored(t *testing.T) {
	root := repoRoot(t)

	// Positive controls first: the ignore rules this repository already states
	// for secrets must really fire, or the negative result below is vacuous.
	for _, ignored := range []string{".env", "config/re0auth.toml", "config/x.secret.toml"} {
		_, _, code := runGit(t, root, "check-ignore", "-v", ignored)
		if code != 0 {
			t.Fatalf("control: %s is not gitignored (exit %d); the probe cannot read .gitignore", ignored, code)
		}
	}

	// The scripts' own default is the repository root's ./backups.
	for _, script := range []string{"scripts/backup.sh", "scripts/backup-keys.sh"} {
		if src := readFile(t, root, filepath.FromSlash(script)); !strings.Contains(src, `dir="${1:-./backups}"`) {
			t.Errorf("%s no longer defaults its output to ./backups; re-read this probe before trusting it", script)
		}
	}

	// What those scripts write there: the key backup is the KEK, both OIDC keys
	// and the audit key in plaintext .env form; the dump is plain SQL.
	for _, leak := range []string{
		"backups/re0auth-keys-20260101T000000Z.env",
		"backups/re0auth-keys-20260101T000000Z.env.age",
		"backups/re0auth-20260101T000000Z.dump",
		"backups/re0auth-20260101T000000Z.dump.age",
	} {
		out, _, code := runGit(t, root, "check-ignore", "-v", leak)
		if code == 0 {
			continue
		}
		t.Errorf("%s is NOT gitignored (exit %d), but `git add -A` in the documented "+
			"backup workflow would stage it: the file holds the KEK, the OIDC signing and token "+
			"keys and the audit key (or a plaintext dump of credentials and audit history). "+
			"Sibling secret paths are ignored (.env at .gitignore:41, config/*.secret.* at :45); this one is not.%s",
			leak, code, indentBlock(out))
	}

	// Same gap on the image side: .dockerignore's own comment says "deployment-local
	// secrets and the tool's own state stay out" of a layer.
	dockerignore := readFile(t, root, ".dockerignore")
	for _, control := range []string{"\n.env\n", "config/*.secret.*"} {
		if !strings.Contains(dockerignore, control) {
			t.Fatalf("control: .dockerignore no longer excludes %q; the probe cannot read it", control)
		}
	}
	for _, line := range strings.Split(dockerignore, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.Contains(trimmed, "backup") {
			return // someone excluded it; the finding is gone
		}
	}
	t.Errorf(".dockerignore excludes .env and config/*.secret.* but has no rule for backups/, " +
		"the directory both backup scripts write into by default: `docker build .` copies it " +
		"into the build context and into the backend stage's layer, contrary to the file's own " +
		"stated reason for existing")
}

func indentBlock(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	return " (git check-ignore said: " + s + ")"
}

// ---------------------------------------------------------------------------
// Z13-2: the release tag is pushed to GHCR before the Trivy gate runs.
// ---------------------------------------------------------------------------

// step is one `- uses:`/`- name:` entry of a workflow job, reduced to the fields
// this probe reads.
type step struct {
	Name string
	Uses string
	With string
	Run  string
}

// jobSteps returns the steps of the named job in a workflow, as raw text blocks.
// It is deliberately textual rather than a YAML decode: the ordering of steps is
// the property under test, and a decode into a map would lose it.
func jobSteps(t *testing.T, workflow, job string) []step {
	t.Helper()
	lines := strings.Split(workflow, "\n")
	start := -1
	for i, line := range lines {
		if line == "  "+job+":" {
			start = i
			break
		}
	}
	if start < 0 {
		t.Fatalf("no job %q in the workflow", job)
	}
	end := len(lines)
	for i := start + 1; i < len(lines); i++ {
		if strings.HasPrefix(lines[i], "  ") && !strings.HasPrefix(lines[i], "    ") &&
			strings.HasSuffix(lines[i], ":") && !strings.HasPrefix(strings.TrimSpace(lines[i]), "-") {
			end = i
			break
		}
	}
	var steps []step
	var cur *step
	mode := ""
	for _, line := range lines[start:end] {
		trimmed := strings.TrimSpace(line)
		// Comments inside `with:` and `run:` blocks talk about the very words
		// these assertions look for (`latest`, the step order), so they are
		// dropped rather than scanned.
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		switch {
		case indent == 6 && strings.HasPrefix(trimmed, "- "):
			steps = append(steps, step{})
			cur = &steps[len(steps)-1]
			mode = ""
			rest := strings.TrimPrefix(trimmed, "- ")
			switch {
			case strings.HasPrefix(rest, "uses:"):
				cur.Uses = strings.TrimSpace(strings.TrimPrefix(rest, "uses:"))
			case strings.HasPrefix(rest, "name:"):
				cur.Name = unquote(strings.TrimSpace(strings.TrimPrefix(rest, "name:")))
			}
		case cur == nil:
		case indent == 8 && strings.HasPrefix(trimmed, "uses:"):
			cur.Uses = strings.TrimSpace(strings.TrimPrefix(trimmed, "uses:"))
			mode = ""
		case indent == 8 && strings.HasPrefix(trimmed, "name:"):
			cur.Name = unquote(strings.TrimSpace(strings.TrimPrefix(trimmed, "name:")))
		case indent == 8 && trimmed == "with:":
			mode = "with"
		case indent == 8 && strings.HasPrefix(trimmed, "run:"):
			mode = "run"
			cur.Run += trimmed + "\n"
		case mode == "with":
			cur.With += trimmed + "\n"
		case mode == "run":
			cur.Run += trimmed + "\n"
		}
	}
	return steps
}

func unquote(s string) string { return strings.Trim(s, `"'`) }

func TestZ13ReleasePushesTheReleaseTagBeforeTheScan(t *testing.T) {
	root := repoRoot(t)
	release := readFile(t, root, ".github", "workflows", "release.yml")
	steps := jobSteps(t, release, "image")
	if len(steps) < 6 {
		t.Fatalf("parsed only %d steps from the image job; the probe is stale", len(steps))
	}

	pushAt, scanAt, promoteAt, signAt := -1, -1, -1, -1
	var metaWith, pushWith string
	for i, s := range steps {
		switch {
		case strings.Contains(s.Uses, "docker/metadata-action"):
			metaWith = s.With
		case strings.Contains(s.Uses, "docker/build-push-action"):
			pushAt, pushWith = i, s.With
		case strings.Contains(s.Name, "scan the image"):
			scanAt = i
		case strings.Contains(s.Name, "promote to latest"):
			promoteAt = i
		case strings.Contains(s.Name, "sign the image digest"):
			signAt = i
		}
	}
	// Controls: every step the ordering claim depends on must have been found,
	// and the Trivy gate must really be a gate.
	if pushAt < 0 || scanAt < 0 || promoteAt < 0 || signAt < 0 {
		t.Fatalf("could not locate all four steps (push=%d scan=%d promote=%d sign=%d)", pushAt, scanAt, promoteAt, signAt)
	}
	if !strings.Contains(steps[scanAt].Run, "--exit-code 1") || !strings.Contains(steps[scanAt].Run, "HIGH,CRITICAL") {
		t.Fatalf("the scan step is no longer a blocking HIGH/CRITICAL gate: %q", steps[scanAt].Run)
	}
	if !strings.Contains(pushWith, "push: true") {
		t.Fatalf("the build-push step no longer pushes: %q", pushWith)
	}
	// The round-5 fix must still be in place, or this probe is measuring the old bug.
	if strings.Contains(metaWith, "type=raw,value=latest") || strings.Contains(metaWith, "latest") {
		t.Errorf("metadata-action now produces a `latest` tag before the scan: the P2-12 fix has regressed")
	}
	if promoteAt < scanAt {
		t.Errorf("`latest` is promoted before the scan; the P2-12 fix has regressed")
	}
	if !strings.Contains(metaWith, "type=ref,event=tag") {
		t.Fatalf("metadata-action no longer tags from the git ref: %q", metaWith)
	}
	if !strings.Contains(pushWith, "steps.meta.outputs.tags") {
		t.Fatalf("build-push-action no longer uses the metadata tags: %q", pushWith)
	}

	// The residual: the RELEASE tag itself is pushed by the step above the scan.
	if pushAt < scanAt {
		t.Errorf("the image is pushed to GHCR (push: true, tags from type=ref,event=tag) at step %d "+
			"while the Trivy gate is step %d: when the scan fails, `ghcr.io/<repo>:<tag>` already "+
			"exists and is indistinguishable from a scanned one. Only `latest` and the GitHub release "+
			"are gated. Gate the push (build with load: true, scan, then push) or scan before the push",
			pushAt, scanAt)
	}
	if signAt < promoteAt {
		t.Errorf("the image digest is signed (step %d) after `latest` is promoted (step %d): a signing "+
			"failure leaves the floating tag pointing at an unsigned image", signAt, promoteAt)
	}
}

// ---------------------------------------------------------------------------
// Z13-3: the runtime image ships the Go attribution but not the npm one.
// ---------------------------------------------------------------------------

func TestZ13RuntimeImageShipsTheNpmAttribution(t *testing.T) {
	root := repoRoot(t)
	dockerfile := readFile(t, root, "Dockerfile")
	idx := strings.LastIndex(dockerfile, "FROM scratch")
	if idx < 0 {
		t.Fatal("the runtime stage is not FROM scratch")
	}
	runtime := dockerfile[idx:]

	var copied []string
	for _, line := range strings.Split(runtime, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "COPY ") || strings.HasPrefix(trimmed, "ADD ") {
			copied = append(copied, trimmed)
		}
	}
	if len(copied) < 3 {
		t.Fatalf("the runtime stage copies only %v; the probe is stale", copied)
	}
	// Controls: the two files the P2-21/DEP-21 fix added must be there, and the
	// SPA's licence listing must be a real Makefile target.
	joined := strings.Join(copied, "\n")
	for _, control := range []string{"LICENSE", "NOTICE"} {
		if !strings.Contains(joined, control) {
			t.Fatalf("control: the runtime stage no longer copies %s, so this probe is measuring the wrong thing", control)
		}
	}
	mk := readFile(t, root, "Makefile")
	if !strings.Contains(mk, "npm-attribution:") || !strings.Contains(mk, "pnpm licenses list --json") {
		t.Fatalf("control: the Makefile no longer builds an npm attribution file")
	}

	if !strings.Contains(joined, "npm-attribution") {
		t.Errorf("the runtime image ships LICENSE and NOTICE but not the npm attribution file the "+
			"Makefile builds (dist/re0auth_${VERSION}_npm-attribution.json). The SPA is embedded in the "+
			"same binary, and the Makefile's own comment says it \"ships inside every binary, archive and "+
			"image, so it needs the same attribution\"; every release archive carries the listing and the "+
			"image does not. Runtime stage COPY lines: %v", copied)
	}
}

// ---------------------------------------------------------------------------
// Z13-4: backup-keys.sh orders umask and the age probe after the file it should
// protect, unlike its sibling.
// ---------------------------------------------------------------------------

func TestZ13KeyBackupScriptOrdersItsGuards(t *testing.T) {
	root := repoRoot(t)
	keys := filepath.Join(root, "scripts", "backup-keys.sh")
	dump := filepath.Join(root, "scripts", "backup.sh")

	umaskAt := lineOf(t, keys, "umask 077")
	mkdirAt := lineOf(t, keys, `mkdir -p "$dir"`)
	if umaskAt < 0 || mkdirAt < 0 {
		t.Fatalf("could not find umask/mkdir in backup-keys.sh (umask=%d mkdir=%d)", umaskAt, mkdirAt)
	}
	// Control: the sibling script states the rule in a comment and follows it.
	dsrc := readFile(t, dump)
	if lineOf(t, dump, "umask 077") > lineOf(t, dump, `mkdir -p "$dir"`) {
		t.Fatalf("control: backup.sh no longer sets umask before mkdir, so the standard this probe compares against is gone")
	}
	if umaskAt > mkdirAt {
		t.Errorf("scripts/backup-keys.sh:24 creates the backup directory before :%d sets umask 077, so a freshly "+
			"created key-backup directory gets the ambient umask (0755 on the common 022) and is traversable by "+
			"every local user. scripts/backup.sh sets umask first and its comment says why: \"Setting it before "+
			"mkdir also makes a freshly created backup directory 0700\"", umaskAt)
	}

	// The age probe: backup.sh checks for the tool BEFORE it writes anything, so a
	// missing age cannot leave plaintext behind. backup-keys.sh checks last.
	ageCheck := lineOf(t, keys, "command -v age")
	firstWrite := lineOf(t, keys, `: > "$out"`)
	writeKeyAt := lineOf(t, keys, "printf '%s=%s\\n' \"$name\" \"$value\" >> \"$out\"")
	if ageCheck < 0 || firstWrite < 0 || writeKeyAt < 0 {
		t.Fatalf("could not find the file-write and age lines (age=%d create=%d write=%d)", ageCheck, firstWrite, writeKeyAt)
	}
	dAge := lineOf(t, dump, "command -v age")
	dDump := lineOf(t, dump, "pg_dump ")
	if dAge < 0 || dDump < 0 || dAge > dDump {
		t.Fatalf("control: backup.sh no longer checks for age before dumping")
	}
	if ageCheck > firstWrite && ageCheck > writeKeyAt {
		t.Errorf("scripts/backup-keys.sh writes the key file at :%d and :%d and only checks that `age` exists at :%d. "+
			"When BACKUP_AGE_RECIPIENT is set and age is not installed the script exits 1 *after* the plaintext KEK, "+
			"OIDC signing key, OIDC token key and audit key have been written to disk under backups/, where an "+
			"operator who saw the non-zero exit has no reason to look. scripts/backup.sh:28 does this check before "+
			"any dump exists; the keys script should do the same", firstWrite, writeKeyAt, ageCheck)
	}
	if !strings.Contains(dsrc, "plaintext dump on disk that the operator believes") {
		t.Log("backup.sh no longer carries the comment this finding quotes; re-read it")
	}
}

// ---------------------------------------------------------------------------
// Z13-7: the release docs do not describe two of the artifacts that ship.
// ---------------------------------------------------------------------------

func TestZ13ReleaseDocsDescribeTheShippedArtifacts(t *testing.T) {
	root := repoRoot(t)
	readme := readFile(t, root, "README.md")

	// Controls: the section the claims live in is still there, and the artifacts
	// it does describe are still described.
	for _, control := range []string{"## 发布产物", "## 容器镜像", "SHA256SUMS", "sbom.cdx.json"} {
		if !strings.Contains(readme, control) {
			t.Fatalf("control: README.md no longer contains %q; the probe is stale", control)
		}
	}

	if !strings.Contains(readme, "npm-attribution") {
		t.Errorf("README.md's release section lists the archives' contents, the SBOM and the cosign " +
			"signature but never the npm licence listing the Makefile now ships as " +
			"`re0auth_<version>_npm-attribution.json`: the artifact an operator needs to satisfy the SPA's " +
			"MIT/ISC notice requirement is undocumented (only CHANGELOG.md:58-61 mentions it)")
	}
	if strings.Contains(readme, "只带二进制与 CA") || strings.Contains(readme, "只带二进制与 CA 证书") {
		t.Errorf("README.md:160 still says the runtime image carries \"只带二进制与 CA 证书\", while " +
			"Dockerfile:74 now also copies LICENSE and NOTICE: the sentence an operator reads to decide what " +
			"is in the image is wrong in both directions (it omits the attribution it does carry and does not " +
			"say the SPA's is missing)")
	}
}

// ---------------------------------------------------------------------------
// Z13-5 / Z13-6: run the real internal/archtest gates against a mutated copy of
// the artifacts, to find out whether they really turn red.
// ---------------------------------------------------------------------------

// archtestBinary compiles the real gate package once per test run.
func archtestBinary(t *testing.T, root string) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "archtest.test")
	if runtime.GOOS == "windows" {
		out += ".exe"
	}
	cmd := exec.Command("go", "test", "-c", "-o", out, "./internal/archtest/")
	cmd.Dir = root
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cannot compile internal/archtest: %v\n%s", err, b)
	}
	return out
}

// fakeTree copies just the artifacts the archtest file-reading gates need into a
// throwaway module root, so a mutation can be introduced without touching the
// checkout.
func fakeTree(t *testing.T, root string) string {
	t.Helper()
	dir := t.TempDir()
	for _, rel := range []string{".github", "Dockerfile", "Makefile", "NOTICE", "deploy", filepath.Join("docs", "operations.md")} {
		src := filepath.Join(root, rel)
		info, err := os.Stat(src)
		if err != nil {
			t.Fatalf("stat %s: %v", src, err)
		}
		dst := filepath.Join(dir, rel)
		if info.IsDir() {
			copyTree(t, src, dst)
			continue
		}
		os.MkdirAll(filepath.Dir(dst), 0o755)
		raw, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// The gates derive the repository root from their working directory.
	if err := os.MkdirAll(filepath.Join(dir, "internal", "archtest"), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	if err := filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, raw, 0o644)
	}); err != nil {
		t.Fatalf("copy %s: %v", src, err)
	}
}

// runArchtest runs one gate inside a fake tree and reports whether it failed.
func runArchtest(t *testing.T, bin, tree, gate string) (bool, string) {
	t.Helper()
	cmd := exec.Command(bin, "-test.run", "^"+gate+"$", "-test.v")
	cmd.Dir = filepath.Join(tree, "internal", "archtest")
	out, err := cmd.CombinedOutput()
	return err != nil, string(out)
}

func TestZ13PermissionsGateIgnoresJobLevelGrants(t *testing.T) {
	root := repoRoot(t)
	bin := archtestBinary(t, root)
	const gate = "TestWorkflowsGrantWriteScopesOnlyToTheJobThatUsesThem"

	// Control 1: on the unmutated artifacts the gate passes.
	tree := fakeTree(t, root)
	if failed, out := runArchtest(t, bin, tree, gate); failed {
		t.Fatalf("control: the gate fails on the untouched artifacts:\n%s", out)
	}
	// Control 2: the gate really does turn red on a workflow-level write.
	ci := filepath.Join(tree, ".github", "workflows", "ci.yml")
	src := readFile(t, ci)
	mutated := strings.Replace(src, "permissions:\n  contents: read", "permissions:\n  contents: read\n  packages: write", 1)
	if mutated == src {
		t.Fatalf("control: could not find the workflow-level permissions block to mutate")
	}
	if err := os.WriteFile(ci, []byte(mutated), 0o644); err != nil {
		t.Fatal(err)
	}
	if failed, out := runArchtest(t, bin, tree, gate); !failed {
		t.Fatalf("control: a workflow-level `packages: write` did not fail the gate:\n%s", out)
	}
	if err := os.WriteFile(ci, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	// The finding: the same write on a single job is invisible, which is the
	// blast-radius the gate's own comment is about.
	jobLevel := strings.Replace(src, "  test:\n",
		"  test:\n    permissions:\n      packages: write\n", 1)
	if jobLevel == src {
		t.Fatalf("could not find the `test` job to mutate")
	}
	if err := os.WriteFile(ci, []byte(jobLevel), 0o644); err != nil {
		t.Fatal(err)
	}
	failed, out := runArchtest(t, bin, tree, gate)
	if !failed {
		t.Errorf("`packages: write` on the ci.yml `test` job does not fail "+
			"TestWorkflowsGrantWriteScopesOnlyToTheJobThatUsesThem: the gate decodes only the "+
			"workflow-level `permissions` block, so it holds release.yml's \"each job names the scopes "+
			"it actually uses\" only until someone adds a job-level grant. %s", firstLines(out, 3))
	}
}

func TestZ13NpmAttributionGateIgnoresTheChecksumsGlob(t *testing.T) {
	root := repoRoot(t)
	bin := archtestBinary(t, root)
	const gate = "TestReleaseShipsNpmAttribution"

	tree := fakeTree(t, root)
	if failed, out := runArchtest(t, bin, tree, gate); failed {
		t.Fatalf("control: the gate fails on the untouched Makefile:\n%s", out)
	}
	mk := filepath.Join(tree, "Makefile")
	src := readFile(t, mk)
	// Rename the output so `sha256sum re0auth_${VERSION}_*` no longer covers it,
	// while leaving every string the gate greps for in place.
	const before = `../dist/re0auth_$${VERSION}_npm-attribution.json`
	const after = `../dist/npm-attribution.json`
	if !strings.Contains(src, before) {
		t.Fatalf("the npm attribution output name changed; re-read this probe (`%s`)", before)
	}
	if err := os.WriteFile(mk, []byte(strings.Replace(src, before, after, 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	failed, out := runArchtest(t, bin, tree, gate)
	if !failed {
		t.Errorf("the Makefile can write the npm licence listing to a name the `checksums` glob "+
			"(`sha256sum re0auth_${VERSION}_*`) does not match, and TestReleaseShipsNpmAttribution stays "+
			"green: it asserts that the target is wired into `release` and `checksums`, not that the file "+
			"it writes is covered. `gh release create dist/*` publishes whatever is there, so an "+
			"unchecksummed licence file would ship. %s", firstLines(out, 3))
	}
	// Control: the glob really does not match the mutated name, and does match
	// the real one.
	glob := regexp.MustCompile(`^re0auth_[^_]+_`)
	if glob.MatchString("npm-attribution.json") {
		t.Fatalf("control: the mutated name matches the checksum glob; the probe proves nothing")
	}
	if !glob.MatchString("re0auth_v0.0.0-rc.3_npm-attribution.json") {
		t.Fatalf("control: the real name does not match the checksum glob")
	}
}

func firstLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return "tail: " + strings.Join(lines, " | ")
}
