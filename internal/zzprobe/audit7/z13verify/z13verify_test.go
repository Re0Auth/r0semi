//go:build audit7

package z13verify

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// shared helpers
// ---------------------------------------------------------------------------

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

// bashPath finds a real bash. The zone report reasoned from `Get-Command bash`
// (a PATH lookup), which misses the Git for Windows installation. If this host
// really had none the dependent tests would skip rather than pretend.
func bashPath(t *testing.T) string {
	t.Helper()
	candidates := []string{
		`C:\Program Files\Git\bin\bash.exe`,
		`C:\Program Files\Git\usr\bin\bash.exe`,
		`C:\Program Files (x86)\Git\bin\bash.exe`,
	}
	if p, err := exec.LookPath("bash"); err == nil {
		candidates = append([]string{p}, candidates...)
	}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return c
		}
	}
	t.Skip("no bash interpreter on this host; the shell claims stay source-level")
	return ""
}

// bashPathOf converts a Windows path to the form msys bash wants in PATH. A raw
// `C:/...` entry would be split on its drive colon.
func bashPathOf(p string) string {
	p = filepath.ToSlash(p)
	if len(p) > 1 && p[1] == ':' {
		return "/" + strings.ToLower(p[:1]) + p[2:]
	}
	return p
}

// runBashScript writes body to a file and runs it with bash, returning stdout,
// stderr and the exit code. A non-zero exit is a normal result.
func runBashScript(t *testing.T, bin, body string, env []string) (string, string, int) {
	t.Helper()
	script := filepath.Join(t.TempDir(), "run.sh")
	if err := os.WriteFile(script, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, script)
	cmd.Env = append(os.Environ(), env...)
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
	t.Fatalf("bash: %v (%s)", err, errb.String())
	return "", "", -1
}

func writeStub(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatal(err)
	}
}

// runGit returns stdout, stderr and the exit code; a non-zero exit is a result
// (check-ignore uses it for "not ignored").
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
	t.Fatalf("git %s: %v", strings.Join(args, " "), err)
	return "", "", -1
}

// kv turns "K=V" lines into a map (values may contain spaces and pipes).
func kv(out string) map[string]string {
	got := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		i := strings.Index(line, "=")
		if i <= 0 {
			continue
		}
		key := line[:i]
		if strings.ContainsAny(key, " /|") {
			continue
		}
		got[key] = line[i+1:]
	}
	return got
}

// ---------------------------------------------------------------------------
// .dockerignore matching, in both readings of the documented rule set.
//
// Docker documents a pattern without a slash as matching in the context root
// (`temp?` = "files and directories in the root directory"), while a pattern
// with a slash is anchored as written. The finding paths below are claimed
// excluded by NEITHER reading, so the red does not depend on which one the
// engine implements; the controls prove both matchers work on the patterns this
// file does contain.
// ---------------------------------------------------------------------------

func dockerignorePatterns(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	for _, line := range strings.Split(readFile(t, root, ".dockerignore"), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		out = append(out, trimmed)
	}
	if len(out) < 5 {
		t.Fatalf("parsed only %d .dockerignore patterns; the parse is stale", len(out))
	}
	return out
}

func matchOne(p, cand string, strict bool) bool {
	p = strings.TrimPrefix(strings.TrimPrefix(p, "!"), "/")
	if strings.HasSuffix(p, "/") {
		return cand == strings.TrimSuffix(p, "/") || strings.HasPrefix(cand, p)
	}
	if strings.Contains(p, "/") {
		ok, _ := filepath.Match(p, cand)
		return ok
	}
	if strict && strings.Contains(cand, "/") {
		return false // strict: a slash-free pattern is root-level only
	}
	base := cand
	if i := strings.LastIndex(cand, "/"); i >= 0 {
		base = cand[i+1:]
	}
	ok, _ := filepath.Match(p, base)
	return ok
}

func excluded(patterns []string, path string, strict bool) bool {
	path = strings.TrimPrefix(filepath.ToSlash(path), "./")
	parts := strings.Split(path, "/")
	for _, p := range patterns {
		for i := 1; i <= len(parts); i++ { // a pattern matching a parent dir covers the subtree
			if matchOne(p, strings.Join(parts[:i], "/"), strict) {
				return true
			}
		}
	}
	return false
}

// excludedUnderAnyReading is true only when both readings agree the path is out.
func excludedUnderAnyReading(patterns []string, path string) bool {
	return excluded(patterns, path, true) && excluded(patterns, path, false)
}

func TestZ13VDockerignoreMatchersHavePositiveControls(t *testing.T) {
	root := repoRoot(t)
	patterns := dockerignorePatterns(t, root)
	for _, c := range []struct {
		path string
		want bool
	}{
		{".env", true},
		{"config/re0auth.toml", true},
		{"config/deploy.secret.toml", true},
		{"web/node_modules/pkg/index.js", true},
		{"dist/re0auth.zip", true},
		{"internal/webui/dist/index.html", true},
		{"config/re0auth.example.toml", false},
		{"README.md", false},
		{"internal/httpapi/router.go", false},
	} {
		if got := excludedUnderAnyReading(patterns, c.path); got != c.want {
			t.Fatalf("control: .dockerignore matcher says %q excluded=%v, want %v", c.path, got, c.want)
		}
	}
}

// ---------------------------------------------------------------------------
// NEW Z13V-1: .dockerignore covers most of .gitignore, but not the audit
// workspace (which holds a keys.env carrying a KEK and an OIDC private key) nor
// the other gitignored local state.
// ---------------------------------------------------------------------------

func TestZ13VDockerignoreLeavesGitIgnoredSecretsInTheBuildContext(t *testing.T) {
	root := repoRoot(t)
	patterns := dockerignorePatterns(t, root)

	// Positive control on the git side: the file really is ignored, so nobody
	// notices it, and `git add -A` is NOT the exposure here — the build context is.
	control := "scratchpad/audit7/z08v/keys.env"
	if _, _, code := runGit(t, root, "check-ignore", "-v", control); code != 0 {
		t.Fatalf("control: %s is not gitignored, so the premise of this probe is gone", control)
	}
	if src := readFile(t, root, ".gitignore"); !strings.Contains(src, "/scratchpad/") {
		t.Fatalf("control: .gitignore no longer anchors /scratchpad/")
	}

	// The audit workspace is real and holds secret-shaped material right now.
	if st, err := os.Stat(filepath.Join(root, "scratchpad")); err != nil || !st.IsDir() {
		t.Fatalf("control: no scratchpad directory to measure (%v)", err)
	}
	if raw, err := os.ReadFile(filepath.Join(root, control)); err == nil {
		// The file is UTF-16LE (PowerShell redirection), so NULs are stripped
		// before looking for the variable names.
		text := strings.ReplaceAll(string(raw), "\x00", "")
		if !strings.Contains(text, "RE0AUTH_KEK=") {
			t.Errorf("control: %s exists but does not look like a key file", control)
		}
		if !strings.Contains(text, "RE0AUTH_OIDC_SIGNING_KEY=MII") {
			t.Logf("%s does not carry a PEM private key any more; the directory-level claim is unchanged", control)
		}
	} else {
		t.Logf("%s is gone now; the directory-level claim still stands", control)
	}

	// No pattern names any of these, in either reading of the .dockerignore rule
	// set, so `docker build .` (make docker / README) copies them into the build
	// context and the backend stage's `COPY . .` layer.
	for _, path := range []string{
		"scratchpad/audit7/z08v/keys.env",                         // KEK + OIDC signing private key
		"scratchpad/audit7/findings/Z13-deploy-ci-supplychain.md", // reports quote failing-test output
		"go.work",        // .gitignore:37; changes what `go build` sees
		"foo.local.toml", // .gitignore:46; deployment-local config
		"coverage.out",   // .gitignore:23
		"bench.txt",      // .gitignore:29
	} {
		if excludedUnderAnyReading(patterns, path) {
			t.Logf("note: %s is now excluded by .dockerignore; re-read this probe", path)
			continue
		}
		t.Errorf(".dockerignore does not exclude %q under either reading of the pattern rules "+
			"(no pattern contains `scratchpad`, `go.work`, `*.local.toml`, `*.out` or `bench.txt`). "+
			"`docker build .` — the documented `make docker` path, and any remote/cloud builder that "+
			"uploads the context — copies it into the build context and into the backend stage's "+
			"`COPY . .` layer (Dockerfile:42). .gitignore anchors /scratchpad/, so the file is "+
			"invisible to `git status` while a build still ships it. The zone-13 report Z13-1 found "+
			"the same gap for ./backups only; the gitignored local state has more members, and one of "+
			"them is a key file present in this working tree", path)
	}
}

// ---------------------------------------------------------------------------
// NEW Z13V-2: restore.sh's verifier cannot run at all under its own
// `set -euo pipefail`. Its first line expands `$file` before `local` assigns it.
// ---------------------------------------------------------------------------

func TestZ13VRestoreScriptVerifierAbortsBeforeItVerifies(t *testing.T) {
	root := repoRoot(t)
	bin := bashPath(t)
	work := t.TempDir()
	stubDir := filepath.Join(work, "bin")
	writeStub(t, filepath.Join(stubDir, "psql"), "#!/bin/sh\necho \"${STUB_TABLES:-0}\"\n")
	writeStub(t, filepath.Join(stubDir, "pg_restore"), "#!/bin/sh\necho \"STUB pg_restore: $*\" >&2\nexit 0\n")

	// A corrected copy of the very same script, so the only difference under test
	// is the one line. Nothing in the checkout is touched.
	src := readFile(t, root, "scripts", "restore.sh")
	const badLine = `  local file="$1" sidecar="$file.sha256" want got`
	const goodLine = "  local file=\"$1\"\n  local sidecar=\"$file.sha256\" want got"
	if !strings.Contains(src, badLine) {
		t.Fatalf("restore.sh no longer carries the single-`local` line; re-read this probe")
	}
	fixed := filepath.Join(work, "restore-fixed.sh")
	if err := os.WriteFile(fixed, []byte(strings.Replace(src, badLine, goodLine, 1)), 0o755); err != nil {
		t.Fatal(err)
	}

	body := `
set -u
export PATH="$STUBDIR:/usr/bin:/bin"
cd "$ROOT" || exit 9
d=$(mktemp -d)
printf 'dump-bytes-one' > "$d/big.dump"
sha256sum "$d/big.dump" > "$d/big.dump.sha256"

# (0) the exact construct, isolated
( set -euo pipefail
  f() { local s="$1" t="$s.sha256"; printf 'LOCALPROBE=[%s]\n' "$t"; }
  f /tmp/x ) 2>/tmp/local.err; echo "LOCALPROBE_EXIT=$? LOCALPROBE_ERR=$(tr '\n' '|' < /tmp/local.err)"

# (1) the script as checked in
DATABASE_URL=postgres://x STUB_TABLES=0 bash scripts/restore.sh "$d/big.dump" >/tmp/r1.log 2>&1
echo "R1_EXIT=$?"; echo "R1_MSG=$(tr '\n' '|' < /tmp/r1.log)"

# (2) the same script with that one line split
DATABASE_URL=postgres://x STUB_TABLES=0 bash "$FIXED" "$d/big.dump" >/tmp/r2.log 2>&1
echo "R2_EXIT=$?"; echo "R2_MSG=$(tr '\n' '|' < /tmp/r2.log)"

# (3) the guards, against the corrected copy
d2=$(mktemp -d); printf 'dump-bytes-one' > "$d2/big.dump"; printf 'other' > "$d2/other.dump"
DATABASE_URL=postgres://x STUB_TABLES=0 bash "$FIXED" "$d2/big.dump" >/tmp/r3.log 2>&1
echo "R3_EXIT=$?"; echo "R3_MSG=$(tr '\n' '|' < /tmp/r3.log)"
sha256sum "$d2/other.dump" | sed "s#other.dump#big.dump#" > "$d2/big.dump.sha256"
DATABASE_URL=postgres://x STUB_TABLES=0 bash "$FIXED" "$d2/big.dump" >/tmp/r4.log 2>&1
echo "R4_EXIT=$?"; echo "R4_MSG=$(tr '\n' '|' < /tmp/r4.log)"
sha256sum "$d2/big.dump" > "$d2/big.dump.sha256"
DATABASE_URL=postgres://x STUB_TABLES=3 bash "$FIXED" "$d2/big.dump" >/tmp/r5.log 2>&1
echo "R5_EXIT=$?"; echo "R5_MSG=$(tr '\n' '|' < /tmp/r5.log)"
`
	out, errb, code := runBashScript(t, bin, body, []string{
		"ROOT=" + bashPathOf(root),
		"STUBDIR=" + bashPathOf(stubDir),
		"FIXED=" + bashPathOf(fixed),
	})
	if code != 0 {
		t.Fatalf("the harness itself failed (exit %d):\n%s\n%s", code, out, errb)
	}
	got := kv(out)

	// Control: the corrected copy reaches pg_restore and completes, so the
	// harness exercises the script and the failure below is that one line.
	if got["R2_EXIT"] != "0" || !strings.Contains(got["R2_MSG"], "restore complete") ||
		!strings.Contains(got["R2_MSG"], "checksum verified") {
		t.Fatalf("control: the corrected copy did not complete (%v)\n%s", got, out)
	}
	// Control: the guards themselves work once the verifier runs.
	if got["R3_EXIT"] != "1" || !strings.Contains(got["R3_MSG"], "is missing") {
		t.Errorf("restore.sh no longer refuses a dump with no sidecar: %v", got["R3_MSG"])
	}
	if got["R4_EXIT"] != "1" || !strings.Contains(got["R4_MSG"], "checksum mismatch") {
		t.Errorf("restore.sh no longer refuses a sidecar naming another file: %v", got["R4_MSG"])
	}
	if got["R5_EXIT"] != "1" || !strings.Contains(got["R5_MSG"], "refusing to restore") {
		t.Errorf("restore.sh no longer refuses a non-empty target: %v", got["R5_MSG"])
	}

	// The finding: the checked-in script never gets past its own verifier.
	if got["R1_EXIT"] == "0" {
		t.Fatalf("restore.sh now runs; the version-specific claim must be re-read (%v)", got)
	}
	t.Errorf("scripts/restore.sh cannot restore anything on this host: `set -euo pipefail` (line 13) "+
		"plus line 29's single-`local` form (`local file=\"$1\" sidecar=\"$file.sha256\" want got`) "+
		"aborts with `file: unbound variable` before the checksum is ever looked at — the isolated "+
		"construct exits %s too, and with `set -u` removed the same line silently computes the WRONG "+
		"sidecar path (`.sha256`, not `$1.sha256`). Splitting the two assignments makes the same file "+
		"complete (%s). The zone-13 report listed restore.sh's guards under \"探过没破\" from a "+
		"line-by-line reading; it was never executed",
		got["LOCALPROBE_EXIT"], got["R2_MSG"])
}

// ---------------------------------------------------------------------------
// Z13-4, executed: with BACKUP_AGE_RECIPIENT set and no `age`, the keys script
// leaves the plaintext key file behind after exiting 1, while the sibling script
// leaves nothing. Both directions run through real bash.
// ---------------------------------------------------------------------------

func TestZ13VKeyBackupLeavesPlaintextWhereTheSiblingLeavesNothing(t *testing.T) {
	root := repoRoot(t)
	bin := bashPath(t)
	work := t.TempDir()
	stubDir := filepath.Join(work, "bin")
	// The last argument of `pg_dump ... --file "$out"` is the output path.
	writeStub(t, filepath.Join(stubDir, "pg_dump"),
		"#!/bin/sh\nfor last; do :; done\nprintf dump > \"$last\"\n")

	body := `
set -u
export PATH="$STUBDIR:/usr/bin:/bin"
cd "$ROOT" || exit 9
d1=$(mktemp -d); d2=$(mktemp -d); k1=$(mktemp -d)
echo "AGE_PRESENT=$(command -v age || echo no)"
DATABASE_URL=postgres://x RE0AUTH_CONFIG=/nonexistent BACKUP_AGE_RECIPIENT=age1test \
  bash scripts/backup.sh "$d1" >/tmp/d1.log 2>&1; echo "D1EXIT=$?"
echo "D1FILES=$(ls -1 "$d1" | tr '\n' ',')"
DATABASE_URL=postgres://x RE0AUTH_CONFIG=/nonexistent \
  bash scripts/backup.sh "$d2" >/tmp/d2.log 2>&1; echo "D2EXIT=$?"
echo "D2FILES=$(ls -1 "$d2" | tr '\n' ',')"
RE0AUTH_KEK=KEKVAL RE0AUTH_OIDC_TOKEN_KEY=TOKVAL RE0AUTH_OIDC_SIGNING_KEY=SIGNVAL \
  RE0AUTH_AUDIT_KEY=AUDVAL RE0AUTH_CONFIG=/nonexistent BACKUP_AGE_RECIPIENT=age1test \
  bash scripts/backup-keys.sh "$k1" >/tmp/k1.log 2>&1; echo "K1EXIT=$?"
echo "K1FILES=$(ls -1 "$k1" | tr '\n' ',')"
echo "K1PLAINTEXT=$(head -c 300 "$k1"/re0auth-keys-*.env 2>/dev/null | tr '\n' '|')"
echo "K1STDERR=$(tr '\n' '|' < /tmp/k1.log)"
`
	out, errb, code := runBashScript(t, bin, body, []string{
		"ROOT=" + bashPathOf(root),
		"STUBDIR=" + bashPathOf(stubDir),
	})
	if code != 0 {
		t.Fatalf("the harness itself failed (exit %d):\n%s\n%s", code, out, errb)
	}
	got := kv(out)

	if got["AGE_PRESENT"] != "no" {
		t.Skipf("age is installed here (%s); the missing-tool path cannot be reproduced", got["AGE_PRESENT"])
	}
	// Controls: the dump path runs, and it is the recipient-less run that writes.
	if got["D2EXIT"] != "0" || !strings.Contains(got["D2FILES"], ".dump") {
		t.Fatalf("control: backup.sh did not write a dump when age was not required (%v)", got)
	}
	if got["D1EXIT"] != "1" {
		t.Fatalf("control: backup.sh did not fail on the missing age (%v)", got)
	}
	// The sibling's stated invariant, really holding: no plaintext dump is left.
	if strings.Contains(got["D1FILES"], ".dump") {
		t.Errorf("backup.sh left a dump behind after the age check failed: %s", got["D1FILES"])
	}
	// The finding.
	if got["K1EXIT"] != "1" {
		t.Fatalf("control: backup-keys.sh did not fail without age (%v)", got)
	}
	if !strings.Contains(got["K1STDERR"], "age is not installed") {
		t.Fatalf("control: the failure was not the missing-age branch: %s", got["K1STDERR"])
	}
	if !strings.Contains(got["K1FILES"], ".env") {
		t.Fatalf("control: no key file was written, so the write path was never reached (%v)", got)
	}
	if !strings.Contains(got["K1PLAINTEXT"], "RE0AUTH_KEK=KEKVAL") ||
		!strings.Contains(got["K1PLAINTEXT"], "RE0AUTH_OIDC_SIGNING_KEY=SIGNVAL") {
		t.Errorf("the plaintext key file survived the failed age path but does not carry the keys: %s",
			got["K1PLAINTEXT"])
	} else {
		t.Errorf("backup-keys.sh exits 1 on the missing-age branch AFTER writing %s in plaintext "+
			"(backup.sh checks for the tool before it writes anything and leaves no dump). The operator "+
			"who sees the non-zero exit has no reason to look for the file, and the script's own header "+
			"says the KEK must not sit in plaintext in the backup bucket", got["K1FILES"])
	}
}

// ---------------------------------------------------------------------------
// Z13-5 / Z13-6, with the controls the reviewed probes lacked.
// ---------------------------------------------------------------------------

func archtestBinary(t *testing.T, root string) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "archtest.test.exe")
	cmd := exec.Command("go", "test", "-c", "-o", out, "./internal/archtest/")
	cmd.Dir = root
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cannot compile internal/archtest: %v\n%s", err, b)
	}
	return out
}

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
			if err := filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
				if err != nil {
					return err
				}
				rel, _ := filepath.Rel(src, path)
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
			continue
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, []byte(readFile(t, src)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(dir, "internal", "archtest"), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

func runArchtest(t *testing.T, bin, tree, gate string) (bool, string) {
	t.Helper()
	cmd := exec.Command(bin, "-test.run", "^"+gate+"$", "-test.v")
	cmd.Dir = filepath.Join(tree, "internal", "archtest")
	out, err := cmd.CombinedOutput()
	return err != nil, string(out)
}

func TestZ13VNpmAttributionGateIgnoresTheChecksumsGlob(t *testing.T) {
	root := repoRoot(t)
	bin := archtestBinary(t, root)
	const gate = "TestReleaseShipsNpmAttribution"
	tree := fakeTree(t, root)
	mk := filepath.Join(tree, "Makefile")
	src := readFile(t, mk)

	// Control 1: green on the untouched artifacts.
	if failed, out := runArchtest(t, bin, tree, gate); failed {
		t.Fatalf("control: the gate fails on an untouched Makefile:\n%s", out)
	}
	// Control 2 — the one the zone-13 probe was missing: the gate really reads
	// THIS Makefile, so a mutation of the mechanism is visible to it.
	broken := strings.Replace(src, "npm-attribution: dist", "npm-licences: dist", 1)
	if broken == src {
		t.Fatalf("control: could not find the npm-attribution target to break")
	}
	if err := os.WriteFile(mk, []byte(broken), 0o644); err != nil {
		t.Fatal(err)
	}
	if failed, out := runArchtest(t, bin, tree, gate); !failed {
		t.Fatalf("control: the gate did not fail when the npm-attribution target was renamed, so it "+
			"does not read this tree and the result below proves nothing:\n%s", out)
	}
	if err := os.WriteFile(mk, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	// The finding: the output NAME can move out of the `checksums` glob while
	// every string the gate looks for stays put.
	renamed := strings.Replace(src,
		`../dist/re0auth_$${VERSION}_npm-attribution.json`, `../dist/npm-attribution.json`, 1)
	if renamed == src {
		t.Fatalf("the npm attribution output name changed; re-read this probe")
	}
	if err := os.WriteFile(mk, []byte(renamed), 0o644); err != nil {
		t.Fatal(err)
	}
	failed, out := runArchtest(t, bin, tree, gate)
	if !failed {
		t.Errorf("TestReleaseShipsNpmAttribution stays green when the npm listing is written to "+
			"`dist/npm-attribution.json`, a name the `checksums` glob (`sha256sum re0auth_${VERSION}_*`, "+
			"Makefile:227) does not match: the gate asserts that the target is wired into `release` and "+
			"`checksums`, not that the file it writes is covered. `gh release create dist/*` publishes "+
			"whatever is in dist/, so the licence file would ship without a checksum. tail: %s",
			tailLines(out, 3))
	}
}

func TestZ13VPermissionsGateIsBlindToJobLevelGrants(t *testing.T) {
	root := repoRoot(t)
	bin := archtestBinary(t, root)
	const gate = "TestWorkflowsGrantWriteScopesOnlyToTheJobThatUsesThem"
	tree := fakeTree(t, root)
	ci := filepath.Join(tree, ".github", "workflows", "ci.yml")
	src := readFile(t, ci)

	if failed, out := runArchtest(t, bin, tree, gate); failed {
		t.Fatalf("control: the gate fails on untouched workflows:\n%s", out)
	}
	workflowLevel := strings.Replace(src, "permissions:\n  contents: read",
		"permissions:\n  contents: read\n  packages: write", 1)
	if workflowLevel == src {
		t.Fatalf("control: could not find the workflow-level permissions block")
	}
	if err := os.WriteFile(ci, []byte(workflowLevel), 0o644); err != nil {
		t.Fatal(err)
	}
	if failed, out := runArchtest(t, bin, tree, gate); !failed {
		t.Fatalf("control: a workflow-level packages: write did not fail the gate:\n%s", out)
	}

	jobLevel := strings.Replace(src, "  test:\n", "  test:\n    permissions:\n      packages: write\n", 1)
	if jobLevel == src {
		t.Fatalf("could not find the `test` job")
	}
	if err := os.WriteFile(ci, []byte(jobLevel), 0o644); err != nil {
		t.Fatal(err)
	}
	if failed, out := runArchtest(t, bin, tree, gate); !failed {
		t.Errorf("`packages: write` on the ci.yml `test` job does not fail the gate: workflows_test.go:280-282 "+
			"decodes `permissions` into a struct with no `jobs` field, so only the workflow-level block is "+
			"ever inspected. release.yml:10-14 promises each job names its own scopes; a single job-level "+
			"grant silently re-arms it. tail: %s", tailLines(out, 3))
	}
}

func tailLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}
