package archtest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// S15-1: a failed `age` must not leave the plaintext dump behind.
//
// scripts/backup.sh dumps in the clear and encrypts afterwards, and it runs under
// `set -euo pipefail` — so when `age` fails (bad recipient, full disk) the script
// exits at that command and the `shred`/`rm` on the next line never runs, leaving
// a plaintext SQL dump of credentials and audit history in a directory the
// operator set BACKUP_AGE_RECIPIENT precisely to keep ciphertext-only. The fix is
// an EXIT trap installed before the dump is written; this check is about that
// ordering, because a trap added after `pg_dump` cleans up only the failures that
// happen later. The executable form of the same check — a failing `age` stub and
// a real bash run — is in internal/zzprobe/audit7/z13verify.
func TestBackupScriptRemovesThePlaintextWhenEncryptionFails(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "scripts", "backup.sh"))
	if err != nil {
		t.Fatal(err)
	}
	script := string(raw)

	trapAt := strings.Index(script, "trap cleanup EXIT")
	if trapAt < 0 {
		t.Fatal("scripts/backup.sh installs no EXIT trap: a failing age exits through `set -e` before the " +
			"shred/rm, leaving the plaintext dump (S15-1)")
	}
	dumpAt := strings.Index(script, "pg_dump ")
	if dumpAt < 0 {
		t.Fatal("scripts/backup.sh no longer dumps; this probe is measuring the wrong file")
	}
	if trapAt > dumpAt {
		t.Fatal("the EXIT trap is installed after the dump is written: a failure before it is never " +
			"cleaned up, which is exactly the case the trap exists for")
	}

	cleanupAt := strings.Index(script, "cleanup()")
	if cleanupAt < 0 || cleanupAt > trapAt {
		t.Fatal("scripts/backup.sh has no cleanup() defined before its trap")
	}
	body := script[cleanupAt:trapAt]
	if !strings.Contains(body, `rm -f "$plain"`) {
		t.Errorf("the EXIT trap does not remove the plaintext dump, so a failed encryption still leaves "+
			"it behind:\n%s", body)
	}
	// The trap must only act on failure: a successful run's artifacts (the
	// ciphertext and its sidecar) are the point of the script.
	if !strings.Contains(body, "status") {
		t.Errorf("the EXIT trap does not distinguish success from failure:\n%s", body)
	}
}
