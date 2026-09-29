//go:build audit7

package z19verify

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestZ19VPrintSecretEnvEchoesAPastedValueNullifiesThePositiveClaim checks zone
// 19's "probed, not broken" item 4:
//
//	"-print-secret-env 只打印角色+变量名（cmd/re0auth/config.go:412-442）：
//	 不解析、不回显值"
//
// That is true of a config that follows the convention. It is false of the very
// mistake zone 19's Z19-1 is about: -print-secret-env emits the string in the
// name slot verbatim (configSecretEnvNames, cmd/re0auth/config.go:418-421, does
// `role+"="+name` with no shape check), so the same paste error that Z19-1
// caught in the startup log is also written to stdout — the channel a
// runbook/CI step captures.
//
// This is the same mechanism as Z19-1 but a different sink, and it is the one
// the proposed fix (validate the name's shape before echoing it in
// config.Secret) does not cover: -print-secret-env has to print the name.
//
// The control is the ordinary shape: a real variable name is printed, as the
// subcommand is supposed to do.
func TestZ19VPrintSecretEnvEchoesAPastedValueNullifiesThePositiveClaim(t *testing.T) {
	const secret = "Z19V-PRINT-SECRET-ENV-PASTED-a0b4"

	write := func(t *testing.T, body string) string {
		t.Helper()
		p := filepath.Join(t.TempDir(), "re0auth.toml")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	// Control: a real name is echoed, which is the documented contract.
	ctrl := filepath.Join("Z19V_CONTROL_KEK")
	got := runBinaryArgs(t, nil, "-print-secret-env", "-config", write(t, "[vault]\nkek_env = \""+ctrl+"\"\n"))
	if got.code != 0 || !strings.Contains(got.out, "vault.kek_env="+ctrl) {
		t.Fatalf("control failed: -print-secret-env did not print the declared name (exit=%d):\n%s", got.code, got.out)
	}
	t.Logf("control: %s", strings.TrimSpace(got.out))

	// Subject: the value pasted into the name slot.
	sub := runBinaryArgs(t, nil, "-print-secret-env", "-config", write(t, "[vault]\nkek_env = \""+secret+"\"\n"))
	if !strings.Contains(sub.out, "vault.kek_env=") {
		t.Fatalf("the subject run never printed the declaration, so it observed nothing:\n%s", sub.out)
	}
	if strings.Contains(sub.out, secret) {
		t.Errorf("DISCLOSURE: -print-secret-env echoes a secret pasted into an *_env name verbatim "+
			"(exit=%d). The zone-19 report lists this subcommand as a guard that only prints role+name; "+
			"it prints whatever is in the name slot, unvalidated.\noutput: %s", sub.code, strings.TrimSpace(sub.out))
	} else {
		t.Logf("the pasted value was not printed: %s", strings.TrimSpace(sub.out))
	}
}
