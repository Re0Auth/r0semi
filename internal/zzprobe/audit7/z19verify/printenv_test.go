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
// That was true of a config that follows the convention, and false of the very
// mistake zone 19's Z19-1 is about: -print-secret-env emitted the string in the
// name slot verbatim (configSecretEnvNames did `role+"="+name` with no shape
// check), so the same paste error that Z19-1 caught in the startup log was also
// written to stdout — the channel a runbook/CI step captures. `scripts/backup-keys.sh`
// put that line in a shell variable and the CI transcript (S08-6 / Z19V-2).
//
// 【原为发现演示，现为回归守卫】It is FIXED: configSecretEnvNames declares the
// name slot by shape (`isEnvVarName`, cmd/re0auth/config.go:550-561) and refuses
// anything else, naming the field and never repeating the offending value
// (cmd/re0auth/config.go:495-518). See `docs/issues/_fragments/round7.md:155`
// (Z19V-2) and `docs/issues/P3-low.md` (S08-6).
//
// The probe now guards both halves: the ordinary shape is still printed (the
// interface `scripts/backup-keys.sh` depends on — `docs/issues/not-doing.md:116`),
// and a value pasted into the name slot is refused by shape without being echoed.
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

	// Control: a real name is echoed, which is the documented contract and the
	// line format scripts/backup-keys.sh parses.
	ctrl := filepath.Join("Z19V_CONTROL_KEK")
	got := runBinaryArgs(t, nil, "-print-secret-env", "-config", write(t, "[vault]\nkek_env = \""+ctrl+"\"\n"))
	if got.code != 0 || !strings.Contains(got.out, "vault.kek_env="+ctrl) {
		t.Fatalf("control failed: -print-secret-env did not print the declared name (exit=%d):\n%s", got.code, got.out)
	}
	t.Logf("control: %s", strings.TrimSpace(got.out))

	// Subject: the value pasted into the name slot. The shape check must refuse
	// it, the refusal must name the field, and the value must not appear anywhere
	// in the output — that last one is what the finding was about.
	sub := runBinaryArgs(t, nil, "-print-secret-env", "-config", write(t, "[vault]\nkek_env = \""+secret+"\"\n"))
	if strings.Contains(sub.out, secret) {
		t.Errorf("REGRESSION (S08-6 / Z19V-2): -print-secret-env echoed a value pasted into an *_env name "+
			"slot (exit=%d), so the mistake still reaches stdout and whatever captures it.\noutput: %s",
			sub.code, strings.TrimSpace(sub.out))
	}
	if sub.code == 0 {
		t.Errorf("REGRESSION (S08-6 / Z19V-2): -print-secret-env accepted a value pasted into an *_env name "+
			"slot (exit=0); configSecretEnvNames must refuse a name that is not shaped like an environment "+
			"variable (cmd/re0auth/config.go:508).\noutput: %s", strings.TrimSpace(sub.out))
	}
	if !strings.Contains(sub.out, "vault.kek_env") {
		t.Errorf("the refusal does not name the field, so an operator cannot tell which slot to fix: %s",
			strings.TrimSpace(sub.out))
	}
	t.Logf("subject (pasted value): exit=%d, value not echoed, refusal names the field: %s",
		sub.code, strings.TrimSpace(sub.out))
}
