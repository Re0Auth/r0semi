//go:build audit7

// Z12-VERIFY new-finding probes: the same "empty environment is not an override"
// rule applied to the key material itself.
package z12verify

import (
	"strings"
	"testing"
)

// TestZ12VerifyKekReadsRE0AUTHKEKRegardlessOfKekEnv checks whether "the file names
// the variable and the environment holds the value" actually holds for the KEK.
//
// cmd/re0auth/config.go:721-731 asks for the hardcoded RE0AUTH_KEK FIRST and only
// consults vault.kek_env when that variable is empty — the opposite order from
// FirstNonEmpty(env, file) used everywhere else. If RE0AUTH_KEK is set to anything,
// the file's kek_env is never read.
//
// The observable is purely local and needs no database: a file whose vault section
// names a variable that is set to a DIFFERENT 32-byte key must either read that
// key (the file would then be in force) or ignore it. Both spellings are valid
// 32-byte keys, so the only difference is which one is used — measured by whether
// the run with a correct file declaration starts at all.
func TestZ12VerifyKekReadsRE0AUTHKEKRegardlessOfKekEnv(t *testing.T) {
	const (
		otherVar = "Z12V_OTHER_KEK"
	)
	env := baseEnv()
	// The variable the FILE points at: present and valid.
	env[otherVar] = key32("Z12V-FILE-NAMED-KEK-32-BYTES-AA!")
	// RE0AUTH_KEK: also present and valid, but NOT what the file names.
	env["RE0AUTH_KEK"] = key32("Z12V-AMBIENT-KEK-32-BYTES-BBBBB!")

	body := "[server]\nissuer = \"https://re0auth.test\"\n[vault]\nkek_env = \"" + otherVar + "\"\nkek_id = \"kek-1\"\n"
	code, out := runBinary(t, env, "-config", writeFile(t, "kek.toml", body))

	reached := strings.Contains(out, "stage=listen")
	t.Logf("vault.kek_env = %s (set) with RE0AUTH_KEK set -> exit %d, reached the listener: %v",
		otherVar, code, reached)
	if strings.Contains(out, "stage=config") {
		t.Logf("the run was refused by the loader: %s", lastLine(out))
	}

	// Control: the same file with NO ambient RE0AUTH_KEK must use the file-named
	// variable, proving the file declaration is honoured when the hardcoded name is
	// absent — i.e. that the precedence (not the key) is what is being measured.
	ctrl := baseEnv()
	ctrl[otherVar] = key32("Z12V-FILE-NAMED-KEK-32-BYTES-AA!")
	delete(ctrl, "RE0AUTH_KEK")
	ccode, cout := runBinary(t, ctrl, "-config", writeFile(t, "kekctrl.toml", body))
	if !strings.Contains(cout, "stage=listen") {
		t.Fatalf("control failed: with RE0AUTH_KEK absent, vault.kek_env was not honoured either "+
			"(exit %d): %s", ccode, lastLine(cout))
	}
	t.Logf("control: without the ambient RE0AUTH_KEK the file-named variable was used")

	// Control 2: RE0AUTH_KEK set to something that is NOT a valid 32-byte key, while
	// the file names a perfectly good one. If the hardcoded name really wins, the
	// run must die at the config stage on the bad ambient value.
	bad := baseEnv()
	bad[otherVar] = key32("Z12V-FILE-NAMED-KEK-32-BYTES-AA!")
	bad["RE0AUTH_KEK"] = "RE0AUTH_KEK-WINS-OVER-THE-FILE-KEK-ENV-NOT-32B"
	_, bout := runBinary(t, bad, "-config", writeFile(t, "kekbad.toml", body))
	failed := strings.Contains(bout, "stage=config")
	t.Logf("with RE0AUTH_KEK set to a bad value and vault.kek_env naming a good one: config-stage failure = %v", failed)
	if !failed {
		t.Errorf("the hardcoded RE0AUTH_KEK did not decide the run: a bad ambient value was tolerated " +
			"while the file named a good key, so the file's kek_env took precedence after all")
	}
}

// TestZ12VerifyEnvEmptyFallsBackToTheFileDriver is the storage-driver instance of
// the same rule, to show it is a pattern and not one call site.
func TestZ12VerifyEnvEmptyFallsBackToTheFileDriver(t *testing.T) {
	env := baseEnv()
	delete(env, "RE0AUTH_STORAGE_DRIVER") // The environment says nothing about the driver.
	env["RE0AUTH_STORAGE_DRIVER"] = ""    // Explicitly empty.
	body := "[server]\nissuer = \"https://re0auth.test\"\n[storage]\ndriver = \"memory\"\n"
	_, out := runBinary(t, env, "-config", writeFile(t, "drv.toml", body))
	if !strings.Contains(out, "driver=memory") {
		t.Fatalf("control failed: the file's memory driver was not reported:\n%s", out)
	}
	t.Logf("an empty RE0AUTH_STORAGE_DRIVER leaves the file's driver in force (the same rule as the " +
		"admin allowlist): there is no spelling that says \"no driver\", which is fine here because the " +
		"file is the only other source")

	// The KEK's own variable is the interesting one: emptying it is an operator's
	// way of saying "stop using this key", and the file can name another.
	env2 := baseEnv()
	env2["RE0AUTH_KEK"] = ""
	env2["Z12V_FILE_KEK"] = key32("Z12V-FILE-KEK-32-BYTES-AAAA-0000!")
	body2 := "[server]\nissuer = \"https://re0auth.test\"\n[vault]\nkek_env = \"Z12V_FILE_KEK\"\nkek_id = \"kek-1\"\n"
	code, out2 := runBinary(t, env2, "-config", writeFile(t, "kek2.toml", body2))
	t.Logf("RE0AUTH_KEK=\"\" with vault.kek_env naming a set variable -> exit %d, reached listener: %v",
		code, strings.Contains(out2, "stage=listen"))
}
