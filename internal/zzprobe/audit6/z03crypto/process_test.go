//go:build audit6

// Real-process probes: the actual cmd/re0auth binary, started environment-only
// in memory mode against this zone's assigned public port (127.0.0.1:16301).
// These exercise the KEK parsing and the -rotate-keys command path end to end.
package z03crypto

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"
)

// TestProbeKEKEncodingVariantsEachStartTheServer pins the accepted encodings
// of the KEK through the real config path: padded base64, raw (unpadded)
// base64, and hex. The hex branch was dead code before the round-5 fix, so a
// regression here would bring back "the key is the wrong size" for a
// correctly-sized hex key.
func TestProbeKEKEncodingVariantsEachStartTheServer(t *testing.T) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	for name, encoded := range map[string]string{
		"padded base64": base64.StdEncoding.EncodeToString(raw),
		"raw base64":    base64.RawStdEncoding.EncodeToString(raw),
		"hex":           hex.EncodeToString(raw),
	} {
		t.Run(name, func(t *testing.T) {
			env := baseEnv()
			env["RE0AUTH_KEK"] = encoded
			p := startProcess(t, env)
			p.waitServing()
			p.stop()
		})
	}
}

// TestProbeKEKMalformedValuesRefuseStartup pins the fail-closed side: a KEK
// with a trailing space, a URL-safe-base64 key, and a short key must each
// refuse to start, with an error that names the key.
func TestProbeKEKMalformedValuesRefuseStartup(t *testing.T) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"trailing space":  base64.StdEncoding.EncodeToString(raw) + " ",
		"url-safe base64": base64.RawURLEncoding.EncodeToString(raw),
		"31 bytes":        base64.StdEncoding.EncodeToString(raw[:31]),
	}
	for name, encoded := range cases {
		t.Run(name, func(t *testing.T) {
			env := baseEnv()
			env["RE0AUTH_KEK"] = encoded
			code, out := runToExit(t, env)
			if code == 0 {
				t.Fatalf("the server started with a %s KEK; output:\n%s", name, out)
			}
			if !strings.Contains(out, "KEK") {
				t.Fatalf("the failure does not name the key:\n%s", out)
			}
		})
	}
}

// TestProbeKEKTrailingNewlineIsTolerated pins the one whitespace Go's base64
// decoder ignores (\r and \n): a KEK read from a CI secret with a trailing
// newline is accepted, so that shape is not a trap. The serving assertion
// proves acceptance; "same bytes" follows from the stdlib contract
// (DecodeString ignores \r and \n), so the decoded material cannot differ
// from the value without the newline.
func TestProbeKEKTrailingNewlineIsTolerated(t *testing.T) {
	env := baseEnv()
	env["RE0AUTH_KEK"] = probeKEK + "\n"
	p := startProcess(t, env)
	p.waitServing()
	p.stop()
}

// TestProbeStartupLogDoesNotEchoKeyMaterial checks the leak surface of the
// startup path: none of the three key materials (KEK, token key, signing key)
// may appear in the process log of a serving instance.
func TestProbeStartupLogDoesNotEchoKeyMaterial(t *testing.T) {
	p := startProcess(t, baseEnv())
	p.waitServing()
	log := p.log()
	p.stop()
	for name, needle := range map[string]string{
		"KEK value":         probeKEK,
		"token key value":   probeTokKey,
		"signing key value": oidcSignKey,
	} {
		if strings.Contains(log, needle) {
			t.Fatalf("the process log contains the %s", name)
		}
	}
}

// TestProbeRotateKeysReportsTheGateOnAnEmptyVault is the command-level
// regression guard for the P1-1 fix: a clean run exits 0, prints its counts,
// and unconditionally names the re-run gate ("rewrapped=0 skipped=0") the
// operator must pass before removing the retired key.
func TestProbeRotateKeysReportsTheGateOnAnEmptyVault(t *testing.T) {
	env := baseEnv()
	env["RE0AUTH_KEK_ID"] = "kek-2"
	env["RE0AUTH_KEK_OLD"] = base64.StdEncoding.EncodeToString([]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
	code, out := runToExit(t, env, "-rotate-keys", "-config", retiredConfig(t, "kek-1", "RE0AUTH_KEK_OLD"))
	if code != 0 {
		t.Fatalf("-rotate-keys on an empty vault exited %d; output:\n%s", code, out)
	}
	for _, needle := range []string{
		"scanned=0 rewrapped=0",
		"rewrapped=0 skipped=0",
		"retired KEKs are configured",
	} {
		if !strings.Contains(out, needle) {
			t.Fatalf("the rotation report does not say %q:\n%s", needle, out)
		}
	}
}

// TestProbeRotateKeysRefusesARetiredKeySharingTheCurrentID pins the
// fail-closed guard on the id namespace: a retired key declared with the
// current id must refuse to start rather than shadow it.
func TestProbeRotateKeysRefusesARetiredKeySharingTheCurrentID(t *testing.T) {
	env := baseEnv()
	env["RE0AUTH_KEK_OLD"] = base64.StdEncoding.EncodeToString([]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
	code, out := runToExit(t, env, "-rotate-keys", "-config", retiredConfig(t, "kek-1", "RE0AUTH_KEK_OLD"))
	if code == 0 {
		t.Fatalf("a retired key sharing the current id was accepted; output:\n%s", out)
	}
	if !strings.Contains(out, "is the current key's id") {
		t.Fatalf("the refusal does not name the conflict:\n%s", out)
	}
}

// TestProbeKeyMaterialSharedAcrossRolesIsAccepted is the red probe for the
// key-separation finding: the vault KEK and the OP's token-encryption key may
// be the very same 32 bytes, and the process starts and serves with no warning
// and no refusal.
func TestProbeKeyMaterialSharedAcrossRolesIsAccepted(t *testing.T) {
	env := baseEnv()
	env["RE0AUTH_OIDC_TOKEN_KEY"] = probeKEK // the same 32 bytes as the vault KEK
	p := startProcess(t, env)
	p.waitServing()
	log := p.log()
	p.stop()
	if !strings.Contains(log, "token key") && !strings.Contains(log, "same key") &&
		!strings.Contains(log, "key separation") {
		t.Fatalf("CONFIRMED: the server serves with RE0AUTH_KEK and RE0AUTH_OIDC_TOKEN_KEY set to the "+
			"same 32 bytes, and the startup log says nothing about the reuse. One compromise of that "+
			"value is then simultaneously the vault's KEK leak and the opaque-token encryption key leak; "+
			"the log:\n%s", log)
	}
}

// retiredConfig writes a minimal TOML declaring one retired key.
func retiredConfig(t *testing.T, id, envName string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "re0auth.toml")
	body := "[vault]\nkek_env = \"RE0AUTH_KEK\"\n\n[[vault.retired]]\nkek_id = \"" + id +
		"\"\nkek_env = \"" + envName + "\"\n"
	if err := writeFile(path, body); err != nil {
		t.Fatal(err)
	}
	return path
}
