//go:build audit7

package z19secretslifecycle

import (
	"strings"
	"testing"
)

// oneLine returns the last non-empty line of a run's output.
func oneLine(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.TrimSpace(lines[i]) != "" {
			return lines[i]
		}
	}
	return ""
}

// Z19-2 — the `*_env` convention is enforced nowhere, and when an operator puts
// a secret VALUE where the variable NAME belongs, the startup error prints the
// secret.
//
// The whole config schema is built on one convention (internal/config/config.go:
// "a config file never contains a secret. It names the environment variable that
// holds it"). Nothing checks the name's shape. `config.Secret`
// (internal/config/config.go:57-66) looks the name up and, on a miss, used to
// return
//
//	%s names %q, which is not set
//
// with the name interpolated verbatim — and cmd/re0auth/main.go:304 turns that
// into `slog.Error("cannot start", "stage", …, "err", failure.err)`.
//
// The FIX (Z19-1) removes the interpolation entirely: the refusal names the field
// only. The control below asserts the new contract.
//
// Swapping a value for its own variable name is the mistake the convention
// invites: `client_secret_env = "<the secret>"`, `kek_env = "<the base64 KEK>"`.
// The probe drives the real binary with each of the four secret-holding keys
// pointed at a secret value, and fails when the value appears in the log.
//
// Round 5's CS-8 guard and round 7's zone-12 leak probe both plant values in the
// ENVIRONMENT and assert the startup log does not repeat them; this is the same
// invariant reached from the FILE, which neither guard inspects.
func TestZ19SecretEnvNameHoldingTheSecretValueIsEchoed(t *testing.T) {
	const (
		kekSecret     = "Z19-KEK-VALUE-PASTED-INTO-THE-NAME-9d2c"
		clientSecret  = "Z19-UPSTREAM-CLIENT-SECRET-4b71"
		idpSecret     = "Z19-IDP-CLIENT-SECRET-77ae"
		auditKeyValue = "Z19-AUDIT-KEY-VALUE-1f0d"
	)

	// The KEK is deliberately absent from the environment for the vault.* cases:
	// the file is then the only place one could come from, which is the deployment
	// shape a renamed kek_env exists for. The other cases need a valid KEK so the
	// loader reaches the section under test.
	base := map[string]string{
		"RE0AUTH_ISSUER":           "https://re0auth.test",
		"RE0AUTH_COOKIE_SECURE":    "true",
		"RE0AUTH_OIDC_TOKEN_KEY":   key32("Z19-OP-TOKEN-KEY-MATERIAL-32C"),
		"RE0AUTH_OIDC_SIGNING_KEY": signingKey,
	}
	withKEK := map[string]string{}
	for k, v := range base {
		withKEK[k] = v
	}
	withKEK["RE0AUTH_KEK"] = key32("Z19-KEK-MATERIAL-32-BYTES-DDD")

	run := func(t *testing.T, env map[string]string, body string) runResult {
		t.Helper()
		return runBinary(t, env, "-config", writeConfig(t, "re0auth.toml", body))
	}

	// Control: the same shape with a NAME that is merely unset. The message names
	// the FIELD; it deliberately no longer repeats the configured string, because
	// the fixed message cannot tell a mistyped name from a pasted secret (and a
	// shape test would let an alphanumeric secret through). The field plus the
	// config file in hand are what locate it.
	ctrl := run(t, base, "[vault]\nkek_env = \"NO_SUCH_VARIABLE\"\n")
	if !strings.Contains(ctrl.out, "stage=config") || !strings.Contains(ctrl.out, "vault.kek_env") {
		t.Fatalf("control did not reach the config stage naming the field:\n%s", ctrl.out)
	}
	if strings.Contains(ctrl.out, kekSecret) {
		t.Fatalf("control is wrong: an unset NAME revealed a value:\n%s", ctrl.out)
	}

	cases := []struct {
		name  string
		env   map[string]string
		body  string
		value string
	}{
		{"vault.kek_env holds the KEK", base,
			"[vault]\nkek_env = \"" + kekSecret + "\"\n", kekSecret},
		{"client.secret_env holds the secret", withKEK,
			"[client]\nid = \"cli\"\nsecret_env = \"" + clientSecret + "\"\n", clientSecret},
		{"idp.*.client_secret_env holds the secret", withKEK,
			"[server]\nissuer = \"https://re0auth.test\"\n[idp.github]\nclient_id = \"cid\"\nclient_secret_env = \"" + idpSecret + "\"\n", idpSecret},
		{"sources[].client_secret_env holds the secret", withKEK,
			"[server]\nissuer = \"https://re0auth.test\"\n[[sources]]\ngame = \"g\"\nsource = \"s\"\nclient_id = \"cid\"\nclient_secret_env = \"" + auditKeyValue + "\"\n", auditKeyValue},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := run(t, tc.env, tc.body)
			if !strings.Contains(got.out, "stage=config") {
				t.Fatalf("the run never reached the config stage, so this probe observed nothing:\n%s", got.out)
			}
			if strings.Contains(got.out, tc.value) {
				t.Errorf("DISCLOSURE: a secret pasted into the *_env NAME is printed by the startup error; "+
					"the process refuses to start but the value is now in the log pipeline (exit=%d):\n%s",
					got.code, oneLine(got.out))
			} else {
				t.Logf("%s: %s", tc.name, oneLine(got.out))
			}
		})
	}
}

// Z19-2b — the same file-value-echo shape from the validation half: a raw config
// string is interpolated with %q, so a secret written into any free-form field is
// printed by whichever validator refuses it. trusted_proxies is the one where a
// single string field takes arbitrary text.
func TestZ19ConfigValidationDoesNotEchoFileValues(t *testing.T) {
	const secret = "Z19-FILE-VALUE-ECHO-2c8b"
	env := map[string]string{
		"RE0AUTH_ISSUER":           "https://re0auth.test",
		"RE0AUTH_COOKIE_SECURE":    "true",
		"RE0AUTH_KEK":              key32("Z19-KEK-MATERIAL-32-BYTES-CCC"),
		"RE0AUTH_OIDC_TOKEN_KEY":   key32("Z19-OP-TOKEN-KEY-MATERIAL-32D"),
		"RE0AUTH_OIDC_SIGNING_KEY": signingKey,
	}
	got := runBinary(t, env, "-config", writeConfig(t, "re0auth.toml",
		"[server]\ntrusted_proxies = [\""+secret+"\"]\n"))
	if !strings.Contains(got.out, "stage=config") {
		t.Fatalf("the run never reached the config stage:\n%s", got.out)
	}
	if strings.Contains(got.out, secret) {
		t.Errorf("DISCLOSURE: a config-file value is echoed by validation (cmd/re0auth/config.go:1037):\n%s",
			oneLine(got.out))
	} else {
		t.Logf("validation did not echo the value: %s", oneLine(got.out))
	}
}
