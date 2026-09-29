//go:build audit7

// Z12-1: a secret the process reads is echoed into the startup log, and the guard
// that exists for exactly this (round 5's CS-8) does not plant this variable.
package z12configstartupobservability

import (
	"strings"
	"testing"
)

// Z12-1: a malformed RE0AUTH_OIDC_RETIRED_TOKEN_KEYS entry is echoed verbatim
// into the startup error, so the key material itself lands in the log.
//
// cmd/re0auth/main.go:1410 returns
//
//	fmt.Errorf("RE0AUTH_OIDC_RETIRED_TOKEN_KEYS entry %q must be id:base64", part)
//
// where `part` is the whole comma-separated segment — key material included. The
// only shape that reaches it is an entry with no `id:` prefix (or an empty id),
// which is exactly the shape produced by pasting the key alone.
//
// A retired token key is a live secret: it still decrypts every opaque access
// token issued before the rotation, which is why it is configured through the
// environment at all. Round 5's CS-8 guard ("no secret the process reads is
// echoed during startup") plants the KEK, the OP token key, the signing key, the
// audit key and three client secrets — but not the retired token key, so it
// cannot see this path.
//
// The control is the documented `id:base64` form: it parses, the run gets past
// every OP wire and dies at the listener, and the key appears nowhere.
func TestZ12RetiredTokenKeyIsEchoedIntoTheStartupLog(t *testing.T) {
	// A 32-byte key with a recognisable base64 form.
	secret := key32("Z12-RETIRED-TOKEN-KEY-MATERIA")
	if len(secret) < 20 {
		t.Fatalf("the probe key is degenerate: %q", secret)
	}

	env := func(value string) map[string]string {
		e := minimalEnv()
		e["RE0AUTH_OIDC_TOKEN_KEY"] = key32("Z12-OP-TOKEN-KEY-MATERIAL-32B!")
		e["RE0AUTH_OIDC_SIGNING_KEY"] = signingKey
		e["RE0AUTH_OIDC_RETIRED_TOKEN_KEYS"] = value
		return e
	}

	// Control: the documented form parses and is not echoed.
	ctrl := runBinary(t, env("z12-old:"+secret))
	if !strings.Contains(ctrl.out, "stage=listen") {
		t.Fatalf("the control never reached the listener, so it did not get past the retired-key parser:\n%s", ctrl.out)
	}
	if strings.Contains(ctrl.out, secret) {
		t.Fatalf("control is wrong: a well-formed retired token key was echoed:\n%s", ctrl.out)
	}

	// Subject: the id prefix is missing, which is the mistake the error message is
	// meant to report.
	got := runBinary(t, env(secret))
	if !strings.Contains(got.out, "stage=oidc") {
		t.Fatalf("the run never reached the retired-token-key parser, so this probe observed nothing:\n%s", got.out)
	}
	if strings.Contains(got.out, secret) {
		t.Errorf("the retired token key was printed into the startup log: a secret the process reads "+
			"reached the log pipeline verbatim. The message must name the FIELD, not the value.\n"+
			"exit=%d\n%s", got.code, got.out)
	} else {
		t.Logf("no leak: the refusal did not repeat the key material (%d bytes of log)", len(got.out))
	}
}
