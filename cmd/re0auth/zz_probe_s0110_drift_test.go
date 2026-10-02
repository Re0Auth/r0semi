package main

// Probe for the S01-10 consequence in cmd/re0auth: clientDrift must compare the
// configured plaintext against the registered verifier, not the two digests as
// bytes. After NewSecretHash salts every verifier, two clients built from the same
// secret carry different digests, so byte equality would report drift on every
// start and refuse to boot a correctly configured deployment.
//
// Pre-fix (bytes.Equal on SecretHash) the "same secret" assertion fails.

import (
	"bytes"
	"testing"

	"github.com/Re0Auth/r0semi/oauth"
)

func TestProbeS0110SecretDriftVerifiesThePlaintext(t *testing.T) {
	build := func(secret string) oauth.Client {
		t.Helper()
		c, err := oauth.NewClient("cli", "CLI", oauth.ClientConfidential, secret,
			[]string{"https://app.example/cb"}, []oauth.Scope{oauth.ScopeAccountID})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}

	registered := build("s3cret")
	configured := build("s3cret")

	// The premise: the two verifiers of the same secret are different bytes, so a
	// byte comparison could not possibly be right.
	if bytes.Equal(registered.SecretHash(), configured.SecretHash()) {
		t.Fatal("two verifiers of the same secret are identical; the drift test cannot show anything")
	}

	if drift := clientDrift(registered, configured, "s3cret"); len(drift) != 0 {
		t.Fatalf("the same secret was reported as drift: %v", drift)
	}
	if drift := clientDrift(registered, configured, "rotated"); len(drift) == 0 {
		t.Fatal("a rotated secret was not reported as drift")
	}
}
