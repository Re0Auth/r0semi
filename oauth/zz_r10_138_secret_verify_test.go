package oauth

import (
	"strings"
	"testing"
	"time"
)

// R10-138: every confidential-client authentication paid PBKDF2-HMAC-SHA256 x
// 210,000 — ~23 ms of CPU per introspection or token exchange, on the public
// protocol plane, reachable by a public client id plus any secret. A verifier for
// a CSPRNG-generated secret needs no slow KDF; the scheme travels in the stored
// string, so both kinds keep working.

func generatedSecret() string {
	return "9f2c1d4b6a8e0f3c5d7b9a1e2f4c6d8a0b1c3e5f7a9b0c2d4e6f8a1b3c5d7e9f"
}

func TestR10138GeneratedSecretUsesTheFastVerifier(t *testing.T) {
	client, err := NewClientWithVerifier("cli", "CLI", ClientConfidential, generatedSecret(),
		[]string{"https://app.example/cb"}, []Scope{ScopeAccountID}, VerifierGenerated)
	if err != nil {
		t.Fatal(err)
	}
	hash := client.SecretHash()
	if !strings.HasPrefix(string(hash), "$"+secretHashFastAlgorithm+"$") {
		t.Fatalf("a generated secret's verifier is %q, want the %s scheme", hash, secretHashFastAlgorithm)
	}
	if strings.Contains(string(hash), secretHashAlgorithm) {
		t.Fatalf("a generated secret's verifier still carries the slow scheme: %q", hash)
	}
	if !client.Authenticate(generatedSecret()) {
		t.Fatal("the generated secret does not authenticate against its own verifier")
	}
	if client.Authenticate("wrong-secret") {
		t.Fatal("a wrong secret authenticated")
	}
	restored, err := RestoreClient("cli", "CLI", ClientConfidential, hash,
		[]string{"https://app.example/cb"}, []Scope{ScopeAccountID}, time.Now())
	if err != nil {
		t.Fatalf("the fast verifier is not restorable: %v", err)
	}
	if !restored.Authenticate(generatedSecret()) {
		t.Fatal("the restored client does not authenticate")
	}
}

// TestR10138ConfigSecretKeepsTheSlowVerifier is the S01-10 control: NewClient and
// a human-chosen secret must still be PBKDF2 (and still parse through the
// original reader), so the fast path cannot quietly become the default.
func TestR10138ConfigSecretKeepsTheSlowVerifier(t *testing.T) {
	client, err := NewClient("cli", "CLI", ClientConfidential, "s3cret",
		[]string{"https://app.example/cb"}, []Scope{ScopeAccountID})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(client.SecretHash()), "$"+secretHashAlgorithm+"$i=") {
		t.Fatalf("NewClient wrote %q, want the PBKDF2 scheme", client.SecretHash())
	}
	if _, _, iterations, ok := splitSecretHash(client.SecretHash()); !ok || iterations != secretHashIterations {
		t.Fatalf("splitSecretHash no longer reads the PBKDF2 verifier (ok=%v iterations=%d)", ok, iterations)
	}
	if !client.Authenticate("s3cret") || client.Authenticate("wrong") {
		t.Fatal("the PBKDF2 verifier does not authenticate correctly")
	}
}

// TestR10138GeneratedSecretVerificationAvoidsTheSlowKDF is the measured half: 20
// verifications of a generated secret must not cost 20 x ~23 ms.
func TestR10138GeneratedSecretVerificationAvoidsTheSlowKDF(t *testing.T) {
	client, err := NewClientWithVerifier("cli", "CLI", ClientConfidential, generatedSecret(),
		[]string{"https://app.example/cb"}, []Scope{ScopeAccountID}, VerifierGenerated)
	if err != nil {
		t.Fatal(err)
	}
	const rounds = 20
	start := time.Now()
	for i := 0; i < rounds; i++ {
		if !client.Authenticate(generatedSecret()) {
			t.Fatal("the generated secret stopped authenticating")
		}
	}
	elapsed := time.Since(start)
	// 20 PBKDF2 verifications are ~460 ms on this project's reference machine;
	// 20 HMAC verifications are microseconds. A 50 ms wall is a wide margin.
	if elapsed > 50*time.Millisecond {
		t.Fatalf("R10-138: %d verifications of a generated secret took %v; the slow KDF is still on the "+
			"generated-secret path", rounds, elapsed)
	}
}

func TestR10138LooksGeneratedSecretRecognisesTheDocumentedRecipes(t *testing.T) {
	for _, ok := range []string{
		generatedSecret(), // openssl rand -hex 32
		"Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZmdoaWo=",   // base64 of 32 random-ish bytes
		"aB3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0eF3hI6kL9nO2qX5w", // 44-char base64url alphabet
	} {
		if !LooksGeneratedSecret(ok) {
			t.Errorf("LooksGeneratedSecret(%q) = false, want true", ok)
		}
	}
	for _, bad := range []string{
		"", "s3cret", "hunter2hunter2hunter2hunter2", "correct horse battery staple",
		"aaaa", "0123456789abcdef0123456789abcdef", // 32 chars, below the recipe length
	} {
		if LooksGeneratedSecret(bad) {
			t.Errorf("LooksGeneratedSecret(%q) = true, want false", bad)
		}
	}
}
