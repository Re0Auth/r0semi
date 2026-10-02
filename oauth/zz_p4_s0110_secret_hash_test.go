package oauth

// Probes for S01-10 (client-secret hashing) and S09-4 (Store expiry contract
// wording). Written to FAIL against the pre-fix code: S01-10's first assertion is
// that two digests of the same secret differ, which the unsalted SHA-256 could
// never satisfy.
//
// They run in the default build, so `go test ./oauth/ -count=1` exercises them.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// S01-10: the stored secret must be a salted, self-describing, slow verifier —
// never a bare fast digest. Pre-fix: NewSecretHash returned the same 32-byte
// SHA-256 for the same secret, so the first check fails.
func TestS0110SecretHashIsSaltedAndSelfDescribing(t *testing.T) {
	first := NewSecretHash("s3cret")
	second := NewSecretHash("s3cret")

	if bytes.Equal(first, second) {
		t.Fatal("two digests of the same secret are identical: the verifier is unsalted (S01-10)")
	}
	if len(first) == sha256.Size {
		t.Fatalf("the digest is still %d raw bytes: a slow hash with parameters must not have the "+
			"shape of a bare SHA-256", len(first))
	}

	encoded := string(first)
	prefix := "$" + secretHashAlgorithm + "$i="
	if !strings.HasPrefix(encoded, prefix) {
		t.Fatalf("digest %q does not start with %q: the algorithm and its parameters must travel with "+
			"the verifier", encoded, prefix)
	}
	salt, dk, iterations, ok := splitSecretHash(first)
	if !ok {
		t.Fatalf("splitSecretHash rejected a verifier NewSecretHash produced: %q", encoded)
	}
	if iterations != secretHashIterations {
		t.Errorf("stored iterations = %d, want %d", iterations, secretHashIterations)
	}
	if iterations < 100_000 {
		t.Errorf("work factor %d is not a slow hash", iterations)
	}
	if len(salt) != secretHashSaltBytes || len(dk) != secretHashKeyBytes {
		t.Errorf("salt/dk = %d/%d bytes, want %d/%d", len(salt), len(dk), secretHashSaltBytes, secretHashKeyBytes)
	}
	// The parameter is genuinely carried, not merely formatted: the encoded value
	// is what a verifier reads back.
	if !strings.Contains(encoded, "$i="+strconv.Itoa(iterations)+"$") {
		t.Errorf("digest %q does not carry i=%d", encoded, iterations)
	}

	c, err := NewClient("cli", "App", ClientConfidential, "s3cret",
		[]string{"https://app.example/cb"}, []Scope{ScopeAccountID})
	if err != nil {
		t.Fatal(err)
	}
	if !c.Authenticate("s3cret") {
		t.Fatal("the client cannot authenticate with its own secret")
	}
	if c.Authenticate("wrong") {
		t.Fatal("the client authenticated a wrong secret")
	}
}

// S01-10: there is no legacy verify path. A bare SHA-256 digest — the old storage
// shape — is refused by both admission points rather than being accepted and then
// unusable. Pre-fix: RestoreClient accepted any 32-byte value and RotateSecret
// stored it, so both checks fail.
func TestS0110LegacyBareDigestIsRefused(t *testing.T) {
	legacy := sha256.Sum256([]byte("s3cret"))

	if validSecretHash(legacy[:]) || ValidSecretHash(legacy[:]) {
		t.Fatal("a bare SHA-256 digest is still treated as a well-formed verifier: the old format " +
			"must not remain verifiable (S01-10)")
	}
	if !ValidSecretHash(NewSecretHash("s3cret")) {
		t.Fatal("ValidSecretHash rejected the encoding NewSecretHash produces: a registry cannot " +
			"validate a rotation with it")
	}

	if _, err := RestoreClient("cli", "App", ClientConfidential, legacy[:],
		[]string{"https://app.example/cb"}, []Scope{ScopeAccountID}, time.Unix(0, 0).UTC()); err == nil {
		t.Fatal("RestoreClient accepted a legacy bare SHA-256 digest")
	}

	reg := NewMemoryClientRegistry()
	ctx := context.Background()
	c, err := NewClient("cli", "App", ClientConfidential, "s3cret",
		[]string{"https://app.example/cb"}, []Scope{ScopeAccountID})
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Create(ctx, c); err != nil {
		t.Fatal(err)
	}
	if err := reg.RotateSecret(ctx, "cli", legacy[:]); err == nil {
		t.Fatal("RotateSecret accepted a legacy bare SHA-256 digest")
	}
	if got, err := reg.Get(ctx, "cli"); err != nil || !got.Authenticate("s3cret") {
		t.Fatalf("a refused legacy rotation changed the client: %v, %v", got.ID, err)
	}

	// And the new encoding is exactly what both admission points accept.
	fresh := NewSecretHash("rotated")
	if err := reg.RotateSecret(ctx, "cli", fresh); err != nil {
		t.Fatalf("a well-formed rotation was refused: %v", err)
	}
	if _, err := RestoreClient("cli", "App", ClientConfidential, fresh,
		[]string{"https://app.example/cb"}, []Scope{ScopeAccountID}, time.Unix(0, 0).UTC()); err != nil {
		t.Fatalf("the stored verifier cannot be restored: %v", err)
	}
}

// S09-4: the Store's ConsumeRefresh contract says the caller judges expiry, and it
// names how the two shipped stores differ. This is a wording contract, so the
// shipped source is read directly, the same way pkce_shape_guard_test.go reads it.
func TestS094ConsumeRefreshContractLeavesExpiryToTheCaller(t *testing.T) {
	src, err := os.ReadFile("tokens.go")
	if err != nil {
		t.Fatalf("cannot read the store source: %v", err)
	}
	source := string(src)

	if strings.Contains(source, "claims a live refresh value") {
		t.Error("the ConsumeRefresh contract still promises a \"live\" value: expiry is the caller's " +
			"decision, not the store's (S09-4)")
	}
	for _, want := range []string{"judged by the", "CALLER", "expires_at"} {
		if !strings.Contains(source, want) {
			t.Errorf("the ConsumeRefresh contract no longer contains %q: it must say who judges expiry "+
				"and name the PG/memory difference", want)
		}
	}
}
