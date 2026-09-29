//go:build audit || audit6

package oidcstore

// Round-6 audit probe (crypto/key-management area): the signing-key rotation the
// docs advertise (docs/threat-model.md:154, docs/operations.md:163,
// config/re0auth.example.toml:194-195) cannot actually publish the old key under
// the kid the old id_tokens carry.
//
// TEST-ONLY: reads the exported surface (NewSigner, WithRetired, ValidateSigner,
// KeySet) plus go-jose, mirroring what pkg/op/keys.go:35-45 publishes.
//
// Write-up: C:\git\r0semi\_audit\crypto-vault.md

import (
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
)

func auditRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// auditJWKS mirrors pkg/op/keys.go:35-45 —the document served at /oauth/keys.
func auditJWKS(keys []opKeySet) jose.JSONWebKeySet {
	var out jose.JSONWebKeySet
	for _, k := range keys {
		out.Keys = append(out.Keys, jose.JSONWebKey{
			KeyID:     k.id,
			Algorithm: k.alg,
			Use:       "sig",
			Key:       k.key,
		})
	}
	return out
}

type opKeySet struct {
	id  string
	alg string
	key any
}

func auditKeySet(s *Signer) []opKeySet {
	out := make([]opKeySet, 0, 1+len(s.retired))
	out = append(out, opKeySet{id: s.ID(), alg: string(s.SignatureAlgorithm()), key: s.Key()})
	for _, r := range s.retired {
		out = append(out, opKeySet{id: r.ID, alg: string(jose.RS256), key: r.Public})
	}
	return out
}

// TestAuditSigningKeyRotationCannotKeepTheOldKid is the finding, in two halves.
//
// Half one: the composition root hardcodes the current kid —// cmd/re0auth/main.go:1284 `oidcstore.NewSigner("re0auth", key)` —so the kid a
// given key material is published under is a constant, not a property of the key.
// Every id_token signed before a rotation therefore carries kid="re0auth"
// (pkg/op/signer.go:22 puts SigningKey.ID() into the JWS header).
//
// Half two: ValidateSigner refuses a retired key with the same kid
// (oidcstore.go:71-83), so after the rotation the old key can only be published
// under a DIFFERENT kid. The JWKS then answers kid="re0auth" with the NEW key,
// and a verifier that selects by kid —the only thing a kid is for, and what the
// OP library itself does at pkg/op/op.go:507-508 —rejects every id_token issued
// before the rotation for as long as the overlap lasts.
func TestAuditSigningKeyRotationCannotKeepTheOldKid(t *testing.T) {
	oldKey := auditRSAKey(t)
	newKey := auditRSAKey(t)

	// Half one: the kid the previous deployment published and signed under.
	const kid = "re0auth" // cmd/re0auth/main.go:1284

	// An id_token issued before the rotation: signed by oldKey, header kid=kid.
	oldSigner, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: oldKey},
		(&jose.SignerOptions{}).WithHeader(jose.HeaderKey("kid"), kid),
	)
	if err != nil {
		t.Fatal(err)
	}
	oldToken, err := oldSigner.Sign([]byte(`{"sub":"usr_alice"}`))
	if err != nil {
		t.Fatal(err)
	}
	serialized, err := oldToken.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}

	// The operator's attempt to keep the old public key published under the kid
	// the old tokens carry. ValidateSigner is what main.go:1285 runs.
	dup := NewSigner(kid, newKey).
		WithRetired(RetiredSigningKey{ID: kid, Public: &oldKey.PublicKey})
	if err := ValidateSigner(dup); err == nil {
		t.Fatal("ValidateSigner accepted a retired key reusing the current kid; the premise of " +
			"this probe (the old kid cannot be kept) is wrong")
	} else if !strings.Contains(err.Error(), "duplicate signing key id") {
		t.Fatalf("ValidateSigner rejected the pair for an unexpected reason: %v", err)
	}

	// What the operator must do instead: a different kid for the old key.
	rotated := NewSigner(kid, newKey).
		WithRetired(RetiredSigningKey{ID: "re0auth-old", Public: &oldKey.PublicKey})
	if err := ValidateSigner(rotated); err != nil {
		t.Fatalf("control: the accepted rotation shape was refused: %v", err)
	}
	jwks := auditJWKS(auditKeySet(rotated))
	if len(jwks.Keys) != 2 {
		t.Fatalf("jwks has %d keys, want 2", len(jwks.Keys))
	}
	ids := []string{jwks.Keys[0].KeyID, jwks.Keys[1].KeyID}
	t.Logf("published kids after the rotation: %v", ids)

	// The verifier side: kid-based selection, which is what the kid exists for.
	parsed, err := jose.ParseSigned(serialized, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatal(err)
	}
	if got := parsed.Signatures[0].Header.KeyID; got != kid {
		t.Fatalf("old id_token kid = %q, want %q", got, kid)
	}
	selected := jwks.Key(parsed.Signatures[0].Header.KeyID)
	if len(selected) != 1 {
		t.Fatalf("kid-based selection returned %d keys", len(selected))
	}
	if _, err := parsed.Verify(selected[0]); err == nil {
		t.Fatal("the rotated JWKS verified the old id_token: the finding does not reproduce")
	}
	t.Logf("CONFIRMED: kid=%q now resolves to the NEW key, so the old id_token fails to verify "+
		"(%v); the retired key is published under kid=%q, which no outstanding token carries. "+
		"The documented signing-key rotation therefore breaks verification of every id_token "+
		"issued before it, for the whole overlap window.", kid, err, ids[1])
}
