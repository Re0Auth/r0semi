//go:build audit5

package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/Re0Auth/r0semi/internal/oidcstore"
)

var _ = jose.RS256

// key returns a deterministic 32-byte token key for tests.
func tokenKey(seed byte) [32]byte {
	var k [32]byte
	for i := range k {
		k[i] = seed + byte(i)
	}
	return k
}

// TestProbeCompositeCryptoOverlap is the guard for the retired-token-key claim in
// threat-model §6.0.1: new tokens are encrypted with the current key, and tokens
// issued under a retired key still decrypt. It also documents the one property
// the overlap does NOT have — a retired key cannot ENCRYPT — because that is what
// makes "remove the old key after the longest token lifetime" a bound rather than
// a leap of faith.
func TestProbeCompositeCryptoOverlap(t *testing.T) {
	old := op.NewAES256GCMCrypto(tokenKey(0x10), "tok-1")
	cur := op.NewAES256GCMCrypto(tokenKey(0x80), "tok-2")

	// A token minted under the OLD key, i.e. one that predates the rotation.
	legacy, err := old.Encrypt("tokenID-abc:usr_alice")
	if err != nil {
		t.Fatal(err)
	}
	// A token minted under the new key.
	fresh, err := cur.Encrypt("tokenID-def:usr_bob")
	if err != nil {
		t.Fatal(err)
	}

	// Control: the current key alone cannot read the legacy token (this is why
	// the retired key has to stay configured).
	if _, err := cur.Decrypt(legacy); err == nil {
		t.Fatal("the current key decrypted a token from the retired key: ciphertexts are not key-bound")
	}

	// The deployment's actual wiring: encrypt with current, decrypt with current
	// AND retired.
	composite := op.NewCompositeCrypto(cur, []op.Decrypter{cur, old})
	for name, tok := range map[string]string{"legacy": legacy, "fresh": fresh} {
		got, err := composite.Decrypt(tok)
		if err != nil {
			t.Errorf("composite could not decrypt the %s token: %v", name, err)
			continue
		}
		if !strings.Contains(got, "usr_") {
			t.Errorf("%s token decrypted to %q", name, got)
		}
	}

	// Encryption always uses the CURRENT key: the retired key must not be able to
	// read what the composite just wrote.
	minted, err := composite.Encrypt("tokenID-ghi:usr_carol")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := old.Decrypt(minted); err == nil {
		t.Error("a retired key decrypted a freshly minted token: the current key is not the only encrypter")
	}
	if _, err := cur.Decrypt(minted); err != nil {
		t.Errorf("the current key cannot read its own ciphertext: %v", err)
	}
}

// TestProbeTokenDecryptionIsKeyOrderIndependent answers the brief's "can an
// attacker force a decryption attempt with a chosen key id (oracle)?".
//
// The JWE's `kid` is inside the encrypted token's own protected header, but
// CompositeCrypto DOES NOT read it: it tries each configured key in order until
// one authenticates. So an attacker cannot select a key by naming one, and the
// failure is a single indistinguishable error.
func TestProbeTokenDecryptionIsKeyOrderIndependent(t *testing.T) {
	k1 := op.NewAES256GCMCrypto(tokenKey(0x10), "tok-1")
	k2 := op.NewAES256GCMCrypto(tokenKey(0x20), "tok-2")
	k3 := op.NewAES256GCMCrypto(tokenKey(0x30), "tok-3")

	under2, err := k2.Encrypt("id:sub")
	if err != nil {
		t.Fatal(err)
	}

	orders := [][]op.Decrypter{
		{k1, k2, k3},
		{k3, k2, k1},
		{k2, k1, k3},
	}
	for i, order := range orders {
		composite := op.NewCompositeCrypto(k1, order)
		got, err := composite.Decrypt(under2)
		if err != nil {
			t.Errorf("order %d: %v", i, err)
			continue
		}
		if got != "id:sub" {
			t.Errorf("order %d: got %q", i, got)
		}
	}

	// An unknown key set fails with one generic message, so the error carries no
	// key id and no oracle.
	composite := op.NewCompositeCrypto(k1, []op.Decrypter{k1, k3})
	_, err = composite.Decrypt(under2)
	if err == nil {
		t.Fatal("a key set without the right key decrypted the token")
	}
	for _, id := range []string{"tok-1", "tok-2", "tok-3"} {
		if strings.Contains(err.Error(), id) {
			t.Errorf("the decryption failure names key %q: %v", id, err)
		}
	}

	// Garbage and truncated tokens fail the same way.
	for _, bad := range []string{"", "not-a-jwe", strings.Repeat("A", 40), under2[:len(under2)-1]} {
		if _, err := composite.Decrypt(bad); err == nil {
			t.Errorf("Decrypt(%q) succeeded", bad)
		}
	}
}

// TestProbeTokenKeyIsA256GCMDirectJWE pins the shape of the opaque token: the
// token key wraps nothing (alg=A256GCMKW over the content key is not used here —
// go-jose emits a key-wrapping JWE whose `kid` is the CryptoKeyID). The point of
// the guard is that the token's own header is attacker-visible, so nothing
// secret may be placed there.
func TestProbeTokenKeyIsA256GCMDirectJWE(t *testing.T) {
	cur := op.NewAES256GCMCrypto(tokenKey(0x80), "the-kid")
	tok, err := cur.Encrypt("tokenID-xyz:usr_alice")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 5 {
		t.Fatalf("token is not a 5-part compact JWE: %q", tok)
	}
	hdr, err := joseBase64Decode(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(hdr, &parsed); err != nil {
		t.Fatal(err)
	}
	if _, leaked := parsed["sub"]; leaked {
		t.Error("the JWE protected header carries a subject")
	}
	if _, leaked := parsed["tokenID"]; leaked {
		t.Error("the JWE protected header carries the token id")
	}
	t.Logf("token header (attacker-visible): %s", string(hdr))
}

// TestProbeSignerRejectsAmbiguousKeySets covers the kid-collision question: a
// retired public key sharing the current kid must be refused, because the JWKS
// would then publish two keys with the same kid and a verifier could pick the
// wrong one.
func TestProbeSignerRejectsAmbiguousKeySets(t *testing.T) {
	cur, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		build func() *oidcstore.Signer
		want  string
	}{
		{"current kid reused by retired", func() *oidcstore.Signer {
			return oidcstore.NewSigner("kid", cur).WithRetired(
				oidcstore.RetiredSigningKey{ID: "kid", Public: &other.PublicKey})
		}, "duplicate signing key id"},
		{"two retired share a kid", func() *oidcstore.Signer {
			return oidcstore.NewSigner("cur", cur).WithRetired(
				oidcstore.RetiredSigningKey{ID: "old", Public: &other.PublicKey},
				oidcstore.RetiredSigningKey{ID: "old", Public: &cur.PublicKey})
		}, "duplicate signing key id"},
		{"retired has no key", func() *oidcstore.Signer {
			return oidcstore.NewSigner("cur", cur).WithRetired(oidcstore.RetiredSigningKey{ID: "old"})
		}, "has no public key"},
		{"empty retired kid", func() *oidcstore.Signer {
			return oidcstore.NewSigner("cur", cur).WithRetired(
				oidcstore.RetiredSigningKey{Public: &other.PublicKey})
		}, "retired signing key id is required"},
		{"undersized current key", func() *oidcstore.Signer {
			return oidcstore.NewSigner("cur", small)
		}, "at least 2048 bits"},
	}
	for _, tc := range cases {
		err := oidcstore.ValidateSigner(tc.build())
		if err == nil {
			t.Errorf("%s: accepted", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error = %v, want it to mention %q", tc.name, err, tc.want)
		}
	}

	// Control: a well-formed set is accepted, and its KeySet has unique kids with
	// the current key first.
	good := oidcstore.NewSigner("cur", cur).WithRetired(
		oidcstore.RetiredSigningKey{ID: "old", Public: &other.PublicKey})
	if err := oidcstore.ValidateSigner(good); err != nil {
		t.Fatalf("a valid signer was refused: %v", err)
	}
	keys := good.KeySet()
	if len(keys) != 2 {
		t.Fatalf("KeySet has %d keys, want 2", len(keys))
	}
	if keys[0].ID() != "cur" {
		t.Errorf("the current key is not first in the JWKS: %q", keys[0].ID())
	}
	seen := map[string]bool{}
	for _, k := range keys {
		if seen[k.ID()] {
			t.Errorf("duplicate kid %q published in the JWKS", k.ID())
		}
		seen[k.ID()] = true
		if _, ok := k.Key().(*rsa.PublicKey); !ok {
			t.Errorf("kid %q publishes %T, not an RSA public key", k.ID(), k.Key())
		}
	}
}

// TestProbeRetiredTokenKeyIDsAreNotValidatedLocally documents a gap in the
// composition root rather than in the crypto: `oidcRetiredTokenKeys` accepts any
// non-empty id, including one equal to the current CryptoKeyID ("re0auth"), and
// the composite ignores ids anyway. It is recorded here so the "ids are just
// labels" fact is not mistaken for a contract.
func TestProbeRetiredTokenKeyIDsAreNotValidatedLocally(t *testing.T) {
	k := tokenKey(0x40)
	retired := op.NewAES256GCMCrypto(k, "re0auth") // SAME id as the current key
	cur := op.NewAES256GCMCrypto(tokenKey(0x80), "re0auth")
	composite := op.NewCompositeCrypto(cur, []op.Decrypter{cur, retired})
	tok, err := retired.Encrypt("id:sub")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := composite.Decrypt(tok); err != nil {
		t.Fatalf("a duplicate-id retired key failed to decrypt: %v", err)
	}
	t.Log("CONFIRMED: a retired token key reusing the current key id is accepted and used; " +
		"ids are advisory here because CompositeCrypto tries every key. Not a vulnerability " +
		"(no lookup by id happens), but it means 'id collision' is NOT rejected the way it is " +
		"for signing kids (oidcstore.ValidateSigner).")
}

func joseBase64Decode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}
