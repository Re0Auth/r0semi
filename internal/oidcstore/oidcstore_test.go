package oidcstore

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"

	"github.com/Re0Auth/r0semi/oauth"
)

// The narrowing rule is shared by both OP stores; if it regressed, two engines
// would enforce two different consent rules. It is tested here rather than
// through either adapter.
func TestNarrowScopesCannotWiden(t *testing.T) {
	requested := []string{"account.id", "phigros.score.read"}

	got, err := NarrowScopes(requested, []oauth.Scope{oauth.ScopeAccountID})
	if err != nil {
		t.Fatalf("narrowing rejected: %v", err)
	}
	if len(got) != 1 || got[0] != "account.id" {
		t.Fatalf("narrowed = %v", got)
	}

	if _, err := NarrowScopes(requested, []oauth.Scope{oauth.ScopePhigrosB30}); err == nil {
		t.Fatal("widening approval accepted")
	} else {
		var oe *oauth.Error
		if !errors.As(err, &oe) || oe.Code != "invalid_scope" {
			t.Fatalf("error = %v, want invalid_scope", err)
		}
	}
}

func TestNarrowScopesEmptyMeansEverythingRequested(t *testing.T) {
	requested := []string{"account.id", "phigros.score.read"}
	got, err := NarrowScopes(requested, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %v, want the full request", got)
	}
}

// An explicit empty approval is "grant nothing" and must be refused, not
// silently upgraded to the full request. Only an omitted field (nil) means
// "everything requested".
func TestNarrowScopesExplicitEmptyIsRefused(t *testing.T) {
	requested := []string{"account.id", "phigros.score.read"}
	if _, err := NarrowScopes(requested, []oauth.Scope{}); err == nil {
		t.Fatal("an explicit empty approval was accepted as the full request")
	} else {
		var oe *oauth.Error
		if !errors.As(err, &oe) || oe.Code != "invalid_request" {
			t.Fatalf("error = %v, want invalid_request", err)
		}
	}
}

// A signing key set that cannot produce verifiable id_tokens must be refused at
// startup rather than served: no key, too-small RSA, or duplicate kids.
func TestValidateSigner(t *testing.T) {
	good, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	retired, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	if err := ValidateSigner(NewSigner("kid", good)); err != nil {
		t.Fatalf("valid signer refused: %v", err)
	}
	if err := ValidateSigner(NewSigner("kid", small)); err == nil {
		t.Fatal("a 1024-bit signing key was accepted")
	}
	if err := ValidateSigner(NewSigner("", good)); err == nil {
		t.Fatal("an empty signing key id was accepted")
	}
	if err := ValidateSigner(NewSigner("kid", good).WithRetired(RetiredSigningKey{ID: "kid", Public: &retired.PublicKey})); err == nil {
		t.Fatal("a duplicate kid was accepted")
	}
	if err := ValidateSigner(NewSigner("kid", good).WithRetired(RetiredSigningKey{ID: "old", Public: &retired.PublicKey})); err != nil {
		t.Fatalf("a valid retired key was refused: %v", err)
	}
}

func TestRequireExplicitConsent(t *testing.T) {
	critical := oauth.Descriptor{
		Scope: "phigros.score.write", Title: "Write", ExplicitConsent: true,
	}
	plain := oauth.Descriptor{Scope: oauth.ScopeAccountID, Title: "Account"}

	if err := RequireExplicitConsent([]oauth.Descriptor{plain}, nil); err != nil {
		t.Fatalf("non-critical scope demanded consent: %v", err)
	}
	if err := RequireExplicitConsent([]oauth.Descriptor{critical}, nil); err == nil {
		t.Fatal("critical scope accepted without an explicit tick")
	}
	if err := RequireExplicitConsent([]oauth.Descriptor{critical}, []oauth.Scope{"phigros.score.write"}); err != nil {
		t.Fatalf("explicit consent rejected: %v", err)
	}
}

func TestOfflineAccessIsInternalOnly(t *testing.T) {
	with := WithOfflineAccess([]string{"account.id"})
	if !HasScope(with, "offline_access") {
		t.Fatalf("WithOfflineAccess did not add the scope: %v", with)
	}
	// Calling it twice must not duplicate the scope.
	again := WithOfflineAccess(with)
	if len(again) != len(with) {
		t.Fatalf("WithOfflineAccess duplicated offline_access: %v", again)
	}
	clean := WithoutOfflineAccess(again)
	if HasScope(clean, "offline_access") || len(clean) != 1 || clean[0] != "account.id" {
		t.Fatalf("WithoutOfflineAccess = %v", clean)
	}
}

// A rotated signing key must stay in the JWKS so id_tokens signed with it still
// verify. This is the shared signer both OP stores use.
func TestSignerKeySetIncludesRetired(t *testing.T) {
	current, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	old, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keys := NewSigner("cur", current).
		WithRetired(RetiredSigningKey{ID: "old", Public: &old.PublicKey}).
		KeySet()
	if len(keys) != 2 {
		t.Fatalf("keys = %d, want 2", len(keys))
	}
	if keys[0].ID() != "cur" || keys[1].ID() != "old" {
		t.Fatalf("key order = %s,%s", keys[0].ID(), keys[1].ID())
	}
}
