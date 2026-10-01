package oauth

import (
	"context"
	"testing"
	"time"
)

// The PKCE exemption is opt-in and cannot be reached by omission. Every
// construction path that does not name it keeps the mandatory-PKCE default.

func TestPKCEDefaultsToRequired(t *testing.T) {
	c, err := NewClient("cli", "CLI", ClientConfidential, "s3cret",
		[]string{"https://app.example/cb"}, []Scope{ScopeAccountID})
	if err != nil {
		t.Fatal(err)
	}
	if c.AllowMissingPKCE {
		t.Fatal("NewClient granted the PKCE exemption by default")
	}
}

func TestWithAllowMissingPKCECopies(t *testing.T) {
	c, err := NewClient("cli", "CLI", ClientConfidential, "s3cret",
		[]string{"https://app.example/cb"}, []Scope{ScopeAccountID})
	if err != nil {
		t.Fatal(err)
	}
	exempt := c.WithAllowMissingPKCE(true)
	if !exempt.AllowMissingPKCE {
		t.Fatal("WithAllowMissingPKCE(true) did not set the flag")
	}
	if c.AllowMissingPKCE {
		t.Fatal("WithAllowMissingPKCE mutated its receiver")
	}
	// Everything else survives the copy.
	if exempt.ID != c.ID || exempt.Type != c.Type || !exempt.AllowsRedirect("https://app.example/cb") ||
		!exempt.Authenticate("s3cret") {
		t.Fatalf("WithAllowMissingPKCE lost fields: %+v", exempt)
	}
	if back := exempt.WithAllowMissingPKCE(false); back.AllowMissingPKCE {
		t.Fatal("WithAllowMissingPKCE(false) did not clear the flag")
	}
}

func TestRestoreClientDoesNotGrantTheExemption(t *testing.T) {
	c, err := RestoreClientWithStatus("cli", "CLI", ClientConfidential, ClientActive,
		NewSecretHash("s3cret"), []string{"https://app.example/cb"}, []Scope{ScopeAccountID}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if c.AllowMissingPKCE {
		t.Fatal("RestoreClientWithStatus granted the PKCE exemption from an old row")
	}
}

func TestMemoryRegistryRoundTripsTheExemption(t *testing.T) {
	c, err := NewClient("cli", "CLI", ClientConfidential, "s3cret",
		[]string{"https://app.example/cb"}, []Scope{ScopeAccountID})
	if err != nil {
		t.Fatal(err)
	}
	reg := NewMemoryClientRegistry()
	if err := reg.Create(context.Background(), c.WithAllowMissingPKCE(true)); err != nil {
		t.Fatal(err)
	}
	got, err := reg.Get(context.Background(), "cli")
	if err != nil {
		t.Fatal(err)
	}
	if !got.AllowMissingPKCE {
		t.Fatal("the registry dropped the PKCE exemption")
	}
}
