package oauth

import (
	"context"
	"errors"
	"testing"
)

// Rotation replaces the digest, so the old secret stops authenticating and the new
// one does. A public client has no secret to rotate, and an unknown id is not
// found — the two failure modes a caller has to tell apart.
func TestRotateSecretReplacesTheDigest(t *testing.T) {
	reg := NewMemoryClientRegistry()
	ctx := context.Background()
	c, err := NewClient("cli", "App", ClientConfidential, "old-secret", []string{"https://a.example/cb"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Create(ctx, c); err != nil {
		t.Fatal(err)
	}

	if err := reg.RotateSecret(ctx, "cli", NewSecretHash("new-secret")); err != nil {
		t.Fatal(err)
	}
	got, err := reg.Get(ctx, "cli")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Authenticate("new-secret") || got.Authenticate("old-secret") {
		t.Fatal("rotation did not replace the secret")
	}
	if err := reg.RotateSecret(ctx, "cli", nil); err == nil {
		t.Fatal("rotation accepted an empty hash")
	}

	pub, err := NewClient("pub", "SPA", ClientPublic, "", []string{"https://a.example/cb"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Create(ctx, pub); err != nil {
		t.Fatal(err)
	}
	if err := reg.RotateSecret(ctx, "pub", NewSecretHash("x")); !errors.Is(err, ErrNoSecretToRotate) {
		t.Fatalf("rotate public = %v, want ErrNoSecretToRotate", err)
	}
	if err := reg.RotateSecret(ctx, "ghost", NewSecretHash("x")); !errors.Is(err, ErrClientNotFound) {
		t.Fatalf("rotate unknown = %v, want ErrClientNotFound", err)
	}
}
