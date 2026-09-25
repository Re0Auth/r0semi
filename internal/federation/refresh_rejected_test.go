package federation

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/vault"
)

// revokeBrokenVault fails the revoke half while leaving everything else working.
// It stands in for a KEK the deployment rotated away from: the encrypted secret is
// still there and this path cannot clear it.
type revokeBrokenVault struct {
	vault.Service
	err error
}

func (b revokeBrokenVault) Revoke(context.Context, vault.Identity) error { return b.err }

// When the upstream grant is dead but the secret cannot be revoked, the binding
// must stay: refusing to delete the row keeps the secret reachable by Unbind or the
// kill switch, instead of orphaning a decryptable token nothing can reach.
func TestRefreshRejectedKeepsTheBindingWhenTheSecretCannotBeRevoked(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryBindingStore()
	v := newVault(t)
	b := backend{store: store, vault: v}
	b.bind(t, "usr_1", sourceName, "stale", "rt-1", time.Now().Add(-time.Hour))

	svc := mustService(t, Config{
		Registry: adversaryRegistry(t, "https://unused.example"),
		Doer:     http.DefaultClient, HTTPClient: http.DefaultClient,
		BaseURL: "https://re0auth.test",
	}, backend{
		store: store,
		vault: revokeBrokenVault{Service: v, err: errors.New("vault: KEK is not configured")},
	})

	spent := Binding{User: "usr_1", Game: game, Source: sourceName, Version: 1}
	if _, err := svc.(*service).refreshRejected(ctx, spent); !errors.Is(err, ErrNotBound) {
		t.Fatalf("err = %v, want ErrNotBound", err)
	}
	if _, gerr := store.Get(ctx, "usr_1", game, sourceName); gerr != nil {
		t.Fatalf("the binding was deleted even though its secret could not be revoked: %v", gerr)
	}
}
