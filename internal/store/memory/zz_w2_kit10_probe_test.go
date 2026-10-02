package memory

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/internal/oidcstore"
	"github.com/Re0Auth/r0semi/oauth"
)

// W2 KIT-10 probe for the OpenID Provider's memory store.
//
// The Postgres registry revokes inside Clients.Delete, but the in-memory client
// registry owns no tokens — its tokens live in this store. NewOIDCStore
// publishes itself to the registry (oauth.TokenRevokerSetter) so the same
// contract holds in a memory deployment without a composition root wiring the
// two together. This probe removes that line and fails, which is the point: it
// pins the wiring, not the store's revocation, which oauth's own tests cover.
func TestW2KIT10MemoryOIDCDeleteClientRevokesTokens(t *testing.T) {
	ctx := context.Background()
	const clientID = "cli_w2_kit10_mem"

	clients := oauth.NewMemoryClientRegistry()
	c, err := oauth.NewClient(clientID, "W2 KIT-10", oauth.ClientPublic, "",
		[]string{"https://app.example/cb"}, []oauth.Scope{oauth.ScopeAccountID})
	if err != nil {
		t.Fatal(err)
	}
	if err := clients.Create(ctx, c); err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewOIDCStore(OIDCOptions{
		Clients:  clients,
		Registry: oauth.DefaultRegistry(),
		Signer:   oidcstore.NewSigner("test", key),
	})
	if err != nil {
		t.Fatal(err)
	}

	// A live access/refresh pair and a pending device authorization: both are
	// capabilities the delete must take away.
	if _, _, _, err := store.CreateAccessAndRefreshTokens(ctx,
		&fakeTokenRequest{subject: "usr_w2_kit10_mem", clientID: clientID}, ""); err != nil {
		t.Fatal(err)
	}
	if err := store.StoreDeviceAuthorization(ctx, clientID, "w2-device-code", "W2DC-1234",
		time.Now().Add(10*time.Minute), []string{"account.id"}); err != nil {
		t.Fatal(err)
	}

	// Vacuity: there is something to revoke.
	store.mu.Lock()
	before := len(store.accessTokens) + len(store.refreshTokens)
	beforeDevices := len(store.devices)
	store.mu.Unlock()
	if before == 0 || beforeDevices == 0 {
		t.Fatalf("vacuity: seeded %d token rows and %d device authorizations", before, beforeDevices)
	}

	if err := clients.Delete(ctx, clientID); err != nil {
		t.Fatal(err)
	}

	store.mu.Lock()
	after := len(store.accessTokens) + len(store.refreshTokens)
	afterDevices := len(store.devices)
	store.mu.Unlock()
	if after != 0 {
		t.Errorf("ClientAdmin.Delete left %d token rows in the OP store", after)
	}
	if afterDevices != 0 {
		t.Errorf("ClientAdmin.Delete left %d device authorizations in the OP store", afterDevices)
	}
	// The delete itself still happened, and repeating it is harmless.
	if _, err := clients.Get(ctx, clientID); err == nil {
		t.Error("the deleted client still resolves")
	}
	if err := clients.Delete(ctx, clientID); err != nil {
		t.Errorf("deleting an absent client failed on retry: %v", err)
	}
}
