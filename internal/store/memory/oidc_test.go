package memory

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/Re0Auth/r0semi/internal/oidcstore"
	"github.com/Re0Auth/r0semi/oauth"
)

// The memory store is what makes memory mode a real OpenID Provider, so it must
// satisfy the same interfaces the Postgres store does. These assertions fail at
// compile time if a method drifts.
var (
	_ op.Storage                    = (*OIDCStore)(nil)
	_ op.DeviceAuthorizationStorage = (*OIDCStore)(nil)
	_ oauth.TokenAdmin              = (*OIDCStore)(nil)
)

func testStore(t *testing.T) (*OIDCStore, *oauth.Client) {
	t.Helper()
	clients := oauth.NewMemoryClientRegistry()
	c, err := oauth.NewClient("cli", "CLI", oauth.ClientPublic, "",
		[]string{"https://app.example/cb"},
		[]oauth.Scope{oauth.ScopeAccountID, oauth.ScopePhigrosScore})
	if err != nil {
		t.Fatal(err)
	}
	if err := clients.Create(context.Background(), c); err != nil {
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
	return store, &c
}

func TestDeviceDecisionNarrowsAndCannotWiden(t *testing.T) {
	store, _ := testStore(t)
	ctx := context.Background()
	expires := time.Now().Add(10 * time.Minute)
	if err := store.StoreDeviceAuthorization(ctx, "cli", "device-code", "BCDF-GHJK", expires,
		[]string{"account.id", "phigros.score.read"}); err != nil {
		t.Fatal(err)
	}

	// A widening decision is refused before anything is written.
	if err := store.DecideDeviceAuthorization(ctx, "BCDF-GHJK", "usr_1", true,
		[]oauth.Scope{oauth.ScopePhigrosB30}, nil); err == nil {
		t.Fatal("widening device decision accepted")
	}

	if err := store.DecideDeviceAuthorization(ctx, "BCDF-GHJK", "usr_1", true,
		[]oauth.Scope{oauth.ScopeAccountID}, nil); err != nil {
		t.Fatal(err)
	}
	st, err := store.DeviceByUserCode(ctx, "bcdf-ghjk") // case- and dash-insensitive
	if err != nil {
		t.Fatalf("user code lookup is not separator-insensitive: %v", err)
	}
	if !st.Done || st.Subject != "usr_1" {
		t.Fatalf("device state = %+v", st)
	}
	if !oidcstore.HasScope(st.Scopes, "account.id") || !oidcstore.HasScope(st.Scopes, oidc.ScopeOfflineAccess) {
		t.Fatalf("approved scopes = %v", st.Scopes)
	}
	// The decision narrowed the request: the score scope is gone.
	if oidcstore.HasScope(st.Scopes, "phigros.score.read") {
		t.Fatalf("narrowing did not drop phigros.score.read: %v", st.Scopes)
	}
}

func TestUnknownDeviceCodeIsNotFound(t *testing.T) {
	store, _ := testStore(t)
	if _, err := store.DescribeDeviceAuthorization(context.Background(), "NOPE-NOPE"); err != oauth.ErrDeviceNotFound {
		t.Fatalf("err = %v, want ErrDeviceNotFound", err)
	}
}

func TestGrantsAreDerivedFromTokensAndRevocable(t *testing.T) {
	store, _ := testStore(t)
	ctx := context.Background()

	req := &oidcstore.AuthRequest{
		ClientID: "cli", Subject: "usr_1",
		Scopes: []string{"account.id"},
	}
	if _, _, _, err := store.CreateAccessAndRefreshTokens(ctx, req, ""); err != nil {
		t.Fatal(err)
	}

	grants, err := store.Grants(ctx, "usr_1")
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 1 || grants[0].ClientID != "cli" || !grants[0].HasRefresh {
		t.Fatalf("grants = %+v", grants)
	}

	// Revoking the client is deleting its tokens, so the grant disappears.
	if err := store.RevokeGrant(ctx, "usr_1", "cli"); err != nil {
		t.Fatal(err)
	}
	if grants, _ := store.Grants(ctx, "usr_1"); len(grants) != 0 {
		t.Fatalf("grant survived revocation: %+v", grants)
	}
}

func TestRevokeTokensCountsBothTables(t *testing.T) {
	store, _ := testStore(t)
	ctx := context.Background()
	req := &oidcstore.AuthRequest{ClientID: "cli", Subject: "usr_1", Scopes: []string{"account.id"}}
	if _, _, _, err := store.CreateAccessAndRefreshTokens(ctx, req, ""); err != nil {
		t.Fatal(err)
	}
	n, err := store.RevokeTokens(ctx, oauth.TokenFilter{Subject: "usr_1"})
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("revoked = %d, want access + refresh = 2", n)
	}
}
