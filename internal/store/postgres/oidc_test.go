package postgres

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/oauth"
)

func oidcFixture(t *testing.T) (*OIDCStore, *audit.MemoryLogger, context.Context) {
	t.Helper()
	db := openTestDB(t)
	ctx := context.Background()

	web, err := oauth.NewClient("oidc-web", "Web", oauth.ClientConfidential, "s3cret",
		[]string{"https://client.example/cb"},
		[]oauth.Scope{oauth.ScopeAccountID, oauth.ScopePhigrosScore})
	if err != nil {
		t.Fatal(err)
	}
	device, err := oauth.NewClient("oidc-device", "Device", oauth.ClientPublic, "",
		[]string{"https://device.example/cb"},
		[]oauth.Scope{oauth.ScopeAccountID, oauth.ScopePhigrosScore})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []oauth.Client{web, device} {
		if err := db.Clients().Create(ctx, c); err != nil {
			t.Fatal(err)
		}
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	logger := audit.NewMemoryLogger()
	store, err := db.OIDC(db.Clients(), OIDCOptions{
		Registry: oauth.DefaultRegistry(),
		Signer:   NewOIDCSigner("test-key", key),
		Audit:    logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	return store, logger, ctx
}

func newAuthRequest(t *testing.T, ctx context.Context, store *OIDCStore) op.AuthRequest {
	t.Helper()
	ar, err := store.CreateAuthRequest(ctx, &oidc.AuthRequest{
		ClientID:            "oidc-web",
		RedirectURI:         "https://client.example/cb",
		ResponseType:        oidc.ResponseTypeCode,
		Scopes:              []string{"account.id", "phigros.score.read"},
		State:               "state-1234567890",
		CodeChallenge:       "challenge",
		CodeChallengeMethod: oidc.CodeChallengeMethodS256,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	return ar
}

// The client seam: our registry drives op.Client, IsScopeAllowed consults our
// scope catalog, and client auth uses oauth.Client.Authenticate (SHA-256).
func TestOIDCClientSeam(t *testing.T) {
	store, _, ctx := oidcFixture(t)

	c, err := store.GetClientByClientID(ctx, "oidc-web")
	if err != nil {
		t.Fatal(err)
	}
	if c.GetID() != "oidc-web" || c.AuthMethod() != oidc.AuthMethodBasic {
		t.Fatalf("client adapter wrong: %s / %s", c.GetID(), c.AuthMethod())
	}
	scopeGate := c.(interface{ IsScopeAllowed(string) bool })
	if !scopeGate.IsScopeAllowed("account.id") {
		t.Fatal("known scope rejected")
	}
	if scopeGate.IsScopeAllowed("not.a.scope") {
		t.Fatal("unknown scope allowed")
	}

	if err := store.AuthorizeClientIDSecret(ctx, "oidc-web", "s3cret"); err != nil {
		t.Fatalf("correct secret rejected: %v", err)
	}
	if err := store.AuthorizeClientIDSecret(ctx, "oidc-web", "wrong"); err == nil {
		t.Fatal("wrong secret accepted")
	}
}

// The consent record: round-trips, and scopes can be narrowed before the code
// is issued.
func TestOIDCAuthRequestRoundTripAndNarrowing(t *testing.T) {
	store, _, ctx := oidcFixture(t)
	ar := newAuthRequest(t, ctx, store)
	id := ar.GetID()

	loaded, err := store.AuthRequestByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.GetScopes()) != 2 || loaded.Done() {
		t.Fatalf("fresh request = %v done=%v", loaded.GetScopes(), loaded.Done())
	}
	if loaded.GetCodeChallenge() == nil || loaded.GetCodeChallenge().Method != oidc.CodeChallengeMethodS256 {
		t.Fatalf("code challenge lost: %+v", loaded.GetCodeChallenge())
	}

	// The consent screen approves only account.id.
	if err := store.CompleteLogin(ctx, id, "usr_1", []string{"account.id"}); err != nil {
		t.Fatal(err)
	}
	loaded, err = store.AuthRequestByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Done() || loaded.GetSubject() != "usr_1" {
		t.Fatalf("request not completed: done=%v subject=%q", loaded.Done(), loaded.GetSubject())
	}
	if len(loaded.GetScopes()) != 1 || loaded.GetScopes()[0] != "account.id" {
		t.Fatalf("scopes not narrowed: %v", loaded.GetScopes())
	}
}

// Code -> token -> refresh -> introspect -> revoke, with an audit trail.
func TestOIDCTokenLifecycle(t *testing.T) {
	store, logger, ctx := oidcFixture(t)
	ar := newAuthRequest(t, ctx, store)
	if err := store.CompleteLogin(ctx, ar.GetID(), "usr_1", []string{"account.id"}); err != nil {
		t.Fatal(err)
	}
	ar, err := store.AuthRequestByID(ctx, ar.GetID())
	if err != nil {
		t.Fatal(err)
	}

	accessID, refresh, expires, err := store.CreateAccessAndRefreshTokens(ctx, ar, "")
	if err != nil {
		t.Fatal(err)
	}
	if accessID == "" || refresh == "" || !expires.After(time.Now()) {
		t.Fatalf("tokens = %q / %q / %v", accessID, refresh, expires)
	}

	// Refresh lookup returns the original grant, with narrowed scopes.
	rr, err := store.TokenRequestByRefreshToken(ctx, refresh)
	if err != nil {
		t.Fatal(err)
	}
	if rr.GetSubject() != "usr_1" || rr.GetClientID() != "oidc-web" {
		t.Fatalf("refresh grant = %s / %s", rr.GetSubject(), rr.GetClientID())
	}
	if len(rr.GetScopes()) != 1 || rr.GetScopes()[0] != "account.id" {
		t.Fatalf("refresh scopes = %v", rr.GetScopes())
	}

	// Introspection is by token ID; only its hash is at rest.
	intro := &oidc.IntrospectionResponse{}
	if err := store.SetIntrospectionFromToken(ctx, intro, accessID, "usr_1", "oidc-web"); err != nil {
		t.Fatal(err)
	}
	if !intro.Active || intro.ClientID != "oidc-web" || intro.Subject != "usr_1" {
		t.Fatalf("introspection = %+v", intro)
	}
	if len(intro.Scope) != 1 || intro.Scope[0] != "account.id" {
		t.Fatalf("introspection scopes = %v", intro.Scope)
	}

	// Revoking the access token makes introspection fail.
	if oidcErr := store.RevokeToken(ctx, accessID, "usr_1", "oidc-web"); oidcErr != nil {
		t.Fatalf("revoke: %v", oidcErr)
	}
	if err := store.SetIntrospectionFromToken(ctx, &oidc.IntrospectionResponse{}, accessID, "usr_1", "oidc-web"); err == nil {
		t.Fatal("revoked token still introspects")
	}

	// A revoke from the wrong client is refused.
	if oidcErr := store.RevokeToken(ctx, refresh, "usr_1", "someone-else"); oidcErr == nil {
		t.Fatal("wrong client allowed to revoke")
	}

	var tokenEvents int
	for _, e := range logger.Events() {
		if e.Action == "oidc.token" {
			tokenEvents++
		}
	}
	if tokenEvents == 0 {
		t.Fatal("token issuance was not audited")
	}
}

// The RFC 8628 device flow storage.
func TestOIDCDeviceFlow(t *testing.T) {
	store, _, ctx := oidcFixture(t)
	expires := time.Now().Add(5 * time.Minute)

	if err := store.StoreDeviceAuthorization(ctx, "oidc-device", "dev-code-1", "BCDF-GHJK", expires,
		[]string{"account.id", "phigros.score.read"}); err != nil {
		t.Fatal(err)
	}

	st, err := store.GetDeviceAuthorizatonState(ctx, "oidc-device", "dev-code-1")
	if err != nil {
		t.Fatal(err)
	}
	if st.Done || st.Denied || len(st.Scopes) != 2 {
		t.Fatalf("fresh device state = %+v", st)
	}

	// User-code lookup is case- and separator-insensitive.
	if _, err := store.DeviceByUserCode(ctx, "bcdfghjk"); err != nil {
		t.Fatalf("user code lookup: %v", err)
	}

	// Approval narrows the scopes.
	if err := store.ApproveDevice(ctx, "bcdf-ghjk", "usr_1", []string{"account.id"}); err != nil {
		t.Fatal(err)
	}
	st, err = store.GetDeviceAuthorizatonState(ctx, "oidc-device", "dev-code-1")
	if err != nil {
		t.Fatal(err)
	}
	if !st.Done || st.Subject != "usr_1" || len(st.Scopes) != 1 {
		t.Fatalf("approved device state = %+v", st)
	}

	// A device authorization is a TokenRequest, so tokens can be issued from it.
	accessID, _, err := store.CreateAccessToken(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	if accessID == "" {
		t.Fatal("no access token issued from device state")
	}

	// A duplicate user code is rejected with the sentinel.
	err = store.StoreDeviceAuthorization(ctx, "oidc-device", "dev-code-2", "BCDF-GHJK", expires, nil)
	if !errors.Is(err, op.ErrDuplicateUserCode) {
		t.Fatalf("duplicate user code = %v, want ErrDuplicateUserCode", err)
	}
}
