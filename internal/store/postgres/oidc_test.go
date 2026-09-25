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
	"github.com/Re0Auth/r0semi/internal/oidcstore"
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
		Signer:   oidcstore.NewSigner("test-key", key),
		Audit:    logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	return store, logger, ctx
}

// Rotation must be a claim, not a check: two requests holding the same refresh
// token must not both be issued a new generation. Here the claim is the row the
// DELETE removes, and the row count is what makes it exclusive — so the second
// caller finds nothing and is refused. Mirrors
// memory.TestRefreshTokenRotationIsSingleUse.
func TestRefreshTokenRotationIsSingleUse(t *testing.T) {
	store, _, ctx := oidcFixture(t)
	req := &oidcstore.AuthRequest{ClientID: "oidc-web", Subject: "usr_1", Scopes: []string{"account.id"}}

	_, first, _, err := store.CreateAccessAndRefreshTokens(ctx, req, "")
	if err != nil {
		t.Fatal(err)
	}
	held1, err := store.TokenRequestByRefreshToken(ctx, first)
	if err != nil {
		t.Fatal(err)
	}
	held2, err := store.TokenRequestByRefreshToken(ctx, first)
	if err != nil {
		t.Fatal(err)
	}

	if _, _, _, err := store.CreateAccessAndRefreshTokens(ctx, held1, first); err != nil {
		t.Fatalf("the first rotation was refused: %v", err)
	}
	if _, _, _, err := store.CreateAccessAndRefreshTokens(ctx, held2, first); !errors.Is(err, ErrRefreshTokenSpent) {
		t.Fatalf("second rotation error = %v, want ErrRefreshTokenSpent — the token was spent twice", err)
	}
}

// Mirrors memory.TestRevokeTokensAlsoDropsPendingAuthorizationCode: a Kill Switch
// must not leave an unredeemed code able to mint fresh tokens afterwards.
func TestRevokeTokensAlsoDropsPendingAuthorizationCode(t *testing.T) {
	store, _, ctx := oidcFixture(t)
	ar := newAuthRequest(t, ctx, store)
	if err := store.CompleteLogin(ctx, ar.GetID(), "usr_1", []string{"account.id"}); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveAuthCode(ctx, ar.GetID(), "code-to-redeem"); err != nil {
		t.Fatal(err)
	}

	// Anti-vacuous: the row exists before the revocation. Counted directly rather
	// than through AuthRequestByCode, which now consumes the code.
	var before int
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM oidc_codes`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if before != 1 {
		t.Fatalf("codes before revocation = %d, want 1", before)
	}

	if _, err := store.RevokeTokens(ctx, oauth.TokenFilter{Subject: "usr_1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AuthRequestByCode(ctx, "code-to-redeem"); err == nil {
		t.Fatal("the authorization code survived the Kill Switch and can still mint tokens")
	}
}

// The lookup is the claim: the DELETE ... RETURNING makes the code single-use, so
// two exchanges cannot both succeed.
func TestAuthorizationCodeIsSingleUse(t *testing.T) {
	store, _, ctx := oidcFixture(t)
	ar := newAuthRequest(t, ctx, store)
	if err := store.CompleteLogin(ctx, ar.GetID(), "usr_1", []string{"account.id"}); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveAuthCode(ctx, ar.GetID(), "single-use-code"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AuthRequestByCode(ctx, "single-use-code"); err != nil {
		t.Fatalf("first exchange refused: %v", err)
	}
	if _, err := store.AuthRequestByCode(ctx, "single-use-code"); err == nil {
		t.Fatal("the authorization code was accepted twice")
	}
}

// An expired code must not be redeemable just because the periodic sweep has not
// run yet.
func TestExpiredAuthorizationCodeIsRefused(t *testing.T) {
	store, _, ctx := oidcFixture(t)
	ar := newAuthRequest(t, ctx, store)
	if err := store.SaveAuthCode(ctx, ar.GetID(), "expired-code"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx,
		`UPDATE oidc_codes SET expires_at = now() - interval '1 minute' WHERE code_hash = $1`,
		hashValue("expired-code")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AuthRequestByCode(ctx, "expired-code"); err == nil {
		t.Fatal("an expired authorization code was accepted")
	}
}

// Mirrors memory.TestRevokeTokenCutsTheWholeGrant.
func TestRevokeTokenCutsTheWholeGrant(t *testing.T) {
	store, _, ctx := oidcFixture(t)
	req := &oidcstore.AuthRequest{ClientID: "oidc-web", Subject: "usr_1", Scopes: []string{"account.id"}}

	accessID, refreshValue, _, err := store.CreateAccessAndRefreshTokens(ctx, req, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeToken(ctx, accessID, "usr_1", "oidc-web"); err != nil {
		t.Fatalf("revoking the access token failed: %v", err)
	}
	if _, err := store.TokenRequestByRefreshToken(ctx, refreshValue); err == nil {
		t.Fatal("the paired refresh token survived access-token revocation")
	}

	accessID2, refreshValue2, _, err := store.CreateAccessAndRefreshTokens(ctx, req, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeToken(ctx, refreshValue2, "", "oidc-web"); err != nil {
		t.Fatalf("revoking the refresh token failed: %v", err)
	}
	var introspect oidc.IntrospectionResponse
	if err := store.SetIntrospectionFromToken(ctx, &introspect, accessID2, "usr_1", "oidc-web"); err == nil {
		t.Fatal("the paired access token survived refresh-token revocation")
	}
}

// Mirrors memory.TestCompleteLoginPreservesRecordedAuthTime.
func TestCompleteLoginPreservesRecordedAuthTime(t *testing.T) {
	store, _, ctx := oidcFixture(t)
	ar := newAuthRequest(t, ctx, store)
	signedIn := time.Now().Add(-30 * time.Minute).UTC().Truncate(time.Second)
	if err := store.SetAuthTime(ctx, ar.GetID(), signedIn); err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteLogin(ctx, ar.GetID(), "usr_1", []string{"account.id"}); err != nil {
		t.Fatal(err)
	}
	done, err := store.AuthRequestByID(ctx, ar.GetID())
	if err != nil {
		t.Fatal(err)
	}
	if !done.GetAuthTime().Equal(signedIn) {
		t.Fatalf("auth_time = %s, want the recorded sign-in time %s", done.GetAuthTime(), signedIn)
	}
}

// Mirrors memory.TestDeviceFlowAcceptsStandardOIDCScopes.
func TestDeviceFlowAcceptsStandardOIDCScopes(t *testing.T) {
	store, _, ctx := oidcFixture(t)
	requested := []string{"openid", "profile", "email", "account.id", "phigros.score.read"}
	if err := store.StoreDeviceAuthorization(ctx, "oidc-device", "device-standard", "WXYZ-1234",
		time.Now().Add(10*time.Minute), requested); err != nil {
		t.Fatal(err)
	}

	auth, err := store.DescribeDeviceAuthorization(ctx, "wxyz-1234")
	if err != nil {
		t.Fatalf("describing an OIDC device request failed: %v", err)
	}
	if len(auth.Scopes) != 2 {
		t.Fatalf("described scopes = %v, want only the two catalogue scopes", auth.Scopes)
	}

	if err := store.DecideDeviceAuthorization(ctx, "WXYZ-1234", "usr_1", true,
		[]oauth.Scope{oauth.ScopeAccountID}, nil); err != nil {
		t.Fatalf("approving an OIDC device request failed: %v", err)
	}
	st, err := store.DeviceByUserCode(ctx, "WXYZ-1234")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"openid", "profile", "email", "account.id", oidc.ScopeOfflineAccess} {
		if !oidcstore.HasScope(st.Scopes, want) {
			t.Fatalf("granted scopes = %v, missing %q", st.Scopes, want)
		}
	}
}

// Mirrors memory.TestDevicePollingIsThrottled: a premature poll is slow_down.
func TestDevicePollingIsThrottled(t *testing.T) {
	store, _, ctx := oidcFixture(t)
	if err := store.StoreDeviceAuthorization(ctx, "oidc-device", "device-poll", "POLL-1234",
		time.Now().Add(10*time.Minute), []string{"account.id"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetDeviceAuthorizatonState(ctx, "oidc-device", "device-poll"); err != nil {
		t.Fatalf("first poll refused: %v", err)
	}
	if _, err := store.GetDeviceAuthorizatonState(ctx, "oidc-device", "device-poll"); err == nil {
		t.Fatal("an immediate second poll was answered instead of slow_down")
	}
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

	// A revoke from the wrong client is refused while the token still exists.
	// (After the owner revokes it below, an unknown-token revoke is RFC 7009
	// success instead — that is tested by the whole-grant assertion after this.)
	if oidcErr := store.RevokeToken(ctx, refresh, "usr_1", "someone-else"); oidcErr == nil {
		t.Fatal("wrong client allowed to revoke")
	}

	// Revoking the access token makes introspection fail, and cuts the paired
	// refresh token with it: the two are one grant.
	if oidcErr := store.RevokeToken(ctx, accessID, "usr_1", "oidc-web"); oidcErr != nil {
		t.Fatalf("revoke: %v", oidcErr)
	}
	if err := store.SetIntrospectionFromToken(ctx, &oidc.IntrospectionResponse{}, accessID, "usr_1", "oidc-web"); err == nil {
		t.Fatal("revoked token still introspects")
	}
	if _, err := store.TokenRequestByRefreshToken(ctx, refresh); err == nil {
		t.Fatal("the paired refresh token survived access-token revocation")
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

	// A duplicate user code is rejected with the sentinel. Checked while the first
	// authorization is still live: the exchange below consumes its row (the device
	// code is single use), and a consumed code frees its user code by design.
	if err := store.StoreDeviceAuthorization(ctx, "oidc-device", "dev-code-2", "bcdf-ghjk", expires, nil); !errors.Is(err, op.ErrDuplicateUserCode) {
		t.Fatalf("duplicate user code = %v, want ErrDuplicateUserCode", err)
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
}

// The grants view, derived from the OP token tables.
func TestOIDCGrantsAndRevoke(t *testing.T) {
	store, _, ctx := oidcFixture(t)
	ar := newAuthRequest(t, ctx, store)
	if err := store.CompleteLogin(ctx, ar.GetID(), "usr_1", []string{"account.id", "phigros.score.read"}); err != nil {
		t.Fatal(err)
	}
	ar, err := store.AuthRequestByID(ctx, ar.GetID())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := store.CreateAccessAndRefreshTokens(ctx, ar, ""); err != nil {
		t.Fatal(err)
	}

	grants, err := store.Grants(ctx, "usr_1")
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 1 {
		t.Fatalf("grants = %+v", grants)
	}
	g := grants[0]
	if g.ClientID != "oidc-web" || !g.HasRefresh || len(g.Scopes) != 2 {
		t.Fatalf("grant = %+v", g)
	}
	if g.IssuedAt.IsZero() || g.ExpiresAt.IsZero() || !g.ExpiresAt.After(g.IssuedAt) {
		t.Fatalf("grant times = %v / %v", g.IssuedAt, g.ExpiresAt)
	}

	if err := store.RevokeGrant(ctx, "usr_1", "oidc-web"); err != nil {
		t.Fatal(err)
	}
	if grants, err = store.Grants(ctx, "usr_1"); err != nil || len(grants) != 0 {
		t.Fatalf("grants after revoke = %+v (%v)", grants, err)
	}
	// Revoking again is success.
	if err := store.RevokeGrant(ctx, "usr_1", "oidc-web"); err != nil {
		t.Fatalf("revoke is not idempotent: %v", err)
	}
}

// The device verification surface: describe, reject widening, approve, deny.
func TestOIDCDeviceDescribeAndDecide(t *testing.T) {
	store, _, ctx := oidcFixture(t)
	expires := time.Now().Add(5 * time.Minute)
	if err := store.StoreDeviceAuthorization(ctx, "oidc-device", "dev-desc-1", "GHJK-BCDF", expires,
		[]string{"account.id", "phigros.score.read"}); err != nil {
		t.Fatal(err)
	}

	auth, err := store.DescribeDeviceAuthorization(ctx, "ghjkbcdf")
	if err != nil {
		t.Fatal(err)
	}
	if auth.Client.ID != "oidc-device" || len(auth.Scopes) != 2 {
		t.Fatalf("describe = %+v", auth)
	}

	// A decision cannot widen the request.
	if err := store.DecideDeviceAuthorization(ctx, "GHJK-BCDF", "usr_1", true,
		[]oauth.Scope{oauth.ScopePhigrosB30}, nil); err == nil {
		t.Fatal("widening decision accepted")
	}

	if err := store.DecideDeviceAuthorization(ctx, "GHJK-BCDF", "usr_1", true,
		[]oauth.Scope{oauth.ScopeAccountID}, nil); err != nil {
		t.Fatal(err)
	}
	st, err := store.GetDeviceAuthorizatonState(ctx, "oidc-device", "dev-desc-1")
	if err != nil {
		t.Fatal(err)
	}
	if !st.Done || st.Subject != "usr_1" ||
		!oidcstore.HasScope(st.Scopes, "account.id") ||
		!oidcstore.HasScope(st.Scopes, oidc.ScopeOfflineAccess) {
		t.Fatalf("state = %+v", st)
	}

	// Once decided, it is no longer describable.
	if _, err := store.DescribeDeviceAuthorization(ctx, "GHJK-BCDF"); !errors.Is(err, oauth.ErrDeviceNotFound) {
		t.Fatalf("describe after decision = %v, want ErrDeviceNotFound", err)
	}
}

// The login hook is what binds an OP auth request to the browser session before
// the consent screen loads it; it must receive the request context.
func TestOIDCLoginHookReceivesRequestContext(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	client, err := oauth.NewClient("hook-cli", "Hook", oauth.ClientConfidential, "s",
		[]string{"https://c.example/cb"}, []oauth.Scope{oauth.ScopeAccountID})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Clients().Create(ctx, client); err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	store, err := db.OIDC(db.Clients(), OIDCOptions{
		Registry: oauth.DefaultRegistry(),
		Signer:   oidcstore.NewSigner("hook", key),
		Login: func(_ context.Context, id string) string {
			got = append(got, id)
			return "/consent?id=" + id
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	c, err := store.GetClientByClientID(ctx, "hook-cli")
	if err != nil {
		t.Fatal(err)
	}
	if u := c.LoginURL("req-1"); u != "/consent?id=req-1" {
		t.Fatalf("login url = %q", u)
	}
	if len(got) != 1 || got[0] != "req-1" {
		t.Fatalf("login hook got %v", got)
	}
}

// A rotated signing key must stay in the JWKS so id_tokens signed with it still
// verify.
func TestOIDCSignerKeySetIncludesRetired(t *testing.T) {
	current, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	old, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keys := oidcstore.NewSigner("cur", current).
		WithRetired(oidcstore.RetiredSigningKey{ID: "old", Public: &old.PublicKey}).
		KeySet()
	if len(keys) != 2 {
		t.Fatalf("keys = %d, want 2", len(keys))
	}
	if keys[0].ID() != "cur" || keys[1].ID() != "old" {
		t.Fatalf("key order = %s,%s", keys[0].ID(), keys[1].ID())
	}
	for _, k := range keys {
		if k.Use() != "sig" || k.Algorithm() == "" {
			t.Fatalf("key %s is not a usable signing key", k.ID())
		}
	}
}
