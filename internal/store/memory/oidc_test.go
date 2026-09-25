package memory

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
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
	if _, err := store.DescribeDeviceAuthorization(context.Background(), "NOPE-NOPE"); !errors.Is(err, oauth.ErrDeviceNotFound) {
		t.Fatalf("err = %v, want ErrDeviceNotFound", err)
	}
}

// A standard OIDC device client asks for `openid profile email`; those are
// protocol flags the catalogue does not describe, so the flow must not fail on
// them and must keep them on the granted set (otherwise no id_token is issued).
func TestDeviceFlowAcceptsStandardOIDCScopes(t *testing.T) {
	store, _ := testStore(t)
	ctx := context.Background()
	expires := time.Now().Add(10 * time.Minute)
	requested := []string{"openid", "profile", "email", "account.id", "phigros.score.read"}
	if err := store.StoreDeviceAuthorization(ctx, "cli", "device-standard", "WXYZ-1234", expires, requested); err != nil {
		t.Fatal(err)
	}

	auth, err := store.DescribeDeviceAuthorization(ctx, "wxyz-1234")
	if err != nil {
		t.Fatalf("describing an OIDC device request failed: %v", err)
	}
	// Only catalogue scopes are shown as permissions.
	if len(auth.Scopes) != 2 {
		t.Fatalf("described scopes = %v, want only the two catalogue scopes", auth.Scopes)
	}
	for _, d := range auth.Scopes {
		if d.Scope == "openid" || d.Scope == "profile" || d.Scope == "email" {
			t.Fatalf("protocol scope %q was rendered as a permission", d.Scope)
		}
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
	if oidcstore.HasScope(st.Scopes, "phigros.score.read") {
		t.Fatalf("narrowing did not drop phigros.score.read: %v", st.Scopes)
	}
}

// RFC 8628 §3.5: polling faster than the advertised interval answers slow_down.
// The library maps context.DeadlineExceeded to that error, so the store must
// return it rather than authorization_pending forever.
func TestDevicePollingIsThrottled(t *testing.T) {
	store, _ := testStore(t)
	ctx := context.Background()
	if err := store.StoreDeviceAuthorization(ctx, "cli", "device-poll", "POLL-1234",
		time.Now().Add(10*time.Minute), []string{"account.id"}); err != nil {
		t.Fatal(err)
	}

	first, err := store.GetDeviceAuthorizatonState(ctx, "cli", "device-poll")
	if err != nil {
		t.Fatalf("first poll refused: %v", err)
	}
	if first == nil || first.Done || first.Denied {
		t.Fatalf("first poll state = %+v", first)
	}
	if _, err := store.GetDeviceAuthorizatonState(ctx, "cli", "device-poll"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("immediate second poll error = %v, want context.DeadlineExceeded (slow_down)", err)
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

// A Kill Switch that leaves an unredeemed authorization code alive is not a kill
// switch: the holder can exchange that code for a new access/refresh pair after
// the operator has been told the account is contained. The code has to go with
// the tokens, even though it is not counted as one.
func TestRevokeTokensAlsoDropsPendingAuthorizationCode(t *testing.T) {
	store, _ := testStore(t)
	ctx := context.Background()

	ar, err := store.CreateAuthRequest(ctx, &oidc.AuthRequest{
		ClientID:            "cli",
		RedirectURI:         "https://app.example/cb",
		ResponseType:        oidc.ResponseTypeCode,
		Scopes:              []string{"account.id"},
		CodeChallenge:       "challenge-1234567890",
		CodeChallengeMethod: oidc.CodeChallengeMethodS256,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteLogin(ctx, ar.GetID(), "usr_1", []string{"account.id"}); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveAuthCode(ctx, ar.GetID(), "code-to-redeem"); err != nil {
		t.Fatal(err)
	}

	// Anti-vacuous: the code exists before the revocation. Counts is used rather
	// than AuthRequestByCode because that lookup now consumes the code.
	if got := store.Counts().Codes; got != 1 {
		t.Fatalf("codes before revocation = %d, want 1", got)
	}

	if _, err := store.RevokeTokens(ctx, oauth.TokenFilter{Subject: "usr_1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AuthRequestByCode(ctx, "code-to-redeem"); err == nil {
		t.Fatal("the authorization code survived the Kill Switch and can still mint tokens")
	}

	// A client-targeted switch must cut the code too.
	ar2, err := store.CreateAuthRequest(ctx, &oidc.AuthRequest{
		ClientID:            "cli",
		RedirectURI:         "https://app.example/cb",
		ResponseType:        oidc.ResponseTypeCode,
		Scopes:              []string{"account.id"},
		CodeChallenge:       "challenge-1234567890",
		CodeChallengeMethod: oidc.CodeChallengeMethodS256,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveAuthCode(ctx, ar2.GetID(), "code-for-client"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RevokeTokens(ctx, oauth.TokenFilter{ClientID: "cli"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AuthRequestByCode(ctx, "code-for-client"); err == nil {
		t.Fatal("the client-targeted Kill Switch left an authorization code redeemable")
	}
}

// RFC 7009 §2.1: revoking either token should cut the whole grant, not just the
// presented one.
func TestRevokeTokenCutsTheWholeGrant(t *testing.T) {
	store, _ := testStore(t)
	ctx := context.Background()
	req := &oidcstore.AuthRequest{ClientID: "cli", Subject: "usr_1", Scopes: []string{"account.id"}}

	accessID, refreshValue, _, err := store.CreateAccessAndRefreshTokens(ctx, req, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeToken(ctx, accessID, "usr_1", "cli"); err != nil {
		t.Fatalf("revoking the access token failed: %v", err)
	}
	if _, err := store.TokenRequestByRefreshToken(ctx, refreshValue); err == nil {
		t.Fatal("the paired refresh token survived access-token revocation")
	}

	accessID2, refreshValue2, _, err := store.CreateAccessAndRefreshTokens(ctx, req, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeToken(ctx, refreshValue2, "", "cli"); err != nil {
		t.Fatalf("revoking the refresh token failed: %v", err)
	}
	var introspect oidc.IntrospectionResponse
	if err := store.SetIntrospectionFromToken(ctx, &introspect, accessID2, "usr_1", "cli"); err == nil {
		t.Fatal("the paired access token survived refresh-token revocation")
	}
}

// auth_time must be the session's authentication time, not when consent was
// decided. The login hook records it before CompleteLogin, which must preserve it.
func TestCompleteLoginPreservesRecordedAuthTime(t *testing.T) {
	store, _ := testStore(t)
	ctx := context.Background()
	ar, err := store.CreateAuthRequest(ctx, &oidc.AuthRequest{
		ClientID:            "cli",
		RedirectURI:         "https://app.example/cb",
		ResponseType:        oidc.ResponseTypeCode,
		Scopes:              []string{"account.id"},
		CodeChallenge:       "challenge-1234567890",
		CodeChallengeMethod: oidc.CodeChallengeMethodS256,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
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

// The lookup itself is the claim, so a code cannot be exchanged twice even if two
// requests race for it. The library only deletes the request after minting, so a
// read-then-delete would let both win.
func TestAuthorizationCodeIsSingleUse(t *testing.T) {
	store, _ := testStore(t)
	ctx := context.Background()
	ar, err := store.CreateAuthRequest(ctx, &oidc.AuthRequest{
		ClientID:            "cli",
		RedirectURI:         "https://app.example/cb",
		ResponseType:        oidc.ResponseTypeCode,
		Scopes:              []string{"account.id"},
		CodeChallenge:       "challenge-1234567890",
		CodeChallengeMethod: oidc.CodeChallengeMethodS256,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
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

// Rotation must be a claim, not a check. Two requests can hold the same refresh
// token at once — a stolen copy, or a client that retried — and the second must
// be refused rather than issued a second generation. Otherwise rotation never
// notices the reuse, so a stolen token is replayable for as long as the victim
// keeps refreshing, and nothing ever signals it.
//
// The interleaving is written out rather than raced, because the defect is a
// window between two lock acquisitions and not a data race: concurrent goroutines
// would make this test flaky while proving nothing extra.
func TestRefreshTokenRotationIsSingleUse(t *testing.T) {
	store, _ := testStore(t)
	ctx := context.Background()
	req := &oidcstore.AuthRequest{ClientID: "cli", Subject: "usr_1", Scopes: []string{"account.id"}}

	_, first, _, err := store.CreateAccessAndRefreshTokens(ctx, req, "")
	if err != nil {
		t.Fatal(err)
	}

	// Both requests see the token before either rotates it.
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

// The refusal must not be a blanket one: a rotation that presents a token the
// store still holds has to succeed, or refresh stops working entirely.
func TestRefreshTokenRotationStillWorksWhenPresentedOnce(t *testing.T) {
	store, _ := testStore(t)
	ctx := context.Background()
	req := &oidcstore.AuthRequest{ClientID: "cli", Subject: "usr_1", Scopes: []string{"account.id"}}

	_, first, _, err := store.CreateAccessAndRefreshTokens(ctx, req, "")
	if err != nil {
		t.Fatal(err)
	}
	held, err := store.TokenRequestByRefreshToken(ctx, first)
	if err != nil {
		t.Fatal(err)
	}
	_, second, _, err := store.CreateAccessAndRefreshTokens(ctx, held, first)
	if err != nil {
		t.Fatalf("rotation was refused: %v", err)
	}
	if second == "" || second == first {
		t.Fatalf("refresh token was not rotated: first=%q second=%q", first, second)
	}
	// The spent one is gone, and the replacement is live.
	if _, err := store.TokenRequestByRefreshToken(ctx, first); err == nil {
		t.Fatal("the spent refresh token is still accepted")
	}
	if _, err := store.TokenRequestByRefreshToken(ctx, second); err != nil {
		t.Fatalf("the replacement refresh token was rejected: %v", err)
	}
}

// Revocation must work through the path a client actually takes.
//
// The library feeds GetRefreshTokenInfo's identifier straight back into
// RevokeToken, so the two have to agree on what that identifier is. When they did
// not, RevokeToken hashed a hash, matched nothing, fell through to RFC 7009's
// "already invalid means success" branch, and answered 200 while the refresh
// token kept minting — a leaked token surviving its own revocation.
func TestRefreshTokenRevocationRoundTrip(t *testing.T) {
	store, client := testStore(t)
	ctx := context.Background()
	req := &oidcstore.AuthRequest{ClientID: client.ID, Subject: "usr_1", Scopes: []string{"account.id"}}

	_, refresh, _, err := store.CreateAccessAndRefreshTokens(ctx, req, "")
	if err != nil {
		t.Fatal(err)
	}

	subject, tokenID, err := store.GetRefreshTokenInfo(ctx, client.ID, refresh)
	if err != nil {
		t.Fatal(err)
	}
	if subject != "usr_1" {
		t.Fatalf("subject = %q, want usr_1", subject)
	}

	if err := store.RevokeToken(ctx, tokenID, subject, client.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	// The whole point: it must no longer be spendable.
	if _, err := store.TokenRequestByRefreshToken(ctx, refresh); err == nil {
		t.Fatal("the refresh token still works after being revoked through " +
			"GetRefreshTokenInfo's identifier")
	}
}

// The revocation must not cross clients: an identifier that resolves is still
// only revocable by the client it was issued to (RFC 7009 §2.1).
func TestRefreshTokenRevocationIsScopedToItsClient(t *testing.T) {
	store, client := testStore(t)
	ctx := context.Background()
	req := &oidcstore.AuthRequest{ClientID: client.ID, Subject: "usr_1", Scopes: []string{"account.id"}}

	_, refresh, _, err := store.CreateAccessAndRefreshTokens(ctx, req, "")
	if err != nil {
		t.Fatal(err)
	}

	if err := store.RevokeToken(ctx, refresh, "usr_1", "some-other-client"); err == nil {
		t.Fatal("another client revoked a refresh token it does not own")
	}
	if _, err := store.TokenRequestByRefreshToken(ctx, refresh); err != nil {
		t.Fatalf("the token was revoked anyway: %v", err)
	}
}
