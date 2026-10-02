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

	"github.com/Re0Auth/r0semi/audit"
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

// G-15: the throttle anchors on the last ATTEMPT, not on the last admitted poll —
// a rejected poll still pushes the deadline out, so a client that keeps polling
// early is throttled until a full interval after its most recent attempt. This is
// the semantic the register adjudicates for both backends; Postgres anchors on the
// last admitted poll today and has to be changed there.
func TestDeviceThrottleAnchorsOnTheLastAttempt(t *testing.T) {
	clock := newTestClock()
	store := clockedStore(t, clock)
	ctx := context.Background()
	if err := store.StoreDeviceAuthorization(ctx, "cli", "device-attempt", "ATTT-0001",
		clock.Now().Add(10*time.Minute), []string{"account.id"}); err != nil {
		t.Fatal(err)
	}

	// Admitted first poll: the anchor is its timestamp.
	if _, err := store.GetDeviceAuthorizatonState(ctx, "cli", "device-attempt"); err != nil {
		t.Fatalf("first poll refused: %v", err)
	}
	clock.Advance(oidcstore.DefaultDevicePollInterval - time.Second)
	// Rejected — and the rejection moves the anchor to now.
	if _, err := store.GetDeviceAuthorizatonState(ctx, "cli", "device-attempt"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("early poll = %v, want context.DeadlineExceeded", err)
	}
	clock.Advance(2 * time.Second)
	// More than one interval after the FIRST poll, but not after the rejected
	// attempt: still throttled, because the anchor is the last attempt.
	if _, err := store.GetDeviceAuthorizatonState(ctx, "cli", "device-attempt"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("poll after the first interval but not the last attempt = %v, want context.DeadlineExceeded (G-15: the anchor is the last attempt)", err)
	}
	clock.Advance(oidcstore.DefaultDevicePollInterval + time.Second)
	if _, err := store.GetDeviceAuthorizatonState(ctx, "cli", "device-attempt"); err != nil {
		t.Fatalf("poll a full interval after the last attempt refused: %v", err)
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

// The same capability rule, through the door a user actually has: revoking a
// client's grant from the account page. A code the client withheld must not
// outlive the revocation — redeeming it returns an access *and* a refresh token,
// so the client the user just cut off comes back for good.
//
// It must also stay scoped: another client's code, and another account's code for
// the same client, are not this revocation's to delete.
func TestRevokeGrantAlsoDropsPendingAuthorizationCode(t *testing.T) {
	store, _ := testStore(t)
	ctx := context.Background()
	newCode := func(clientID, subject, code string) {
		t.Helper()
		ar, err := store.CreateAuthRequest(ctx, &oidc.AuthRequest{
			ClientID:            clientID,
			RedirectURI:         "https://app.example/cb",
			ResponseType:        oidc.ResponseTypeCode,
			Scopes:              []string{"account.id"},
			CodeChallenge:       "challenge-1234567890",
			CodeChallengeMethod: oidc.CodeChallengeMethodS256,
		}, "")
		if err != nil {
			t.Fatal(err)
		}
		if err := store.CompleteLogin(ctx, ar.GetID(), subject, []string{"account.id"}); err != nil {
			t.Fatal(err)
		}
		if err := store.SaveAuthCode(ctx, ar.GetID(), code); err != nil {
			t.Fatal(err)
		}
	}
	newCode("cli", "usr_1", "grant-code")
	newCode("cli", "usr_2", "other-account-code")
	newCode("other-cli", "usr_1", "other-client-code")

	// Anti-vacuous: all three codes exist before the revocation.
	if got := store.Counts().Codes; got != 3 {
		t.Fatalf("codes before revocation = %d, want 3", got)
	}

	if err := store.RevokeGrant(ctx, "usr_1", "cli"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AuthRequestByCode(ctx, "grant-code"); err == nil {
		t.Fatal("an unspent authorization code survived the grant revocation")
	}
	// The two that are not this (subject, client) pair are untouched and usable.
	if _, err := store.AuthRequestByCode(ctx, "other-account-code"); err != nil {
		t.Fatalf("another account's code was revoked: %v", err)
	}
	if _, err := store.AuthRequestByCode(ctx, "other-client-code"); err != nil {
		t.Fatalf("another client's code was revoked: %v", err)
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

// A revocation that presents an access token whose row is already gone must still
// cut the half that can mint replacements.
//
// The two lifetimes make this reachable without any failure: the access token
// expires after an hour and the refresh token after thirty days, and the sweep
// removes each on its own. Looking only in the access table, the presented value
// matched nothing and the call answered RFC 7009's "unknown token is success"
// while the refresh token stayed live. Mirrors the Postgres store's
// TestRevokeTokenRepairsAStrandedRefreshHalf.
func TestRevokeTokenCutsARefreshHalfWhoseAccessRowIsGone(t *testing.T) {
	store, client := testStore(t)
	ctx := context.Background()
	req := &oidcstore.AuthRequest{ClientID: client.ID, Subject: "usr_1", Scopes: []string{"account.id"}}

	accessID, refresh, _, err := store.CreateAccessAndRefreshTokens(ctx, req, "")
	if err != nil {
		t.Fatal(err)
	}
	// Precondition: the pair is live, so a pass cannot come from nothing working.
	if _, err := store.TokenRequestByRefreshToken(ctx, refresh); err != nil {
		t.Fatalf("precondition: the refresh token was not usable: %v", err)
	}

	// The access row disappears the way the sweep removes it: on its own.
	store.mu.Lock()
	delete(store.accessTokens, oauth.TokenHash(accessID))
	store.mu.Unlock()

	if err := store.RevokeToken(ctx, accessID, "usr_1", client.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := store.TokenRequestByRefreshToken(ctx, refresh); err == nil {
		t.Fatal("the stranded refresh token survived a revocation that reported success")
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

// The consent decision is the authorization event — who granted which client
// which scopes — so both exits of it are audited: the approval with the granted
// scope set, the denial with the client that was refused.
func TestConsentDecisionsAreAudited(t *testing.T) {
	logger := audit.NewMemoryLogger()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewOIDCStore(OIDCOptions{
		Clients:  oauth.NewMemoryClientRegistry(),
		Registry: oauth.DefaultRegistry(),
		Signer:   oidcstore.NewSigner("test", key),
		Audit:    logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	newRequest := func() string {
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
		return ar.GetID()
	}

	if err := store.CompleteLogin(ctx, newRequest(), "usr_1", []string{"account.id"}); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteAuthRequest(ctx, newRequest()); err != nil {
		t.Fatal(err)
	}

	var approve, deny *audit.Event
	for i := range logger.Events() {
		e := logger.Events()[i]
		switch e.Action {
		case "oidc.consent.approve":
			approve = &e
		case "oidc.consent.deny":
			deny = &e
		}
	}
	if approve == nil {
		t.Fatal("the approval recorded no audit event")
	}
	if approve.Subject != "usr_1" || approve.Detail["client_id"] != "cli" || approve.Detail["scopes"] != "account.id" {
		t.Fatalf("approval event = %+v", *approve)
	}
	if deny == nil {
		t.Fatal("the denial recorded no audit event")
	}
	if deny.Detail["client_id"] != "cli" || deny.Outcome != audit.OutcomeDenied {
		t.Fatalf("denial event = %+v", *deny)
	}
}

// TestAuthRequestByIDRefusesAnExpiredHandle is the reader-side half of Z07-1: the
// by-ID read the consent screen performs adjudicates the stored deadline itself,
// so a pending handle stops being describable before the janitor runs. The
// positive control is the same read inside the TTL, and the stored-record control
// proves the refusal was the read's, not the sweep's.
func TestAuthRequestByIDRefusesAnExpiredHandle(t *testing.T) {
	clock := newTestClock()
	store := clockedStore(t, clock)
	ctx := context.Background()

	ar, err := store.CreateAuthRequest(ctx, &oidc.AuthRequest{
		ClientID:     "cli",
		RedirectURI:  "https://app.example/cb",
		ResponseType: oidc.ResponseTypeCode,
		Scopes:       oidc.SpaceDelimitedArray{"account.id"},
	}, "usr_1")
	if err != nil {
		t.Fatal(err)
	}

	// Control: inside the TTL the handle is readable, so a read that refused
	// everything would not satisfy the assertion below.
	if _, err := store.AuthRequestByID(ctx, ar.GetID()); err != nil {
		t.Fatalf("AuthRequestByID inside the TTL: %v", err)
	}

	// A minute past the default 30-minute request TTL, with no sweep run: the
	// read itself must refuse (Z07-1, docs/issues/P2-medium.md).
	clock.Advance(31 * time.Minute)
	if _, err := store.AuthRequestByID(ctx, ar.GetID()); err == nil {
		t.Fatal("AuthRequestByID returned a pending handle past its deadline; only the sweep ended it (Z07-1)")
	}
	if got := store.Counts().AuthRequests; got != 1 {
		t.Fatalf("stored auth requests = %d, want 1: the sweep must not have been the refusal", got)
	}
}

// TestDeleteAuthRequestAuditsOnlyARealRefusal is the Z20-1 store-level check. The
// library deletes the auth request again after minting, when it is already done;
// that cleanup must not write a refusal event. The controls are the genuinely
// pending request, whose deletion IS the refusal, and a missing row, which
// records nothing.
func TestDeleteAuthRequestAuditsOnlyARealRefusal(t *testing.T) {
	clock := newTestClock()
	clients := oauth.NewMemoryClientRegistry()
	c, err := oauth.NewClient("cli", "CLI", oauth.ClientPublic, "",
		[]string{"https://app.example/cb"}, []oauth.Scope{oauth.ScopeAccountID})
	if err != nil {
		t.Fatal(err)
	}
	if err := clients.Create(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	logger := audit.NewMemoryLogger()
	store, err := NewOIDCStore(OIDCOptions{
		Clients:  clients,
		Registry: oauth.DefaultRegistry(),
		Signer:   signerForTests(t),
		Audit:    logger,
		Now:      clock.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	newRequest := func() string {
		t.Helper()
		ar, err := store.CreateAuthRequest(ctx, &oidc.AuthRequest{
			ClientID:     "cli",
			RedirectURI:  "https://app.example/cb",
			ResponseType: oidc.ResponseTypeCode,
			Scopes:       oidc.SpaceDelimitedArray{"account.id"},
		}, "usr_1")
		if err != nil {
			t.Fatal(err)
		}
		return ar.GetID()
	}
	denies := func() int {
		n := 0
		for _, e := range logger.Events() {
			if e.Action == "oidc.consent.deny" {
				n++
			}
		}
		return n
	}

	// Control: deleting a still-pending request is the refusal and records it.
	if err := store.DeleteAuthRequest(ctx, newRequest()); err != nil {
		t.Fatal(err)
	}
	if got := denies(); got != 1 {
		t.Fatalf("deleting a pending request recorded %d deny events, want 1", got)
	}

	// Z20-1: the post-mint cleanup deletes an already-done request. That is not a
	// refusal, so the deny count must not move.
	done := newRequest()
	if err := store.CompleteLogin(ctx, done, "usr_1", []string{"account.id"}); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteAuthRequest(ctx, done); err != nil {
		t.Fatal(err)
	}
	if got := denies(); got != 1 {
		t.Errorf("the cleanup of a done request recorded a consent deny: %d deny events, want still 1 (Z20-1)", got)
	}

	// The same cleanup after AuthRequestByCode consumed the row finds nothing at
	// all, which must also record nothing.
	if err := store.DeleteAuthRequest(ctx, "no-such-request"); err != nil {
		t.Fatal(err)
	}
	if got := denies(); got != 1 {
		t.Errorf("deleting a missing row recorded a consent deny: %d deny events, want still 1 (Z20-1)", got)
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
// store still holds has to succeed, or refresh stops working entirely. And once a
// replay is detected, the whole family goes with it (RFC 9700 §4.14.2): refusing
// only the presented value would leave the generation the thief already rotated
// alive, which is exactly the silent access the family rule exists to cut.
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
	secondAccess, second, _, err := store.CreateAccessAndRefreshTokens(ctx, held, first)
	if err != nil {
		t.Fatalf("rotation was refused: %v", err)
	}
	if second == "" || second == first {
		t.Fatalf("refresh token was not rotated: first=%q second=%q", first, second)
	}
	// The replacement is live BEFORE the replay, so the family revocation below
	// cannot be confused with a rotation that never worked.
	if _, err := store.TokenRequestByRefreshToken(ctx, second); err != nil {
		t.Fatalf("the replacement refresh token was rejected: %v", err)
	}

	// The replay: the spent value, presented again. It is refused (a live first
	// would have succeeded), and the family is revoked — so the replacement dies
	// too, along with its paired access row.
	if _, err := store.TokenRequestByRefreshToken(ctx, first); !errors.Is(err, ErrRefreshTokenSpent) {
		t.Fatalf("replay error = %v, want ErrRefreshTokenSpent — the presented token was not a spent one", err)
	}
	if _, err := store.TokenRequestByRefreshToken(ctx, second); err == nil {
		t.Fatal("the replacement survived a detected replay: the token family was not revoked")
	}
	var introspect oidc.IntrospectionResponse
	if err := store.SetIntrospectionFromToken(ctx, &introspect, secondAccess, "usr_1", "cli"); err == nil {
		t.Fatal("the replacement's paired access token survived the family revocation")
	}
}

// OIDC Core §12.2: the id_token a refresh returns may repeat the original
// authorization request's nonce. The nonce therefore has to survive the storage
// round trip and every rotation, or the refreshed id_token loses it. This reads
// the minted row back, rotates the token twice and asserts the nonce is still
// there after each rotation.
func TestRefreshRequestCarriesTheNonceAcrossRotations(t *testing.T) {
	store, client := testStore(t)
	ctx := context.Background()
	const nonce = "nonce-1234567890"
	req := &oidcstore.AuthRequest{
		ClientID: client.ID, Subject: "usr_1",
		Scopes: []string{"account.id"}, Nonce: nonce,
	}

	_, refresh, _, err := store.CreateAccessAndRefreshTokens(ctx, req, "")
	if err != nil {
		t.Fatal(err)
	}

	// The stored row carries the nonce before any rotation.
	held, err := store.TokenRequestByRefreshToken(ctx, refresh)
	if err != nil {
		t.Fatal(err)
	}
	if got := oidcstore.NonceOf(held); got != nonce {
		t.Fatalf("the minted refresh request's nonce = %q, want %q", got, nonce)
	}

	// Two rotations, each time reading the replacement back through the same path
	// the library uses. The nonce must be inherited rather than dropped.
	for i := 0; i < 2; i++ {
		_, rotated, _, err := store.CreateAccessAndRefreshTokens(ctx, held, refresh)
		if err != nil {
			t.Fatalf("rotation %d was refused: %v", i+1, err)
		}
		held, err = store.TokenRequestByRefreshToken(ctx, rotated)
		if err != nil {
			t.Fatalf("rotation %d's replacement was rejected: %v", i+1, err)
		}
		if got := oidcstore.NonceOf(held); got != nonce {
			t.Fatalf("after rotation %d the nonce = %q, want %q", i+1, got, nonce)
		}
		refresh = rotated
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
// only revocable by the client it was issued to (RFC 7009 §2.1). G-8: the
// foreign client's attempt is the uniform success and deletes nothing, so the
// endpoint does not confirm ownership to a stranger.
func TestRefreshTokenRevocationIsScopedToItsClient(t *testing.T) {
	store, client := testStore(t)
	ctx := context.Background()
	req := &oidcstore.AuthRequest{ClientID: client.ID, Subject: "usr_1", Scopes: []string{"account.id"}}

	_, refresh, _, err := store.CreateAccessAndRefreshTokens(ctx, req, "")
	if err != nil {
		t.Fatal(err)
	}

	if err := store.RevokeToken(ctx, refresh, "usr_1", "some-other-client"); err != nil {
		t.Fatalf("a foreign revocation was not the uniform RFC 7009 success: %v", err)
	}
	if _, err := store.TokenRequestByRefreshToken(ctx, refresh); err != nil {
		t.Fatalf("the foreign revocation deleted the token: %v", err)
	}
	// The owner still can.
	if err := store.RevokeToken(ctx, refresh, "usr_1", client.ID); err != nil {
		t.Fatalf("the owner could not revoke its own token: %v", err)
	}
	if _, err := store.TokenRequestByRefreshToken(ctx, refresh); err == nil {
		t.Fatal("the owner's revocation did not delete the token")
	}
}
