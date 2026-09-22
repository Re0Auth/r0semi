package oauth

import (
	"context"
	"testing"
	"time"
)

const (
	grantRedirect = "https://app.example/cb"
	grantVerifier = "grant-verifier-long-enough-for-rfc7636"
)

// issueTokens drives the whole authorization_code flow the way a client would,
// so a grant is built from tokens that were really issued rather than from rows
// written by hand.
func issueTokens(t *testing.T, svc Service, clientID, subject string, scopes []Scope) TokenResponse {
	t.Helper()
	ctx := context.Background()
	resp, err := svc.Authorize(ctx, AuthorizationRequest{
		ClientID: clientID, RedirectURI: grantRedirect, Subject: subject, Scopes: scopes,
		CodeChallenge: pkceChallenge(grantVerifier), CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := svc.Exchange(ctx, CodeExchangeRequest{
		ClientID: clientID, Code: resp.Code, RedirectURI: grantRedirect, CodeVerifier: grantVerifier,
	})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func grantFor(t *testing.T, svc Service, subject, clientID string) (Grant, bool) {
	t.Helper()
	grants, err := svc.Grants(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range grants {
		if g.ClientID == clientID {
			return g, true
		}
	}
	return Grant{}, false
}

func TestGrantsListWhatAClientCanStillDo(t *testing.T) {
	svc, clients, _, _, _ := newTestAS(t)
	registerClient(t, clients, "cli", ClientPublic, "", []Scope{ScopeAccountID, ScopePhigrosScore})
	registerClient(t, clients, "other", ClientPublic, "", []Scope{ScopeAccountID})

	issueTokens(t, svc, "cli", "usr_1", []Scope{ScopeAccountID, ScopePhigrosScore})
	issueTokens(t, svc, "other", "usr_1", []Scope{ScopeAccountID})

	grants, err := svc.Grants(context.Background(), "usr_1")
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 2 {
		t.Fatalf("grants = %+v, want two", grants)
	}
	// Sorted by client id, so the same list does not reorder between two loads.
	if grants[0].ClientID != "cli" || grants[1].ClientID != "other" {
		t.Fatalf("grants are not ordered by client id: %+v", grants)
	}

	cli, _ := grantFor(t, svc, "usr_1", "cli")
	if cli.ClientName == "" {
		t.Error("the client name was not resolved from the registry")
	}
	if len(cli.Scopes) != 2 {
		t.Errorf("scopes = %v, want the two that were granted", cli.Scopes)
	}
	if !cli.HasRefresh {
		t.Error("has_refresh = false, but an authorization_code exchange issues one")
	}
	if cli.ExpiresAt.Before(cli.IssuedAt) {
		t.Errorf("expiry %v precedes issue %v", cli.ExpiresAt, cli.IssuedAt)
	}

	// A different subject sees nothing: the list is per account, not global.
	other, err := svc.Grants(context.Background(), "usr_2")
	if err != nil {
		t.Fatal(err)
	}
	if len(other) != 0 {
		t.Fatalf("another subject sees %+v", other)
	}
}

// A grant is derived from live tokens, which means an expired one does not count.
// That is the whole reason there is no separate consent table to disagree with.
func TestGrantsDropWhenTheLastTokenExpires(t *testing.T) {
	svc, clients, _, _, clock := newTestAS(t)
	registerClient(t, clients, "cli", ClientPublic, "", []Scope{ScopeAccountID})
	issueTokens(t, svc, "cli", "usr_1", []Scope{ScopeAccountID})

	// Past the access token's hour, but well inside the refresh token's day: the
	// client can still renew, so the grant is still real.
	clock.advance(2 * time.Hour)
	g, ok := grantFor(t, svc, "usr_1", "cli")
	if !ok {
		t.Fatal("the grant vanished while the refresh token was still valid")
	}
	if !g.HasRefresh {
		t.Error("has_refresh = false while a refresh token is live")
	}

	// Past the refresh token too. Nothing is left that could act as the user.
	clock.advance(48 * time.Hour)
	if g, ok := grantFor(t, svc, "usr_1", "cli"); ok {
		t.Fatalf("the grant survived every token expiring: %+v", g)
	}
}

func TestRevokeGrantMakesTheTokensStopWorking(t *testing.T) {
	svc, clients, _, _, _ := newTestAS(t)
	registerClient(t, clients, "cli", ClientPublic, "", []Scope{ScopeAccountID})
	tok := issueTokens(t, svc, "cli", "usr_1", []Scope{ScopeAccountID})

	ctx := context.Background()
	info, err := svc.Introspect(ctx, tok.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Active {
		t.Fatal("the token was not active before the revocation")
	}

	if err := svc.RevokeGrant(ctx, "usr_1", "cli"); err != nil {
		t.Fatal(err)
	}

	// The access token is gone, so introspection says so.
	info, err = svc.Introspect(ctx, tok.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if info.Active {
		t.Error("an access token survived the revocation of its grant")
	}
	// And so is the refresh token: a client that could renew would not have been
	// revoked in any meaningful sense.
	if _, err := svc.Refresh(ctx, RefreshRequest{
		ClientID: "cli", RefreshToken: tok.RefreshToken,
	}); err == nil {
		t.Error("a refresh token survived the revocation of its grant")
	}
	if _, ok := grantFor(t, svc, "usr_1", "cli"); ok {
		t.Error("the grant is still listed after being revoked")
	}
}

// Revoking one client must not reach across to another client, or to the same
// client acting for somebody else.
func TestRevokeGrantIsScoped(t *testing.T) {
	svc, clients, _, _, _ := newTestAS(t)
	registerClient(t, clients, "cli", ClientPublic, "", []Scope{ScopeAccountID})
	registerClient(t, clients, "other", ClientPublic, "", []Scope{ScopeAccountID})

	mine := issueTokens(t, svc, "cli", "usr_1", []Scope{ScopeAccountID})
	sibling := issueTokens(t, svc, "other", "usr_1", []Scope{ScopeAccountID})
	elsewhere := issueTokens(t, svc, "cli", "usr_2", []Scope{ScopeAccountID})

	ctx := context.Background()
	if err := svc.RevokeGrant(ctx, "usr_1", "cli"); err != nil {
		t.Fatal(err)
	}

	if info, _ := svc.Introspect(ctx, mine.AccessToken); info.Active {
		t.Error("the revoked client's token still works")
	}
	if info, _ := svc.Introspect(ctx, sibling.AccessToken); !info.Active {
		t.Error("revoking one client revoked another's access")
	}
	if info, _ := svc.Introspect(ctx, elsewhere.AccessToken); !info.Active {
		t.Error("revoking for one subject revoked the same client's access elsewhere")
	}
}

func TestRevokeGrantIsIdempotent(t *testing.T) {
	svc, clients, _, _, _ := newTestAS(t)
	registerClient(t, clients, "cli", ClientPublic, "", []Scope{ScopeAccountID})

	ctx := context.Background()
	// Never granted at all: still a success, which is what lets the endpoint
	// answer 204 and a retry after a dropped response be harmless.
	if err := svc.RevokeGrant(ctx, "usr_1", "nobody"); err != nil {
		t.Fatal(err)
	}
	issueTokens(t, svc, "cli", "usr_1", []Scope{ScopeAccountID})
	for i := 0; i < 2; i++ {
		if err := svc.RevokeGrant(ctx, "usr_1", "cli"); err != nil {
			t.Fatalf("revoke %d: %v", i+1, err)
		}
	}
}

func TestGrantsRequiresIdentifiers(t *testing.T) {
	svc, _, _, _, _ := newTestAS(t)
	ctx := context.Background()

	if _, err := svc.Grants(ctx, ""); err == nil {
		t.Error("Grants accepted an empty subject")
	}
	if err := svc.RevokeGrant(ctx, "", "cli"); err == nil {
		t.Error("RevokeGrant accepted an empty subject")
	}
	if err := svc.RevokeGrant(ctx, "usr_1", ""); err == nil {
		t.Error("RevokeGrant accepted an empty client id")
	}
}
