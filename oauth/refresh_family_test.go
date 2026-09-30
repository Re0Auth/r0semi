package oauth

import (
	"context"
	"errors"
	"testing"
)

// This is the service-level half of RFC 9700 §4.14.2: the library, not a store,
// owns the decision to revoke a family when a rotated refresh token is replayed.
// It drives the real code-exchange → rotation → replay sequence, so it proves the
// wiring (ConsumeRefresh's typed error, the family revocation, and the audit
// event) rather than any store in isolation.

func TestRefreshReplayRevokesTheFamilyWithoutOverRevoking(t *testing.T) {
	svc, clients, _, logger, _ := newTestAS(t)
	registerClient(t, clients, "app", ClientPublic, "", []Scope{ScopeAccountID})
	ctx := context.Background()
	redirect := "https://app.example/cb"
	verifier := "replay-verifier-replay-verifier-replay"

	// newGrant runs a fresh authorization and exchange, so each call is its own
	// rotation family even for the same subject and client.
	newGrant := func() TokenResponse {
		t.Helper()
		auth, err := svc.Authorize(ctx, AuthorizationRequest{
			ClientID: "app", RedirectURI: redirect, Subject: "usr_1",
			Scopes:        []Scope{ScopeAccountID},
			CodeChallenge: pkceChallenge(verifier), CodeChallengeMethod: "S256",
		})
		if err != nil {
			t.Fatal(err)
		}
		tok, err := svc.Exchange(ctx, CodeExchangeRequest{
			ClientID: "app", Code: auth.Code, RedirectURI: redirect, CodeVerifier: verifier,
		})
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}

	victim := newGrant()
	neighbour := newGrant()

	// The thief rotates the stolen token first, so they hold the newest
	// generation before the legitimate client ever presents its copy.
	stolen, err := svc.Refresh(ctx, RefreshRequest{ClientID: "app", RefreshToken: victim.RefreshToken})
	if err != nil {
		t.Fatalf("the control rotation failed: %v", err)
	}
	if stolen.RefreshToken == victim.RefreshToken || stolen.AccessToken == victim.AccessToken {
		t.Fatalf("rotation returned the same values: %+v", stolen)
	}

	// The legitimate client replays its copy. The replay is refused with the same
	// invalid_grant the unknown case gets — never a 500 — and that refusal is the
	// detection.
	_, err = svc.Refresh(ctx, RefreshRequest{ClientID: "app", RefreshToken: victim.RefreshToken})
	if got := protocolCode(t, err); got != "invalid_grant" {
		t.Fatalf("the replay answered %q, want invalid_grant", got)
	}

	// The thief's generation must have died with the detection: both its refresh
	// token and the access token it was minted with.
	if _, err := svc.Refresh(ctx, RefreshRequest{ClientID: "app", RefreshToken: stolen.RefreshToken}); protocolCode(t, err) != "invalid_grant" {
		t.Fatalf("the thief's refresh token survived the detected replay (refresh err = %v)", err)
	}
	info, err := svc.Introspect(ctx, stolen.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if info.Active {
		t.Fatal("the thief's access token is still active after the family revocation")
	}
	// The victim's original access token belongs to the same family and dies too.
	if info, err := svc.Introspect(ctx, victim.AccessToken); err != nil || info.Active {
		t.Fatalf("the original generation's access token survived: active=%v err=%v", info.Active, err)
	}

	// The detection is audited.
	var audited bool
	for _, e := range logger.Events() {
		if e.Action == "oauth.reuse_detected" {
			audited = true
		}
	}
	if !audited {
		t.Error("the detected reuse was not recorded in the audit log")
	}

	// No over-revocation: an untouched grant for the same subject and client still
	// rotates and its access token still introspects as active.
	next, err := svc.Refresh(ctx, RefreshRequest{ClientID: "app", RefreshToken: neighbour.RefreshToken})
	if err != nil {
		t.Fatalf("an unrelated grant was revoked: %v", err)
	}
	info, err = svc.Introspect(ctx, next.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Active {
		t.Fatal("the unrelated grant's new access token is not active")
	}
	if info, err := svc.Introspect(ctx, neighbour.AccessToken); err != nil || !info.Active {
		t.Fatalf("the unrelated grant's original access token was revoked: active=%v err=%v", info.Active, err)
	}
}

// The rotation must inherit the family rather than mint a new one, or the replay
// detector is looking at a chain of independent tokens and the thief's generation
// is never named.
func TestRefreshRotationInheritsTheFamily(t *testing.T) {
	svc, clients, store, _, _ := newTestAS(t)
	registerClient(t, clients, "app", ClientPublic, "", []Scope{ScopeAccountID})
	ctx := context.Background()
	redirect := "https://app.example/cb"
	verifier := "family-verifier-family-verifier-family"

	auth, err := svc.Authorize(ctx, AuthorizationRequest{
		ClientID: "app", RedirectURI: redirect, Subject: "usr_1",
		Scopes:        []Scope{ScopeAccountID},
		CodeChallenge: pkceChallenge(verifier), CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := svc.Exchange(ctx, CodeExchangeRequest{
		ClientID: "app", Code: auth.Code, RedirectURI: redirect, CodeVerifier: verifier,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Rotating writes a tombstone for the spent value; its family is what issue
	// inherited. The rotated token's own tombstone is written by consuming it next,
	// and the two families have to match.
	rotated, err := svc.Refresh(ctx, RefreshRequest{ClientID: "app", RefreshToken: first.RefreshToken})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumeRefresh(ctx, rotated.RefreshToken); err != nil {
		t.Fatal(err)
	}

	store.mu.Lock()
	firstTomb := store.tombstones[TokenHash(first.RefreshToken)]
	rotatedTomb := store.tombstones[TokenHash(rotated.RefreshToken)]
	store.mu.Unlock()
	if firstTomb.FamilyID == "" {
		t.Fatal("an issued refresh token carries no family id")
	}
	if firstTomb.FamilyID != rotatedTomb.FamilyID {
		t.Fatalf("rotation did not inherit the family: first=%q rotated=%q",
			firstTomb.FamilyID, rotatedTomb.FamilyID)
	}
}

// An unknown value is still an ordinary invalid_grant and must not revoke
// anything: the detection branch keys on the typed reuse error, not on every
// failure to consume.
func TestRefreshUnknownTokenDoesNotRevokeAFamily(t *testing.T) {
	svc, clients, store, _, _ := newTestAS(t)
	registerClient(t, clients, "app", ClientPublic, "", []Scope{ScopeAccountID})
	ctx := context.Background()
	redirect := "https://app.example/cb"
	verifier := "unknown-verifier-unknown-verifier-unknown"

	auth, err := svc.Authorize(ctx, AuthorizationRequest{
		ClientID: "app", RedirectURI: redirect, Subject: "usr_1",
		Scopes:        []Scope{ScopeAccountID},
		CodeChallenge: pkceChallenge(verifier), CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := svc.Exchange(ctx, CodeExchangeRequest{
		ClientID: "app", Code: auth.Code, RedirectURI: redirect, CodeVerifier: verifier,
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = svc.Refresh(ctx, RefreshRequest{ClientID: "app", RefreshToken: "never-issued"})
	if got := protocolCode(t, err); got != "invalid_grant" {
		t.Fatalf("unknown value answered %q, want invalid_grant", got)
	}
	if _, err := store.ConsumeRefresh(ctx, tok.RefreshToken); err != nil {
		t.Fatalf("an unknown value revoked a live family: %v", err)
	}
}

// A store failure must fail closed: if the family cannot be revoked, the caller
// is told the revocation failed rather than handed a clean invalid_grant while the
// thief's generation stays live.
type failingRevokeStore struct {
	Store
	revokeErr error
}

func (s *failingRevokeStore) RevokeRefreshFamily(context.Context, string) (int, error) {
	return 0, s.revokeErr
}

func TestRefreshReuseWithAFailingRevocationFailsClosed(t *testing.T) {
	boom := errors.New("store down")
	svc, clients, _, _, _ := newTestAS(t)
	registerClient(t, clients, "app", ClientPublic, "", []Scope{ScopeAccountID})
	ctx := context.Background()
	redirect := "https://app.example/cb"
	verifier := "failing-verifier-failing-verifier-failing"

	auth, err := svc.Authorize(ctx, AuthorizationRequest{
		ClientID: "app", RedirectURI: redirect, Subject: "usr_1",
		Scopes:        []Scope{ScopeAccountID},
		CodeChallenge: pkceChallenge(verifier), CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatal(err)
	}
	// Exchange through the real service, then swap the store underneath it for one
	// whose family revocation fails.
	svcImpl, ok := svc.(*service)
	if !ok {
		t.Fatalf("service is %T, want *service", svc)
	}
	tok, err := svc.Exchange(ctx, CodeExchangeRequest{
		ClientID: "app", Code: auth.Code, RedirectURI: redirect, CodeVerifier: verifier,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Refresh(ctx, RefreshRequest{ClientID: "app", RefreshToken: tok.RefreshToken}); err != nil {
		t.Fatal(err)
	}
	svcImpl.tokens = &failingRevokeStore{Store: svcImpl.tokens, revokeErr: boom}

	_, err = svc.Refresh(ctx, RefreshRequest{ClientID: "app", RefreshToken: tok.RefreshToken})
	if !errors.Is(err, boom) {
		t.Fatalf("a failed family revocation was reported as %v, want the store error", err)
	}
	// Not a protocol error: the failure is the store's, so the transport cannot
	// turn it into a 400 that reads like an ordinary refused grant.
	var protocol *Error
	if errors.As(err, &protocol) {
		t.Fatalf("the store failure was dressed as the protocol error %q", protocol.Code)
	}
}

// R5-10: ownership is judged before the value is spent. ConsumeRefresh is a
// DELETE, so checking the client binding afterwards let any authenticated client
// burn another client's refresh token just by presenting it — the refusal came,
// but the owner's grant was gone. With family tombstones that got worse: the
// owner's own retry was then read as a replay and revoked the whole family. This
// is the guard that the non-destructive ownership read happens first.
func TestCrossClientPresentationDoesNotSpendTheOwnersToken(t *testing.T) {
	svc, clients, _, logger, _ := newTestAS(t)
	registerClient(t, clients, "owner", ClientPublic, "", []Scope{ScopeAccountID})
	registerClient(t, clients, "thief", ClientPublic, "", []Scope{ScopeAccountID})
	ctx := context.Background()
	redirect := "https://app.example/cb"
	verifier := "owner-verifier-owner-verifier-owner"

	auth, err := svc.Authorize(ctx, AuthorizationRequest{
		ClientID: "owner", RedirectURI: redirect, Subject: "usr_1",
		Scopes:        []Scope{ScopeAccountID},
		CodeChallenge: pkceChallenge(verifier), CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatal(err)
	}
	owner, err := svc.Exchange(ctx, CodeExchangeRequest{
		ClientID: "owner", Code: auth.Code, RedirectURI: redirect, CodeVerifier: verifier,
	})
	if err != nil {
		t.Fatal(err)
	}

	// The thief presents the owner's refresh token. Refused, without spending it
	// and without arming the reuse detector — the token is not a replay, it is
	// somebody else's property.
	if _, err := svc.Refresh(ctx, RefreshRequest{ClientID: "thief", RefreshToken: owner.RefreshToken}); protocolCode(t, err) != "invalid_grant" {
		t.Fatalf("a cross-client presentation answered %v, want invalid_grant", err)
	}
	for _, e := range logger.Events() {
		if e.Action == "oauth.reuse_detected" {
			t.Fatal("a cross-client presentation was recorded as a detected replay")
		}
	}

	// The owner's token must still be spendable: that is the point of the check.
	rotated, err := svc.Refresh(ctx, RefreshRequest{ClientID: "owner", RefreshToken: owner.RefreshToken})
	if err != nil {
		t.Fatalf("the cross-client attempt burned the owner's refresh token: %v", err)
	}
	if rotated.RefreshToken == "" || rotated.RefreshToken == owner.RefreshToken {
		t.Fatalf("the owner's rotation did not mint a new refresh token: %+v", rotated)
	}
	// And the family survived: the original access token is still live.
	info, err := svc.Introspect(ctx, owner.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Active {
		t.Fatal("the owner's access token was revoked by the cross-client attempt")
	}
}
