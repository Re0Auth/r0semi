package oauth

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestDeviceAuthorizationHappyPath(t *testing.T) {
	svc, clients, _, _, clock := newTestAS(t)
	registerClient(t, clients, "cli", ClientPublic, "", []Scope{ScopeAccountID, ScopePhigrosScore})
	ctx := context.Background()

	start, err := svc.BeginDeviceAuthorization(ctx, DeviceAuthorizationRequest{
		ClientID: "cli", Scopes: []Scope{ScopeAccountID, ScopePhigrosScore},
	})
	if err != nil {
		t.Fatal(err)
	}
	if start.DeviceCode == "" || start.UserCode == "" {
		t.Fatalf("start = %+v", start)
	}
	if start.VerificationURI != "https://auth.test/device" {
		t.Fatalf("verification_uri = %q", start.VerificationURI)
	}
	if start.Interval != 5 || start.ExpiresIn != 600 {
		t.Fatalf("interval/expires = %d/%d", start.Interval, start.ExpiresIn)
	}

	// Polling before approval is a pending state, not an error the client hides.
	_, err = svc.PollDeviceAuthorization(ctx, DeviceCodeExchangeRequest{ClientID: "cli", DeviceCode: start.DeviceCode})
	if got := protocolCode(t, err); got != "authorization_pending" {
		t.Fatalf("first poll = %q, want authorization_pending", got)
	}

	// The verification page sees the client and the requested scopes.
	auth, err := svc.DescribeDeviceAuthorization(ctx, start.UserCode)
	if err != nil {
		t.Fatal(err)
	}
	if auth.Client.ID != "cli" || len(auth.Scopes) != 2 {
		t.Fatalf("describe = %+v", auth)
	}
	// User codes are separator-insensitive.
	if _, err := svc.DescribeDeviceAuthorization(ctx, "bcdf"[:4]); err == nil {
		t.Fatal("a truncated user code resolved")
	}

	if err := svc.DecideDeviceAuthorization(ctx, start.UserCode, "usr_1", true, nil, nil); err != nil {
		t.Fatal(err)
	}

	clock.advance(6 * time.Second)
	tokens, err := svc.PollDeviceAuthorization(ctx, DeviceCodeExchangeRequest{ClientID: "cli", DeviceCode: start.DeviceCode})
	if err != nil {
		t.Fatal(err)
	}
	if tokens.AccessToken == "" || tokens.RefreshToken == "" {
		t.Fatalf("tokens = %+v", tokens)
	}
	if tokens.Scope != "account.id phigros.score.read" {
		t.Fatalf("scope = %q", tokens.Scope)
	}

	info, err := svc.Introspect(ctx, tokens.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Active || info.Subject != "usr_1" {
		t.Fatalf("introspect = %+v", info)
	}
}

func TestDeviceAuthorizationSlowDownThenPending(t *testing.T) {
	svc, clients, _, _, clock := newTestAS(t)
	registerClient(t, clients, "cli", ClientPublic, "", []Scope{ScopeAccountID})
	ctx := context.Background()

	start, err := svc.BeginDeviceAuthorization(ctx, DeviceAuthorizationRequest{ClientID: "cli", Scopes: []Scope{ScopeAccountID}})
	if err != nil {
		t.Fatal(err)
	}
	poll := func() string {
		_, err := svc.PollDeviceAuthorization(ctx, DeviceCodeExchangeRequest{ClientID: "cli", DeviceCode: start.DeviceCode})
		return protocolCode(t, err)
	}

	if got := poll(); got != "authorization_pending" {
		t.Fatalf("first poll = %q", got)
	}
	if got := poll(); got != "slow_down" {
		t.Fatalf("immediate second poll = %q, want slow_down", got)
	}
	clock.advance(6 * time.Second)
	if got := poll(); got != "authorization_pending" {
		t.Fatalf("poll after backoff = %q, want authorization_pending", got)
	}
}

func TestDeviceAuthorizationDenied(t *testing.T) {
	svc, clients, _, _, clock := newTestAS(t)
	registerClient(t, clients, "cli", ClientPublic, "", []Scope{ScopeAccountID})
	ctx := context.Background()

	start, _ := svc.BeginDeviceAuthorization(ctx, DeviceAuthorizationRequest{ClientID: "cli", Scopes: []Scope{ScopeAccountID}})
	if err := svc.DecideDeviceAuthorization(ctx, start.UserCode, "usr_1", false, nil, nil); err != nil {
		t.Fatal(err)
	}
	clock.advance(6 * time.Second)
	_, err := svc.PollDeviceAuthorization(ctx, DeviceCodeExchangeRequest{ClientID: "cli", DeviceCode: start.DeviceCode})
	if got := protocolCode(t, err); got != "access_denied" {
		t.Fatalf("poll = %q, want access_denied", got)
	}
}

func TestDeviceAuthorizationExpires(t *testing.T) {
	svc, clients, _, _, clock := newTestAS(t)
	registerClient(t, clients, "cli", ClientPublic, "", []Scope{ScopeAccountID})
	ctx := context.Background()

	start, _ := svc.BeginDeviceAuthorization(ctx, DeviceAuthorizationRequest{ClientID: "cli", Scopes: []Scope{ScopeAccountID}})
	clock.advance(11 * time.Minute)

	_, err := svc.PollDeviceAuthorization(ctx, DeviceCodeExchangeRequest{ClientID: "cli", DeviceCode: start.DeviceCode})
	if got := protocolCode(t, err); got != "expired_token" {
		t.Fatalf("poll = %q, want expired_token", got)
	}
	if _, err := svc.DescribeDeviceAuthorization(ctx, start.UserCode); !errors.Is(err, ErrDeviceNotFound) {
		t.Fatalf("describe after expiry = %v", err)
	}
	// Deciding an expired request must not resurrect it.
	if err := svc.DecideDeviceAuthorization(ctx, start.UserCode, "usr_1", true, nil, nil); !errors.Is(err, ErrDeviceNotFound) {
		t.Fatalf("decide after expiry = %v", err)
	}
}

func TestDeviceAuthorizationDeviceCodeIsBoundToClient(t *testing.T) {
	svc, clients, _, _, _ := newTestAS(t)
	registerClient(t, clients, "cli", ClientPublic, "", []Scope{ScopeAccountID})
	registerClient(t, clients, "other", ClientPublic, "", []Scope{ScopeAccountID})
	ctx := context.Background()

	start, _ := svc.BeginDeviceAuthorization(ctx, DeviceAuthorizationRequest{ClientID: "cli", Scopes: []Scope{ScopeAccountID}})
	svc.DecideDeviceAuthorization(ctx, start.UserCode, "usr_1", true, nil, nil)

	_, err := svc.PollDeviceAuthorization(ctx, DeviceCodeExchangeRequest{ClientID: "other", DeviceCode: start.DeviceCode})
	if got := protocolCode(t, err); got != "invalid_grant" {
		t.Fatalf("cross-client poll = %q, want invalid_grant", got)
	}
}

func TestDeviceAuthorizationCannotWidenOrSkipExplicit(t *testing.T) {
	svc, clients, _, _, _ := newTestAS(t)
	registerClient(t, clients, "cli", ClientPublic, "", []Scope{ScopeAccountID, ScopeTapTapStoken})
	ctx := context.Background()

	start, err := svc.BeginDeviceAuthorization(ctx, DeviceAuthorizationRequest{
		ClientID: "cli", Scopes: []Scope{ScopeAccountID, ScopeTapTapStoken},
	})
	if err != nil {
		t.Fatal(err)
	}

	// ScopeTapTapStoken is critical: approving without ticking it must fail.
	if err := svc.DecideDeviceAuthorization(ctx, start.UserCode, "usr_1", true, nil, nil); protocolCode(t, err) != "access_denied" {
		t.Fatalf("approve without explicit = %v", err)
	}
	// Widening is refused too.
	if err := svc.DecideDeviceAuthorization(ctx, start.UserCode, "usr_1", true, []Scope{ScopePhigrosB30}, nil); protocolCode(t, err) != "invalid_scope" {
		t.Fatalf("approve widening = %v", err)
	}
	// Narrowing to account.id and ticking the critical scope it keeps is fine.
	if err := svc.DecideDeviceAuthorization(ctx, start.UserCode, "usr_1", true,
		[]Scope{ScopeAccountID, ScopeTapTapStoken}, []Scope{ScopeTapTapStoken}); err != nil {
		t.Fatalf("approve with explicit = %v", err)
	}
}

func TestDeviceAuthorizationRejectsUnknownClientAndScope(t *testing.T) {
	svc, clients, _, _, _ := newTestAS(t)
	registerClient(t, clients, "cli", ClientPublic, "", []Scope{ScopeAccountID})
	ctx := context.Background()

	if _, err := svc.BeginDeviceAuthorization(ctx, DeviceAuthorizationRequest{ClientID: "ghost", Scopes: []Scope{ScopeAccountID}}); protocolCode(t, err) != "invalid_client" {
		t.Fatalf("unknown client = %v", err)
	}
	if _, err := svc.BeginDeviceAuthorization(ctx, DeviceAuthorizationRequest{ClientID: "cli", Scopes: []Scope{ScopePhigrosScore}}); protocolCode(t, err) != "invalid_scope" {
		t.Fatalf("unregistered scope = %v", err)
	}
}

// A device code is single-use in the sense that it stops working once decided,
// and the record cannot be flipped twice.
func TestDeviceAuthorizationDecidedOnce(t *testing.T) {
	svc, clients, _, _, _ := newTestAS(t)
	registerClient(t, clients, "cli", ClientPublic, "", []Scope{ScopeAccountID})
	ctx := context.Background()

	start, _ := svc.BeginDeviceAuthorization(ctx, DeviceAuthorizationRequest{ClientID: "cli", Scopes: []Scope{ScopeAccountID}})
	if err := svc.DecideDeviceAuthorization(ctx, start.UserCode, "usr_1", true, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := svc.DecideDeviceAuthorization(ctx, start.UserCode, "usr_2", true, nil, nil); protocolCode(t, err) != "invalid_request" {
		t.Fatalf("second decide = %v", err)
	}
}

func TestUserCodeIsHumanFriendlyAndNormalized(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		code, err := newUserCode()
		if err != nil {
			t.Fatal(err)
		}
		if len(code) != 9 || code[4] != '-' {
			t.Fatalf("code = %q, want XXXX-XXXX", code)
		}
		for _, r := range code {
			if r == '-' {
				continue
			}
			if !containsRune(userCodeAlphabet, r) {
				t.Fatalf("code %q has a character outside the alphabet", code)
			}
		}
		seen[code] = true
	}
	if len(seen) < 190 {
		t.Fatalf("only %d distinct codes in 200 draws; entropy looks wrong", len(seen))
	}
	if NormalizeUserCode(" bcdf-ghjk ") != "BCDFGHJK" {
		t.Fatalf("normalize = %q", NormalizeUserCode(" bcdf-ghjk "))
	}
}

func containsRune(s string, r rune) bool {
	for _, c := range s {
		if c == r {
			return true
		}
	}
	return false
}
