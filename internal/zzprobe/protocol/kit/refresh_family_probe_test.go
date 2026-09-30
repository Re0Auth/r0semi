//go:build audit5

package kit

import (
	"context"
	"testing"

	"github.com/Re0Auth/r0semi/oauth"
)

// TestProbeRefreshFamilyRevocationOnTheThinAS drives RFC 9700 §4.14.2 through the
// hand-written engine's public Service — the same end-to-end shape the OP's Z02-5b
// probe uses for the provider, and a different surface from the MemoryStore unit
// tests in the oauth package: this one goes through Exchange, Refresh's rotation,
// the theft-signal branch, and Introspect, wired exactly as the kit fixture builds
// them.
//
// The probe asserts no gap (the rule is implemented); a regression turns it into a
// named failure rather than a silent survivable generation.
func TestProbeRefreshFamilyRevocationOnTheThinAS(t *testing.T) {
	svc, _, _, _ := newAS(t)
	ctx := context.Background()

	victim := mint(t, svc, confClientID, confSecret, confRedirect, accountScope)
	neighbour := mint(t, svc, confClientID, confSecret, confRedirect, accountScope)

	// The thief rotates the stolen token first and now holds the newest generation.
	thief, err := svc.Refresh(ctx, oauth.RefreshRequest{
		ClientID: confClientID, ClientSecret: confSecret, RefreshToken: victim.RefreshToken})
	if err != nil {
		t.Fatalf("the thief could not rotate the stolen token: %v", err)
	}
	if thief.RefreshToken == victim.RefreshToken || thief.AccessToken == victim.AccessToken {
		t.Fatal("rotation returned the presented values")
	}

	// The legitimate client replays its copy: refused with the ordinary
	// invalid_grant, and that refusal is the detection.
	_, err = svc.Refresh(ctx, oauth.RefreshRequest{
		ClientID: confClientID, ClientSecret: confSecret, RefreshToken: victim.RefreshToken})
	if code := oauthCode(t, err); code != "invalid_grant" {
		t.Fatalf("the replay answered %q, want invalid_grant", code)
	}

	// The thief's generation must die with the detection: both halves.
	if _, err := svc.Refresh(ctx, oauth.RefreshRequest{
		ClientID: confClientID, ClientSecret: confSecret, RefreshToken: thief.RefreshToken}); err == nil {
		t.Fatal("the thief's refresh token survived the detected replay (RFC 9700 §4.14.2 requires the " +
			"whole family to be revoked)")
	}
	info, err := svc.Introspect(ctx, thief.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if info.Active {
		t.Fatal("the thief's access token is still active after the family revocation")
	}

	// No over-revocation: a second, untouched grant for the same client rotates and
	// its replacement introspects as active.
	next, err := svc.Refresh(ctx, oauth.RefreshRequest{
		ClientID: confClientID, ClientSecret: confSecret, RefreshToken: neighbour.RefreshToken})
	if err != nil {
		t.Fatalf("an unrelated grant was revoked: %v", err)
	}
	info, err = svc.Introspect(ctx, next.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Active {
		t.Fatal("the unrelated grant's replacement is not active")
	}
}
