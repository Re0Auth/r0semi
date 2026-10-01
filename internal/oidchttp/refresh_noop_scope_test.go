package oidchttp

import (
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
)

// O-6 (revised): offline_access is a compatibility no-op — accepted, never stored
// and never surfaced — and a refresh token is issued regardless. A refresh request
// that echoes the scope back (the OIDF conformance suite does, taking it from its
// own client configuration) must therefore be accepted, while every other scope is
// still held to the grant.
func TestRefreshIgnoresTheOfflineAccessNoOpScope(t *testing.T) {
	f := newFixture(t)
	tokens := codeFlow(t, f, []string{"openid", "account.id", "offline_access"})
	refresh, _ := tokens["refresh_token"].(string)
	if refresh == "" {
		t.Fatalf("the code flow issued no refresh token: %v", tokens)
	}

	rotated, status := postToken(t, f.server.URL, f.webID, "s3cret", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refresh},
		"scope":         {"openid account.id offline_access"},
	})
	if status != http.StatusOK {
		t.Fatalf("refresh with offline_access = %d %v", status, rotated)
	}
	// The acceptance changed; the hiding did not.
	if got, _ := rotated["scope"].(string); slices.Contains(strings.Fields(got), "offline_access") {
		t.Fatalf("the refresh response surfaced offline_access: %q", got)
	}
	next, _ := rotated["refresh_token"].(string)
	if next == "" {
		t.Fatalf("the refresh did not rotate: %v", rotated)
	}
	if _, status := postToken(t, f.server.URL, f.webID, "s3cret", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {next},
	}); status != http.StatusOK {
		t.Fatalf("the rotated refresh token was rejected: %d", status)
	}
}

// The no-op scope is ignored, not the rule. A refresh that asks for a real scope
// the grant never had is still invalid_scope.
func TestRefreshStillRefusesAWideningScope(t *testing.T) {
	f := newFixture(t)
	tokens := codeFlow(t, f, []string{"openid", "account.id", "offline_access"})
	refresh, _ := tokens["refresh_token"].(string)
	if refresh == "" {
		t.Fatalf("the code flow issued no refresh token: %v", tokens)
	}

	out, status := postToken(t, f.server.URL, f.webID, "s3cret", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refresh},
		// phigros.score.read is registered for this client but was never granted
		// by this authorization, so asking for it on the refresh is a widening.
		"scope": {"openid account.id offline_access phigros.score.read"},
	})
	if status != http.StatusBadRequest || out["error"] != "invalid_scope" {
		t.Fatalf("widening refresh = %d %v, want 400 invalid_scope", status, out)
	}
}
