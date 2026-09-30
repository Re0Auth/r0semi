package oidcstore

import (
	"testing"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// AUDIT9 / S02-1 (fixed) — the two freshness judgements the fix rests on.
//
// FreshnessNeeded is the LOGIN BOUNDARY's question: must the browser be sent
// through the provider again? It has no tolerance, so a stale session is sent.
// FreshnessSatisfied is the STORE's question: may this recorded authentication
// complete a freshness-bound request? It allows the redirect round trip, because
// the re-authentication the boundary forced takes a few seconds to reach the
// consent decision.
func TestAudit9FreshnessJudgements(t *testing.T) {
	now := time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)
	seconds := func(n uint) *uint { return &n }

	// prompt=login (normalized to max_age=0).
	login := &AuthRequest{Prompt: []string{oidc.PromptLogin}, MaxAge: seconds(0)}
	if !login.FreshnessNeeded(now.Add(-time.Second), now) {
		t.Error("prompt=login must always need a fresh authentication at the boundary")
	}
	if login.FreshnessSatisfied(now.Add(-time.Hour), now) {
		t.Error("prompt=login accepted an hour-old authentication at completion")
	}
	// The re-authentication lands a few seconds before the decision.
	if !login.FreshnessSatisfied(now.Add(-5*time.Second), now) {
		t.Error("prompt=login rejected the re-authentication that immediately followed it")
	}

	// max_age=300.
	five := &AuthRequest{MaxAge: seconds(300)}
	if five.FreshnessNeeded(now.Add(-10*time.Second), now) {
		t.Error("max_age=300 sent a 10-second-old session back at the boundary")
	}
	if !five.FreshnessNeeded(now.Add(-10*time.Minute), now) {
		t.Error("max_age=300 accepted a 10-minute-old session at the boundary")
	}
	if five.FreshnessSatisfied(now.Add(-10*time.Minute), now) {
		t.Error("max_age=300 accepted a 10-minute-old authentication at completion")
	}

	// No bound: never forces a re-login, never needs a recorded time.
	plain := &AuthRequest{}
	if plain.FreshnessNeeded(now.Add(-time.Hour), now) {
		t.Error("a request with no freshness bound must not force a re-login")
	}
	if !plain.FreshnessSatisfied(time.Time{}, now) {
		t.Error("a request with no freshness bound must not require a recorded time")
	}
	if plain.RequiresReauthentication(now) {
		t.Error("RequiresReauthentication must be false without a bound")
	}
	if !login.RequiresReauthentication(now) {
		t.Error("RequiresReauthentication must be true for prompt=login with no recorded time")
	}
}
