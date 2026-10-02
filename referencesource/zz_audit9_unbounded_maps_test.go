package referencesource

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/idp"
	"github.com/Re0Auth/r0semi/tapsign"
	"github.com/Re0Auth/r0semi/taptapoauth"
)

// AUDIT9 / S06-4 — SocialLogin.states used to be an unbounded map swept with a
// full O(n) scan on every unauthenticated start.
//
// handleStart runs sweepLocked() and then inserts one entry per request. There
// is no timer: expiry is enforced only by that scan, so the map used to grow
// with the request rate times the state TTL. The fix adds maxInFlightStates gate
// inside the lock, so the resident set stops tracking the number of started
// flows.
//
// Guard (flipped after the fix): pins the bound. It fails if the map is allowed
// to grow past maxInFlightStates again.
func TestAudit9SocialLoginStatesAreBounded(t *testing.T) {
	reg, err := idp.NewRegistry(idp.RegistryConfig{
		RedirectBase: "https://referencesource.example",
		Credentials: []idp.Credentials{{
			Provider: idp.GitHub, ClientID: "cid", ClientSecret: "sec",
			AuthURL:     "https://github.example/authorize",
			TokenURL:    "https://github.example/token",
			UserInfoURL: "https://github.example/user",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	login, err := NewSocialLogin(SocialConfig{}, SocialDeps{Registry: reg})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	login.Mount(mux, func(context.Context, Principal) error { return nil })

	const starts = maxInFlightStates + 500
	refused := 0
	for i := 0; i < starts; i++ {
		req := httptest.NewRequest(http.MethodGet, "/login/github/start", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		switch rec.Code {
		case http.StatusFound:
		case http.StatusServiceUnavailable:
			refused++
		default:
			t.Fatalf("start %d = %d, want 302 or 503: %s", i, rec.Code, rec.Body.String())
		}
	}
	if refused == 0 {
		t.Errorf("%d starts all issued a redirect, want the cap to refuse the tail", starts)
	}

	login.mu.Lock()
	held := len(login.states)
	login.mu.Unlock()
	if held > maxInFlightStates {
		t.Errorf("states holds %d, want <= maxInFlightStates (%d)", held, maxInFlightStates)
	}
}

// AUDIT9 / S06-5 — the same shape on TapTapLogin.attempts, reachable through the
// unauthenticated POST /login/taptap/challenge, with one sweep per challenge.
//
// Guard (flipped after the fix): pins the bound. It fails if the map is allowed
// to grow past maxTapTapAttempts again.
func TestAudit9TapTapAttemptsAreBounded(t *testing.T) {
	login, err := NewTapTapLogin(TapTapConfig{}, TapTapDeps{
		Enroller: audit9Enroller{},
		Redeem:   audit9Redeem{},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	const attempts = maxTapTapAttempts + 500
	refused := 0
	for i := 0; i < attempts; i++ {
		if _, err := login.begin(ctx); err != nil {
			if !errors.Is(err, errTooManyAttempts) {
				t.Fatalf("begin %d: %v", i, err)
			}
			refused++
		}
	}
	if refused == 0 {
		t.Errorf("%d begins all succeeded, want the cap to refuse the tail", attempts)
	}

	login.mu.Lock()
	held := len(login.attempts)
	login.mu.Unlock()
	if held > maxTapTapAttempts {
		t.Errorf("attempts holds %d, want <= maxTapTapAttempts (%d)", held, maxTapTapAttempts)
	}
}

// audit9Enroller is a device-authorization enroller that never needs a network.
type audit9Enroller struct{}

func (audit9Enroller) Start(context.Context) (taptapoauth.DeviceAuth, error) {
	return taptapoauth.DeviceAuth{
		DeviceID:        "device-1",
		DeviceCode:      "dc-1",
		UserCode:        "uc-1",
		VerificationURL: "https://taptap.example/approve",
		Interval:        time.Second,
		ExpiresAt:       time.Now().Add(time.Hour),
	}, nil
}

func (audit9Enroller) Poll(context.Context, taptapoauth.DeviceAuth) (tapsign.TapTapToken, error) {
	return tapsign.TapTapToken{}, errors.New("not approved")
}

// audit9Redeem satisfies tapsign.Service; the growth test never calls it.
type audit9Redeem struct{}

func (audit9Redeem) Verify(context.Context, tapsign.Credential) error { return nil }
func (audit9Redeem) Rotate(context.Context, tapsign.Credential) (tapsign.Credential, error) {
	return tapsign.Credential{}, nil
}
func (audit9Redeem) Revoke(context.Context, tapsign.Credential) error { return nil }
func (audit9Redeem) Redeem(context.Context, tapsign.TapTapToken) (tapsign.Credential, error) {
	return tapsign.Credential{}, nil
}
