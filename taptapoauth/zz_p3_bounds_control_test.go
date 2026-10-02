package taptapoauth

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/Re0Auth/r0semi/httpclient"
)

func startWithDeviceData(t *testing.T, data map[string]any) DeviceAuth {
	t.Helper()
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "data": data})
	}))
	auth, err := c.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return auth
}

// S07-5 — interval and expires_in come from the untrusted upstream reply. They
// must be clamped to protocol-sane ranges, and the seconds*time.Second
// multiplication must never be allowed to overflow int64.
func TestStartClampsUpstreamIntervalAndExpires(t *testing.T) {
	for _, tc := range []struct {
		name             string
		interval, expire int64
		wantInterval     time.Duration
	}{
		{"nominal", 3, 300, 3 * time.Second},
		{"below the floor", 1, 1, time.Second},
		{"non-positive falls back to the default", 0, 0, defaultInterval},
		{"negative falls back to the default", -5, -5, defaultInterval},
		{"above the ceiling", 90, 7200, maxInterval},
		{"int64 overflow candidate", 9223372036854775807, 9223372036854775807, maxInterval},
		// A value whose seconds*time.Second would wrap negative but that is
		// itself a plausible-looking number: 9_223_372_036 seconds.
		{"just under the wrap point", 9223372036, 9223372036, maxInterval},
	} {
		t.Run(tc.name, func(t *testing.T) {
			auth := startWithDeviceData(t, map[string]any{
				"device_code":      "dc",
				"verification_url": "https://www.taptap.com/account/device",
				"user_code":        "UC",
				"interval":         tc.interval,
				"expires_in":       tc.expire,
			})
			if auth.Interval != tc.wantInterval {
				t.Errorf("Interval = %v, want %v", auth.Interval, tc.wantInterval)
			}
			if auth.Interval < minInterval || auth.Interval > maxInterval {
				t.Errorf("Interval = %v, outside [%v,%v]", auth.Interval, minInterval, maxInterval)
			}
			// ExpiresAt is set from the real clock inside Start; the window it
			// opens must stay inside the clamp, whatever the upstream said.
			window := time.Until(auth.ExpiresAt)
			if window <= 0 {
				t.Fatalf("ExpiresAt %v is not in the future (window %v)", auth.ExpiresAt, window)
			}
			if window > maxExpires+time.Second {
				t.Errorf("expiry window %v exceeds the %v cap", window, maxExpires)
			}
		})
	}
}

// S07-7 — the error text is flattened to keep a hostile upstream from forging a
// log record. Stripping only CR and LF left ESC, NUL and every other control
// rune intact, which reaches an operator's terminal through the logged error.
func TestUpstreamErrorTextKeepsNoControlRunes(t *testing.T) {
	hostile := "bad\x1b[2J\x1b[31mFATAL: audit disabled\x00\x07\tend"
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": false,
			"data":    map[string]string{"error": "invalid_client", "error_description": hostile},
		})
	}))

	_, err := c.Start(context.Background())
	if err == nil {
		t.Fatal("expected an error")
	}
	for i, r := range err.Error() {
		if !unicode.IsPrint(r) {
			t.Fatalf("rune %d (%q) is non-printable in %q", i, r, err.Error())
		}
	}
	// Anti-vacuous: bounding must not have dropped the machine-readable code.
	if !strings.Contains(err.Error(), "invalid_client") {
		t.Fatalf("the upstream error code was dropped: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "FATAL: audit disabled") {
		t.Fatalf("the printable part of the upstream text was lost: %q", err.Error())
	}
}

// S07-8 (same family as the tapsign finding) — a Doer allowed to return (nil,
// nil) or a body-less response must produce an error rather than a panic.
func TestNilResponseFromTheDoerIsAnErrorNotAPanic(t *testing.T) {
	c := newClient(Config{
		DeviceCodeEndpoint: "http://upstream.invalid/device/code",
		TokenEndpoint:      "http://upstream.invalid/token",
		UserInfoEndpoint:   "http://upstream.invalid/userinfo",
		ClientID:           "cid",
	}, httpclient.DoerFunc(func(*http.Request) (*http.Response, error) { return nil, nil }))

	if _, err := c.Start(context.Background()); err == nil {
		t.Fatal("Start accepted a nil response with a nil error")
	}
	if _, _, err := c.postForm(context.Background(), "http://upstream.invalid/token", nil); err == nil {
		t.Fatal("postForm accepted a nil response with a nil error")
	}
	if _, err := c.fetchAccount(context.Background(), "kid", "mac"); err == nil {
		t.Fatal("fetchAccount accepted a nil response with a nil error")
	}
}
