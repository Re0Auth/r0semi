package tapsign

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Re0Auth/r0semi/audit"
)

func testCred() Credential {
	return Credential{SessionToken: "test-session-token", ObjectID: "test-object-id"}
}

func newTestClient(t *testing.T, h http.Handler) (*client, *audit.MemoryLogger) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	logger := audit.NewMemoryLogger()
	return newClient(Config{BaseURL: srv.URL, AppID: "test-app", AppKey: "test-key"}, srv.Client(), logger), logger
}

func TestVerifyOK(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/users/me" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("X-LC-Session"); got != "test-session-token" {
			t.Errorf("X-LC-Session = %q", got)
		}
		if r.Header.Get("X-LC-Id") != "test-app" || r.Header.Get("X-LC-Key") != "test-key" {
			t.Errorf("missing app headers: %v", r.Header)
		}
		w.WriteHeader(http.StatusOK)
	}))
	if err := c.Verify(context.Background(), testCred()); err != nil {
		t.Fatalf("Verify = %v", err)
	}
}

func TestVerifyInvalidCredential(t *testing.T) {
	for _, code := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(code)
		}))
		if err := c.Verify(context.Background(), testCred()); !errors.Is(err, ErrInvalidCredential) {
			t.Fatalf("status %d: err = %v, want ErrInvalidCredential", code, err)
		}
	}
}

func TestVerifyUnexpectedStatusIsNotADeathSignal(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	err := c.Verify(context.Background(), testCred())
	if err == nil || errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("err = %v, want a transient error", err)
	}
}

func TestRotateReturnsReplacement(t *testing.T) {
	c, logger := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/users/test-object-id/refreshSessionToken" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"sessionToken": "rotated-token"})
	}))
	next, err := c.Rotate(context.Background(), testCred())
	if err != nil {
		t.Fatal(err)
	}
	if next.SessionToken != "rotated-token" || next.ObjectID != "test-object-id" {
		t.Fatalf("next = %+v", next)
	}
	events := logger.Events()
	if len(events) != 1 || events[0].Action != "tapsign.rotate" || events[0].Outcome != audit.OutcomeOK {
		t.Fatalf("events = %+v", events)
	}
}

func TestRotateInvalidCredential(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	if _, err := c.Rotate(context.Background(), testCred()); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("err = %v, want ErrInvalidCredential", err)
	}
}

// Revoke performs the rotation but must discard the replacement token.
func TestRevokeDiscardsReplacement(t *testing.T) {
	called := false
	c, logger := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		_ = json.NewEncoder(w).Encode(map[string]string{"sessionToken": "should-be-discarded"})
	}))
	if err := c.Revoke(context.Background(), testCred()); err != nil {
		t.Fatalf("Revoke = %v", err)
	}
	if !called {
		t.Fatal("upstream was not called")
	}
	events := logger.Events()
	if len(events) != 1 || events[0].Action != "tapsign.revoke" || events[0].Outcome != audit.OutcomeOK {
		t.Fatalf("events = %+v", events)
	}
}

// Revoke's goal is "the old token is invalid", so a 403 means it is already
// achieved and must be reported as success.
func TestRevokeIsIdempotentOnInvalid(t *testing.T) {
	c, logger := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	if err := c.Revoke(context.Background(), testCred()); err != nil {
		t.Fatalf("Revoke = %v, want nil", err)
	}
	events := logger.Events()
	if len(events) != 1 || events[0].Outcome != audit.OutcomeOK {
		t.Fatalf("events = %+v", events)
	}
}

func TestRotateRequiresObjectID(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	if _, err := c.Rotate(context.Background(), Credential{SessionToken: "x"}); err == nil {
		t.Fatal("expected an error for a missing object id")
	}
}

func TestRedeemReturnsCredential(t *testing.T) {
	var body map[string]any
	c, logger := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/users" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("content-type = %q", ct)
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"sessionToken": "sess-1", "objectId": "obj-1"})
	}))

	cred, err := c.Redeem(context.Background(), TapTapToken{Kid: "kid", MacKey: "mac", OpenID: "openid", UnionID: "union"})
	if err != nil {
		t.Fatal(err)
	}
	if cred.SessionToken != "sess-1" || cred.ObjectID != "obj-1" {
		t.Fatalf("cred = %+v", cred)
	}
	auth, ok := body["authData"].(map[string]any)["taptap"].(map[string]any)
	if !ok {
		t.Fatalf("authData = %v", body)
	}
	if auth["openid"] != "openid" || auth["mac_key"] != "mac" || auth["mac_algorithm"] != "hmac-sha-1" {
		t.Fatalf("authData = %v", auth)
	}
	if events := logger.Events(); len(events) != 1 || events[0].Action != "tapsign.redeem" || events[0].Outcome != audit.OutcomeOK {
		t.Fatalf("events = %+v", events)
	}
}

func TestRedeemRejectsIncompleteToken(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	if _, err := c.Redeem(context.Background(), TapTapToken{Kid: "k"}); err == nil {
		t.Fatal("expected an error")
	}
}

func TestCredentialCodec(t *testing.T) {
	in := testCred()
	b, err := in.Encode()
	if err != nil {
		t.Fatal(err)
	}
	out, err := DecodeCredential(b)
	if err != nil {
		t.Fatal(err)
	}
	if out != in {
		t.Fatalf("round trip = %+v, want %+v", out, in)
	}
	if _, err := DecodeCredential([]byte("{")); err == nil {
		t.Fatal("accepted invalid json")
	}
}
