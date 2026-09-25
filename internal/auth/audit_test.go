package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Re0Auth/r0semi/audit"
)

// findEvent returns the first retained event with the given action, or nil.
func findEvent(h *harness, action string) *audit.Event {
	for _, e := range h.audit.Events() {
		if e.Action == action {
			ev := e
			return &ev
		}
	}
	return nil
}

// A first sign-in produces two events: the account creation and the sign-in
// itself. Both carry the subject, so "who was created" and "who signed in" are
// answerable from the log alone.
func TestLoginAndSignupAreAudited(t *testing.T) {
	h := newHarness(t)
	h.login(t, "github")

	signup := findEvent(h, "auth.signup")
	if signup == nil {
		t.Fatal("no auth.signup event was recorded")
	}
	if signup.Outcome != audit.OutcomeOK || signup.Provider != "github" || signup.Subject == "" {
		t.Fatalf("signup event = %+v", signup)
	}
	login := findEvent(h, "auth.login")
	if login == nil {
		t.Fatal("no auth.login event was recorded")
	}
	if login.Outcome != audit.OutcomeOK || login.Subject != signup.Subject {
		t.Fatalf("login event = %+v, signup subject = %q", login, signup.Subject)
	}
}

// A refused callback is recorded with the bounded code (never a request value)
// and no subject, because nobody authenticated.
func TestFailedLoginIsAudited(t *testing.T) {
	h := newHarness(t)
	resp := h.get(t, h.server.URL+"/auth/github/callback?code=c&state=forged")
	resp.Body.Close()

	ev := findEvent(h, "auth.login")
	if ev == nil {
		t.Fatal("no auth.login event was recorded for a refused callback")
	}
	if ev.Outcome != audit.OutcomeDenied {
		t.Errorf("outcome = %q, want denied", ev.Outcome)
	}
	if ev.Detail["code"] != "invalid_state" {
		t.Errorf("code = %q, want invalid_state", ev.Detail["code"])
	}
	if ev.Subject != "" {
		t.Errorf("subject = %q, want empty for an unauthenticated failure", ev.Subject)
	}
}

// Sign-out is recorded with the subject, so a session's end is as auditable as
// its start.
func TestSignOutIsAudited(t *testing.T) {
	log := audit.NewMemoryLogger()
	manager := NewManager(Options{Secure: false, Audit: log})

	rec := httptest.NewRecorder()
	manager.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := manager.SignIn(r.Context(), "usr_1"); err != nil {
			t.Errorf("sign in: %v", err)
		}
	})).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(sessionCookie(t, rec))
	manager.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := manager.SignOut(r.Context()); err != nil {
			t.Errorf("sign out: %v", err)
		}
	})).ServeHTTP(httptest.NewRecorder(), req)

	var found *audit.Event
	for _, e := range log.Events() {
		if e.Action == "auth.logout" {
			ev := e
			found = &ev
		}
	}
	if found == nil {
		t.Fatal("no auth.logout event was recorded")
	}
	if found.Subject != "usr_1" || found.Outcome != audit.OutcomeOK {
		t.Fatalf("logout event = %+v", found)
	}
}
