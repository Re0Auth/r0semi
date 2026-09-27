package httpapi

// The device flow's session state, pinned end to end: a handle is bound when the
// verification page is loaded, and it is released when the decision lands. The
// consent flow always did this; the device flow did not, so every code a browser
// had ever loaded stayed in the session for the life of the cookie.

import (
	"bytes"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"
)

// recordingSessions is an scs.Store that keeps what was committed, so a test can
// read the session a browser actually holds. The production stores are opaque on
// purpose; this one exists to assert on what is left inside.
type recordingSessions struct {
	mu   sync.Mutex
	data map[string][]byte
}

func newRecordingSessions() *recordingSessions {
	return &recordingSessions{data: map[string][]byte{}}
}

func (s *recordingSessions) Find(token string) ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.data[token]
	return b, ok, nil
}

func (s *recordingSessions) Commit(token string, b []byte, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[token] = append([]byte(nil), b...)
	return nil
}

func (s *recordingSessions) Delete(token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, token)
	return nil
}

// holds reports whether any committed session carries key. The codec is gob, which
// writes a map key as its own bytes, so a substring search sees the keys — and no
// value in these sessions ("1", "usr_…", a code) can contain one by accident.
func (s *recordingSessions) holds(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, b := range s.data {
		if bytes.Contains(b, []byte(key)) {
			return true
		}
	}
	return false
}

func TestDeviceDecisionReleasesTheSessionHandle(t *testing.T) {
	sessions := newRecordingSessions()
	base, _, _ := newFlowEnvWithOptions(t, flowEnvOptions{SessionStore: sessions})

	start := decodeResp(t, postForm(t, newBrowser(t), base+"/oauth/device_authorization",
		url.Values{"client_id": {"cli"}, "scope": {"account.id"}}))
	userCode, _ := start["user_code"].(string)
	if userCode == "" {
		t.Fatalf("no user code: %v", start)
	}

	victim := newBrowser(t)
	signInAs(t, victim, base, "v")
	csrf := sessionCSRF(t, base, victim)

	// Loading the verification page is what binds the handle to the session.
	view := decodeResp(t, getURL(t, victim, base+"/v1/device/verification?user_code="+url.QueryEscape(userCode)))
	bound, _ := view["user_code"].(string)
	if bound == "" {
		t.Fatalf("the verification page did not answer: %v", view)
	}
	handleKey := "handle_device_" + bound
	if !sessions.holds(handleKey) {
		t.Fatalf("the verification page did not bind %q to the session", handleKey)
	}

	resp := adminJSON(t, victim, http.MethodPost, base+"/v1/device/decision", csrf, map[string]any{
		"user_code": bound,
		"decision":  "approve",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("decision = %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()

	if sessions.holds(handleKey) {
		t.Errorf("the device handle %q outlived its decision", handleKey)
	}
	if sessions.holds("owner_device_" + bound) {
		t.Errorf("the device handle's owner tag outlived its decision")
	}
}
