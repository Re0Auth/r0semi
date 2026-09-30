package auth

import (
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/idp"
	"github.com/Re0Auth/r0semi/internal/account"
	"github.com/Re0Auth/r0semi/internal/safeurl"
)

// audit9Store is a minimal scs.Store that records the largest committed session
// payload. The equivalent probe in zz_audit_session_test.go is behind the
// `audit || audit6` build tag, so this file cannot share it and the default suite
// would otherwise have no way to observe session size.
type audit9Store struct {
	mu     sync.Mutex
	maxLen int
	data   map[string][]byte
}

func newAudit9Store() *audit9Store { return &audit9Store{data: map[string][]byte{}} }

func (s *audit9Store) Find(token string) ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.data[token]
	return b, ok, nil
}

func (s *audit9Store) Commit(token string, b []byte, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(b) > s.maxLen {
		s.maxLen = len(b)
	}
	s.data[token] = append([]byte(nil), b...)
	return nil
}

func (s *audit9Store) Delete(token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, token)
	return nil
}

// AUDIT9 / S03-1 — return_to has no length bound and is persisted verbatim in the
// server-side session.
//
// AUDIT9 / S03-1 (fixed) — return_to is bounded by safeurl.RelativePath, so an
// oversized value never reaches the session.
//
// handleStart stores the sanitised return_to in the server-side session
// (auth.go:616), and scs re-encodes and commits the whole session. Before the fix
// the sanitiser enforced form only, so an anonymous GET could persist up to the
// server's whole header budget per request; RelativePath now replaces a value over
// MaxRelativePathBytes with "/".
func TestAudit9OversizedReturnToIsNotStoredInTheSession(t *testing.T) {
	registry, err := idp.NewRegistry(idp.RegistryConfig{
		RedirectBase: "https://re0auth.test",
		Credentials: []idp.Credentials{{
			Provider: idp.GitHub, ClientID: "cid", ClientSecret: "sec",
			AuthURL:     "https://github.test/authorize",
			TokenURL:    "https://github.test/token",
			UserInfoURL: "https://github.test/user",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	store := newAudit9Store()
	m := NewManager(Options{Secure: false, Store: store})
	handler, err := NewHandler(m, registry, account.NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	handler.Register(mux)
	srv := httptest.NewServer(m.LoadAndSave(mux))
	defer srv.Close()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	const padLen = 8 << 10
	resp, err := client.Get(srv.URL + "/auth/github/start?return_to=/" + strings.Repeat("a", padLen))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("start = %d, want 302", resp.StatusCode)
	}

	store.mu.Lock()
	maxLen := store.maxLen
	store.mu.Unlock()
	// The session carries the flow state, provider, mode, verifier, nonce and a
	// "/" instead of the 8 KiB value. The allowance covers those fixed-size
	// fields; anything near padLen means the oversized value was stored.
	if maxLen > safeurl.MaxRelativePathBytes+512 {
		t.Errorf("largest committed session = %d bytes after a %d-byte return_to: "+
			"the value reached the session despite the %d-byte cap",
			maxLen, padLen, safeurl.MaxRelativePathBytes)
	}
}
