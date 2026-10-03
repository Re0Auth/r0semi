//go:build audit5

package sessionrevive

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/internal/account"
	"github.com/Re0Auth/r0semi/internal/auth"
	"github.com/Re0Auth/r0semi/internal/store/postgres"
)

// --- the memory path: deterministic, no Postgres ---

// probeRequest drives one request through the session middleware and returns the
// recorder. cookie may be nil.
func probeRequest(m *auth.Manager, cookie *http.Cookie, path string, fn func(http.ResponseWriter, *http.Request)) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	m.LoadAndSave(http.HandlerFunc(fn)).ServeHTTP(rec, req)
	return rec
}

// probeSessionCookie extracts the session cookie scs wrote, if any.
func probeSessionCookie(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if strings.HasPrefix(c.Name, "r0semi_session") || strings.HasPrefix(c.Name, "__Host-") {
			return c
		}
	}
	t.Fatalf("no session cookie in %v", rec.Result().Cookies())
	return nil
}

// probeSignIn performs a real sign-in through the middleware and returns the
// resulting browser cookie.
func probeSignIn(t *testing.T, m *auth.Manager) *http.Cookie {
	t.Helper()
	rec := probeRequest(m, nil, "/login", func(_ http.ResponseWriter, r *http.Request) {
		if err := m.SignIn(r.Context(), account.UserID("usr_victim")); err != nil {
			t.Errorf("SignIn: %v", err)
		}
	})
	return probeSessionCookie(t, rec)
}

// probeUser reports whether the cookie currently authenticates.
func probeUser(t *testing.T, m *auth.Manager, cookie *http.Cookie) (string, bool) {
	t.Helper()
	var (
		got    string
		signed bool
	)
	probeRequest(m, cookie, "/whoami", func(_ http.ResponseWriter, r *http.Request) {
		u, ok := m.User(r.Context())
		got, signed = string(u), ok
	})
	return got, signed
}

// TestProbeR1096ASessionDestroyedInFlightIsNotRevived is the deterministic
// reproduction: request A loads the session and parks; request B signs out;
// A commits its stale copy when it returns. The cookie must still be dead.
func TestProbeR1096ASessionDestroyedInFlightIsNotRevived(t *testing.T) {
	m := auth.NewManager(auth.Options{Secure: false})
	cookie := probeSignIn(t, m)

	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		probeRequest(m, cookie, "/hold", func(_ http.ResponseWriter, r *http.Request) {
			if _, ok := m.User(r.Context()); !ok {
				t.Errorf("control: request A loaded a cookie that does not authenticate")
			}
			close(entered)
			<-release
		})
	}()
	<-entered

	// B destroys the session while A holds its loaded copy.
	probeRequest(m, cookie, "/sign_out", func(_ http.ResponseWriter, r *http.Request) {
		if err := m.SignOut(r.Context()); err != nil {
			t.Errorf("SignOut: %v", err)
		}
	})
	if _, ok := probeUser(t, m, cookie); ok {
		t.Fatal("control: sign-out did not invalidate the cookie")
	}

	close(release)
	<-done

	if user, ok := probeUser(t, m, cookie); ok {
		t.Fatalf("R10-96: a session destroyed while a request was in flight was written back "+
			"by scs's deferred commit and authenticates again as %q; the memory fallback store has no "+
			"tombstone and Commit overwrites the delete unconditionally (M10-1)", user)
	}
}

// --- the durable path: source/migration guard, no database needed ---

func probeReadFile(t *testing.T, rel string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "store", "postgres", filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(raw)
}

// TestProbeR1096CommitRefusesToOverwriteADeletedRow pins the durable half from
// the outside: the upsert needs a predicate, the delete needs to leave a marker,
// and the marker needs a migration. Each assertion names text that HEAD lacks.
func TestProbeR1096CommitRefusesToOverwriteADeletedRow(t *testing.T) {
	src := probeReadFile(t, "sessions.go")
	for _, want := range []string{
		"func (s *Sessions) CommitCtx(",
		"WHERE sessions.invalidated_at IS NULL",
		"UPDATE sessions SET invalidated_at",
	} {
		if !strings.Contains(src, want) {
			t.Fatalf("R10-96: sessions.go has no %q, so a destroyed session is re-inserted by the "+
				"unconditional upsert in CommitCtx", want)
		}
	}
	if !strings.Contains(src, "invalidated_at IS NULL") {
		t.Fatal("R10-96: FindCtx does not ignore the tombstone")
	}

	migrations, err := filepath.Glob(filepath.Join("..", "..", "store", "postgres", "migrations", "*session_invalidated_at*.sql"))
	if err != nil || len(migrations) == 0 {
		t.Fatalf("R10-96: no migration adds sessions.invalidated_at (glob err=%v)", err)
	}
	up := probeReadFile(t, filepath.Join("migrations", filepath.Base(migrations[0])))
	for _, want := range []string{"ADD COLUMN IF NOT EXISTS invalidated_at", "DROP COLUMN IF EXISTS invalidated_at"} {
		if !strings.Contains(up, want) {
			t.Fatalf("the invalidated_at migration has no %q:\n%s", want, up)
		}
	}
}

// --- the durable path: behavioural, skipped without a database ---

// TestProbeR1096PostgresCommitCannotResurrectADeletedSession exercises the store
// directly. scs supplies the deferred commit in production, so the sequential
// sequence below is enough — no concurrency.
func TestProbeR1096PostgresCommitCannotResurrectADeletedSession(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is not set; skipping Postgres integration probe")
	}
	ctx := context.Background()
	db, err := postgres.Open(ctx, dsn, postgres.DefaultPoolOptions())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(db.Close)
	sessions := db.Sessions()

	token := "probe-r1096-" + time.Now().UTC().Format("20060102150405.000000000")
	expiry := time.Now().Add(time.Hour)

	if err := sessions.Commit(token, []byte("before"), expiry); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if err := sessions.Delete(token); err != nil {
		t.Fatalf("delete: %v", err)
	}
	// The in-flight request's deferred commit.
	if err := sessions.Commit(token, []byte("after"), expiry); err != nil {
		t.Fatalf("second commit: %v", err)
	}
	if _, found, err := sessions.Find(token); err != nil {
		t.Fatalf("find: %v", err)
	} else if found {
		t.Fatal("R10-96: Commit re-created a session that Delete had removed")
	}

	// And the per-subject path: a revived session would also be missing from
	// session_subjects, so RevokeSubjectSessions must not be able to miss it.
	token2 := token + "-subject"
	if err := sessions.Commit(token2, []byte("before"), expiry); err != nil {
		t.Fatalf("commit2: %v", err)
	}
	if err := sessions.Remember(ctx, token2, "usr_r1096"); err != nil {
		t.Fatalf("remember: %v", err)
	}
	if _, err := sessions.RevokeSubjectSessions(ctx, "usr_r1096"); err != nil {
		t.Fatalf("revoke subject: %v", err)
	}
	if err := sessions.Commit(token2, []byte("after"), expiry); err != nil {
		t.Fatalf("commit2 after revoke: %v", err)
	}
	if _, found, err := sessions.Find(token2); err != nil {
		t.Fatalf("find2: %v", err)
	} else if found {
		t.Fatal("R10-96: a subject-revoked session was revived by a later commit")
	}
}
