package auth

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"

	"github.com/Re0Auth/r0semi/internal/account"
)

// serveInSession runs probe inside one served request, so the probe sees the
// context scs puts a live session in, and returns what the probe produced. The
// probe runs on the server's goroutine: t.Errorf is fine there, t.Fatal is not.
//
// One server per call is deliberate. The cookie jar is what carries the session
// between calls, exactly as a browser does — and cookies ignore the port, so a
// jar built once works across every short-lived server here.
func serveInSession[T any](t *testing.T, m *Manager, jar http.CookieJar, probe func(context.Context) T) T {
	t.Helper()
	out := make(chan T, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(_ http.ResponseWriter, r *http.Request) { out <- probe(r.Context()) })
	srv := httptest.NewServer(m.LoadAndSave(mux))
	defer srv.Close()

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := (&http.Client{Jar: jar}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return <-out
}

func testJar(t *testing.T) http.CookieJar {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return jar
}

// handles is what one probe observed about a kind's bound handles.
type handles struct {
	queue       []string
	count       int
	oldestBound bool
	newestBound bool
	oldestOwner string
	owner       string
}

func observe(m *Manager, kind, oldest, newest string) func(context.Context) handles {
	return func(ctx context.Context) handles {
		queue := m.boundQueue(ctx, kind)
		return handles{
			queue:       append([]string(nil), queue...),
			count:       len(queue),
			oldestBound: m.Bound(ctx, kind, oldest),
			newestBound: m.Bound(ctx, kind, newest),
			oldestOwner: m.sessions.GetString(ctx, ownerKey(kind, oldest)),
			owner:       m.sessions.GetString(ctx, ownerKey(kind, newest)),
		}
	}
}

// A browser can be sent to handle-creating links without ever deciding them: a
// consent screen, a device verification, a bind start. Nothing consumed an
// undecided handle, so the session grew with every link — and a session is read
// and rewritten on every request. The cap evicts the oldest; the newest, which is
// the one the person is actually looking at, survives.
func TestBindCapsHandlesPerKind(t *testing.T) {
	m := NewManager(Options{Secure: false})
	jar := testJar(t)
	const kind = "authz"

	if err := serveInSession(t, m, jar, func(ctx context.Context) error {
		return m.SignIn(ctx, account.UserID("usr_1"))
	}); err != nil {
		t.Fatal(err)
	}

	ids := make([]string, 0, maxBoundHandlesPerKind*2)
	for i := 0; i < maxBoundHandlesPerKind*2; i++ {
		ids = append(ids, fmt.Sprintf("arq_%03d", i))
	}
	serveInSession(t, m, jar, func(ctx context.Context) any {
		for _, id := range ids {
			m.Bind(ctx, kind, id)
		}
		return nil
	})

	got := serveInSession(t, m, jar, observe(m, kind, ids[0], ids[len(ids)-1]))
	if got.count != maxBoundHandlesPerKind {
		t.Fatalf("bound handles = %d, want the cap %d", got.count, maxBoundHandlesPerKind)
	}
	if got.oldestBound {
		t.Error("the oldest handle survived past the cap")
	}
	if got.oldestOwner != "" {
		t.Errorf("an evicted handle kept its owner tag: %q", got.oldestOwner)
	}
	if !got.newestBound {
		t.Error("the newest handle was evicted instead of the oldest")
	}
	if got.owner != "usr_1" {
		t.Errorf("the surviving handle lost its owner tag: %q", got.owner)
	}
}

// Binding is idempotent: re-binding a handle must not enqueue it twice, which
// would evict a live handle for nothing.
func TestBindIsIdempotent(t *testing.T) {
	m := NewManager(Options{Secure: false})
	jar := testJar(t)
	const kind = "device"

	for i := 0; i < 3; i++ {
		serveInSession(t, m, jar, func(ctx context.Context) any {
			m.Bind(ctx, kind, "KHJF-HBNQ")
			return nil
		})
	}
	got := serveInSession(t, m, jar, observe(m, kind, "KHJF-HBNQ", "KHJF-HBNQ"))
	if got.count != 1 {
		t.Fatalf("queue = %v, want one entry", got.queue)
	}
}

// Unbind takes the handle out of the queue as well as out of the session, so the
// cap counts live handles and a consumed one frees its slot.
func TestUnbindFreesTheSlotAndTheQueueEntry(t *testing.T) {
	m := NewManager(Options{Secure: false})
	jar := testJar(t)
	const kind = "authz"

	serveInSession(t, m, jar, func(ctx context.Context) any {
		for _, id := range []string{"one", "two", "three"} {
			m.Bind(ctx, kind, id)
		}
		return nil
	})
	serveInSession(t, m, jar, func(ctx context.Context) any {
		m.Unbind(ctx, kind, "two")
		return nil
	})

	got := serveInSession(t, m, jar, func(ctx context.Context) handles {
		return handles{
			queue:       m.boundQueue(ctx, kind),
			count:       len(m.boundQueue(ctx, kind)),
			oldestBound: m.Bound(ctx, kind, "two"),
			newestBound: m.Bound(ctx, kind, "three"),
		}
	})
	if got.count != 2 {
		t.Fatalf("queue = %v, want two entries after one unbind", got.queue)
	}
	if got.oldestBound {
		t.Error("the unbound handle is still usable")
	}
	if !got.newestBound {
		t.Error("unbinding one handle took another with it")
	}

	// The freed slot is usable, and the new handle goes to the back of the queue.
	serveInSession(t, m, jar, func(ctx context.Context) any {
		m.Bind(ctx, kind, "four")
		return nil
	})
	got = serveInSession(t, m, jar, observe(m, kind, "four", "four"))
	if got.count != 3 || got.queue[len(got.queue)-1] != "four" {
		t.Fatalf("queue = %v, want three entries ending in the newly bound handle", got.queue)
	}
}

// Unbinding everything leaves no queue value behind: an empty queue is the
// absence of the key, not a key holding an empty string.
func TestUnbindRemovesAnEmptiedQueue(t *testing.T) {
	m := NewManager(Options{Secure: false})
	jar := testJar(t)
	const kind = "bind"

	serveInSession(t, m, jar, func(ctx context.Context) any {
		m.Bind(ctx, kind, "bnd_1")
		return nil
	})
	left := serveInSession(t, m, jar, func(ctx context.Context) string {
		m.Unbind(ctx, kind, "bnd_1")
		return m.sessions.GetString(ctx, queueKey(kind))
	})
	if left != "" {
		t.Fatalf("queue value = %q, want it removed", left)
	}
}

// An id that cannot be tracked is not bound at all: binding it without a queue
// entry would put state in the session that nothing can evict.
func TestBindIgnoresAnUntrackableID(t *testing.T) {
	m := NewManager(Options{Secure: false})
	jar := testJar(t)
	const kind = "authz"

	got := serveInSession(t, m, jar, func(ctx context.Context) handles {
		m.Bind(ctx, kind, "with\x1fseparator")
		m.Bind(ctx, kind, "")
		return handles{
			queue:       m.boundQueue(ctx, kind),
			oldestBound: m.Bound(ctx, kind, "with\x1fseparator"),
		}
	})
	if got.count != 0 || got.oldestBound {
		t.Fatalf("an untrackable id was bound: queue=%v bound=%v", got.queue, got.oldestBound)
	}
}
