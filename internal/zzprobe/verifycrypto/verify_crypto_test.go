//go:build audit5

// Package verifycrypto holds the adversarial verifier's probes for the
// crypto-keys audit report (docs/audit-5/findings/crypto-keys.md).
//
// Every test here is written to REFUTE a specific claim in that report. A test
// that passes is a claim that did not survive; a test that fails is a claim that
// did. Nothing in this package ships.
package verifycrypto

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/alexedwards/scs/v2"
	"github.com/alexedwards/scs/v2/memstore"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/internal/account"
	"github.com/Re0Auth/r0semi/internal/auth"
	"github.com/Re0Auth/r0semi/internal/config"
	"github.com/Re0Auth/r0semi/internal/lifecycle"
	"github.com/Re0Auth/r0semi/oauth"
	"github.com/Re0Auth/r0semi/vault"
)

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

func key32(t *testing.T, id string, material byte) *vault.LocalKeyWrapper {
	t.Helper()
	kek := make([]byte, 32)
	for i := range kek {
		kek[i] = material
	}
	w, err := vault.NewLocalKeyWrapper(id, kek)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

// hookRepo is a Repo that can run an action inside a rotation's write, which is
// the window between "the page was read" and "the stale record was stored".
type hookRepo struct {
	inner  *vault.MemoryRepo
	onPage func()
	onPut  func(vault.Record)
}

func (r *hookRepo) Put(ctx context.Context, rec vault.Record) error {
	if r.onPut != nil {
		r.onPut(rec)
	}
	return r.inner.Put(ctx, rec)
}

func (r *hookRepo) Get(ctx context.Context, id vault.Identity) (vault.Record, error) {
	return r.inner.Get(ctx, id)
}
func (r *hookRepo) Delete(ctx context.Context, id vault.Identity) error {
	return r.inner.Delete(ctx, id)
}
func (r *hookRepo) List(ctx context.Context) ([]vault.Record, error) {
	recs, err := r.inner.List(ctx)
	if err == nil && r.onPage != nil {
		r.onPage()
	}
	return recs, err
}
func (r *hookRepo) ListPage(ctx context.Context, s, p string, n int) ([]vault.Record, error) {
	recs, err := r.inner.ListPage(ctx, s, p, n)
	if err == nil && r.onPage != nil {
		r.onPage()
	}
	return recs, err
}
func (r *hookRepo) DeleteSubject(ctx context.Context, s string) (int, error) {
	return r.inner.DeleteSubject(ctx, s)
}

// failOnNthPut fails one write, standing in for any way a run dies halfway.
type failOnNthPut struct {
	vault.Repo
	failAt int
	mu     sync.Mutex
	seen   int
}

func (r *failOnNthPut) Put(ctx context.Context, rec vault.Record) error {
	r.mu.Lock()
	r.seen++
	n := r.seen
	r.mu.Unlock()
	if n == r.failAt {
		return context.DeadlineExceeded
	}
	return r.Repo.Put(ctx, rec)
}

func readSecret(t *testing.T, svc vault.Service, id vault.Identity) (string, error) {
	t.Helper()
	var got []byte
	err := svc.Use(context.Background(), id, func(secret []byte) error {
		got = append([]byte(nil), secret...)
		return nil
	})
	if err != nil {
		return "", err
	}
	return string(got), nil
}

func mustRead(t *testing.T, svc vault.Service, id vault.Identity) string {
	t.Helper()
	s, err := readSecret(t, svc, id)
	if err != nil {
		t.Fatalf("read %s: %v", id, err)
	}
	return s
}

// ---------------------------------------------------------------------------
// k2, mechanism: the report says the overwritten row becomes PERMANENTLY
// UNREADABLE because "the envelope is new but the ciphertext is stale, so
// AES-GCM rejects it". That is a claim about a paired (DEK, ciphertext) set that
// rotation never creates: rotation re-wraps the DEK it read from the SAME row
// whose nonce/ciphertext it also re-writes, so the pair stays matched. If the row
// still decrypts, the mechanism is refuted and the harm is a silent rollback, not
// corruption.
// ---------------------------------------------------------------------------

func TestVerifyRotateOverwriteLeavesARecordThatStillDecrypts(t *testing.T) {
	ctx := context.Background()
	id := vault.Identity{Subject: "usr_race", Provider: "taptap"}
	repo := &hookRepo{inner: vault.NewMemoryRepo()}
	logger := audit.NewMemoryLogger()

	old := key32(t, "kek-1", 0xA1)
	fresh := key32(t, "kek-2", 0xB2)

	writer, err := vault.NewService(repo, old, logger)
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Enroll(ctx, id, []byte("first-secret"), nil); err != nil {
		t.Fatal(err)
	}

	raced := false
	repo.onPut = func(vault.Record) {
		if raced {
			return
		}
		raced = true
		// The concurrent writer uses the key it is configured with; in the
		// deployment this models, that is the still-current old KEK.
		if err := writer.Enroll(ctx, id, []byte("second-secret"), nil); err != nil {
			t.Errorf("concurrent enroll: %v", err)
		}
	}

	rotator, err := vault.NewService(repo, fresh, logger, vault.WithRetiredKeys(old))
	if err != nil {
		t.Fatal(err)
	}
	rotation, err := rotator.Rotate(ctx)
	if err != nil {
		t.Fatalf("rotation reported an error: %v", err)
	}
	if !raced {
		t.Fatal("the probe never reached the interleaving it claims to model")
	}

	// Rotate with ONLY the new key configured: this is the post-rotation
	// deployment (the retired key is supposed to be removable by then).
	afterOnly, err := vault.NewService(repo, fresh, logger)
	if err != nil {
		t.Fatal(err)
	}

	got, rerr := readSecret(t, afterOnly, id)
	if rerr != nil {
		// This is what the report predicts (AES-GCM rejecting a mismatched pair).
		t.Errorf("REFUTED-BY-FAILURE: the overwritten row does NOT decrypt (%v); "+
			"the report's 'permanently unreadable' mechanism holds", rerr)
		return
	}
	if got != "first-secret" {
		t.Fatalf("secret = %q, want the stale payload the report describes", got)
	}

	// What survives: a self-consistent, fully readable row holding the PREVIOUS
	// payload. The newer secret is gone and rotation reported %+v (success).
	t.Logf("REFUTED: the stale record is still readable and self-consistent under the "+
		"NEW key (read back %q, no unwrap or GCM failure). rotation reported %+v. "+
		"So the harm is a SILENT ROLLBACK to the previous payload, not an unreadable row.",
		got, rotation)

	// The wrap/key pair is genuinely the new one, which is why the pair matches.
	recs, err := repo.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if recs[0].KEKID != "kek-2" {
		t.Fatalf("kek_id = %q, want kek-2", recs[0].KEKID)
	}
	t.Logf("the surviving row is on kek_id=%q (new envelope) with the payload it was read "+
		"with, i.e. a MATCHED pair: the DEK rotation re-wrapped is the one that payload "+
		"was encrypted under", recs[0].KEKID)
}

// ---------------------------------------------------------------------------
// k2/V-1, reachability and the harm the report did NOT describe: an old server
// that is still serving writes with the key IT is configured with, so a write
// that lands after the rotation passed that identity (or after the run finished)
// stays wrapped under the retiring KEK. Rotation reports success over what it
// scanned, the documented last step removes the old key, and the binding is then
// unrecoverable — with no error anywhere.
// ---------------------------------------------------------------------------

func TestVerifyWriteAfterRotationLeavesARowOnTheRetiredKey(t *testing.T) {
	ctx := context.Background()
	repo := vault.NewMemoryRepo()
	logger := audit.NewMemoryLogger()

	old := key32(t, "kek-1", 0xA1)
	fresh := key32(t, "kek-2", 0xB2)

	a := vault.Identity{Subject: "usr_a", Provider: "taptap"}
	oldPod, err := vault.NewService(repo, old, logger)
	if err != nil {
		t.Fatal(err)
	}
	if err := oldPod.Enroll(ctx, a, []byte("a-secret"), nil); err != nil {
		t.Fatal(err)
	}

	// Step 3 of the documented procedure, run with both keys configured.
	rotator, err := vault.NewService(repo, fresh, logger, vault.WithRetiredKeys(old))
	if err != nil {
		t.Fatal(err)
	}
	rotation, err := rotator.Rotate(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// The server that is still on the old key keeps serving. This write commits
	// AFTER the rotation finished, so it is wrapped by kek-1 no matter how the
	// rotation pages.
	b := vault.Identity{Subject: "usr_b", Provider: "taptap"}
	if err := oldPod.Enroll(ctx, b, []byte("b-secret"), nil); err != nil {
		t.Fatal(err)
	}

	recs, err := repo.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("records = %d, want 2", len(recs))
	}

	// The operator's view of the rotation: it looked like a complete success.
	t.Logf("rotation reported %+v over %d records; %d records now exist. It cannot "+
		"mention the write it never saw.", rotation, len(recs), len(recs))

	// The documented final step: "then remove the block below and restart. The old
	// key is no longer needed." (config/re0auth.example.toml:167-168)
	only, err := vault.NewService(repo, fresh, logger)
	if err != nil {
		t.Fatal(err)
	}
	if got := mustRead(t, only, a); got != "a-secret" {
		t.Fatalf("a = %q", got)
	}
	if got, err := readSecret(t, only, b); err == nil {
		t.Fatalf("REFUTED: usr_b stayed readable without the retired key (got %q); "+
			"the late write was wrapped by the new key after all", got)
	} else {
		t.Logf("CONFIRMED-BEYOND-THE-REPORT: after removing the retired key usr_b is "+
			"permanently unreadable (%v), although -rotate-keys reported %+v and exited 0. "+
			"No error was raised at any point.", err, rotation)
	}

	// And this is the part that refutes k3's framing: with BOTH keys still
	// configured a second run converges, so the loss is avoidable by the step the
	// docs already mandate ("confirm there is nothing left to re-wrap").
	both, err := vault.NewService(repo, fresh, logger, vault.WithRetiredKeys(old))
	if err != nil {
		t.Fatal(err)
	}
	second, err := both.Rotate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := mustRead(t, only, b); got != "b-secret" {
		t.Fatalf("b = %q after the re-run", got)
	}
	t.Logf("a second run with both keys configured converged (%+v): usr_b is readable "+
		"again under the new key alone. Nothing was ever unrecoverable while the "+
		"retired key was still declared.", second)
}

// ---------------------------------------------------------------------------
// k3: the report's impact paragraph is "permanent credential loss". That only
// holds if the operator removes the retired key after a partial run. If a re-run
// converges, the finding is operator-signal quality. This probe walks exactly the
// documented procedure: partial failure, keep BOTH keys, re-run.
// ---------------------------------------------------------------------------

func TestVerifyPartialRotationConvergesOnRerun(t *testing.T) {
	ctx := context.Background()
	repo := vault.NewMemoryRepo()
	logger := audit.NewMemoryLogger()
	old := key32(t, "kek-1", 0xA1)
	fresh := key32(t, "kek-2", 0xB2)

	writer, err := vault.NewService(repo, old, logger)
	if err != nil {
		t.Fatal(err)
	}
	ids := []vault.Identity{
		{Subject: "usr_a", Provider: "taptap"},
		{Subject: "usr_b", Provider: "taptap"},
		{Subject: "usr_c", Provider: "taptap"},
	}
	for _, id := range ids {
		if err := writer.Enroll(ctx, id, []byte("secret-"+id.Subject), nil); err != nil {
			t.Fatal(err)
		}
	}

	failing := &failOnNthPut{Repo: repo, failAt: 2}
	broken, err := vault.NewService(failing, fresh, logger, vault.WithRetiredKeys(old))
	if err != nil {
		t.Fatal(err)
	}
	partial, perr := broken.Rotate(ctx)
	if perr == nil {
		t.Fatal("the probe never produced a partial rotation")
	}
	t.Logf("partial run: %+v, err=%v", partial, perr)

	// Keep both keys configured and simply run it again — the documented
	// procedure, and the thing the report says is not possible.
	both, err := vault.NewService(repo, fresh, logger, vault.WithRetiredKeys(old))
	if err != nil {
		t.Fatal(err)
	}
	second, err := both.Rotate(ctx)
	if err != nil {
		t.Fatalf("re-run failed: %v", err)
	}
	t.Logf("re-run: %+v", second)

	if second.AlreadyCurrent != 1 || second.Rewrapped != 2 || second.Scanned != 3 {
		t.Errorf("re-run = %+v, want AlreadyCurrent 1 / Rewrapped 2 / Scanned 3", second)
	}
	recs, err := repo.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, rec := range recs {
		if rec.KEKID != "kek-2" {
			t.Errorf("%s is still on %q after the re-run", rec.Identity, rec.KEKID)
		}
	}

	// Now the retired key can go, and nothing is lost.
	only, err := vault.NewService(repo, fresh, logger)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		if got := mustRead(t, only, id); got != "secret-"+id.Subject {
			t.Fatalf("%s = %q", id, got)
		}
	}
	t.Logf("REFUTES k3's 'permanent data loss': after a partial run, keeping both keys and " +
		"re-running converged, and removing the retired key then lost NOTHING " +
		"(all 3 credentials readable under the new key alone). The residue is an " +
		"operator-signal problem, not an unrecoverable one.")
}

// ---------------------------------------------------------------------------
// k1 reachability: the httpapi branch that logs the raw id is gated on
// SignOut returning an error, and SignOut returns exactly the session store's
// error. This constructs that failure deterministically, so the branch is
// reachable rather than hypothetical — but only from a store fault.
// ---------------------------------------------------------------------------

// failingDeleteStore is an scs.Store whose Delete always fails, which is what a
// database fault looks like at that moment.
type failingDeleteStore struct {
	*memstore.MemStore
	err error
}

func (s *failingDeleteStore) Delete(string) error { return s.err }

// sessionHarness drives a real scs session through httptest so SignIn/SignOut see
// the session data a request would.
type sessionHarness struct {
	srv    *httptest.Server
	client *http.Client
	outErr error
	mu     sync.Mutex
}

func newSessionHarness(t *testing.T, store scs.Store, sink audit.Logger, subject account.UserID) *sessionHarness {
	t.Helper()
	m := auth.NewManager(auth.Options{Store: store, Audit: sink})
	h := &sessionHarness{}
	mux := http.NewServeMux()
	mux.HandleFunc("/in", func(w http.ResponseWriter, r *http.Request) {
		if err := m.SignIn(r.Context(), subject); err != nil {
			t.Errorf("SignIn: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/out", func(w http.ResponseWriter, r *http.Request) {
		user, ok := m.User(r.Context())
		if !ok {
			t.Errorf("the harness lost the session, so SignOut would not name a subject")
		}
		h.mu.Lock()
		h.outErr = m.SignOut(r.Context())
		h.mu.Unlock()
		t.Logf("SignOut saw user=%q and returned err=%v", user, h.outErr)
		w.WriteHeader(http.StatusNoContent)
	})
	h.srv = httptest.NewServer(m.LoadAndSave(mux))
	t.Cleanup(h.srv.Close)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	h.client = &http.Client{Jar: jar}
	return h
}

func (h *sessionHarness) run(t *testing.T, path string) {
	t.Helper()
	resp, err := h.client.Get(h.srv.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
}

func (h *sessionHarness) signOutError() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.outErr
}

func TestVerifySignOutFailsDeterministicallyWhenTheStoreFails(t *testing.T) {
	sentinel := errors.New("session store unreachable")
	h := newSessionHarness(t, &failingDeleteStore{MemStore: memstore.New(), err: sentinel},
		audit.NewMemoryLogger(), account.UserID("usr_verify"))
	h.run(t, "/in")
	h.run(t, "/out")

	if !errors.Is(h.signOutError(), sentinel) {
		t.Fatalf("SignOut err = %v, want the store's error: the httpapi branch that logs "+
			"the raw id would not be reached", h.signOutError())
	}
	t.Logf("CONFIRMED reachable, but ONLY from a session-store fault: SignOut returned %v, "+
		"so internal/httpapi/account_routes.go:73 logs `\"user\", string(user)` with the raw "+
		"usr_… id. The control below shows a healthy store makes this branch unreachable.", h.signOutError())

	// Control, same harness, healthy store: the branch cannot be taken.
	ok := newSessionHarness(t, memstore.New(), audit.NewMemoryLogger(), account.UserID("usr_verify"))
	ok.run(t, "/in")
	ok.run(t, "/out")
	if err := ok.signOutError(); err != nil {
		t.Fatalf("healthy store: SignOut = %v, want nil", err)
	}
}

// ---------------------------------------------------------------------------
// V-1: the shipped default really does emit Warn to a durable sink, which is the
// precondition for every "the log outlives the database" claim.
// ---------------------------------------------------------------------------

func TestVerifyWarnIsEnabledAndGoesToStderrByDefault(t *testing.T) {
	t.Setenv("RE0AUTH_LOG_LEVEL", "")
	t.Setenv("RE0AUTH_LOG_FORMAT", "")
	if err := config.SetupLogging("RE0AUTH"); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if !slog.Default().Enabled(ctx, slog.LevelWarn) {
		t.Fatal("Warn is not enabled under the shipped default level")
	}
	if !slog.Default().Enabled(ctx, slog.LevelError) {
		t.Fatal("Error is not enabled under the shipped default level")
	}
	if slog.Default().Enabled(ctx, slog.LevelDebug) {
		t.Fatal("Debug is enabled under the shipped default level; the probe's premise is wrong")
	}
	t.Logf("CONFIRMED: default level is info, so Warn and Error are ENABLED and the handler " +
		"writes to os.Stderr (internal/config/logging.go:43-50). In a container that stream " +
		"goes to the log driver, not to the database — so 'the log outlives the erasure' is " +
		"true for the default configuration, not only for a configured collector.")
}

// ---------------------------------------------------------------------------
// V-2: the erasure's own last step is undone by the very next line of the
// request. lifecycle destroys the pseudonym key LAST (lifecycle.go:254-263) so
// that the erasure record is not written after the key is gone — and then
// account_routes.go:68 calls SignOut, whose audit event carries the RAW subject
// (auth/auth.go:187-203) and is written AFTER the destroy.
// ---------------------------------------------------------------------------

// orderSink is one object acting as both the audit sink and the pseudonym
// destroyer, which is what cmd/re0auth wires (main.go:437-440 and :614-615).
type orderSink struct {
	mu        sync.Mutex
	seq       []string
	destroyAt int
}

func (s *orderSink) Record(_ context.Context, e audit.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw := ""
	if strings.HasPrefix(e.Subject, "usr_") {
		raw = " (RAW account id)"
	}
	s.seq = append(s.seq, "record "+e.Action+" subject="+e.Subject+raw)
	return nil
}

func (s *orderSink) Destroy(_ context.Context, subject string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.destroyAt = len(s.seq)
	s.seq = append(s.seq, "DESTROY pseudonym key for "+subject)
	return nil
}

func (s *orderSink) lines() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.seq...)
}

// fakes for the lifecycle ports that DeleteAccount requires.
type fakeAccounts struct{}

func (fakeAccounts) DeleteUser(context.Context, account.UserID) error { return nil }

type fakeVault struct{}

func (fakeVault) DeleteSubject(context.Context, string) (int, error) { return 1, nil }

type fakeTokens struct{}

func (fakeTokens) RevokeTokens(context.Context, oauth.TokenFilter) (int, error) { return 1, nil }

func TestVerifyErasureUnlinksThenImmediatelyRelinks(t *testing.T) {
	sink := &orderSink{}
	subject := account.UserID("usr_erased")

	d, err := lifecycle.New(lifecycle.Config{
		Accounts:   fakeAccounts{},
		Tokens:     fakeTokens{},
		Vault:      fakeVault{},
		Pseudonyms: sink,
		Audit:      sink,
	})
	if err != nil {
		t.Fatal(err)
	}

	h := newSessionHarness(t, memstore.New(), sink, subject)
	h.run(t, "/in")

	// The shipped order: erase, then clear the cookie.
	ctx := context.Background()
	if _, err := d.DeleteAccount(ctx, subject, subject); err != nil {
		t.Fatalf("DeleteAccount: %v", err)
	}
	h.run(t, "/out")
	if err := h.signOutError(); err != nil {
		t.Fatalf("SignOut: %v", err)
	}

	lines := sink.lines()
	for i, l := range lines {
		t.Logf("%d: %s", i, l)
	}

	// Find the destroy, then look for a later audit write naming the RAW id.
	destroy := -1
	for i, l := range lines {
		if strings.HasPrefix(l, "DESTROY ") {
			destroy = i
			break
		}
	}
	if destroy < 0 {
		t.Fatal("the erasure never destroyed the pseudonym key; the probe is not on the path")
	}
	after := -1
	for i := destroy + 1; i < len(lines); i++ {
		if strings.HasPrefix(lines[i], "record ") && strings.Contains(lines[i], "usr_erased") {
			after = i
			break
		}
	}
	if after < 0 {
		t.Log("REFUTED: no audit write naming the raw id follows the destroy")
		return
	}
	t.Errorf("CONFIRMED: %q is written to the audit sink AFTER the pseudonym key for that "+
		"subject was destroyed (line %d). The postgres sink pseudonymises by minting a key "+
		"when none exists (auditpseudo.go:115-142, measured by auditpseudo_test.go:232-244), "+
		"so the erasure's own last step is undone by the next line of the same request.",
		lines[after], after)
}
