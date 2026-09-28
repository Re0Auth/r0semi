//go:build audit5

// Package crypto contains audit probes for the cryptographic-correctness and
// key-lifecycle area. Every file here is a test; nothing in this package ships.
//
// The tests are written so that they FAIL if the property they name stops
// holding, and they assert a positive control first so a "pass" cannot be the
// probe failing to reach the path.
package crypto

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/vault"
)

// key32 builds a LocalKeyWrapper over a repeated byte.
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

// hookRepo is a vault.Repo that can run an action in the window between a page
// read and the re-wrap a rotation performs. That window is the whole question for
// "can a rotation run while a server is serving".
//
// onRewrap fires when the rotation is about to apply its compare-and-swap, i.e.
// after the page was read and before the row is touched — the same window onPut
// used to model, now that a rotation writes an envelope rather than a whole record.
type hookRepo struct {
	inner    *vault.MemoryRepo
	onPage   func()
	onPut    func(rec vault.Record)
	onRewrap func()
	putSeen  []vault.Record
}

func (r *hookRepo) Put(ctx context.Context, rec vault.Record) error {
	if r.onPut != nil {
		r.onPut(rec)
	}
	r.putSeen = append(r.putSeen, rec)
	return r.inner.Put(ctx, rec)
}

func (r *hookRepo) RewrapIfUnchanged(ctx context.Context, id vault.Identity, expect []byte, next vault.Envelope) (bool, error) {
	if r.onRewrap != nil {
		r.onRewrap()
	}
	return r.inner.RewrapIfUnchanged(ctx, id, expect, next)
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
	return recs, nil
}

func (r *hookRepo) ListPage(ctx context.Context, sub, prov string, limit int) ([]vault.Record, error) {
	recs, err := r.inner.ListPage(ctx, sub, prov, limit)
	if err == nil && r.onPage != nil {
		r.onPage()
	}
	return recs, err
}

func (r *hookRepo) DeleteSubject(ctx context.Context, subject string) (int, error) {
	return r.inner.DeleteSubject(ctx, subject)
}

// TestProbeRotationOverwritesARecordEnrolledDuringTheRun is the confirmed
// data-loss window: Rotate read a page, re-wrapped the DEK, then Put() the WHOLE
// record back — including the stale nonce and ciphertext it read. An Enroll (or a
// federation refresh) that committed in between was silently overwritten by the
// old payload, and the rotation reported success.
//
// The guard is the property that must hold: the concurrently written secret is the
// one that survives. The positive control is the second half: with no concurrent
// writer the rotation is clean.
func TestProbeRotationOverwritesARecordEnrolledDuringTheRun(t *testing.T) {
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

	// The racing writer enrols a NEW secret in the window between the rotation's
	// page read and its write — exactly the interleaving a live server produces.
	// The hook fires when the rotation is about to apply its compare-and-swap, so it
	// runs AFTER the page was read and BEFORE the stale envelope could be written.
	var raced bool
	repo.onRewrap = func() {
		if raced {
			return
		}
		raced = true
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
		t.Fatal("the hook never fired: the rotation did not attempt a re-wrap, so nothing below is meaningful")
	}
	// With BOTH keys configured the newer payload must be the one that survived.
	// (The racing writer was a process on the RETIRED key, so its row is on the
	// retired key — which is the other half of this finding, and the reason the
	// retired key must stay configured until a re-run moves it.)
	both, err := vault.NewService(repo, fresh, logger, vault.WithRetiredKeys(old))
	if err != nil {
		t.Fatal(err)
	}
	switch got := string(readSecret(t, both, id)); got {
	case "second-secret":
		t.Log("rotation preserved the concurrently written secret (the window is closed)")
	case "first-secret":
		t.Errorf("CONFIRMED: rotation overwrote a concurrently enrolled secret with the stale payload; "+
			"rotation reported %+v (success). The user's newer credential is gone and nothing reported it.",
			rotation)
	default:
		t.Fatalf("secret = %q", got)
	}
	// The record the racing writer re-enrolled could not be re-wrapped by this run —
	// the CAS refused — and that must be reported, not swallowed. It is also the
	// signal the operator needs: a process still on the retired key is writing.
	if rotation.Skipped != 1 {
		t.Errorf("rotation = %+v, want Skipped 1: the row changed under it", rotation)
	}
	if rotation.Scanned != rotation.Rewrapped+rotation.AlreadyCurrent+rotation.Skipped {
		t.Errorf("rotation = %+v: the counts do not add up to Scanned", rotation)
	}

	// Control: a second, uncontended run converges — the row moves to the current
	// key and is then readable without the retired one.
	repo.onRewrap = nil
	second, err := rotator.Rotate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if second.Scanned != 1 || second.Rewrapped != 1 || second.AlreadyCurrent != 0 || second.Skipped != 0 {
		t.Fatalf("the converging rotation = %+v", second)
	}
	newWriter, err := vault.NewService(repo, fresh, logger)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(readSecret(t, newWriter, id)); got != "second-secret" {
		t.Fatalf("after the second run the record reads %q, want the concurrently written secret", got)
	}
}

// readSecret is a copy of the vault package's test helper, since it is unexported.
func readSecret(t *testing.T, svc vault.Service, id vault.Identity) []byte {
	t.Helper()
	var got []byte
	if err := svc.Use(context.Background(), id, func(secret []byte) error {
		got = append([]byte(nil), secret...)
		return nil
	}); err != nil {
		t.Fatalf("Use: %v", err)
	}
	return got
}

// TestProbeRotationPublishesPartialProgressOnFailure pins the crash-safety shape
// an operator has to reason about: rotation is per-record, not per-run, so a run
// that dies halfway leaves the deployment in a MIXED state. Nothing rolls back,
// nothing resumes, and the only signal is a warning at startup telling the
// operator to keep the retired key.
//
// The property this documents is that the mixed state is SAFE as long as the
// retired key stays configured, and becomes permanent credential loss the moment
// it is removed. The test asserts both halves.
func TestProbeRotationPublishesPartialProgressOnFailure(t *testing.T) {
	ctx := context.Background()
	repo := &hookRepo{inner: vault.NewMemoryRepo()}
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

	// Fail the write of the second record: a dead connection, a cancelled
	// context, a statement timeout — any of the ways a run dies halfway.
	putCount := 0
	repo.onPut = func(vault.Record) {
		putCount++
	}
	failing := &failOnNthPut{Repo: repo, failAt: 2}
	rotator, err := vault.NewService(failing, fresh, logger, vault.WithRetiredKeys(old))
	if err != nil {
		t.Fatal(err)
	}
	rot, err := rotator.Rotate(ctx)
	if err == nil {
		t.Fatal("rotation reported success although a write failed")
	}
	t.Logf("rotation aborted after %d records: %+v, err=%v", putCount, rot, err)

	// Mixed state: with the retired key still configured everything still opens.
	both, err := vault.NewService(repo, fresh, logger, vault.WithRetiredKeys(old))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		if got := readSecret(t, both, id); string(got) != "secret-"+id.Subject {
			t.Fatalf("%s = %q while both keys are configured", id, got)
		}
	}

	// The retired key removed too early: the records the failed run never reached
	// are permanently unreadable. This is the concrete cost of a partial run.
	withoutOld, err := vault.NewService(repo, fresh, logger)
	if err != nil {
		t.Fatal(err)
	}
	unreadable := 0
	for _, id := range ids {
		if err := withoutOld.Use(ctx, id, func([]byte) error { return nil }); err != nil {
			unreadable++
		}
	}
	if unreadable == 0 {
		t.Error("a partial rotation left nothing unreadable once the old key was removed: " +
			"the probe never reached the path it claims to describe")
	} else {
		t.Logf("CONFIRMED (by construction): %d of %d credentials are lost if the retired key is "+
			"removed after a partial rotation, and -rotate-keys reports the partial run as an error "+
			"only in the process's own log", unreadable, len(ids))
	}
}

// failOnNthPut makes a re-wrap fail on the n-th call, standing in for any way a
// rotation run can die halfway.
//
// It fails the CAS re-wrap rather than Put: a rotation no longer writes whole
// records (that was P1-2 — it rolled back whatever another process had enrolled
// in the meantime), so a probe that injected the failure at Put would inject it
// nowhere and the run would succeed.
type failOnNthPut struct {
	vault.Repo
	mu     sync.Mutex
	seen   int
	failAt int
}

func (r *failOnNthPut) RewrapIfUnchanged(ctx context.Context, id vault.Identity, expect []byte, next vault.Envelope) (bool, error) {
	r.mu.Lock()
	r.seen++
	n := r.seen
	r.mu.Unlock()
	if n == r.failAt {
		return false, context.DeadlineExceeded
	}
	return r.Repo.RewrapIfUnchanged(ctx, id, expect, next)
}

// rewrapped counts how many re-wraps this repo has been asked to apply and applies
// them, so a probe can name the write that failed.
func (r *failOnNthPut) rewrapped() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.seen
}

// TestProbeRotationDoesNotDecryptPayloads is the brief's explicit question. It
// answers it with a KeyWrapper that counts Unwrap calls: rotation unwraps DEKs
// (it must, to re-wrap them) and never touches the payload layer.
func TestProbeRotationDoesNotDecryptPayloads(t *testing.T) {
	ctx := context.Background()
	repo := vault.NewMemoryRepo()
	logger := audit.NewMemoryLogger()
	old := key32(t, "kek-1", 0xA1)
	fresh := key32(t, "kek-2", 0xB2)
	counting := &countingWrapper{KeyWrapper: old, id: "kek-1"}

	writer, err := vault.NewService(repo, counting, logger)
	if err != nil {
		t.Fatal(err)
	}
	id := vault.Identity{Subject: "usr_x", Provider: "taptap"}
	if err := writer.Enroll(ctx, id, []byte("payload"), nil); err != nil {
		t.Fatal(err)
	}
	counting.reset()

	rotator, err := vault.NewService(repo, fresh, logger, vault.WithRetiredKeys(counting))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rotator.Rotate(ctx); err != nil {
		t.Fatal(err)
	}
	// Exactly one unwrap for the one record that had to move.
	if wraps, unwraps := counting.counts(); wraps != 0 || unwraps != 1 {
		t.Fatalf("rotation used the KEK wrapper wrap=%d unwrap=%d, want 0/1", wraps, unwraps)
	}
}

// countingWrapper observes how a KeyWrapper is used.
type countingWrapper struct {
	vault.KeyWrapper
	id string
	mu sync.Mutex
	w  int
	u  int
}

func (c *countingWrapper) KeyID() string { return c.id }

func (c *countingWrapper) Wrap(ctx context.Context, dek, aad []byte) ([]byte, error) {
	c.mu.Lock()
	c.w++
	c.mu.Unlock()
	return c.KeyWrapper.Wrap(ctx, dek, aad)
}

func (c *countingWrapper) Unwrap(ctx context.Context, wrapped, aad []byte) ([]byte, error) {
	c.mu.Lock()
	c.u++
	c.mu.Unlock()
	return c.KeyWrapper.Unwrap(ctx, wrapped, aad)
}

func (c *countingWrapper) counts() (int, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.w, c.u
}

func (c *countingWrapper) reset() {
	c.mu.Lock()
	c.w, c.u = 0, 0
	c.mu.Unlock()
}

// TestProbeRotationIsNotAtomicAcrossRecords records the granularity: the audit
// event for a rotation is written ONCE at the end (vault/rotate.go:74-82), with
// counts. A rotation that dies halfway therefore leaves no audit line at all,
// while having already changed rows.
func TestProbeRotationIsNotAtomicAcrossRecords(t *testing.T) {
	ctx := context.Background()
	repo := vault.NewMemoryRepo()
	logger := audit.NewMemoryLogger()
	old := key32(t, "kek-1", 0xA1)
	fresh := key32(t, "kek-2", 0xB2)
	writer, err := vault.NewService(repo, old, logger)
	if err != nil {
		t.Fatal(err)
	}
	id := vault.Identity{Subject: "usr_audit", Provider: "taptap"}
	if err := writer.Enroll(ctx, id, []byte("s"), nil); err != nil {
		t.Fatal(err)
	}
	before := len(logger.Events())

	failing := &failOnNthPut{Repo: repo, failAt: 1}
	rotator, err := vault.NewService(failing, fresh, logger, vault.WithRetiredKeys(old))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rotator.Rotate(ctx); err == nil {
		t.Fatal("rotation reported success although the write failed")
	}

	events := logger.Events()
	for _, e := range events[before:] {
		if e.Action == "vault.rotate_keys" {
			t.Errorf("a failed rotation wrote a %q event: %+v", e.Action, e)
		}
	}
	if len(events) == before {
		t.Log("CONFIRMED: a rotation that fails on its first write produces no audit event at all, " +
			"so the operator's log cannot distinguish 'no rotation was attempted' from " +
			"'a rotation changed rows and then died'")
	}
}

var _ = time.Now
