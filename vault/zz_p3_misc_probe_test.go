package vault

// P3-low probes for the vault area: S07-4, S07-9, S07-11, Z19-3, G-19, G-21.
//
// Each probe fails against the unfixed code and passes against the fix. S07-3's
// probe is repo_page_cost_test.go: the ordered index and the rowsCopied counter
// that close S07-3 are already in repo.go (added for S14-3).

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/audit"
)

// --- S07-4: Use must derive the AAD from the stored record, as Rotate does

// resolveAliasRepo resolves a requested identity to the identity a row is
// actually stored under. It models the one thing that makes Use's choice of AAD
// source observable: a repo whose Get returns a Record whose Identity is not the
// one the caller asked for (a case-normalizing or provider-canonicalizing store).
type resolveAliasRepo struct {
	*MemoryRepo
	alias map[Identity]Identity
}

func (r *resolveAliasRepo) Get(ctx context.Context, id Identity) (Record, error) {
	if stored, ok := r.alias[id]; ok {
		id = stored
	}
	return r.MemoryRepo.Get(ctx, id)
}

// TestUseBindsAADToTheStoredIdentityNotTheRequestedOne pins that Use and Rotate
// agree on which identity the AEAD binds. Rotate uses rec.Identity (rotate.go:104);
// Use used the requested id (service.go:304), so a repo that resolves an alias gave
// a record the rotation could read and the read path could not.
func TestUseBindsAADToTheStoredIdentityNotTheRequestedOne(t *testing.T) {
	ctx := context.Background()
	w := testKey(t)
	repo := &resolveAliasRepo{MemoryRepo: NewMemoryRepo(), alias: map[Identity]Identity{}}

	stored := Identity{Subject: "usr_canonical", Provider: "taptap"}
	requested := Identity{Subject: "USR_CANONICAL", Provider: "TAPTAP"}
	repo.alias[requested] = stored
	if err := repo.Put(ctx, mustSeal(t, w, stored, []byte("upstream-token"))); err != nil {
		t.Fatal(err)
	}

	svc, err := NewService(repo, w, audit.NewMemoryLogger())
	if err != nil {
		t.Fatal(err)
	}

	var got string
	err = svc.Use(ctx, requested, func(secret []byte) error {
		got = string(secret)
		return nil
	})
	if err != nil {
		t.Fatalf("Use(resolved alias) = %v, want the row to open: Use builds the AEAD AAD from the "+
			"requested identity while Rotate builds it from rec.Identity (vault/service.go:304, "+
			"vault/rotate.go:104), so the two disagree about which row they are reading", err)
	}
	if got != "upstream-token" {
		t.Fatalf("secret = %q, want %q", got, "upstream-token")
	}
}

// --- S07-9: a re-enrollment replaces the secret, not the credential's birth

// TestReEnrollKeepsTheOriginalCreatedAt pins that a re-enroll preserves CreatedAt
// while moving UpdatedAt. Put replaces the whole row, so an Enroll that wrote
// `now` into CreatedAt discarded the credential's real creation time — the one
// field that says how long an account has held this credential.
func TestReEnrollKeepsTheOriginalCreatedAt(t *testing.T) {
	svc, repo, _, _ := newTestService(t)
	ctx := context.Background()
	id := Identity{Subject: "usr_reenroll", Provider: "taptap"}

	if err := svc.Enroll(ctx, id, []byte("first"), nil); err != nil {
		t.Fatal(err)
	}
	first, err := repo.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(5 * time.Millisecond)
	if err := svc.Enroll(ctx, id, []byte("second"), nil); err != nil {
		t.Fatal(err)
	}
	second, err := repo.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}

	if !second.CreatedAt.Equal(first.CreatedAt) {
		t.Fatalf("CreatedAt moved on re-enroll: %s -> %s; the credential's creation time was "+
			"overwritten (S07-9)", first.CreatedAt, second.CreatedAt)
	}
	if !second.UpdatedAt.After(first.UpdatedAt) {
		t.Fatalf("UpdatedAt did not move on re-enroll: %s -> %s", first.UpdatedAt, second.UpdatedAt)
	}
	if got := readSecret(t, svc, id); string(got) != "second" {
		t.Fatalf("secret after re-enroll = %q, want the replacement", got)
	}
}

// --- S07-11: identity fields stay inside the store's bound

// TestOverLongIdentityFieldsAreRefused pins that an identity whose field is far
// outside any stored identity shape is refused at the door. The bound predates
// the AAD's uvarint prefix (which cannot truncate a Go-length field), so this now
// guards the store-side hygiene bound rather than a prefix collision.
func TestOverLongIdentityFieldsAreRefused(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	ctx := context.Background()

	// Control: a realistic identity, far below any bound, still enrolls.
	control := Identity{Subject: "usr_" + strings.Repeat("a", 16), Provider: "taptap"}
	if err := svc.Enroll(ctx, control, []byte("x"), nil); err != nil {
		t.Fatalf("control: a 20-byte subject was refused: %v", err)
	}

	// 1 MiB is far inside uint64 but far outside any stored identity shape, so a
	// builder with no bound at all has no excuse for accepting it.
	over := Identity{Subject: strings.Repeat("s", 1<<20), Provider: "taptap"}
	err := svc.Enroll(ctx, over, []byte("x"), nil)
	if !errors.Is(err, ErrInvalidIdentity) {
		t.Fatalf("Enroll accepted a %d-byte subject (err = %v); maxIdentityFieldLen bounds "+
			"identity fields (vault/repo.go)", 1<<20, err)
	}
}

// --- Z19-3: Use's failure paths must join the audit failure, not drop it

// newFailingAuditService builds a service whose audit sink always fails.
func newFailingAuditService(t *testing.T, repo Repo, kek KeyWrapper, opts ...Option) Service {
	t.Helper()
	svc, err := NewService(repo, kek, failingLogger{}, opts...)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc
}

// sealRecordFor seals a record under an arbitrary KeyWrapper, so a probe can build
// a row wrapped by a key the service under test does not hold.
func sealRecordFor(t *testing.T, kek KeyWrapper, id Identity, secret []byte) Record {
	t.Helper()
	ctx := context.Background()
	aad := bindingAAD(recordVersion, id.Subject, id.Provider)
	dek, err := readRandom(dekSize)
	if err != nil {
		t.Fatal(err)
	}
	defer Scrub(dek)
	wrapped, err := kek.Wrap(ctx, dek, aad)
	if err != nil {
		t.Fatal(err)
	}
	nonce, ct, err := sealSecret(dek, secret, aad)
	if err != nil {
		t.Fatal(err)
	}
	return Record{
		Identity:   id,
		Version:    recordVersion,
		WrappedDEK: wrapped,
		KEKID:      kek.KeyID(),
		Nonce:      nonce,
		Ciphertext: ct,
	}
}

// transplantedPayloadRecord builds a row whose envelope is bound to id but whose
// payload is bound to another identity: the one way to reach openSecret's failure
// with a healthy envelope.
func transplantedPayloadRecord(t *testing.T, kek KeyWrapper, id Identity) *Record {
	t.Helper()
	ctx := context.Background()
	dek, err := readRandom(dekSize)
	if err != nil {
		t.Fatal(err)
	}
	defer Scrub(dek)
	wrapped, err := kek.Wrap(ctx, dek, bindingAAD(recordVersion, id.Subject, id.Provider))
	if err != nil {
		t.Fatal(err)
	}
	nonce, ct, err := sealSecret(dek, []byte("secret"), bindingAAD(recordVersion, "usr_someone_else", id.Provider))
	if err != nil {
		t.Fatal(err)
	}
	return &Record{
		Identity:   id,
		Version:    recordVersion,
		WrappedDEK: wrapped,
		KEKID:      kek.KeyID(),
		Nonce:      nonce,
		Ciphertext: ct,
	}
}

// TestUseJoinsTheAuditFailureOnEveryFailurePath pins that all four failing exits of
// Use carry the audit failure, as the success path is fail-closed. They used to
// discard it with `_ =` (service.go:247-252,269-271,278-280,288-290), so an
// unavailable audit sink was invisible on exactly the paths an operator investigates.
func TestUseJoinsTheAuditFailureOnEveryFailurePath(t *testing.T) {
	ctx := context.Background()
	current := testKey(t)
	retired := keyFor(t, "kek-retired", 0xA1)
	id := Identity{Subject: "usr_auditfail", Provider: "taptap"}

	// The envelope that cannot be opened under the key it names.
	brokenEnvelope := &Record{
		Identity: id, Version: recordVersion, KEKID: current.KeyID(), WrappedDEK: []byte("short"),
	}
	// A row wrapped by a key this service does not hold.
	retiredRow := sealRecordFor(t, retired, id, []byte("secret"))

	cases := []struct {
		name         string
		rec          *Record
		wantNotFound bool
	}{
		{"the repository has no row", nil, true},
		{"the wrapping key is not configured", &retiredRow, false},
		{"the envelope does not unwrap", brokenEnvelope, false},
		{"the payload is bound to another identity", transplantedPayloadRecord(t, current, id), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo := NewMemoryRepo()
			if tc.rec != nil {
				if err := repo.Put(ctx, *tc.rec); err != nil {
					t.Fatal(err)
				}
			}
			svc := newFailingAuditService(t, repo, current)

			err := svc.Use(ctx, id, func([]byte) error { return nil })
			if err == nil {
				t.Fatal("Use succeeded with an unopenable credential and an unavailable audit sink")
			}
			if tc.wantNotFound && !errors.Is(err, ErrNotFound) {
				t.Fatalf("err = %v, want errors.Is(err, ErrNotFound) to survive the join: callers "+
					"depend on the sentinel", err)
			}
			if !strings.Contains(err.Error(), "audit unavailable") {
				t.Fatalf("err = %v, want the audit failure joined into it; the failure paths drop "+
					"the audit error while the success path is fail-closed (Z19-3)", err)
			}
		})
	}
}

// --- G-19: Rotate must report its own audit failure

// TestRotateReturnsTheAuditFailure pins that a rotation whose vault.rotate_keys
// write fails returns the error instead of discarding it with `_ =` (rotate.go:82).
// The event is what an operator consults before deleting the retired key, so an
// unwritable sink must make -rotate-keys exit non-zero, as Enroll/Use/Revoke do.
func TestRotateReturnsTheAuditFailure(t *testing.T) {
	ctx := context.Background()
	repo := NewMemoryRepo()
	id := Identity{Subject: "usr_rotate_audit", Provider: "taptap"}

	seeder, err := NewService(repo, keyFor(t, "kek-1", 0xA1), audit.NewMemoryLogger())
	if err != nil {
		t.Fatal(err)
	}
	if err := seeder.Enroll(ctx, id, []byte("s"), nil); err != nil {
		t.Fatal(err)
	}

	rotator, err := NewService(repo, keyFor(t, "kek-2", 0xB2), failingLogger{},
		WithRetiredKeys(keyFor(t, "kek-1", 0xA1)))
	if err != nil {
		t.Fatal(err)
	}

	rot, err := rotator.Rotate(ctx)
	if err == nil {
		t.Fatalf("Rotate dropped its own audit failure (rotation = %+v); the vault.rotate_keys "+
			"event records whether the retired key may be deleted (G-19)", rot)
	}
	if !strings.Contains(err.Error(), "audit unavailable") {
		t.Fatalf("Rotate error = %v, want the audit failure", err)
	}
}

// --- G-21: vault error text must not carry the raw subject

// TestVaultErrorsDoNotCarryTheRawSubject pins that the errors reaching the
// -rotate-keys die path and the unbind/cascade warn paths describe the row's shape
// (provider, key id) rather than the identity itself. Identity.String() renders
// "provider:usr_…", and a raw usr_ in a retained process log outlives the account
// erasure's pseudonym key.
func TestVaultErrorsDoNotCarryTheRawSubject(t *testing.T) {
	ctx := context.Background()
	repo := NewMemoryRepo()
	logger := audit.NewMemoryLogger()
	victim := Identity{Subject: "usr_victim", Provider: "taptap"}

	seeder, err := NewService(repo, keyFor(t, "kek-1", 0xA1), logger)
	if err != nil {
		t.Fatal(err)
	}
	if err := seeder.Enroll(ctx, victim, []byte("s"), nil); err != nil {
		t.Fatal(err)
	}

	blind, err := NewService(repo, keyFor(t, "kek-2", 0xB2), logger)
	if err != nil {
		t.Fatal(err)
	}

	// The read path: an error that internal/federation/unbind.go:124 logs with slog.
	uerr := blind.Use(ctx, victim, func([]byte) error { return nil })
	if uerr == nil {
		t.Fatal("control: the row opened under a key that did not wrap it")
	}
	if strings.Contains(uerr.Error(), "usr_victim") {
		t.Errorf("a Use error carries the raw subject: %q; the same text reaches the process log "+
			"via the unbind/cascade warn paths (G-21)", uerr)
	}
	if !strings.Contains(uerr.Error(), "kek-1") || !strings.Contains(uerr.Error(), "taptap") {
		t.Errorf("the Use error no longer lets an operator locate the row: %q (want the provider "+
			"and the missing key id)", uerr)
	}

	// The rotation path: the text cmd/re0auth hands to slog on failure.
	_, rerr := blind.Rotate(ctx)
	if rerr == nil {
		t.Fatal("control: the rotation succeeded without the retired key")
	}
	if strings.Contains(rerr.Error(), "usr_victim") {
		t.Errorf("a rotation error carries the raw subject: %q; -rotate-keys logs this text "+
			"verbatim on its failure path (G-21)", rerr)
	}
	if !strings.Contains(rerr.Error(), "kek-1") {
		t.Errorf("the rotation error no longer names the missing key: %q", rerr)
	}
}
