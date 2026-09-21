package vault

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/Re0Auth/r0semi/audit"
)

type failingLogger struct{}

func (failingLogger) Record(context.Context, audit.Event) error {
	return errors.New("audit unavailable")
}

func newTestService(t *testing.T) (Service, *MemoryRepo, *audit.MemoryLogger, *LocalKeyWrapper) {
	t.Helper()
	repo := NewMemoryRepo()
	logger := audit.NewMemoryLogger()
	w := testKey(t)
	svc, err := NewService(repo, w, logger)
	if err != nil {
		t.Fatal(err)
	}
	return svc, repo, logger, w
}

func mustSeal(t *testing.T, w *LocalKeyWrapper, id Identity, secret []byte) Record {
	t.Helper()
	aad := bindingAAD(recordVersion, id.Subject, id.Provider)
	dek, err := readRandom(dekSize)
	if err != nil {
		t.Fatal(err)
	}
	defer zeroize(dek)
	wrapped, err := w.Wrap(context.Background(), dek, aad)
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
		KEKID:      w.KeyID(),
		Nonce:      nonce,
		Ciphertext: ct,
	}
}

func TestEnrollUseRevoke(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	ctx := context.Background()
	id := Identity{Subject: "user-1", Provider: "taptap"}
	secret := []byte("the-stoken")

	if err := svc.Enroll(ctx, id, secret, map[string]string{"taptap_user": "42"}); err != nil {
		t.Fatal(err)
	}

	var got []byte
	if err := svc.Use(ctx, id, func(s []byte) error {
		got = append([]byte(nil), s...)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("use = %q, want %q", got, secret)
	}

	if ok, err := svc.Exists(ctx, id); err != nil || !ok {
		t.Fatalf("exists = %v, %v; want true, nil", ok, err)
	}
	if err := svc.Revoke(ctx, id); err != nil {
		t.Fatal(err)
	}
	if ok, err := svc.Exists(ctx, id); err != nil || ok {
		t.Fatalf("exists after revoke = %v, %v; want false, nil", ok, err)
	}
}

func TestUseUnknownIdentity(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	err := svc.Use(context.Background(), Identity{Subject: "nobody", Provider: "taptap"}, func([]byte) error { return nil })
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

// I2: the plaintext handed to the callback is zeroized when Use returns.
func TestUseZeroizesPlaintext(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	ctx := context.Background()
	id := Identity{Subject: "u", Provider: "taptap"}
	secret := []byte("super-secret-stoken")
	if err := svc.Enroll(ctx, id, secret, nil); err != nil {
		t.Fatal(err)
	}

	var captured []byte
	if err := svc.Use(ctx, id, func(s []byte) error {
		captured = s // alias the vault's buffer on purpose
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	for i, b := range captured {
		if b != 0 {
			t.Fatalf("plaintext byte %d not zeroized: %x", i, captured)
		}
	}
}

func TestUseZeroizesOnCallbackError(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	ctx := context.Background()
	id := Identity{Subject: "u", Provider: "taptap"}
	if err := svc.Enroll(ctx, id, []byte("secret"), nil); err != nil {
		t.Fatal(err)
	}

	var captured []byte
	boom := errors.New("downstream failed")
	err := svc.Use(ctx, id, func(s []byte) error {
		captured = s
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want boom", err)
	}
	for i, b := range captured {
		if b != 0 {
			t.Fatalf("byte %d not zeroized after error", i)
		}
	}
}

// I3: the access record is persisted before the secret is handed over.
func TestUseAuditsBeforeCallback(t *testing.T) {
	svc, _, logger, _ := newTestService(t)
	ctx := context.Background()
	id := Identity{Subject: "u", Provider: "taptap"}
	if err := svc.Enroll(ctx, id, []byte("s"), nil); err != nil {
		t.Fatal(err)
	}

	before := len(logger.Events())
	var seen int
	if err := svc.Use(ctx, id, func([]byte) error {
		seen = len(logger.Events())
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if seen <= before {
		t.Fatalf("events at callback = %d, before = %d; want the access audited first", seen, before)
	}
}

// I3: if the audit log is unavailable, the secret is not used.
func TestUseFailsClosedWhenAuditFails(t *testing.T) {
	repo := NewMemoryRepo()
	w := testKey(t)
	svc, err := NewService(repo, w, failingLogger{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	id := Identity{Subject: "u", Provider: "taptap"}
	if err := repo.Put(ctx, mustSeal(t, w, id, []byte("secret"))); err != nil {
		t.Fatal(err)
	}

	called := false
	err = svc.Use(ctx, id, func([]byte) error {
		called = true
		return nil
	})
	if err == nil {
		t.Fatal("Use succeeded despite an unavailable audit log")
	}
	if called {
		t.Fatal("the secret was used despite an unavailable audit log")
	}
}

// The ciphertext is bound to its identity: moving a record to another subject
// does not make it decryptable.
func TestCiphertextBindsIdentity(t *testing.T) {
	svc, repo, _, _ := newTestService(t)
	ctx := context.Background()
	a := Identity{Subject: "a", Provider: "taptap"}
	b := Identity{Subject: "b", Provider: "taptap"}
	if err := svc.Enroll(ctx, a, []byte("secret"), nil); err != nil {
		t.Fatal(err)
	}

	rec, err := repo.Get(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	rec.Identity = b
	if err := repo.Put(ctx, rec); err != nil {
		t.Fatal(err)
	}

	if err := svc.Use(ctx, b, func([]byte) error { return nil }); err == nil {
		t.Fatal("decrypted a record moved to a different identity")
	}
}

func TestEnrollReplacesExisting(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	ctx := context.Background()
	id := Identity{Subject: "u", Provider: "taptap"}
	if err := svc.Enroll(ctx, id, []byte("first"), nil); err != nil {
		t.Fatal(err)
	}
	if err := svc.Enroll(ctx, id, []byte("second"), nil); err != nil {
		t.Fatal(err)
	}

	var got string
	if err := svc.Use(ctx, id, func(s []byte) error {
		got = string(s)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got != "second" {
		t.Fatalf("got %q, want %q", got, "second")
	}
}

// The vault is provider-agnostic: the same subject can hold independent
// credentials for different games / auth providers.
func TestProviderIsolation(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	ctx := context.Background()
	taptap := Identity{Subject: "u", Provider: "taptap"}
	other := Identity{Subject: "u", Provider: "other"}
	if err := svc.Enroll(ctx, taptap, []byte("A"), nil); err != nil {
		t.Fatal(err)
	}
	if err := svc.Enroll(ctx, other, []byte("B"), nil); err != nil {
		t.Fatal(err)
	}

	read := func(id Identity) string {
		t.Helper()
		var got string
		if err := svc.Use(ctx, id, func(s []byte) error {
			got = string(s)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return got
	}
	if got := read(taptap); got != "A" {
		t.Fatalf("taptap = %q, want A", got)
	}
	if got := read(other); got != "B" {
		t.Fatalf("other = %q, want B", got)
	}
}

func TestEnrollRejectsEmptyIdentity(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	err := svc.Enroll(context.Background(), Identity{Provider: "taptap"}, []byte("x"), nil)
	if !errors.Is(err, ErrInvalidIdentity) {
		t.Fatalf("err = %v, want ErrInvalidIdentity", err)
	}
}
