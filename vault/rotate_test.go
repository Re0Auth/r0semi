package vault

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/audit"
)

// testKey builds a wrapper with explicit key material, so two wrappers can share
// an id and differ in material — which is a mistake worth being able to test.
func keyFor(t *testing.T, id string, material byte) KeyWrapper {
	t.Helper()
	w, err := NewLocalKeyWrapper(id, bytes.Repeat([]byte{material}, dekSize))
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func readSecret(t *testing.T, svc Service, id Identity) []byte {
	t.Helper()
	var got []byte
	if err := svc.Use(context.Background(), id, func(secret []byte) error {
		got = append([]byte(nil), secret...)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return got
}

func TestRotateRewrapsUnderTheCurrentKey(t *testing.T) {
	repo := NewMemoryRepo()
	logger := audit.NewMemoryLogger()
	old := keyFor(t, "kek-1", 0xA1)
	fresh := keyFor(t, "kek-2", 0xB2)
	ctx := context.Background()
	id := Identity{Subject: "usr_1", Provider: "taptap"}

	before, err := NewService(repo, old, logger)
	if err != nil {
		t.Fatal(err)
	}
	if err := before.Enroll(ctx, id, []byte("the-session-token"), nil); err != nil {
		t.Fatal(err)
	}
	original, err := repo.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}

	// The new key is current; the old one is retired so its records stay readable.
	after, err := NewService(repo, fresh, logger, WithRetiredKeys(old))
	if err != nil {
		t.Fatal(err)
	}
	rotation, err := after.Rotate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rotation.Scanned != 1 || rotation.Rewrapped != 1 || rotation.AlreadyCurrent != 0 {
		t.Fatalf("rotation = %+v", rotation)
	}

	rewrapped, err := repo.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if rewrapped.KEKID != "kek-2" {
		t.Fatalf("kek_id = %q, want kek-2", rewrapped.KEKID)
	}
	// The envelope changed; the payload did not. Rotation must never decrypt and
	// re-encrypt, or it would be doing the thing it exists to avoid.
	if !bytes.Equal(rewrapped.Ciphertext, original.Ciphertext) {
		t.Error("rotation rewrote the payload ciphertext")
	}
	if !bytes.Equal(rewrapped.Nonce, original.Nonce) {
		t.Error("rotation changed the payload nonce")
	}
	if bytes.Equal(rewrapped.WrappedDEK, original.WrappedDEK) {
		t.Error("the wrapped DEK is unchanged, so nothing was actually re-wrapped")
	}
	if got := readSecret(t, after, id); string(got) != "the-session-token" {
		t.Fatalf("secret = %q after rotation", got)
	}
}

// The re-wrap has to be real: a service holding only the old key must no longer
// be able to read the record.
func TestRotateActuallyMovesTheRecordOffTheOldKey(t *testing.T) {
	repo := NewMemoryRepo()
	logger := audit.NewMemoryLogger()
	old := keyFor(t, "kek-1", 0xA1)
	fresh := keyFor(t, "kek-2", 0xB2)
	ctx := context.Background()
	id := Identity{Subject: "usr_1", Provider: "taptap"}

	before, _ := NewService(repo, old, logger)
	if err := before.Enroll(ctx, id, []byte("s"), nil); err != nil {
		t.Fatal(err)
	}
	after, _ := NewService(repo, fresh, logger, WithRetiredKeys(old))
	if _, err := after.Rotate(ctx); err != nil {
		t.Fatal(err)
	}

	// Only the old key: it must fail, and say which key the record now needs.
	onlyOld, _ := NewService(repo, old, logger)
	err := onlyOld.Use(ctx, id, func([]byte) error { return nil })
	if err == nil {
		t.Fatal("the old key still opened a record that was supposedly re-wrapped")
	}
	if !strings.Contains(err.Error(), "kek-2") {
		t.Fatalf("error does not name the key that is missing: %v", err)
	}
}

// A rotation with nothing to do is not an error, and is safe to run again — which
// is what makes "run it and then remove the old key" a thing an operator can do
// without reasoning about a partial run.
func TestRotateIsIdempotent(t *testing.T) {
	repo := NewMemoryRepo()
	logger := audit.NewMemoryLogger()
	old := keyFor(t, "kek-1", 0xA1)
	fresh := keyFor(t, "kek-2", 0xB2)
	ctx := context.Background()
	id := Identity{Subject: "usr_1", Provider: "taptap"}

	before, _ := NewService(repo, old, logger)
	if err := before.Enroll(ctx, id, []byte("s"), nil); err != nil {
		t.Fatal(err)
	}
	after, _ := NewService(repo, fresh, logger, WithRetiredKeys(old))
	if _, err := after.Rotate(ctx); err != nil {
		t.Fatal(err)
	}

	second, err := after.Rotate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if second.Scanned != 1 || second.Rewrapped != 0 || second.AlreadyCurrent != 1 {
		t.Fatalf("second rotation = %+v", second)
	}

	// And now the old key can be dropped entirely.
	withoutOld, err := NewService(repo, fresh, logger)
	if err != nil {
		t.Fatal(err)
	}
	if got := readSecret(t, withoutOld, id); string(got) != "s" {
		t.Fatalf("secret = %q after the old key was removed", got)
	}
}

// The mistake this catches is silent otherwise: change the key material, keep the
// id, and every credential becomes unreadable while a rotation reports success.
func TestRotateRefusesWhenTheIdMatchesButTheKeyDoesNot(t *testing.T) {
	repo := NewMemoryRepo()
	logger := audit.NewMemoryLogger()
	ctx := context.Background()
	id := Identity{Subject: "usr_1", Provider: "taptap"}

	first, _ := NewService(repo, keyFor(t, "kek-1", 0xA1), logger)
	if err := first.Enroll(ctx, id, []byte("s"), nil); err != nil {
		t.Fatal(err)
	}

	// Same id, different material — what an operator gets by regenerating the key
	// and forgetting to bump kek_id.
	mistaken, _ := NewService(repo, keyFor(t, "kek-1", 0xB2), logger)
	_, err := mistaken.Rotate(ctx)
	if err == nil {
		t.Fatal("rotation reported success with a key that cannot open anything")
	}
	if !strings.Contains(err.Error(), "kek_id") {
		t.Fatalf("error does not point at the id: %v", err)
	}

	// Reading fails too, and says something better than "ciphertext is not authentic".
	if err := mistaken.Use(ctx, id, func([]byte) error { return nil }); err == nil {
		t.Fatal("the mismatched key opened the record")
	}
}

// Rotating without the key that wrapped a record cannot work, and must say so
// rather than fail with a decryption error nobody can act on.
func TestRotateRequiresTheRetiredKey(t *testing.T) {
	repo := NewMemoryRepo()
	logger := audit.NewMemoryLogger()
	old := keyFor(t, "kek-1", 0xA1)
	fresh := keyFor(t, "kek-2", 0xB2)
	ctx := context.Background()
	id := Identity{Subject: "usr_1", Provider: "taptap"}

	before, _ := NewService(repo, old, logger)
	if err := before.Enroll(ctx, id, []byte("s"), nil); err != nil {
		t.Fatal(err)
	}

	// The old key is not configured.
	blind, _ := NewService(repo, fresh, logger)
	if _, err := blind.Rotate(ctx); err == nil {
		t.Fatal("rotation succeeded without the key that wrapped the record")
	} else if !strings.Contains(err.Error(), "kek-1") {
		t.Fatalf("error does not name the missing key: %v", err)
	}
	// Reading says the same thing, which is the point: an operator sees one
	// explanation, not two.
	err := blind.Use(ctx, id, func([]byte) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("Use error = %v", err)
	}
}

func TestWithRetiredKeysRejectsBadConfigurations(t *testing.T) {
	repo := NewMemoryRepo()
	logger := audit.NewMemoryLogger()
	current := keyFor(t, "kek-2", 0xB2)

	if _, err := NewService(repo, current, logger, WithRetiredKeys(nil)); err == nil {
		t.Error("a nil retired key was accepted")
	}
	// The same id as the current key: it could only ever shadow the current one,
	// and the intent behind it is certainly not what the operator means.
	if _, err := NewService(repo, current, logger, WithRetiredKeys(keyFor(t, "kek-2", 0xA1))); err == nil {
		t.Error("a retired key reusing the current id was accepted")
	}
	same := keyFor(t, "kek-1", 0xA1)
	if _, err := NewService(repo, current, logger, WithRetiredKeys(same, same)); err == nil {
		t.Error("the same retired key declared twice was accepted")
	}
	// And a wrapper with no id is unusable, because the id is the lookup key.
	// LocalKeyWrapper refuses to be built that way, so this needs a stand-in: the
	// guard in NewService is for any implementation, not just the local one.
	if _, err := NewService(repo, emptyIDKey{}, logger); err == nil {
		t.Error("a KeyWrapper with an empty id was accepted")
	}
}

// emptyIDKey is a KeyWrapper that reports no id.
type emptyIDKey struct{}

func (emptyIDKey) KeyID() string { return "" }

func (emptyIDKey) Wrap(context.Context, []byte, []byte) ([]byte, error) { return nil, nil }

func (emptyIDKey) Unwrap(context.Context, []byte, []byte) ([]byte, error) { return nil, nil }

// A revoked credential is gone; rotating must not bring it back.
func TestRotateDoesNotResurrectRevokedCredentials(t *testing.T) {
	repo := NewMemoryRepo()
	logger := audit.NewMemoryLogger()
	old := keyFor(t, "kek-1", 0xA1)
	fresh := keyFor(t, "kek-2", 0xB2)
	ctx := context.Background()
	id := Identity{Subject: "usr_1", Provider: "taptap"}

	before, _ := NewService(repo, old, logger)
	if err := before.Enroll(ctx, id, []byte("s"), nil); err != nil {
		t.Fatal(err)
	}
	if err := before.Revoke(ctx, id); err != nil {
		t.Fatal(err)
	}

	after, _ := NewService(repo, fresh, logger, WithRetiredKeys(old))
	rotation, err := after.Rotate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rotation.Scanned != 0 || rotation.Rewrapped != 0 {
		t.Fatalf("rotation touched a shredded credential: %+v", rotation)
	}
}

// An empty vault rotates cleanly. It is the normal case on a fresh deployment,
// and it should not be an error an operator has to interpret.
func TestRotateOnAnEmptyVault(t *testing.T) {
	svc, err := NewService(NewMemoryRepo(), keyFor(t, "kek-1", 0xA1), audit.NewMemoryLogger())
	if err != nil {
		t.Fatal(err)
	}
	rotation, err := svc.Rotate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rotation.Scanned != 0 || rotation.Rewrapped != 0 {
		t.Fatalf("rotation = %+v", rotation)
	}
}
