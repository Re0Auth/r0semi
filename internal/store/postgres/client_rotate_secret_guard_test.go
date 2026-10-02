package postgres

// client_rotate_secret_guard_test.go is the store half of S01-10 (requested by
// w1-oauth).
//
// Client secrets are now stored as a salted slow-hash encoding
// (`$pbkdf2-sha256$i=…$salt$dk`), and oauth.RestoreClientWithStatus rejects any
// other shape — a legacy bare 32-byte SHA-256 digest is refused outright. If
// Clients.RotateSecret only checked for an empty digest, an admin rotation that
// handed it a non-empty but malformed value would be accepted, and the client
// would turn into an unknown client at the next restore. The write must refuse a
// digest the reader will not admit.

import (
	"strings"
	"testing"
)

func TestRotateSecretRefusesADigestTheReaderCannotVerify(t *testing.T) {
	body := sourceOf(t, "oauth.go")
	rotate := receiverMethod(t, body, "oauth.go", "RotateSecret")

	if !strings.Contains(rotate, "oauth.ValidSecretHash(secretHash)") {
		t.Error("Clients.RotateSecret does not validate the digest's shape; a non-empty but malformed " +
			"secret hash is stored and the client becomes unknown at the next RestoreClient (S01-10)")
	}
	if !strings.Contains(rotate, "len(secretHash) == 0") {
		t.Error("the empty-digest guard disappeared; the guard is reading the wrong method")
	}
	// The check must come before the UPDATE, so no malformed row is ever written.
	check := strings.Index(rotate, "oauth.ValidSecretHash(secretHash)")
	update := strings.Index(rotate, "UPDATE oauth_clients SET secret_hash")
	if check < 0 || update < 0 || check > update {
		t.Error("the shape check does not run before the UPDATE, so a malformed digest can still be persisted")
	}
}
