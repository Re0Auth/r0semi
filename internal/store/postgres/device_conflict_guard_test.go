package postgres

// device_conflict_guard_test.go is the store half of S04-5=A.
//
// S04-5: two concurrent device flows could both be told a user code was free,
// because the uniqueness test was a GET-then-INSERT with no constraint between
// them. Migration 0033 gave the legacy table the same canonical unique index
// oidc_devices already had (0008), so the database is now the gate. This guard
// pins the two facts the service side depends on:
//
//   - both device tables carry the canonical key
//     upper(replace(user_code, '-', '')), not a raw-column key;
//   - the legacy Devices.SaveDevice turns THAT violation into an error wrapping
//     oauth.ErrUserCodeConflict, and leaves every other failure alone, because the
//     service retries only on the typed conflict.

import (
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Re0Auth/r0semi/oauth"
)

// TestBothDeviceTablesCarryACanonicalUserCodeUniqueIndex re-proves the schema
// parity this batch rests on. The audit7 probe
// (usercode_unique_test.go) asserts the same property under its own build tag;
// this copy runs in the package's ordinary suite so the store's own tests cannot
// go green after a migration regression.
func TestBothDeviceTablesCarryACanonicalUserCodeUniqueIndex(t *testing.T) {
	for name, table := range map[string]string{
		"0008_oidc.sql":                          "oidc_devices",
		"0033_oauth_device_user_code_unique.sql": "oauth_device_authorizations",
	} {
		body := migrationOf(t, name)
		up := body
		if i := strings.Index(body, "-- +goose Down"); i >= 0 {
			up = body[:i]
		}
		flat := strings.Join(strings.Fields(strings.ToUpper(up)), " ")
		if !strings.Contains(flat, "CREATE UNIQUE INDEX") {
			t.Errorf("%s does not create a UNIQUE index; %s.user_code is not protected", name, table)
		}
		if !strings.Contains(flat, "UPPER(REPLACE(USER_CODE, '-', ''))") {
			t.Errorf("%s's unique index is not the canonical upper(replace(user_code,'-','')); a "+
				"raw-column key still lets ABC-D and abcd collide", name)
		}
	}
}

// TestDeviceSaveErrorMapsOnlyTheCanonicalUserCodeConflict pins the classification
// itself: a conflict must be a typed conflict, and a different unique violation or
// an ordinary error must not be.
func TestDeviceSaveErrorMapsOnlyTheCanonicalUserCodeConflict(t *testing.T) {
	conflict := &pgconn.PgError{Code: "23505", ConstraintName: "oauth_device_authorizations_user_code_uniq"}
	if !deviceUserCodeConflict(conflict) {
		t.Fatal("the canonical user-code unique violation is not classified as a conflict; the service " +
			"would fail the request instead of redrawing the code (S04-5)")
	}
	if got := deviceSaveError(conflict); !errors.Is(got, oauth.ErrUserCodeConflict) {
		t.Fatalf("SaveDevice would surface %v, want an error wrapping oauth.ErrUserCodeConflict", got)
	}

	otherUnique := &pgconn.PgError{Code: "23505", ConstraintName: "oauth_device_authorizations_pkey"}
	if deviceUserCodeConflict(otherUnique) {
		t.Error("a device-code-primary-key collision is classified as a user-code conflict; a conflict " +
			"must mean the canonical user code, or the retry redraws a code that is not the problem")
	}
	if got := deviceSaveError(otherUnique); errors.Is(got, oauth.ErrUserCodeConflict) {
		t.Error("a non-user-code unique violation was surfaced as a conflict")
	}

	infra := errors.New("connection reset by peer")
	if deviceUserCodeConflict(infra) {
		t.Error("an ordinary infrastructure error is classified as a user-code conflict; the service " +
			"would burn its retries on a fault that redrawing cannot fix")
	}
	if got := deviceSaveError(infra); !errors.Is(got, infra) {
		t.Errorf("an infrastructure error lost its identity through the mapping: %v", got)
	}
	if got := deviceSaveError(nil); got != nil {
		t.Errorf("SaveDevice's error mapping turned success into %v", got)
	}
}

// And the mapping is actually on the store's write path, not only in a helper.
func TestSaveDeviceUsesTheConflictMapping(t *testing.T) {
	save := receiverMethod(t, sourceOf(t, "oauth.go"), "oauth.go", "SaveDevice")
	if !strings.Contains(save, "deviceSaveError(") {
		t.Error("Devices.SaveDevice returns the raw driver error; the typed conditional and the message " +
			"disappear before the oauth layer can see them (S04-5)")
	}
	if !strings.Contains(save, "INSERT INTO oauth_device_authorizations") {
		t.Error("SaveDevice no longer inserts into oauth_device_authorizations; the guard is reading the wrong method")
	}
}
