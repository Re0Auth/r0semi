package postgres

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/idp"
	"github.com/Re0Auth/r0semi/internal/account"
	"github.com/Re0Auth/r0semi/internal/federation"
	"github.com/Re0Auth/r0semi/oauth"
	"github.com/Re0Auth/r0semi/vault"
)

// openTestDB connects to TEST_DATABASE_URL and resets the tables.
//
// Locally, an unset variable skips the tests -- that is the point, so
// `go test ./...` works with no database running. In CI it is a hard failure:
// a green build there must mean the SQL was executed, not that it was skipped.
// (`go test` prints "ok" either way, so silence is not evidence.)
func openTestDB(t *testing.T) *DB {
	t.Helper()
	return openTestDBWith(t, DefaultPoolOptions())
}

// openTestDBWith is openTestDB with handle options — today, a replacement store
// clock (WithClock), which is how the single-clock policy is asserted. Everything
// else is shared, so a skewed-clock test cannot drift from the ordinary fixture.
func openTestDBWith(t *testing.T, opts PoolOptions, options ...Option) *DB {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("TEST_DATABASE_URL is required in CI: the Postgres integration tests must not silently skip")
		}
		t.Skip("TEST_DATABASE_URL is not set; skipping Postgres integration tests")
	}
	db, err := Open(context.Background(), dsn, opts, options...)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(db.Close)

	if _, err := db.pool.Exec(context.Background(), `
		TRUNCATE accounts_users, accounts_identities, oauth_codes,
		         oauth_access_tokens, oauth_refresh_tokens,
		         oauth_device_authorizations, oauth_clients,
		         vault_credentials, federation_bindings, federation_bind_flows,
		         sessions, audit_events,
		         session_subjects,
		         oidc_auth_requests, oidc_codes, oidc_access_tokens,
		         oidc_refresh_tokens, oidc_devices,
		         -- The audit chain's head and the subject keys are state OUTSIDE
		         -- audit_events, so truncating that table alone leaves a stale head:
		         -- the next appended row carries a non-empty prev_hash and Verify
		         -- rejects it as "does not point at the genesis hash", which fails
		         -- every audit test after the first one in the package.
		         audit_chain, audit_subject_keys
		CASCADE`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	// The chain head row is seeded by migration 0013; truncating removed it, so put
	// the genesis back.
	if _, err := db.pool.Exec(context.Background(),
		`INSERT INTO audit_chain (only_row, head_hash) VALUES (true, '\x'::bytea)`); err != nil {
		t.Fatalf("reseed chain head: %v", err)
	}
	return db
}

func testIdentity(provider idp.Provider, subject string) idp.Identity {
	return idp.Identity{Provider: provider, Subject: subject, DisplayName: "Test", Email: "t@example.com"}
}

func TestAccountsCreateAndFind(t *testing.T) {
	db := openTestDB(t)
	accounts := db.Accounts()
	ctx := context.Background()

	user, ident, err := accounts.CreateWithIdentity(ctx, testIdentity(idp.GitHub, "42"))
	if err != nil {
		t.Fatal(err)
	}
	if user.ID == "" || ident.ID == "" || user.PrimaryIdentity != ident.ID {
		t.Fatalf("user = %+v, ident = %+v", user, ident)
	}

	found, err := accounts.FindByIdentity(ctx, idp.GitHub, "42")
	if err != nil || found != user.ID {
		t.Fatalf("find = %q, %v", found, err)
	}
	if _, err := accounts.FindByIdentity(ctx, idp.GitHub, "nope"); !errors.Is(err, account.ErrNotFound) {
		t.Fatalf("unknown identity = %v, want ErrNotFound", err)
	}

	stored, err := accounts.GetUser(ctx, user.ID)
	if err != nil || stored.ID != user.ID {
		t.Fatalf("get user = %+v, %v", stored, err)
	}
}

// I-3: an identity belongs to exactly one account, even under a concurrent race.
func TestAccountsIdentityIsolation(t *testing.T) {
	db := openTestDB(t)
	accounts := db.Accounts()
	ctx := context.Background()

	first, _, err := accounts.CreateWithIdentity(ctx, testIdentity(idp.GitHub, "42"))
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := accounts.CreateWithIdentity(ctx, testIdentity(idp.Google, "go-1"))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := accounts.LinkIdentity(ctx, second.ID, testIdentity(idp.GitHub, "42")); !errors.Is(err, account.ErrIdentityTaken) {
		t.Fatalf("link taken identity = %v, want ErrIdentityTaken", err)
	}
	// The unique constraint, not just the pre-check, must reject a duplicate.
	if _, _, err := accounts.CreateWithIdentity(ctx, testIdentity(idp.GitHub, "42")); !errors.Is(err, account.ErrIdentityTaken) {
		t.Fatalf("duplicate create = %v, want ErrIdentityTaken", err)
	}
	_ = first
}

// Re-linking the same identity to the same user is idempotent.
func TestAccountsLinkIsIdempotent(t *testing.T) {
	db := openTestDB(t)
	accounts := db.Accounts()
	ctx := context.Background()

	user, ident, err := accounts.CreateWithIdentity(ctx, testIdentity(idp.GitHub, "42"))
	if err != nil {
		t.Fatal(err)
	}
	again, err := accounts.LinkIdentity(ctx, user.ID, testIdentity(idp.GitHub, "42"))
	if err != nil {
		t.Fatal(err)
	}
	if again.ID != ident.ID {
		t.Fatalf("re-link minted a new identity: %q vs %q", again.ID, ident.ID)
	}
	list, err := accounts.Identities(ctx, user.ID)
	if err != nil || len(list) != 1 {
		t.Fatalf("identities = %v, %v; want 1", list, err)
	}
}

// I-2: the last identity cannot be unlinked.
func TestAccountsUnlinkKeepsLastIdentity(t *testing.T) {
	db := openTestDB(t)
	accounts := db.Accounts()
	ctx := context.Background()

	user, ident, err := accounts.CreateWithIdentity(ctx, testIdentity(idp.GitHub, "42"))
	if err != nil {
		t.Fatal(err)
	}
	if err := accounts.UnlinkIdentity(ctx, user.ID, ident.ID); !errors.Is(err, account.ErrLastIdentity) {
		t.Fatalf("unlink last = %v, want ErrLastIdentity", err)
	}
}

// I-1: primary is display-only, so removing it just nominates a survivor.
func TestAccountsUnlinkReassignsPrimary(t *testing.T) {
	db := openTestDB(t)
	accounts := db.Accounts()
	ctx := context.Background()

	user, primary, err := accounts.CreateWithIdentity(ctx, testIdentity(idp.GitHub, "42"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := accounts.LinkIdentity(ctx, user.ID, testIdentity(idp.Google, "go-1"))
	if err != nil {
		t.Fatal(err)
	}
	if err := accounts.UnlinkIdentity(ctx, user.ID, primary.ID); err != nil {
		t.Fatal(err)
	}

	stored, err := accounts.GetUser(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.PrimaryIdentity != second.ID {
		t.Fatalf("primary = %q, want the surviving identity %q", stored.PrimaryIdentity, second.ID)
	}
	list, err := accounts.Identities(ctx, user.ID)
	if err != nil || len(list) != 1 {
		t.Fatalf("identities = %v, %v; want 1", list, err)
	}
}

func TestAccountsTouchLogin(t *testing.T) {
	db := openTestDB(t)
	accounts := db.Accounts()
	ctx := context.Background()

	if _, _, err := accounts.CreateWithIdentity(ctx, testIdentity(idp.GitHub, "42")); err != nil {
		t.Fatal(err)
	}
	if err := accounts.TouchLogin(ctx, idp.GitHub, "42"); err != nil {
		t.Fatal(err)
	}
	if err := accounts.TouchLogin(ctx, idp.GitHub, "ghost"); !errors.Is(err, account.ErrNotFound) {
		t.Fatalf("touch unknown = %v, want ErrNotFound", err)
	}
}

// A dump of the token tables must not contain the opaque value. This is the
// whole reason the store keys on SHA-256.
func TestTokensArePersistedAsHashesOnly(t *testing.T) {
	db := openTestDB(t)
	tokens := db.Tokens()
	ctx := context.Background()
	const plaintext = "the-opaque-access-token"

	if err := tokens.SaveAccess(ctx, plaintext, oauth.AccessToken{ClientID: "c", Subject: "s"}); err != nil {
		t.Fatal(err)
	}
	if err := tokens.SaveRefresh(ctx, plaintext, oauth.RefreshToken{ClientID: "c", Subject: "s"}); err != nil {
		t.Fatal(err)
	}

	var leaked int
	if err := db.pool.QueryRow(ctx,
		`SELECT count(*) FROM oauth_access_tokens WHERE token_hash = $1`, plaintext).Scan(&leaked); err != nil {
		t.Fatal(err)
	}
	if leaked != 0 {
		t.Fatal("the access token was stored under its plaintext")
	}
	var hashed int
	if err := db.pool.QueryRow(ctx,
		`SELECT count(*) FROM oauth_access_tokens WHERE token_hash = $1`, oauth.TokenHash(plaintext)).Scan(&hashed); err != nil {
		t.Fatal(err)
	}
	if hashed != 1 {
		t.Fatalf("rows keyed by the hash = %d, want 1", hashed)
	}
}

func TestTokensConsumeIsSingleUse(t *testing.T) {
	db := openTestDB(t)
	tokens := db.Tokens()
	ctx := context.Background()

	if err := tokens.SaveCode(ctx, "code", oauth.AuthorizationCode{ClientID: "c", Subject: "s"}); err != nil {
		t.Fatal(err)
	}
	if _, err := tokens.ConsumeCode(ctx, "code"); err != nil {
		t.Fatal(err)
	}
	if _, err := tokens.ConsumeCode(ctx, "code"); !errors.Is(err, oauth.ErrTokenNotFound) {
		t.Fatalf("second consume = %v, want ErrTokenNotFound", err)
	}

	if err := tokens.SaveRefresh(ctx, "rt", oauth.RefreshToken{ClientID: "c", Subject: "s"}); err != nil {
		t.Fatal(err)
	}
	if _, err := tokens.ConsumeRefresh(ctx, "rt"); err != nil {
		t.Fatal(err)
	}
	if _, err := tokens.ConsumeRefresh(ctx, "rt"); !errors.Is(err, oauth.ErrTokenNotFound) {
		t.Fatalf("second refresh = %v, want ErrTokenNotFound", err)
	}
}

func TestTokensAccessRoundTrip(t *testing.T) {
	db := openTestDB(t)
	tokens := db.Tokens()
	ctx := context.Background()
	expiry := time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond)

	if err := tokens.SaveAccess(ctx, "at", oauth.AccessToken{
		ClientID: "c", Subject: "s", Scopes: []oauth.Scope{"account.id", "phigros.score.read"}, ExpiresAt: expiry,
	}); err != nil {
		t.Fatal(err)
	}
	got, err := tokens.GetAccess(ctx, "at")
	if err != nil {
		t.Fatal(err)
	}
	if got.Subject != "s" || len(got.Scopes) != 2 || !got.ExpiresAt.Equal(expiry) {
		t.Fatalf("access = %+v", got)
	}
	if err := tokens.DeleteAccess(ctx, "at"); err != nil {
		t.Fatal(err)
	}
	if _, err := tokens.GetAccess(ctx, "at"); !errors.Is(err, oauth.ErrTokenNotFound) {
		t.Fatalf("after delete = %v, want ErrTokenNotFound", err)
	}
	// Deletion stays idempotent.
	if err := tokens.DeleteAccess(ctx, "at"); err != nil {
		t.Fatal(err)
	}
}

// The grants view enumerates one subject's tokens and groups them by client;
// revoking deletes one client's rows for one subject. Both are per (subject,
// client_id) and both must leave every other row alone, which is exactly what a
// missing WHERE clause would break.
func TestTokensListAndDeleteBySubject(t *testing.T) {
	db := openTestDB(t)
	tokens := db.Tokens()
	ctx := context.Background()
	expiry := time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond)

	// Namespaced by test name so a shared database cannot make this read another
	// test's rows.
	s1 := t.Name() + "-subject-1"
	s2 := t.Name() + "-subject-2"

	save := func(value, client, subject string, scopes ...oauth.Scope) {
		t.Helper()
		if err := tokens.SaveAccess(ctx, value, oauth.AccessToken{
			ClientID: client, Subject: subject, Scopes: scopes, ExpiresAt: expiry,
		}); err != nil {
			t.Fatal(err)
		}
	}
	save("grants-a1", "c1", s1, "account.id")
	save("grants-a2", "c1", s1, "phigros.score.read")
	save("grants-a3", "c2", s1, "account.id")
	save("grants-a4", "c1", s2, "account.id")
	if err := tokens.SaveRefresh(ctx, "grants-r1", oauth.RefreshToken{
		ClientID: "c1", Subject: s1, Scopes: []oauth.Scope{"account.id"}, ExpiresAt: expiry,
	}); err != nil {
		t.Fatal(err)
	}

	records, err := tokens.ListBySubject(ctx, s1)
	if err != nil {
		t.Fatal(err)
	}
	byKind := map[oauth.TokenKind]int{}
	byClient := map[string]int{}
	for _, r := range records {
		byKind[r.Kind]++
		byClient[r.ClientID]++
		if r.ExpiresAt.IsZero() {
			t.Errorf("record for %s lost its expiry: %+v", r.ClientID, r)
		}
	}
	if len(records) != 4 || byKind[oauth.TokenKindAccess] != 3 || byKind[oauth.TokenKindRefresh] != 1 {
		t.Fatalf("records = %+v, want three access and one refresh", records)
	}
	if byClient["c1"] != 3 || byClient["c2"] != 1 {
		t.Fatalf("records grouped wrongly: %+v", byClient)
	}

	// An unknown subject is empty, not an error: a fresh account has no grants.
	if empty, err := tokens.ListBySubject(ctx, t.Name()+"-nobody"); err != nil || len(empty) != 0 {
		t.Fatalf("unknown subject = %+v, %v", empty, err)
	}

	if err := tokens.DeleteBySubjectClient(ctx, s1, "c1"); err != nil {
		t.Fatal(err)
	}

	remaining, err := tokens.ListBySubject(ctx, s1)
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 1 || remaining[0].ClientID != "c2" {
		t.Fatalf("after revoking c1, remaining = %+v", remaining)
	}

	// The same client acting for another subject is untouched: revoking is per
	// account as well as per client.
	elsewhere, err := tokens.ListBySubject(ctx, s2)
	if err != nil {
		t.Fatal(err)
	}
	if len(elsewhere) != 1 {
		t.Fatalf("revoking for one subject removed another's rows: %+v", elsewhere)
	}

	// And the deleted access tokens are really gone, not merely unlisted.
	for _, value := range []string{"grants-a1", "grants-a2"} {
		if _, err := tokens.GetAccess(ctx, value); !errors.Is(err, oauth.ErrTokenNotFound) {
			t.Errorf("%s survived the revocation: %v", value, err)
		}
	}
	if _, err := tokens.ConsumeRefresh(ctx, "grants-r1"); !errors.Is(err, oauth.ErrTokenNotFound) {
		t.Errorf("the refresh token survived the revocation: %v", err)
	}

	// Revoking again is a no-op rather than an error.
	if err := tokens.DeleteBySubjectClient(ctx, s1, "c1"); err != nil {
		t.Fatal(err)
	}
}

func TestDevicesRoundTripAndUserCodeLookup(t *testing.T) {
	db := openTestDB(t)
	devices := db.Devices()
	ctx := context.Background()

	rec := oauth.DeviceAuthorizationRecord{
		UserCode: "BCDF-GHJK", ClientID: "c", Scopes: []oauth.Scope{"account.id"},
		Status: oauth.DevicePending, ExpiresAt: time.Now().Add(10 * time.Minute).UTC().Truncate(time.Microsecond),
	}
	if err := devices.SaveDevice(ctx, "device-secret", rec); err != nil {
		t.Fatal(err)
	}

	// The plaintext device code must not be a key.
	var leaked int
	if err := db.pool.QueryRow(ctx,
		`SELECT count(*) FROM oauth_device_authorizations WHERE device_code_hash = $1`, "device-secret").Scan(&leaked); err != nil {
		t.Fatal(err)
	}
	if leaked != 0 {
		t.Fatal("the device code was stored under its plaintext")
	}

	got, err := devices.GetDevice(ctx, "device-secret")
	if err != nil {
		t.Fatal(err)
	}
	if got.UserCode != "BCDF-GHJK" || got.Status != oauth.DevicePending || got.DeviceCodeHash == "" {
		t.Fatalf("device = %+v", got)
	}

	// User codes are typed by hand, so lookup ignores case and separators.
	for _, typed := range []string{"BCDF-GHJK", "bcdfghjk", "bcdf-ghjk"} {
		found, err := devices.GetDeviceByUserCode(ctx, typed)
		if err != nil {
			t.Fatalf("lookup %q: %v", typed, err)
		}
		if found.DeviceCodeHash != got.DeviceCodeHash {
			t.Fatalf("lookup %q found a different row", typed)
		}
	}

	got.Status = oauth.DeviceApproved
	got.Subject = "usr_1"
	got.Explicit = []oauth.Scope{"account.id"}
	if err := devices.UpdateDevice(ctx, got); err != nil {
		t.Fatal(err)
	}
	updated, err := devices.GetDevice(ctx, "device-secret")
	if err != nil {
		t.Fatal(err)
	}
	if updated.Status != oauth.DeviceApproved || updated.Subject != "usr_1" {
		t.Fatalf("updated = %+v", updated)
	}
}

// List exists for key rotation, which has to visit everything. It must return the
// crypto material intact and in a stable order, or a rotation would re-wrap some
// records and skip others between two runs.
func TestVaultListIsOrderedAndComplete(t *testing.T) {
	db := openTestDB(t)
	repo := db.Vault()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)

	// Namespaced by test name: the database is shared with the other tests.
	scope := t.Name()
	for _, subject := range []string{scope + "-b", scope + "-a"} {
		if err := repo.Put(ctx, vault.Record{
			Identity:   vault.Identity{Subject: subject, Provider: "taptap"},
			Version:    1,
			WrappedDEK: []byte{0xAA, 0xBB},
			KEKID:      "kek-1",
			Nonce:      []byte{1, 2, 3, 4},
			Ciphertext: []byte{0xCC},
			Meta:       map[string]string{"openid": subject},
			CreatedAt:  now,
			UpdatedAt:  now,
		}); err != nil {
			t.Fatal(err)
		}
	}

	all, err := repo.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	mine := make([]vault.Record, 0, 2)
	for _, rec := range all {
		if strings.HasPrefix(rec.Identity.Subject, scope) {
			mine = append(mine, rec)
		}
	}
	if len(mine) != 2 {
		t.Fatalf("list returned %d of our records, want 2", len(mine))
	}
	if mine[0].Identity.Subject != scope+"-a" || mine[1].Identity.Subject != scope+"-b" {
		t.Fatalf("list is not ordered by subject: %s, %s",
			mine[0].Identity.Subject, mine[1].Identity.Subject)
	}
	got := mine[0]
	if !bytes.Equal(got.WrappedDEK, []byte{0xAA, 0xBB}) || got.KEKID != "kek-1" ||
		!bytes.Equal(got.Nonce, []byte{1, 2, 3, 4}) || !bytes.Equal(got.Ciphertext, []byte{0xCC}) {
		t.Fatalf("list dropped crypto material: %+v", got)
	}
	if got.Meta["openid"] != scope+"-a" || !got.CreatedAt.Equal(now) {
		t.Fatalf("list dropped metadata: %+v", got)
	}
}

func TestVaultRepoRoundTrip(t *testing.T) {
	db := openTestDB(t)
	repo := db.Vault()
	ctx := context.Background()
	stamp := time.Now().UTC().Truncate(time.Microsecond)

	rec := vault.Record{
		Identity:   vault.Identity{Subject: "usr_1", Provider: "phigros.taptap"},
		Version:    1,
		WrappedDEK: []byte{1, 2, 3},
		KEKID:      "kek-1",
		Nonce:      []byte{4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
		Ciphertext: []byte{0xde, 0xad, 0xbe, 0xef},
		Meta:       map[string]string{"openid": "o-1", "unionid": "u-1"},
		CreatedAt:  stamp,
		UpdatedAt:  stamp,
	}
	if err := repo.Put(ctx, rec); err != nil {
		t.Fatal(err)
	}

	got, err := repo.Get(ctx, rec.Identity)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != rec.Version || got.KEKID != rec.KEKID ||
		!bytes.Equal(got.WrappedDEK, rec.WrappedDEK) ||
		!bytes.Equal(got.Nonce, rec.Nonce) ||
		!bytes.Equal(got.Ciphertext, rec.Ciphertext) {
		t.Fatalf("record = %+v", got)
	}
	if got.Meta["openid"] != "o-1" || got.Meta["unionid"] != "u-1" {
		t.Fatalf("meta = %v", got.Meta)
	}
	if !got.CreatedAt.Equal(stamp) || !got.UpdatedAt.Equal(stamp) {
		t.Fatalf("timestamps = %v / %v", got.CreatedAt, got.UpdatedAt)
	}
}

func TestVaultPutReplacesAndDeleteIsIdempotent(t *testing.T) {
	db := openTestDB(t)
	repo := db.Vault()
	ctx := context.Background()
	id := vault.Identity{Subject: "usr_1", Provider: "phigros.taptap"}

	// WrappedDEK and Nonce are NOT NULL in the table; a real record always has
	// them. They are irrelevant here, where the subject is replace/delete.
	if err := repo.Put(ctx, vault.Record{
		Identity: id, Version: 1, WrappedDEK: []byte{1}, KEKID: "a", Nonce: []byte{1}, Ciphertext: []byte{1},
	}); err != nil {
		t.Fatal(err)
	}
	if err := repo.Put(ctx, vault.Record{
		Identity: id, Version: 2, WrappedDEK: []byte{2}, KEKID: "b", Nonce: []byte{2}, Ciphertext: []byte{2},
	}); err != nil {
		t.Fatal(err)
	}
	got, err := repo.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != 2 || got.KEKID != "b" || !bytes.Equal(got.Ciphertext, []byte{2}) {
		t.Fatalf("the record was not replaced: %+v", got)
	}
	if got.Meta == nil {
		t.Fatal("meta should come back as an empty map, not nil")
	}

	if err := repo.Delete(ctx, id); err != nil {
		t.Fatal(err)
	}
	if err := repo.Delete(ctx, id); err != nil {
		t.Fatalf("delete is not idempotent: %v", err)
	}
	if _, err := repo.Get(ctx, id); !errors.Is(err, vault.ErrNotFound) {
		t.Fatalf("get after delete = %v, want ErrNotFound", err)
	}
}

// The whole point of the vault is that a database dump is useless. This drives
// the real envelope implementation against the real table and then searches the
// stored row for the plaintext.
func TestVaultLeavesNoPlaintextAtRest(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	wrapper, err := vault.NewLocalKeyWrapper("test-kek", bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	service, err := vault.NewService(db.Vault(), wrapper, audit.NewMemoryLogger())
	if err != nil {
		t.Fatal(err)
	}

	const plaintext = "super-secret-session-token"
	id := vault.Identity{Subject: "usr_1", Provider: "phigros.taptap"}
	if err := service.Enroll(ctx, id, []byte(plaintext), map[string]string{"openid": "o-1"}); err != nil {
		t.Fatal(err)
	}

	var dump string
	if err := db.pool.QueryRow(ctx,
		`SELECT coalesce(string_agg(t::text, ' '), '') FROM vault_credentials t`).Scan(&dump); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(dump, plaintext) {
		t.Fatalf("the plaintext secret is readable at rest: %s", dump)
	}
	// Guard against a vacuous pass: the metadata is deliberately readable, so if
	// it is absent the row was not dumped and the assertion above proved nothing.
	if !strings.Contains(dump, "o-1") {
		t.Fatal("the dump did not contain the row; the assertion above is vacuous")
	}

	var got string
	if err := service.Use(ctx, id, func(secret []byte) error {
		got = string(secret)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got != plaintext {
		t.Fatalf("Use returned %q, want the enrolled secret", got)
	}
}

func TestBindingsRoundTrip(t *testing.T) {
	db := openTestDB(t)
	bindings := db.Bindings()
	ctx := context.Background()
	expiry := time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond)

	if _, err := bindings.Get(ctx, "usr_1", "phigros", "fake"); !errors.Is(err, federation.ErrNotBound) {
		t.Fatalf("get before bind = %v, want ErrNotBound", err)
	}

	want := federation.Binding{
		User: "usr_1", Game: "phigros", Source: "fake",
		// Above MaxInt64 on purpose: the store persists a random uint64 through
		// int64, and this pins that the round trip is bit-exact rather than
		// dependent on the driver's integer codec accepting a high-bit value.
		TokenType: "Bearer", Expiry: expiry, HasRefresh: true, Version: 1<<63 + 5,
	}
	if err := bindings.Put(ctx, want); err != nil {
		t.Fatal(err)
	}
	got, err := bindings.Get(ctx, "usr_1", "phigros", "fake")
	if err != nil {
		t.Fatal(err)
	}
	if got.User != want.User || got.TokenType != want.TokenType || !got.HasRefresh || got.Version != want.Version {
		t.Fatalf("binding = %+v, want version %d", got, want.Version)
	}
	if !got.Expiry.Equal(expiry) {
		t.Fatalf("expiry = %v, want %v", got.Expiry, expiry)
	}
}

// The bindings view lists one account's connections and must not reach across to
// another's, nor reorder itself between two loads of the same page.
func TestBindingsListIsScopedAndOrdered(t *testing.T) {
	db := openTestDB(t)
	bindings := db.Bindings()
	ctx := context.Background()

	// Namespaced by test name so a shared database cannot mix in other rows.
	scope := t.Name()
	mine := []federation.Binding{
		{User: account.UserID(scope), Game: "phigros", Source: "zulu", Version: 1},
		{User: account.UserID(scope), Game: "phigros", Source: "alpha", Version: 1},
		{User: account.UserID(scope), Game: "arcaea", Source: "beta", Version: 1},
		{User: account.UserID("someone-else-" + scope), Game: "phigros", Source: "theirs", Version: 1},
	}
	for _, b := range mine {
		if err := bindings.Put(ctx, b); err != nil {
			t.Fatal(err)
		}
	}

	got, err := bindings.List(ctx, account.UserID(scope))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("list = %+v, want this account's three", got)
	}
	for _, b := range got {
		if b.User != account.UserID(scope) {
			t.Errorf("list included another account's row: %+v", b)
		}
	}
	// game then source, decided by the database so the order is stable.
	want := []string{"arcaea/beta", "phigros/alpha", "phigros/zulu"}
	for i, b := range got {
		if key := b.Game + "/" + b.Source; key != want[i] {
			t.Errorf("row %d = %s, want %s", i, key, want[i])
		}
	}

	// An account with nothing bound gets an empty list, not an error.
	if none, err := bindings.List(ctx, account.UserID("nobody-"+scope)); err != nil || len(none) != 0 {
		t.Fatalf("empty list = %+v, %v", none, err)
	}
}

// The refresh path detects "someone else already rotated this" by comparing
// Version, so the store must round-trip it faithfully.
func TestBindingPutReplacesVersionAndDeleteIsIdempotent(t *testing.T) {
	db := openTestDB(t)
	bindings := db.Bindings()
	ctx := context.Background()

	if err := bindings.Put(ctx, federation.Binding{User: "usr_1", Game: "phigros", Source: "fake", Version: 1}); err != nil {
		t.Fatal(err)
	}
	if err := bindings.Put(ctx, federation.Binding{User: "usr_1", Game: "phigros", Source: "fake", Version: 7, HasRefresh: true}); err != nil {
		t.Fatal(err)
	}
	got, err := bindings.Get(ctx, "usr_1", "phigros", "fake")
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != 7 || !got.HasRefresh {
		t.Fatalf("the binding was not replaced: %+v", got)
	}

	if err := bindings.Delete(ctx, "usr_1", "phigros", "fake"); err != nil {
		t.Fatal(err)
	}
	if err := bindings.Delete(ctx, "usr_1", "phigros", "fake"); err != nil {
		t.Fatalf("delete is not idempotent: %v", err)
	}
	if _, err := bindings.Get(ctx, "usr_1", "phigros", "fake"); !errors.Is(err, federation.ErrNotBound) {
		t.Fatalf("get after delete = %v, want ErrNotBound", err)
	}
}

// PutIfVersion is the compare-and-swap two processes refresh a binding through:
// only the writer that still sees the version it read may advance it.
func TestBindingPutIfVersionIsAtomic(t *testing.T) {
	db := openTestDB(t)
	bindings := db.Bindings()
	ctx := context.Background()

	if err := bindings.Put(ctx, federation.Binding{User: "usr_1", Game: "phigros", Source: "fake", Version: 1}); err != nil {
		t.Fatal(err)
	}

	// A stale expectation loses and must not overwrite.
	won, err := bindings.PutIfVersion(ctx,
		federation.Binding{User: "usr_1", Game: "phigros", Source: "fake", Version: 2, TokenType: "Bearer"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if won {
		t.Fatal("a stale expectation won the compare-and-swap")
	}
	if got, _ := bindings.Get(ctx, "usr_1", "phigros", "fake"); got.Version != 1 {
		t.Fatalf("version = %d after a losing write, want 1", got.Version)
	}

	// The matching expectation wins.
	won, err = bindings.PutIfVersion(ctx,
		federation.Binding{User: "usr_1", Game: "phigros", Source: "fake", Version: 2, TokenType: "Bearer"}, 1)
	if err != nil || !won {
		t.Fatalf("matching expectation: won=%v err=%v", won, err)
	}
	if got, _ := bindings.Get(ctx, "usr_1", "phigros", "fake"); got.Version != 2 || got.TokenType != "Bearer" {
		t.Fatalf("binding = %+v, want the written row", got)
	}

	// An absent binding is not created: refreshing one that is gone is a lost
	// race, not an insert.
	won, err = bindings.PutIfVersion(ctx,
		federation.Binding{User: "usr_1", Game: "phigros", Source: "gone", Version: 1}, 0)
	if err != nil || won {
		t.Fatalf("absent binding: won=%v err=%v, want false", won, err)
	}
}

// A bind flow is single-use: two concurrent callbacks must not both succeed.
func TestBindFlowsConsumeIsSingleUse(t *testing.T) {
	db := openTestDB(t)
	flows := db.BindFlows()
	ctx := context.Background()

	flow := federation.BindFlow{
		ID: "bnd_1", State: "st-1", User: "usr_1",
		Game: "phigros", Source: "fake", Verifier: "verifier-1",
		ReturnTo: "/dashboard", ExpiresAt: time.Now().Add(10 * time.Minute).UTC().Truncate(time.Microsecond),
	}
	if err := flows.Put(ctx, flow); err != nil {
		t.Fatal(err)
	}

	got, err := flows.Consume(ctx, "st-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != flow.ID || got.User != flow.User || got.Game != flow.Game ||
		got.Source != flow.Source || got.Verifier != flow.Verifier || got.ReturnTo != flow.ReturnTo {
		t.Fatalf("flow = %+v", got)
	}
	if _, err := flows.Consume(ctx, "st-1"); !errors.Is(err, federation.ErrUnknownBind) {
		t.Fatalf("second consume = %v, want ErrUnknownBind", err)
	}
	if _, err := flows.Consume(ctx, "never-existed"); !errors.Is(err, federation.ErrUnknownBind) {
		t.Fatalf("unknown state = %v, want ErrUnknownBind", err)
	}
}

// The live schema must not be ABLE to hold a credential anywhere, not only in the
// binding table.
//
// TestNoColumnCanHoldACredential makes the same claim against the migration files,
// with no database. This is the half that cannot be fooled by a schema the
// migrations do not describe: a column added by hand, or by a migration that never
// made it into the embedded set, still shows up in `information_schema`.
func TestNoColumnInTheLiveSchemaCanHoldACredential(t *testing.T) {
	db := openTestDB(t)
	rows, err := db.pool.Query(context.Background(), `
		SELECT table_name, column_name FROM information_schema.columns
		 WHERE table_schema = current_schema()
		 ORDER BY table_name, column_name`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	inspected := 0
	for rows.Next() {
		var table, column string
		if err := rows.Scan(&table, &column); err != nil {
			t.Fatal(err)
		}
		inspected++
		lower := strings.ToLower(column)
		if _, ok := credentialColumnAllowed[table+"."+lower]; ok {
			continue
		}
		for _, word := range credentialColumnWords {
			if strings.Contains(lower, word) {
				t.Errorf("%s.%s can hold a credential (%q)", table, column, word)
				break
			}
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	// Anti-vacuous: an empty schema would make the loop above prove nothing.
	if inspected < 50 {
		t.Fatalf("inspected only %d columns; the schema is not what this test expects", inspected)
	}
}

func TestSessionsCommitFindDelete(t *testing.T) {
	db := openTestDB(t)
	sessions := db.Sessions()
	expiry := time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond)

	if _, found, err := sessions.Find("tok-1"); err != nil || found {
		t.Fatalf("find before commit = %v, %v; want not found", found, err)
	}
	if err := sessions.Commit("tok-1", []byte("payload"), expiry); err != nil {
		t.Fatal(err)
	}
	data, found, err := sessions.Find("tok-1")
	if err != nil || !found || string(data) != "payload" {
		t.Fatalf("find = %q, %v, %v", data, found, err)
	}

	// A second Commit for the same token overwrites rather than duplicating.
	if err := sessions.Commit("tok-1", []byte("payload-2"), expiry); err != nil {
		t.Fatal(err)
	}
	if data, _, _ := sessions.Find("tok-1"); string(data) != "payload-2" {
		t.Fatalf("commit did not overwrite: %q", data)
	}

	if err := sessions.Delete("tok-1"); err != nil {
		t.Fatal(err)
	}
	if err := sessions.Delete("tok-1"); err != nil {
		t.Fatalf("delete is not idempotent: %v", err)
	}
	if _, found, _ := sessions.Find("tok-1"); found {
		t.Fatal("the session survived deletion")
	}
}

// scs defines an expired session as "not found", and the row should not linger.
func TestSessionsExpiredIsNotFoundAndRemoved(t *testing.T) {
	db := openTestDB(t)
	sessions := db.Sessions()
	ctx := context.Background()

	if err := sessions.Commit("tok-old", []byte("payload"), time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, found, err := sessions.Find("tok-old"); err != nil || found {
		t.Fatalf("expired find = %v, %v; want not found", found, err)
	}

	var remaining int
	if err := db.pool.QueryRow(ctx, `SELECT count(*) FROM sessions`).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 0 {
		t.Fatalf("expired rows remaining = %d", remaining)
	}
}

func TestSessionsSweepRemovesOnlyExpired(t *testing.T) {
	db := openTestDB(t)
	sessions := db.Sessions()
	ctx := context.Background()

	if err := sessions.Commit("live", []byte("x"), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := sessions.Commit("dead", []byte("x"), time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}

	removed, err := sessions.SweepExpired(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 {
		t.Fatalf("removed = %d, want 1", removed)
	}
	if _, found, _ := sessions.Find("live"); !found {
		t.Fatal("the sweep removed a live session")
	}
}

// A dumped table must not be a set of usable session cookies.
func TestSessionsStoreNoPlaintextCookie(t *testing.T) {
	db := openTestDB(t)
	sessions := db.Sessions()
	ctx := context.Background()
	const token = "the-raw-session-cookie-value"

	if err := sessions.Commit(token, []byte("payload"), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	var leaked int
	if err := db.pool.QueryRow(ctx,
		`SELECT count(*) FROM sessions WHERE token_hash = $1`, token).Scan(&leaked); err != nil {
		t.Fatal(err)
	}
	if leaked != 0 {
		t.Fatal("the session cookie was stored under its plaintext")
	}
	var hashed int
	if err := db.pool.QueryRow(ctx,
		`SELECT count(*) FROM sessions WHERE token_hash = $1`, sessionTokenHash(token)).Scan(&hashed); err != nil {
		t.Fatal(err)
	}
	if hashed != 1 {
		t.Fatalf("rows keyed by the hash = %d, want 1", hashed)
	}
}

func TestClientsRoundTripKeepsSecretHashOnly(t *testing.T) {
	db := openTestDB(t)
	clients := db.Clients()
	ctx := context.Background()

	confidential, err := oauth.NewClient("cli", "CLI", oauth.ClientConfidential, "s3cret",
		[]string{"https://app.example/cb"}, []oauth.Scope{oauth.ScopeAccountID})
	if err != nil {
		t.Fatal(err)
	}
	if err := clients.Create(ctx, confidential); err != nil {
		t.Fatal(err)
	}

	got, err := clients.Get(ctx, "cli")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "CLI" || got.Type != oauth.ClientConfidential {
		t.Fatalf("client = %+v", got)
	}
	if !got.Authenticate("s3cret") || got.Authenticate("wrong") {
		t.Fatal("the restored client does not authenticate correctly")
	}
	if !got.AllowsRedirect("https://app.example/cb") || !got.AllowsScope(oauth.ScopeAccountID) {
		t.Fatalf("client lost its redirect URIs or scopes: %+v", got)
	}

	// A public client stores no secret at all.
	public, err := oauth.NewClient("spa", "SPA", oauth.ClientPublic, "",
		[]string{"https://spa.example/cb"}, []oauth.Scope{oauth.ScopeAccountID})
	if err != nil {
		t.Fatal(err)
	}
	if err := clients.Create(ctx, public); err != nil {
		t.Fatal(err)
	}
	restored, err := clients.Get(ctx, "spa")
	if err != nil {
		t.Fatal(err)
	}
	if restored.Authenticate("anything") {
		t.Fatal("a public client authenticated with a secret")
	}

	if _, err := clients.Get(ctx, "ghost"); !errors.Is(err, oauth.ErrClientNotFound) {
		t.Fatalf("unknown client = %v, want ErrClientNotFound", err)
	}
}

// testAuditKey is the chain key the audit tests use. Any 32 bytes will do; the
// tests that matter are about what changes when it is wrong, not what it is.
func testAuditKey() []byte { return bytes.Repeat([]byte{0x5a}, 32) }

// openAudit returns the durable audit sink, failing the test if it cannot be
// built.
func openAudit(t *testing.T, db *DB) *AuditLogger {
	t.Helper()
	logger, err := db.Audit(testAuditKey())
	if err != nil {
		t.Fatal(err)
	}
	return logger
}

// The audit log is the one remaining in-memory piece when the server runs
// without a database. With one, every Record must be a durable row and must
// round-trip its structured detail.
func TestAuditLoggerPersistsRecord(t *testing.T) {
	db := openTestDB(t)
	logger := openAudit(t, db)
	ctx := context.Background()
	stamp := time.Now().UTC().Truncate(time.Microsecond)

	if err := logger.Record(ctx, audit.Event{
		Time:     stamp,
		Action:   "vault.use",
		Subject:  "usr_1",
		Provider: "phigros.taptap",
		Outcome:  audit.OutcomeOK,
		Detail:   map[string]string{"client_id": "cli", "request_id": "req_1"},
	}); err != nil {
		t.Fatal(err)
	}

	// The row is found by its action, not by subject: the subject column holds a
	// pseudonym now, so a lookup by the raw account id would find nothing. That is
	// asserted separately below.
	var (
		occurredAt                         time.Time
		action, subject, provider, outcome string
		detail                             map[string]string
	)
	if err := db.pool.QueryRow(ctx, `
		SELECT occurred_at, action, subject, provider, outcome, detail
		  FROM audit_events
		 WHERE action = $1`, "vault.use").
		Scan(&occurredAt, &action, &subject, &provider, &outcome, &detail); err != nil {
		t.Fatal(err)
	}

	if !occurredAt.Equal(stamp) {
		t.Fatalf("occurred_at = %v, want %v", occurredAt, stamp)
	}
	if action != "vault.use" || provider != "phigros.taptap" || outcome != audit.OutcomeOK {
		t.Fatalf("row = %q %q %q", action, provider, outcome)
	}
	// The account id is not what was stored, and it is not recoverable from the row.
	if subject == "usr_1" || subject == "" {
		t.Fatalf("subject = %q: the raw account id should be pseudonymised", subject)
	}
	if detail["client_id"] != "cli" || detail["request_id"] != "req_1" {
		t.Fatalf("detail = %v", detail)
	}

	// A nil detail is stored as an empty object, never JSON null.
	if err := logger.Record(ctx, audit.Event{Action: "vault.enroll", Subject: "usr_2", Outcome: audit.OutcomeOK}); err != nil {
		t.Fatal(err)
	}
	var raw string
	if err := db.pool.QueryRow(ctx,
		`SELECT detail::text FROM audit_events WHERE action = $1`, "vault.enroll").Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if raw != "{}" {
		t.Fatalf("nil detail stored as %q, want {}", raw)
	}
}

func TestClientAdminLifecycleAndSuspension(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	reg := db.Clients()

	c, err := oauth.NewClient("cli_admin", "Admin Test", oauth.ClientPublic, "",
		[]string{"https://app.example/cb"}, []oauth.Scope{"openid"})
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Create(ctx, c); err != nil {
		t.Fatal(err)
	}

	if _, err := reg.Get(ctx, "cli_admin"); err != nil {
		t.Fatalf("active get: %v", err)
	}
	if err := reg.SetStatus(ctx, "cli_admin", oauth.ClientSuspended); err != nil {
		t.Fatal(err)
	}
	// Suspended is reported as unknown, not as a distinct error.
	if _, err := reg.Get(ctx, "cli_admin"); !errors.Is(err, oauth.ErrClientNotFound) {
		t.Fatalf("suspended get = %v, want ErrClientNotFound", err)
	}
	// ... but the admin view still shows it.
	all, err := reg.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, row := range all {
		if row.ID == "cli_admin" {
			found = true
			if row.Status != oauth.ClientSuspended {
				t.Fatalf("listed status = %s, want suspended", row.Status)
			}
		}
	}
	if !found {
		t.Fatal("suspended client missing from List")
	}

	if err := reg.SetStatus(ctx, "cli_admin", oauth.ClientActive); err != nil {
		t.Fatal(err)
	}
	if _, err := reg.Get(ctx, "cli_admin"); err != nil {
		t.Fatalf("reactivated get: %v", err)
	}

	if err := reg.Delete(ctx, "cli_admin"); err != nil {
		t.Fatal(err)
	}
	if err := reg.Delete(ctx, "cli_admin"); err != nil {
		t.Fatalf("delete must be idempotent: %v", err)
	}
	if err := reg.SetStatus(ctx, "cli_admin", oauth.ClientActive); !errors.Is(err, oauth.ErrClientNotFound) {
		t.Fatalf("SetStatus after delete = %v, want ErrClientNotFound", err)
	}
}

// revokeMatching is the one query behind every bulk revocation; its filters must
// select a client, a subject, or everything.
func TestRevokeMatchingFilters(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	mustExec := func(query string) {
		t.Helper()
		if _, err := db.pool.Exec(ctx, query); err != nil {
			t.Fatal(err)
		}
	}
	tables := []string{"oidc_access_tokens", "oidc_refresh_tokens"}

	mustExec(`INSERT INTO oidc_access_tokens (id_hash, client_id, subject, expires_at) VALUES ('a1','cli_a','usr_1', now()+interval '1 hour')`)
	mustExec(`INSERT INTO oidc_access_tokens (id_hash, client_id, subject, expires_at) VALUES ('b1','cli_b','usr_1', now()+interval '1 hour')`)
	mustExec(`INSERT INTO oidc_access_tokens (id_hash, client_id, subject, expires_at) VALUES ('c1','cli_a','usr_2', now()+interval '1 hour')`)
	mustExec(`INSERT INTO oidc_refresh_tokens (token_hash, id_hash, client_id, subject, expires_at) VALUES ('r1','a1','cli_a','usr_1', now()+interval '1 hour')`)

	n, err := revokeMatching(ctx, db.pool, tables, oauth.TokenFilter{ClientID: "cli_a"})
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("client filter removed %d, want 3", n)
	}
	n, err = revokeMatching(ctx, db.pool, tables, oauth.TokenFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("empty filter removed %d, want 1", n)
	}
}

func TestRevokeAllSessionsDeletesEveryRow(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	store := db.Sessions()
	for _, token := range []string{"t1", "t2"} {
		if err := store.Commit(token, []byte("data"), time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		if err := store.Remember(ctx, token, "usr_1"); err != nil {
			t.Fatal(err)
		}
	}
	n, err := store.RevokeAllSessions(ctx)
	if err != nil || n != 2 {
		t.Fatalf("removed %d (%v), want 2", n, err)
	}
	if _, found, _ := store.Find("t1"); found {
		t.Fatal("a session survived the kill switch")
	}
	var left int
	if err := db.pool.QueryRow(ctx, `SELECT count(*) FROM session_subjects`).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left != 0 {
		t.Fatalf("%d subject index rows survived", left)
	}
}

// Remember is what lets the Kill Switch reach one account's sessions; scs itself
// has no idea which account a cookie belongs to.
func TestRememberAndRevokeSubjectSessions(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	store := db.Sessions()
	for _, token := range []string{"t1", "t2"} {
		if err := store.Commit(token, []byte("data"), time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Remember(ctx, "t1", "usr_1"); err != nil {
		t.Fatal(err)
	}
	if err := store.Remember(ctx, "t2", "usr_2"); err != nil {
		t.Fatal(err)
	}

	n, err := store.RevokeSubjectSessions(ctx, "usr_1")
	if err != nil || n != 1 {
		t.Fatalf("removed %d (%v), want 1", n, err)
	}
	if _, found, _ := store.Find("t1"); found {
		t.Fatal("usr_1's session survived")
	}
	if _, found, _ := store.Find("t2"); !found {
		t.Fatal("usr_2's session was touched")
	}

	// Idempotent, and an empty subject is refused rather than matching everyone.
	if n, err := store.RevokeSubjectSessions(ctx, "usr_1"); err != nil || n != 0 {
		t.Fatalf("second revoke = %d (%v), want 0", n, err)
	}
	if _, err := store.RevokeSubjectSessions(ctx, "  "); err == nil {
		t.Fatal("RevokeSubjectSessions accepted an empty subject")
	}
}

// The index row is written during SignIn, but scs commits the session row only
// when the response is written — so for the length of one request a LIVE session
// has no session row. The sweep must not treat that window as an orphan: doing so
// deleted the only record of which account the session belonged to, and nothing
// rewrote it, so a later subject Kill Switch missed a live session.
func TestSweepSparesAFreshIndexRowAndCollectsAnAgedOne(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	store := db.Sessions()

	// Young enough to be mid-flight: a session being signed in right now.
	if err := store.Remember(ctx, "signing-in", "usr_1"); err != nil {
		t.Fatal(err)
	}
	// Old enough to be a genuine orphan.
	if err := store.Remember(ctx, "never-committed", "usr_2"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.pool.Exec(ctx,
		`UPDATE session_subjects SET created_at = now() - interval '2 hours' WHERE subject = $1`,
		"usr_2"); err != nil {
		t.Fatal(err)
	}

	if _, err := store.SweepExpired(ctx); err != nil {
		t.Fatal(err)
	}

	var fresh, aged int
	if err := db.pool.QueryRow(ctx,
		`SELECT count(*) FROM session_subjects WHERE subject = $1`, "usr_1").Scan(&fresh); err != nil {
		t.Fatal(err)
	}
	if err := db.pool.QueryRow(ctx,
		`SELECT count(*) FROM session_subjects WHERE subject = $1`, "usr_2").Scan(&aged); err != nil {
		t.Fatal(err)
	}
	if fresh != 1 {
		t.Error("the sweep removed an index row that could still be mid-flight, " +
			"dropping a live session from that account's revocable set")
	}
	if aged != 0 {
		t.Error("the sweep did not collect a genuinely orphaned index row")
	}
}

// ListAll is the Kill Switch's view: every binding, every user, ordered so two
// sweeps act in the same order.
func TestBindingsListAllReturnsEveryUserInOrder(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	store := db.Bindings()

	for _, b := range []federation.Binding{
		{User: "usr_2", Game: "phigros", Source: "b"},
		{User: "usr_1", Game: "phigros", Source: "a"},
		{User: "usr_1", Game: "arcaea", Source: "c"},
	} {
		if err := store.Put(ctx, b); err != nil {
			t.Fatal(err)
		}
	}

	all, err := store.ListAll(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"usr_1|arcaea|c", "usr_1|phigros|a", "usr_2|phigros|b"}
	if len(all) != len(want) {
		t.Fatalf("ListAll = %d bindings, want %d", len(all), len(want))
	}
	for i, b := range all {
		got := string(b.User) + "|" + b.Game + "|" + b.Source
		if got != want[i] {
			t.Fatalf("all[%d] = %s, want %s", i, got, want[i])
		}
	}

	// The per-user list is unchanged: it still filters.
	if mine, err := store.List(ctx, "usr_1"); err != nil || len(mine) != 2 {
		t.Fatalf("List(usr_1) = %v (%v), want 2", mine, err)
	}
}
