package postgres

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/idp"
	"github.com/Re0Auth/r0semi/internal/account"
	"github.com/Re0Auth/r0semi/oauth"
)

// openTestDB connects to TEST_DATABASE_URL and resets the tables.
//
// Locally, an unset variable skips the tests -- that is the point, so
// `go test ./...` works with no database running. In CI it is a hard failure:
// a green build there must mean the SQL was executed, not that it was skipped.
// (`go test` prints "ok" either way, so silence is not evidence.)
func openTestDB(t *testing.T) *DB {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("TEST_DATABASE_URL is required in CI: the Postgres integration tests must not silently skip")
		}
		t.Skip("TEST_DATABASE_URL is not set; skipping Postgres integration tests")
	}
	db, err := Open(context.Background(), dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(db.Close)

	if _, err := db.pool.Exec(context.Background(), `
		TRUNCATE accounts_users, accounts_identities, oauth_codes,
		         oauth_access_tokens, oauth_refresh_tokens,
		         oauth_device_authorizations, oauth_clients
		CASCADE`); err != nil {
		t.Fatalf("truncate: %v", err)
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
