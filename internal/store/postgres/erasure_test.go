package postgres

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/idp"
	"github.com/Re0Auth/r0semi/internal/account"
	"github.com/Re0Auth/r0semi/internal/federation"
	"github.com/Re0Auth/r0semi/internal/lifecycle"
	"github.com/Re0Auth/r0semi/internal/oidcstore"
	"github.com/Re0Auth/r0semi/oauth"
	"github.com/Re0Auth/r0semi/vault"
)

// accountTablesIgnored are the account-linked tables that must NOT be empty after
// an erasure, each for a stated reason. Kept as data so the exemption is visible
// rather than implied by omission from a list.
var accountTablesIgnored = map[string]string{
	// Append-only and chained. The erasure destroys the subject's pseudonym key
	// (audit_subject_keys) instead, which is what makes these rows unlinkable
	// while leaving the chain intact. See docs/architecture.md §4.17.
	"audit_events": "append-only: the erasure destroys the pseudonym key, not the rows",
}

// TestAccountDeletionLeavesNoOrphans is the compliance guard behind account
// erasure.
//
// The schema has exactly one foreign key to the account (accounts_identities).
// Every other account-linked table carries the subject as a plain column, so a
// deletion that forgets one leaves rows behind with nothing in the database to
// say so. Rather than trust a hand-maintained list, this test asks
// information_schema for every table with a `subject` or `user_id` column and
// asserts each is empty for the erased account. A table added later is covered
// automatically; a step dropped from lifecycle.Deleter fails here.
func TestAccountDeletionLeavesNoOrphans(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	accounts := db.Accounts()
	user, ident, err := accounts.CreateWithIdentity(ctx, testIdentity(idp.GitHub, "erase-me"))
	if err != nil {
		t.Fatal(err)
	}
	subject := string(user.ID)

	if err := seedEveryAccountTable(t, db, subject, string(ident.ID)); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Non-vacuous: the tables must actually hold rows for this subject before the
	// erasure, or "zero after" would prove nothing.
	if before := subjectOrphans(t, db, subject); len(before) < 5 {
		t.Fatalf("seeding produced rows in only %d tables; the test would be vacuous: %v", len(before), before)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	oidcStore, err := db.OIDC(db.Clients(), OIDCOptions{
		Registry: oauth.DefaultRegistry(),
		Signer:   oidcstore.NewSigner("erase", key),
		Audit:    audit.NewMemoryLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}

	// The binding revoker is the federation service, as in the composition root.
	// Its registry is empty, so a seeded binding's source is unknown and the
	// revoke is the local half the erasure must not skip: shred the secret, then
	// delete the row. The vault service wraps the same repository the erasure
	// wipes, and the audit sink is required by both.
	wrapper, err := vault.NewLocalKeyWrapper("erase-kek", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	vaultService, err := vault.NewService(db.Vault(), wrapper, audit.NewMemoryLogger())
	if err != nil {
		t.Fatal(err)
	}
	sources, err := federation.NewRegistry()
	if err != nil {
		t.Fatal(err)
	}
	federationService, err := federation.NewService(federation.Config{
		Registry: sources,
		Bindings: db.Bindings(),
		Flows:    db.BindFlows(),
		Vault:    vaultService,
		Doer:     http.DefaultClient,
		BaseURL:  "http://re0auth.test",
	})
	if err != nil {
		t.Fatal(err)
	}

	deleter, err := lifecycle.New(lifecycle.Config{
		Accounts: accounts,
		// Tokens live in two engines here, as they do in a deployment migrated
		// from the retired hand-rolled engine: the OP owns the tokens it issued,
		// and the tables that engine left behind still hold rows. The composition
		// root revokes in both, so the test must too, or it would prove a
		// narrower erasure than the one that ships.
		Tokens:   oauth.TokenAdmins{oidcStore, db.Tokens()},
		Vault:    db.Vault(),
		Bindings: eraseBindings{fed: federationService},
		Sessions: db.Sessions(),
		OIDC:     oidcStore,
		Flows:    db.BindFlows(),
		Legacy:   db.Tokens(),
		Audit:    audit.NewMemoryLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := deleter.DeleteAccount(ctx, user.ID, user.ID); err != nil {
		t.Fatalf("DeleteAccount: %v", err)
	}

	if after := subjectOrphans(t, db, subject); len(after) > 0 {
		t.Errorf("these tables still hold rows for the erased account: %v", after)
	}

	// The account row itself is keyed by `id`, not `subject`, so the sweep above
	// cannot see it. Checked separately, because an erasure that cleared every
	// child row and left the account would pass the sweep and be wrong.
	var remaining int
	if err := db.pool.QueryRow(ctx, `SELECT count(*) FROM accounts_users WHERE id = $1`, subject).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 0 {
		t.Error("the account row survives the erasure")
	}
}

// eraseBindings adapts the federation service to the erasure's binding port,
// mirroring the composition root's adapter: the erasure reports only a count, so
// the operator plane's richer summary is trimmed here. Kept local to the test
// because it is the adapter, not the service, that the erasure depends on.
type eraseBindings struct{ fed federation.Service }

func (e eraseBindings) RevokeUserBindings(ctx context.Context, user account.UserID) (lifecycle.BindingOutcome, error) {
	summary, err := e.fed.RevokeUserBindings(ctx, user)
	return lifecycle.BindingOutcome{
		Total:   summary.Total,
		Revoked: summary.Revoked,
		Failed:  summary.Failed,
	}, err
}

// seedEveryAccountTable writes one row per account-linked table, so the orphan
// check has something to find. It uses the stores where they exist and direct
// SQL where a table has no writer left (the retired engine's).
func seedEveryAccountTable(t *testing.T, db *DB, subject, identityID string) error {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()

	// The vault: a credential for this subject, which is also what the erasure
	// crypto-shreds.
	if err := db.Vault().Put(ctx, vault.Record{
		Identity:   vault.Identity{Subject: subject, Provider: "phigros.fake"},
		Version:    1,
		WrappedDEK: []byte("wrapped"),
		KEKID:      "kek-1",
		Nonce:      []byte("nonce"),
		Ciphertext: []byte("ct"),
		Meta:       map[string]string{"openid": "o"},
		CreatedAt:  now,
		UpdatedAt:  now,
	}); err != nil {
		return fmt.Errorf("vault: %w", err)
	}

	// The federation binding and a pending flow.
	if err := db.Bindings().Put(ctx, federation.Binding{
		User: account.UserID(subject), Game: "phigros", Source: "fake",
		TokenType: "Bearer", Expiry: now.Add(time.Hour), HasRefresh: true,
	}); err != nil {
		return fmt.Errorf("binding: %w", err)
	}
	if err := db.BindFlows().Put(ctx, federation.BindFlow{
		State: "st-1", ID: "bf-1", User: account.UserID(subject),
		Game: "phigros", Source: "fake", Verifier: "v", ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		return fmt.Errorf("bind flow: %w", err)
	}

	// A session and its subject index. Both go through the store so the token
	// hash the index records is the one the session row carries.
	if err := db.Sessions().Commit("sid", []byte("data"), now.Add(time.Hour)); err != nil {
		return fmt.Errorf("session: %w", err)
	}
	if err := db.Sessions().Remember(ctx, "sid", subject); err != nil {
		return fmt.Errorf("session index: %w", err)
	}

	// Tokens, OP state, and the retired engine's tables.
	statements := []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO oidc_access_tokens (id_hash, client_id, subject, scopes, expires_at) VALUES ($1,$2,$3,$4,$5)`,
			[]any{"ah", "cli", subject, []string{"account.id"}, now.Add(time.Hour)}},
		{`INSERT INTO oidc_refresh_tokens (token_hash, id_hash, client_id, subject, scopes, expires_at) VALUES ($1,$2,$3,$4,$5,$6)`,
			[]any{"rh", "ah", "cli", subject, []string{"account.id"}, now.Add(time.Hour)}},
		{`INSERT INTO oidc_auth_requests (id, client_id, redirect_uri, response_type, subject, created_at, expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
			[]any{"ar-1", "cli", "https://app.example/cb", "code", subject, now, now.Add(time.Hour)}},
		{`INSERT INTO oidc_codes (code_hash, request_id, expires_at) VALUES ($1,$2,$3)`,
			[]any{"code-h", "ar-1", now.Add(time.Hour)}},
		{`INSERT INTO oidc_devices (device_code_hash, user_code, client_id, subject, expires_at) VALUES ($1,$2,$3,$4,$5)`,
			[]any{"dev-h", "ABCD", "cli", subject, now.Add(time.Hour)}},
		{`INSERT INTO oauth_codes (token_hash, client_id, subject, redirect_uri, code_challenge, code_challenge_method, expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
			[]any{"lo-h", "cli", subject, "https://app.example/cb", "ch", "S256", now.Add(time.Hour)}},
		{`INSERT INTO oauth_access_tokens (token_hash, client_id, subject, issued_at, expires_at) VALUES ($1,$2,$3,$4,$5)`,
			[]any{"la-h", "cli", subject, now, now.Add(time.Hour)}},
		{`INSERT INTO oauth_refresh_tokens (token_hash, client_id, subject, issued_at, expires_at) VALUES ($1,$2,$3,$4,$5)`,
			[]any{"lr-h", "cli", subject, now, now.Add(time.Hour)}},
		{`INSERT INTO oauth_device_authorizations (device_code_hash, user_code, client_id, status, subject, expires_at) VALUES ($1,$2,$3,$4,$5,$6)`,
			[]any{"ld-h", "WXYZ", "cli", "approved", subject, now.Add(time.Hour)}},
	}
	for _, s := range statements {
		if _, err := db.pool.Exec(ctx, s.sql, s.args...); err != nil {
			return fmt.Errorf("%s: %w", s.sql, err)
		}
	}
	_ = identityID // the identity itself is created by CreateWithIdentity
	return nil
}

// subjectOrphans returns the account-linked tables that still hold rows for
// subject. The set of tables comes from information_schema, so this cannot drift
// from the schema.
func subjectOrphans(t *testing.T, db *DB, subject string) []string {
	t.Helper()
	ctx := context.Background()

	rows, err := db.pool.Query(ctx, `
		SELECT table_name, column_name FROM information_schema.columns
		 WHERE table_schema = 'public' AND column_name IN ('subject', 'user_id')
		 ORDER BY table_name`)
	if err != nil {
		t.Fatalf("read columns: %v", err)
	}
	type col struct{ table, column string }
	var cols []col
	for rows.Next() {
		var c col
		if err := rows.Scan(&c.table, &c.column); err != nil {
			t.Fatal(err)
		}
		cols = append(cols, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(cols) < 10 {
		t.Fatalf("information_schema returned only %d subject columns; the sweep is broken", len(cols))
	}

	var leftovers []string
	for _, c := range cols {
		if _, skip := accountTablesIgnored[c.table]; skip {
			continue
		}
		var n int
		// Table and column names come from information_schema, never from input.
		q := fmt.Sprintf(`SELECT count(*) FROM %s WHERE %s = $1`, c.table, c.column)
		if err := db.pool.QueryRow(ctx, q, subject).Scan(&n); err != nil {
			t.Fatalf("count %s.%s: %v", c.table, c.column, err)
		}
		if n > 0 {
			leftovers = append(leftovers, fmt.Sprintf("%s.%s=%d", c.table, c.column, n))
		}
	}
	return leftovers
}
