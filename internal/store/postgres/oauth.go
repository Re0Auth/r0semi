package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Re0Auth/r0semi/oauth"
)

// Tokens implements oauth.Store on Postgres.
//
// Every row is keyed by oauth.TokenHash(value): the opaque code or token is used
// only to compute the key and is never written. Single-use operations are a
// one-statement DELETE ... RETURNING, so two concurrent callers cannot both win.
type Tokens struct{ pool *pgxpool.Pool }

// SaveCode implements oauth.Store.
func (s *Tokens) SaveCode(ctx context.Context, value string, c oauth.AuthorizationCode) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO oauth_codes
			(token_hash, client_id, subject, scopes, redirect_uri, code_challenge, code_challenge_method, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		oauth.TokenHash(value), c.ClientID, c.Subject, scopeArray(c.Scopes),
		c.RedirectURI, c.CodeChallenge, c.CodeChallengeMethod, c.ExpiresAt)
	return err
}

// ConsumeCode implements oauth.Store. Expiry is checked by the service, so an
// expired code is still returned (once) rather than swallowed.
func (s *Tokens) ConsumeCode(ctx context.Context, value string) (oauth.AuthorizationCode, error) {
	row := s.pool.QueryRow(ctx, `
		DELETE FROM oauth_codes
		 WHERE token_hash = $1
		RETURNING client_id, subject, scopes, redirect_uri, code_challenge, code_challenge_method, expires_at`,
		oauth.TokenHash(value))

	var (
		c      oauth.AuthorizationCode
		scopes []string
	)
	err := row.Scan(&c.ClientID, &c.Subject, &scopes, &c.RedirectURI,
		&c.CodeChallenge, &c.CodeChallengeMethod, &c.ExpiresAt)
	if noRows(err) {
		return oauth.AuthorizationCode{}, oauth.ErrTokenNotFound
	}
	if err != nil {
		return oauth.AuthorizationCode{}, err
	}
	c.Scopes = scopesFrom(scopes)
	return c, nil
}

// SaveAccess implements oauth.Store.
func (s *Tokens) SaveAccess(ctx context.Context, value string, t oauth.AccessToken) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO oauth_access_tokens (token_hash, client_id, subject, scopes, issued_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		oauth.TokenHash(value), t.ClientID, t.Subject, scopeArray(t.Scopes), t.IssuedAt, t.ExpiresAt)
	return err
}

// GetAccess implements oauth.Store.
func (s *Tokens) GetAccess(ctx context.Context, value string) (oauth.AccessToken, error) {
	var (
		t      oauth.AccessToken
		scopes []string
	)
	err := s.pool.QueryRow(ctx, `
		SELECT client_id, subject, scopes, issued_at, expires_at
		  FROM oauth_access_tokens WHERE token_hash = $1`, oauth.TokenHash(value)).
		Scan(&t.ClientID, &t.Subject, &scopes, &t.IssuedAt, &t.ExpiresAt)
	if noRows(err) {
		return oauth.AccessToken{}, oauth.ErrTokenNotFound
	}
	if err != nil {
		return oauth.AccessToken{}, err
	}
	t.Scopes = scopesFrom(scopes)
	return t, nil
}

// DeleteAccess implements oauth.Store. Deleting an absent token is not an error,
// which keeps RFC 7009 revocation idempotent.
func (s *Tokens) DeleteAccess(ctx context.Context, value string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM oauth_access_tokens WHERE token_hash = $1`, oauth.TokenHash(value))
	return err
}

// SaveRefresh implements oauth.Store.
func (s *Tokens) SaveRefresh(ctx context.Context, value string, t oauth.RefreshToken) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO oauth_refresh_tokens (token_hash, client_id, subject, scopes, issued_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		oauth.TokenHash(value), t.ClientID, t.Subject, scopeArray(t.Scopes), t.IssuedAt, t.ExpiresAt)
	return err
}

// ConsumeRefresh implements oauth.Store. Rotation makes the token single-use.
func (s *Tokens) ConsumeRefresh(ctx context.Context, value string) (oauth.RefreshToken, error) {
	var (
		t      oauth.RefreshToken
		scopes []string
	)
	err := s.pool.QueryRow(ctx, `
		DELETE FROM oauth_refresh_tokens
		 WHERE token_hash = $1
		RETURNING client_id, subject, scopes, issued_at, expires_at`, oauth.TokenHash(value)).
		Scan(&t.ClientID, &t.Subject, &scopes, &t.IssuedAt, &t.ExpiresAt)
	if noRows(err) {
		return oauth.RefreshToken{}, oauth.ErrTokenNotFound
	}
	if err != nil {
		return oauth.RefreshToken{}, err
	}
	t.Scopes = scopesFrom(scopes)
	return t, nil
}

// DeleteRefresh implements oauth.Store.
func (s *Tokens) DeleteRefresh(ctx context.Context, value string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM oauth_refresh_tokens WHERE token_hash = $1`, oauth.TokenHash(value))
	return err
}

// ListBySubject implements oauth.Store.
//
// Expired rows are returned as well: the service owns the clock, and filtering
// here would put "is this still live" in two places, which is how the two
// answers eventually differ.
func (s *Tokens) ListBySubject(ctx context.Context, subject string) ([]oauth.GrantRecord, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT client_id, scopes, issued_at, expires_at, is_refresh FROM (
			SELECT client_id, scopes, issued_at, expires_at, false AS is_refresh
			  FROM oauth_access_tokens WHERE subject = $1
			UNION ALL
			SELECT client_id, scopes, issued_at, expires_at, true AS is_refresh
			  FROM oauth_refresh_tokens WHERE subject = $1
		) AS tokens`, subject)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []oauth.GrantRecord
	for rows.Next() {
		var (
			r         oauth.GrantRecord
			scopes    []string
			isRefresh bool
		)
		if err := rows.Scan(&r.ClientID, &scopes, &r.IssuedAt, &r.ExpiresAt, &isRefresh); err != nil {
			return nil, err
		}
		r.Scopes = scopesFrom(scopes)
		r.Kind = oauth.TokenKindAccess
		if isRefresh {
			r.Kind = oauth.TokenKindRefresh
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// DeleteBySubjectClient implements oauth.Store.
//
// Both statements run even if the first removes nothing, and neither asks how
// many rows went away: revoking is idempotent, so the count is not information
// anyone acts on.
func (s *Tokens) DeleteBySubjectClient(ctx context.Context, subject, clientID string) error {
	if _, err := s.pool.Exec(ctx,
		`DELETE FROM oauth_access_tokens WHERE subject = $1 AND client_id = $2`, subject, clientID); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx,
		`DELETE FROM oauth_refresh_tokens WHERE subject = $1 AND client_id = $2`, subject, clientID)
	return err
}

// TokenOwner implements oauth.Store: which client a presented value belongs to,
// for the ownership check RFC 7009 §2.1 requires of revocation. A read, not a
// consume — revocation must be able to ask without spending the token.
func (s *Tokens) TokenOwner(ctx context.Context, value string) (string, error) {
	hash := oauth.TokenHash(value)
	var clientID string
	err := s.pool.QueryRow(ctx,
		`SELECT client_id FROM oauth_access_tokens WHERE token_hash = $1`, hash).Scan(&clientID)
	if err == nil {
		return clientID, nil
	}
	if !noRows(err) {
		return "", err
	}
	err = s.pool.QueryRow(ctx,
		`SELECT client_id FROM oauth_refresh_tokens WHERE token_hash = $1`, hash).Scan(&clientID)
	if noRows(err) {
		return "", oauth.ErrTokenNotFound
	}
	if err != nil {
		return "", err
	}
	return clientID, nil
}

// RevokeTokens implements oauth.TokenAdmin on the hand-rolled engine's tables.
// In durable deployments the OpenID Provider owns the tokens; this covers the
// in-memory engine's Postgres store, which shares the same seam.
//
// Authorization codes are removed with the tokens: a code that was never
// redeemed is a redeemable capability, and leaving it behind after a Kill Switch
// would let it mint fresh tokens.
func (s *Tokens) RevokeTokens(ctx context.Context, f oauth.TokenFilter) (int, error) {
	total, err := revokeMatching(ctx, s.pool, []string{"oauth_access_tokens", "oauth_refresh_tokens"}, f)
	if err != nil {
		return total, err
	}
	if _, err := s.pool.Exec(ctx,
		`DELETE FROM oauth_codes WHERE ($1 = '' OR client_id = $1) AND ($2 = '' OR subject = $2)`,
		f.ClientID, f.Subject); err != nil {
		return total, err
	}
	return total, nil
}

// PurgeLegacySubject removes a subject's non-token rows from the retired engine's
// tables: its authorization codes and device authorizations.
//
// This exists for deployments that were migrated from the hand-rolled engine,
// where those tables may still hold rows for a live account. The current binary
// never writes them, so for a fresh deployment this deletes nothing — but an
// erasure that skipped them would silently leave a migrated account's data
// behind, which is the failure this whole path exists to prevent.
//
// The legacy token tables (oauth_access_tokens, oauth_refresh_tokens) are NOT
// touched here; they are covered by RevokeTokens, which the same erasure calls.
func (s *Tokens) PurgeLegacySubject(ctx context.Context, subject string) (int, error) {
	if subject == "" {
		return 0, errors.New("postgres: subject is required")
	}
	total := 0
	for _, q := range []string{
		`DELETE FROM oauth_codes WHERE subject = $1`,
		`DELETE FROM oauth_device_authorizations WHERE subject = $1`,
	} {
		tag, err := s.pool.Exec(ctx, q, subject)
		if err != nil {
			return total, err
		}
		total += int(tag.RowsAffected())
	}
	return total, nil
}

// revokeMatching deletes rows selected by the filter from two token tables and
// returns the total. Empty filter fields match everything, so the same statement
// serves "all", "this client" and "this subject".
//
// Table names are compile-time constants, never request input, so building the
// statement with Sprintf does not put anything user-controlled into the SQL.
func revokeMatching(ctx context.Context, pool *pgxpool.Pool, tables []string, f oauth.TokenFilter) (int, error) {
	total := 0
	for _, table := range tables {
		tag, err := pool.Exec(ctx, fmt.Sprintf(
			`DELETE FROM %s WHERE ($1 = '' OR client_id = $1) AND ($2 = '' OR subject = $2)`,
			table), f.ClientID, f.Subject)
		if err != nil {
			return total, err
		}
		total += int(tag.RowsAffected())
	}
	return total, nil
}

// Devices implements oauth.DeviceStore on Postgres. The device code is hashed;
// the user code is stored canonically and looked up case- and
// separator-insensitively through an expression index.
type Devices struct{ pool *pgxpool.Pool }

const deviceCols = `device_code_hash, user_code, client_id, scopes, status, subject, explicit_scopes, expires_at, last_poll`

// SaveDevice implements oauth.DeviceStore.
func (s *Devices) SaveDevice(ctx context.Context, deviceCode string, d oauth.DeviceAuthorizationRecord) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO oauth_device_authorizations (`+deviceCols+`)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		oauth.TokenHash(deviceCode), d.UserCode, d.ClientID, scopeArray(d.Scopes),
		string(d.Status), d.Subject, scopeArray(d.Explicit), d.ExpiresAt, nullTime(d.LastPoll))
	return err
}

// GetDevice implements oauth.DeviceStore.
func (s *Devices) GetDevice(ctx context.Context, deviceCode string) (oauth.DeviceAuthorizationRecord, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+deviceCols+` FROM oauth_device_authorizations WHERE device_code_hash = $1`,
		oauth.TokenHash(deviceCode))
	return scanDevice(row)
}

// GetDeviceByUserCode implements oauth.DeviceStore.
func (s *Devices) GetDeviceByUserCode(ctx context.Context, userCode string) (oauth.DeviceAuthorizationRecord, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+deviceCols+` FROM oauth_device_authorizations
		  WHERE upper(replace(user_code, '-', '')) = $1`,
		oauth.NormalizeUserCode(userCode))
	return scanDevice(row)
}

// UpdateDevice implements oauth.DeviceStore. The record carries its own
// DeviceCodeHash, which is the update key.
func (s *Devices) UpdateDevice(ctx context.Context, d oauth.DeviceAuthorizationRecord) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE oauth_device_authorizations
		   SET user_code = $2, client_id = $3, scopes = $4, status = $5,
		       subject = $6, explicit_scopes = $7, expires_at = $8, last_poll = $9
		 WHERE device_code_hash = $1`,
		d.DeviceCodeHash, d.UserCode, d.ClientID, scopeArray(d.Scopes), string(d.Status),
		d.Subject, scopeArray(d.Explicit), d.ExpiresAt, nullTime(d.LastPoll))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return oauth.ErrDeviceNotFound
	}
	return nil
}

func scanDevice(row pgx.Row) (oauth.DeviceAuthorizationRecord, error) {
	var (
		d       oauth.DeviceAuthorizationRecord
		scopes  []string
		expl    []string
		status  string
		lastPol *time.Time
	)
	err := row.Scan(&d.DeviceCodeHash, &d.UserCode, &d.ClientID, &scopes, &status,
		&d.Subject, &expl, &d.ExpiresAt, &lastPol)
	if noRows(err) {
		return oauth.DeviceAuthorizationRecord{}, oauth.ErrDeviceNotFound
	}
	if err != nil {
		return oauth.DeviceAuthorizationRecord{}, err
	}
	d.Scopes = scopesFrom(scopes)
	d.Explicit = scopesFrom(expl)
	d.Status = oauth.DeviceStatus(status)
	if lastPol != nil {
		d.LastPoll = *lastPol
	}
	return d, nil
}

// Clients implements oauth.ClientRegistry on Postgres. Only the secret digest is
// stored; the plaintext never reaches the database.
type Clients struct{ pool *pgxpool.Pool }

// Create implements oauth.ClientRegistry.
func (s *Clients) Create(ctx context.Context, c oauth.Client) error {
	status := c.Status
	if status == "" {
		status = oauth.ClientActive
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO oauth_clients (id, name, type, status, secret_hash, redirect_uris, allowed_scopes, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		c.ID, c.Name, string(c.Type), string(status), nullableBytes(c.SecretHash()),
		c.RedirectURIs, scopeArray(c.AllowedScopes), c.CreatedAt)
	return err
}

// Get implements oauth.ClientRegistry. A suspended client is reported as not
// found: the protocol plane must treat it as a client id that never existed,
// not as one that is merely forbidden.
func (s *Clients) Get(ctx context.Context, id string) (oauth.Client, error) {
	return scanClient(s.pool.QueryRow(ctx, `
		SELECT id, name, type, status, secret_hash, redirect_uris, allowed_scopes, created_at
		  FROM oauth_clients WHERE id = $1 AND status <> 'suspended'`, id))
}

// List implements oauth.ClientAdmin. Suspended clients are included, because the
// admin view is exactly the place they must remain visible.
func (s *Clients) List(ctx context.Context) ([]oauth.Client, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, name, type, status, secret_hash, redirect_uris, allowed_scopes, created_at
		  FROM oauth_clients ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []oauth.Client
	for rows.Next() {
		c, err := scanClient(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// SetStatus implements oauth.ClientAdmin.
func (s *Clients) SetStatus(ctx context.Context, id string, status oauth.ClientStatus) error {
	if status != oauth.ClientActive && status != oauth.ClientSuspended {
		return fmt.Errorf("postgres: invalid client status %q", status)
	}
	tag, err := s.pool.Exec(ctx, `UPDATE oauth_clients SET status = $2 WHERE id = $1`, id, string(status))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return oauth.ErrClientNotFound
	}
	return nil
}

// Delete implements oauth.ClientAdmin. An absent row is success, so an operator
// retrying a revocation is not told it failed at the last step.
func (s *Clients) Delete(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM oauth_clients WHERE id = $1`, id)
	return err
}

// RotateSecret implements oauth.ClientAdmin. Only a confidential client has a
// secret to rotate; a public client is refused with ErrNoSecretToRotate rather than
// given a secret it would then fail to restore, because RestoreClient rejects a
// public client that carries a secret hash.
func (s *Clients) RotateSecret(ctx context.Context, id string, secretHash []byte) error {
	if len(secretHash) == 0 {
		return errors.New("postgres: a rotation needs a secret hash")
	}
	tag, err := s.pool.Exec(ctx,
		`UPDATE oauth_clients SET secret_hash = $2 WHERE id = $1 AND type = 'confidential'`,
		id, secretHash)
	if err != nil {
		return err
	}
	if tag.RowsAffected() > 0 {
		return nil
	}
	// No confidential row matched: distinguish "unknown" from "public".
	var typ string
	if err := s.pool.QueryRow(ctx, `SELECT type FROM oauth_clients WHERE id = $1`, id).Scan(&typ); err != nil {
		if noRows(err) {
			return oauth.ErrClientNotFound
		}
		return err
	}
	return oauth.ErrNoSecretToRotate
}

// scanClient reads one client row in the column order used above.
func scanClient(row pgx.Row) (oauth.Client, error) {
	var (
		id         string
		name       string
		typ        string
		status     string
		secretHash []byte
		redirects  []string
		allowed    []string
		createdAt  time.Time
	)
	err := row.Scan(&id, &name, &typ, &status, &secretHash, &redirects, &allowed, &createdAt)
	if noRows(err) {
		return oauth.Client{}, oauth.ErrClientNotFound
	}
	if err != nil {
		return oauth.Client{}, err
	}
	return oauth.RestoreClientWithStatus(id, name, oauth.ClientType(typ), oauth.ClientStatus(status),
		secretHash, redirects, scopesFrom(allowed), createdAt)
}

func scopeArray(scopes []oauth.Scope) []string {
	out := make([]string, len(scopes))
	for i, s := range scopes {
		out[i] = s.String()
	}
	return out
}

func scopesFrom(in []string) []oauth.Scope {
	out := make([]oauth.Scope, len(in))
	for i, s := range in {
		out[i] = oauth.Scope(s)
	}
	return out
}

func nullTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// nullableBytes maps an empty digest to SQL NULL, which is how a public client
// (no secret) is stored.
func nullableBytes(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return b
}
