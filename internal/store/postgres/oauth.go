package postgres

import (
	"context"
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
	_, err := s.pool.Exec(ctx, `
		INSERT INTO oauth_clients (id, name, type, secret_hash, redirect_uris, allowed_scopes, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		c.ID, c.Name, string(c.Type), nullableBytes(c.SecretHash()),
		c.RedirectURIs, scopeArray(c.AllowedScopes), c.CreatedAt)
	return err
}

// Get implements oauth.ClientRegistry.
func (s *Clients) Get(ctx context.Context, id string) (oauth.Client, error) {
	var (
		name       string
		typ        string
		secretHash []byte
		redirects  []string
		allowed    []string
		createdAt  time.Time
	)
	err := s.pool.QueryRow(ctx, `
		SELECT name, type, secret_hash, redirect_uris, allowed_scopes, created_at
		  FROM oauth_clients WHERE id = $1`, id).
		Scan(&name, &typ, &secretHash, &redirects, &allowed, &createdAt)
	if noRows(err) {
		return oauth.Client{}, oauth.ErrClientNotFound
	}
	if err != nil {
		return oauth.Client{}, err
	}
	return oauth.RestoreClient(id, name, oauth.ClientType(typ), secretHash, redirects, scopesFrom(allowed), createdAt)
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
