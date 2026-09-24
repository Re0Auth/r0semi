package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/internal/oidcstore"
	"github.com/Re0Auth/r0semi/oauth"
)

// OIDCStore is the production op.Storage + op.DeviceAuthorizationStorage for the
// OpenID Provider (ADR-0001). It is the durable half of the engine: the
// in-memory half lives in internal/store/memory, and both share oidcstore for
// the signing key, the client adapter and the consent policy.
//
// It owns the *policy* the OP cannot: which scopes exist (via the oauth.Registry
// in the client adapter), and an audit trail for every token it issues or
// revokes.
type OIDCStore struct {
	pool     *pgxpool.Pool
	clients  oauth.ClientRegistry
	registry *oauth.Registry
	login    func(ctx context.Context, authRequestID string) string
	signer   *oidcstore.Signer
	audit    audit.Logger

	accessTTL  time.Duration
	refreshTTL time.Duration
	requestTTL time.Duration
}

// OIDCOptions configures an OIDCStore.
type OIDCOptions struct {
	// Registry resolves scopes; it is what makes IsScopeAllowed real.
	Registry *oauth.Registry
	// Login builds the consent URL the authorize endpoint redirects to. It
	// receives the request context, which is how the composition root binds the
	// auth request to the browser session before the consent screen loads it.
	Login func(ctx context.Context, authRequestID string) string
	// Signer signs id_tokens. Required.
	Signer *oidcstore.Signer
	// Audit records token issuance and revocation. Optional.
	Audit audit.Logger
	// RequestTTL is how long a pending consent handle stays valid. It must
	// outlive the federation bind flow, which sends the user to the source and
	// back. Defaults to 30 minutes.
	RequestTTL time.Duration
}

// NewOIDCStore builds the store on an existing pool.
func NewOIDCStore(pool *pgxpool.Pool, clients oauth.ClientRegistry, opts OIDCOptions) (*OIDCStore, error) {
	switch {
	case pool == nil:
		return nil, errors.New("postgres: OIDCStore: pool is required")
	case clients == nil:
		return nil, errors.New("postgres: OIDCStore: client registry is required")
	case opts.Registry == nil:
		return nil, errors.New("postgres: OIDCStore: scope registry is required")
	case opts.Signer == nil:
		return nil, errors.New("postgres: OIDCStore: signer is required")
	}
	return &OIDCStore{
		pool:       pool,
		clients:    clients,
		registry:   opts.Registry,
		login:      opts.Login,
		signer:     opts.Signer,
		audit:      opts.Audit,
		accessTTL:  time.Hour,
		refreshTTL: 30 * 24 * time.Hour,
		requestTTL: requestTTL(opts.RequestTTL),
	}, nil
}

func requestTTL(configured time.Duration) time.Duration {
	if configured > 0 {
		return configured
	}
	return 30 * time.Minute
}

// OIDC returns the OpenID Provider storage on the migrated database.
func (db *DB) OIDC(clients oauth.ClientRegistry, opts OIDCOptions) (*OIDCStore, error) {
	return NewOIDCStore(db.pool, clients, opts)
}

func hashValue(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])
}

func clientIDOf(request op.TokenRequest) string { return oidcstore.ClientIDOf(request) }

func (s *OIDCStore) record(ctx context.Context, action, subject, clientID, outcome string) {
	if s.audit == nil {
		return
	}
	_ = s.audit.Record(ctx, audit.Event{
		Action: action, Subject: subject, Provider: "oidc", Outcome: outcome,
		Detail: map[string]string{"client_id": clientID},
	})
}

// --- op.AuthStorage ---

// CreateAuthRequest implements op.Storage.
func (s *OIDCStore) CreateAuthRequest(ctx context.Context, req *oidc.AuthRequest, userID string) (op.AuthRequest, error) {
	id, err := oidcstore.RandomValue()
	if err != nil {
		return nil, err
	}
	challenge := ""
	method := ""
	if req.CodeChallenge != "" {
		challenge = req.CodeChallenge
		method = string(req.CodeChallengeMethod)
	}
	now := time.Now().UTC()
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO oidc_auth_requests
			(id, client_id, redirect_uri, response_type, response_mode, scopes, state, nonce,
			 code_challenge, code_challenge_method, subject, done, created_at, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,false,$12,$13)`,
		id, req.ClientID, req.RedirectURI, string(req.ResponseType), string(req.ResponseMode),
		oidcstore.NonNil([]string(req.Scopes)), req.State, req.Nonce, challenge, method, userID, now, now.Add(s.requestTTL),
	); err != nil {
		return nil, fmt.Errorf("postgres: create auth request: %w", err)
	}
	return &oidcstore.AuthRequest{
		ID: id, ClientID: req.ClientID, RedirectURI: req.RedirectURI,
		ResponseType: req.ResponseType, ResponseMode: req.ResponseMode,
		Scopes: append([]string(nil), req.Scopes...), State: req.State, Nonce: req.Nonce,
		CodeChallenge: codeChallenge(req.CodeChallenge, method),
		Subject:       userID,
	}, nil
}

func codeChallenge(challenge, method string) *oidc.CodeChallenge {
	if challenge == "" {
		return nil
	}
	return &oidc.CodeChallenge{Challenge: challenge, Method: oidc.CodeChallengeMethod(method)}
}

// AuthRequestByID implements op.Storage.
func (s *OIDCStore) AuthRequestByID(ctx context.Context, id string) (op.AuthRequest, error) {
	return s.scanAuthRequest(ctx, `
		SELECT id, client_id, redirect_uri, response_type, response_mode, scopes, state, nonce,
		       code_challenge, code_challenge_method, subject, done, auth_time
		  FROM oidc_auth_requests WHERE id = $1`, id)
}

// AuthRequestByCode implements op.Storage.
func (s *OIDCStore) AuthRequestByCode(ctx context.Context, code string) (op.AuthRequest, error) {
	var requestID string
	if err := s.pool.QueryRow(ctx,
		`SELECT request_id FROM oidc_codes WHERE code_hash = $1`, hashValue(code)).Scan(&requestID); err != nil {
		return nil, errors.New("postgres: authorization code is unknown or expired")
	}
	return s.AuthRequestByID(ctx, requestID)
}

func (s *OIDCStore) scanAuthRequest(ctx context.Context, query string, args ...any) (op.AuthRequest, error) {
	var (
		a         oidcstore.AuthRequest
		challenge string
		method    string
		authTime  *time.Time
	)
	if err := s.pool.QueryRow(ctx, query, args...).Scan(
		&a.ID, &a.ClientID, &a.RedirectURI, &a.ResponseType, &a.ResponseMode, &a.Scopes,
		&a.State, &a.Nonce, &challenge, &method, &a.Subject, &a.IsDone, &authTime,
	); err != nil {
		return nil, fmt.Errorf("postgres: auth request: %w", err)
	}
	a.CodeChallenge = codeChallenge(challenge, method)
	a.AuthTime = authTime
	return &a, nil
}

// SaveAuthCode implements op.Storage.
func (s *OIDCStore) SaveAuthCode(ctx context.Context, id, code string) error {
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO oidc_codes (code_hash, request_id, expires_at) VALUES ($1,$2,$3)
		ON CONFLICT (code_hash) DO UPDATE SET request_id = EXCLUDED.request_id`,
		hashValue(code), id, time.Now().UTC().Add(s.requestTTL)); err != nil {
		return fmt.Errorf("postgres: save auth code: %w", err)
	}
	return nil
}

// DeleteAuthRequest implements op.Storage.
func (s *OIDCStore) DeleteAuthRequest(ctx context.Context, id string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `DELETE FROM oidc_codes WHERE request_id = $1`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM oidc_auth_requests WHERE id = $1`, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// CreateAccessToken implements op.Storage. The token ID is ours; only its hash
// is persisted, and the library encrypts the ID into the bearer token.
func (s *OIDCStore) CreateAccessToken(ctx context.Context, request op.TokenRequest) (string, time.Time, error) {
	id, err := oidcstore.RandomValue()
	if err != nil {
		return "", time.Time{}, err
	}
	expires := time.Now().UTC().Add(s.accessTTL)
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO oidc_access_tokens (id_hash, client_id, subject, scopes, expires_at)
		VALUES ($1,$2,$3,$4,$5)`,
		hashValue(id), clientIDOf(request), request.GetSubject(), oidcstore.NonNil(oidcstore.WithoutOfflineAccess(request.GetScopes())), expires); err != nil {
		return "", time.Time{}, fmt.Errorf("postgres: create access token: %w", err)
	}
	s.record(ctx, "oidc.token", request.GetSubject(), clientIDOf(request), audit.OutcomeOK)
	return id, expires, nil
}

// ErrRefreshTokenSpent reports a refresh token presented after it had already
// been rotated. It is a refusal, not a lookup miss: the caller asked to spend a
// token this store has already consumed, which is what a replayed (or stolen)
// refresh token looks like. Returning an error rather than minting a second
// generation is the only thing that makes reuse visible.
var ErrRefreshTokenSpent = errors.New("postgres: refresh token was already rotated")

// CreateAccessAndRefreshTokens implements op.Storage. Refresh tokens rotate:
// presenting one consumes it and issues a new one.
//
// Rotation is one transaction, and the presented token is claimed by a DELETE
// whose row count is checked. Rotating as "read it now, delete it later" leaves a
// window in which two requests holding the same refresh token are both honoured —
// and the window is invisible to the race detector, because the two statements
// never contend on a lock. The consequence is worse than one extra token:
// rotation never notices the reuse, so a stolen refresh token can be replayed
// indefinitely alongside the victim's own client, and nothing signals that it
// happened.
func (s *OIDCStore) CreateAccessAndRefreshTokens(ctx context.Context, request op.TokenRequest, currentRefreshToken string) (string, string, time.Time, error) {
	accessID, err := oidcstore.RandomValue()
	if err != nil {
		return "", "", time.Time{}, err
	}
	value, err := oidcstore.RandomValue()
	if err != nil {
		return "", "", time.Time{}, err
	}

	var authTime *time.Time
	if r, ok := request.(interface{ GetAuthTime() time.Time }); ok {
		if t := r.GetAuthTime(); !t.IsZero() {
			authTime = &t
		}
	}
	var amr, audience []string
	if r, ok := request.(interface{ GetAMR() []string }); ok {
		amr = r.GetAMR()
	}
	if r, ok := request.(interface{ GetAudience() []string }); ok {
		audience = r.GetAudience()
	}
	scopes := oidcstore.NonNil(oidcstore.WithoutOfflineAccess(request.GetScopes()))
	amr = oidcstore.NonNil(amr)
	audience = oidcstore.NonNil(audience)

	now := time.Now().UTC()
	expires := now.Add(s.accessTTL)

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", "", time.Time{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Claim the presented token first. Under READ COMMITTED a concurrent DELETE of
	// the same row blocks, then finds nothing once the winner commits — so exactly
	// one of two racing requests sees a row to consume.
	if currentRefreshToken != "" {
		tag, err := tx.Exec(ctx,
			`DELETE FROM oidc_refresh_tokens WHERE token_hash = $1`, hashValue(currentRefreshToken))
		if err != nil {
			return "", "", time.Time{}, fmt.Errorf("postgres: rotate refresh token: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return "", "", time.Time{}, ErrRefreshTokenSpent
		}
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO oidc_access_tokens (id_hash, client_id, subject, scopes, expires_at)
		VALUES ($1,$2,$3,$4,$5)`,
		hashValue(accessID), clientIDOf(request), request.GetSubject(), scopes, expires); err != nil {
		return "", "", time.Time{}, fmt.Errorf("postgres: create access token: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO oidc_refresh_tokens
			(token_hash, id_hash, client_id, subject, scopes, amr, audience, auth_time, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		hashValue(value), hashValue(accessID), clientIDOf(request), request.GetSubject(),
		scopes, amr, audience, authTime, now.Add(s.refreshTTL),
	); err != nil {
		return "", "", time.Time{}, fmt.Errorf("postgres: create refresh token: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return "", "", time.Time{}, err
	}
	s.record(ctx, "oidc.token", request.GetSubject(), clientIDOf(request), audit.OutcomeOK)
	return accessID, value, expires, nil
}

// TokenRequestByRefreshToken implements op.Storage.
func (s *OIDCStore) TokenRequestByRefreshToken(ctx context.Context, value string) (op.RefreshTokenRequest, error) {
	var (
		r        oidcstore.RefreshRequest
		authTime *time.Time
	)
	if err := s.pool.QueryRow(ctx, `
		SELECT id_hash, client_id, subject, scopes, amr, audience, auth_time
		  FROM oidc_refresh_tokens WHERE token_hash = $1`, hashValue(value)).Scan(
		&r.IDHash, &r.ClientID, &r.Subject, &r.Scopes, &r.AMR, &r.Audience, &authTime,
	); err != nil {
		return nil, errors.New("postgres: invalid refresh token")
	}
	r.AuthTime = authTime
	return &r, nil
}

// TerminateSession implements op.Storage.
func (s *OIDCStore) TerminateSession(ctx context.Context, userID, clientID string) error {
	if _, err := s.pool.Exec(ctx,
		`DELETE FROM oidc_access_tokens WHERE subject = $1 AND client_id = $2`, userID, clientID); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx,
		`DELETE FROM oidc_refresh_tokens WHERE subject = $1 AND client_id = $2`, userID, clientID)
	return err
}

// RevokeToken implements op.Storage. Access tokens arrive as the plaintext ID,
// refresh tokens as the plaintext value; both are hashed before lookup.
func (s *OIDCStore) RevokeToken(ctx context.Context, tokenOrTokenID, userID, clientID string) *oidc.Error {
	h := hashValue(tokenOrTokenID)

	var owner string
	if err := s.pool.QueryRow(ctx, `SELECT client_id FROM oidc_access_tokens WHERE id_hash = $1`, h).Scan(&owner); err == nil {
		if owner != clientID {
			return oidc.ErrInvalidClient().WithDescription("token was not issued for this client")
		}
		if _, err := s.pool.Exec(ctx, `DELETE FROM oidc_access_tokens WHERE id_hash = $1`, h); err != nil {
			return oidc.ErrServerError().WithParent(err)
		}
		s.record(ctx, "oidc.revoke", userID, clientID, audit.OutcomeOK)
		return nil
	}

	if err := s.pool.QueryRow(ctx, `SELECT client_id FROM oidc_refresh_tokens WHERE token_hash = $1`, h).Scan(&owner); err == nil {
		if owner != clientID {
			return oidc.ErrInvalidClient().WithDescription("token was not issued for this client")
		}
		if _, err := s.pool.Exec(ctx, `DELETE FROM oidc_refresh_tokens WHERE token_hash = $1`, h); err != nil {
			return oidc.ErrServerError().WithParent(err)
		}
		s.record(ctx, "oidc.revoke", userID, clientID, audit.OutcomeOK)
		return nil
	}
	// RFC 7009: revoking an unknown token is success.
	return nil
}

// GetRefreshTokenInfo implements op.Storage.
//
// The second return value is the identifier the library hands straight back to
// RevokeToken, which HASHES whatever it is given before looking it up (that is
// how a raw token from the wire is normally resolved). So the identifier has to
// be the raw refresh token value, not the row's id_hash — returning a hash made
// RevokeToken hash a hash, match neither column, and fall through to the RFC 7009
// "already invalid" branch, so a refresh token could not be revoked at all.
//
// It is not a disclosure: this method is given the raw token as its argument.
func (s *OIDCStore) GetRefreshTokenInfo(ctx context.Context, clientID, token string) (string, string, error) {
	var subject string
	if err := s.pool.QueryRow(ctx, `
		SELECT subject FROM oidc_refresh_tokens WHERE token_hash = $1 AND client_id = $2`,
		hashValue(token), clientID).Scan(&subject); err != nil {
		return "", "", op.ErrInvalidRefreshToken
	}
	return subject, token, nil
}

// SigningKey implements op.Storage.
func (s *OIDCStore) SigningKey(context.Context) (op.SigningKey, error) { return s.signer, nil }

// SignatureAlgorithms implements op.Storage.
func (s *OIDCStore) SignatureAlgorithms(context.Context) ([]jose.SignatureAlgorithm, error) {
	return []jose.SignatureAlgorithm{jose.RS256}, nil
}

// KeySet implements op.Storage.
func (s *OIDCStore) KeySet(context.Context) ([]op.Key, error) {
	return s.signer.KeySet(), nil
}

// --- op.OPStorage ---

// GetClientByClientID implements op.Storage. The login hook is bound to this
// request's context so it can touch the browser session while building the
// consent URL.
func (s *OIDCStore) GetClientByClientID(ctx context.Context, clientID string) (op.Client, error) {
	c, err := s.clients.Get(ctx, clientID)
	if err != nil {
		if errors.Is(err, oauth.ErrClientNotFound) {
			return nil, oidc.ErrInvalidClient()
		}
		return nil, err
	}
	return oidcstore.ProviderClient{Client: c, Registry: s.registry, Login: func(id string) string {
		if s.login == nil {
			return "/login?authRequestID=" + id
		}
		return s.login(ctx, id)
	}}, nil
}

// AuthorizeClientIDSecret implements op.Storage.
func (s *OIDCStore) AuthorizeClientIDSecret(ctx context.Context, clientID, clientSecret string) error {
	c, err := s.clients.Get(ctx, clientID)
	if err != nil {
		if errors.Is(err, oauth.ErrClientNotFound) {
			return oidc.ErrInvalidClient()
		}
		return err
	}
	if c.Type == oauth.ClientConfidential && !c.Authenticate(clientSecret) {
		return oidc.ErrInvalidClient().WithDescription("invalid client secret")
	}
	return nil
}

// SetUserinfoFromScopes implements op.Storage (deprecated upstream; no-op).
func (s *OIDCStore) SetUserinfoFromScopes(context.Context, *oidc.UserInfo, string, string, []string) error {
	return nil
}

// SetUserinfoFromToken implements op.Storage. The OP only ever exposes `sub`
// (ADR-0001 O-3); richer claims are a later, separate decision.
func (s *OIDCStore) SetUserinfoFromToken(_ context.Context, userinfo *oidc.UserInfo, _, subject, _ string) error {
	userinfo.Subject = subject
	return nil
}

// SetIntrospectionFromToken implements op.Storage.
func (s *OIDCStore) SetIntrospectionFromToken(ctx context.Context, introspection *oidc.IntrospectionResponse, tokenID, subject, _ string) error {
	var (
		clientID string
		scopes   []string
		expires  time.Time
	)
	if err := s.pool.QueryRow(ctx, `
		SELECT client_id, scopes, expires_at FROM oidc_access_tokens WHERE id_hash = $1`,
		hashValue(tokenID)).Scan(&clientID, &scopes, &expires); err != nil {
		return errors.New("postgres: token not found")
	}
	if !expires.After(time.Now()) {
		return errors.New("postgres: token expired")
	}
	introspection.Active = true
	introspection.Subject = subject
	introspection.ClientID = clientID
	introspection.Scope = scopes
	introspection.Expiration = oidc.FromTime(expires)
	return nil
}

// GetPrivateClaimsFromScopes implements op.Storage.
func (s *OIDCStore) GetPrivateClaimsFromScopes(context.Context, string, string, []string) (map[string]any, error) {
	return nil, nil
}

// GetKeyByIDAndClientID implements op.Storage. JWT profile grant is not supported.
func (s *OIDCStore) GetKeyByIDAndClientID(context.Context, string, string) (*jose.JSONWebKey, error) {
	return nil, errors.New("postgres: JWT profile grant is not supported")
}

// ValidateJWTProfileScopes implements op.Storage.
func (s *OIDCStore) ValidateJWTProfileScopes(_ context.Context, _ string, scopes []string) ([]string, error) {
	return scopes, nil
}

// Health implements op.Storage.
func (s *OIDCStore) Health(ctx context.Context) error { return s.pool.Ping(ctx) }

// --- op.DeviceAuthorizationStorage ---

// StoreDeviceAuthorization implements op.Storage.
func (s *OIDCStore) StoreDeviceAuthorization(ctx context.Context, clientID, deviceCode, userCode string, expires time.Time, scopes []string) error {
	if scopes == nil {
		scopes = []string{}
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO oidc_devices (device_code_hash, user_code, client_id, scopes, expires_at)
		VALUES ($1,$2,$3,$4,$5)`,
		hashValue(deviceCode), userCode, clientID, scopes, expires)
	if isUniqueViolation(err) {
		return op.ErrDuplicateUserCode
	}
	if err != nil {
		return fmt.Errorf("postgres: store device authorization: %w", err)
	}
	return nil
}

// GetDeviceAuthorizatonState implements op.Storage.
//
// It consumes an approved authorization on the first read: the library reads the
// state once, immediately before minting the tokens, and never marks the record
// spent. Deleting it here (rather than only reading) makes the device_code single
// use — a second exchange finds nothing — and means a revocation that fired
// between two polls cannot be replayed away. A pending or denied record is not
// touched and falls through to a plain read for the library to answer.
func (s *OIDCStore) GetDeviceAuthorizatonState(ctx context.Context, clientID, deviceCode string) (*op.DeviceAuthorizationState, error) {
	var (
		st       op.DeviceAuthorizationState
		authTime *time.Time
	)
	err := s.pool.QueryRow(ctx, `
		DELETE FROM oidc_devices
		 WHERE device_code_hash = $1 AND client_id = $2 AND done = true AND denied = false
		RETURNING client_id, scopes, expires_at, done, denied, subject, auth_time`,
		hashValue(deviceCode), clientID).Scan(
		&st.ClientID, &st.Scopes, &st.Expires, &st.Done, &st.Denied, &st.Subject, &authTime,
	)
	if err == nil {
		if authTime != nil {
			st.AuthTime = *authTime
		}
		return &st, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("postgres: consume device authorization: %w", err)
	}
	return s.deviceState(ctx, `device_code_hash = $1 AND client_id = $2`, hashValue(deviceCode), clientID)
}

func (s *OIDCStore) deviceState(ctx context.Context, where string, args ...any) (*op.DeviceAuthorizationState, error) {
	var (
		st       op.DeviceAuthorizationState
		authTime *time.Time
	)
	if err := s.pool.QueryRow(ctx, `
		SELECT client_id, scopes, expires_at, done, denied, subject, auth_time
		  FROM oidc_devices WHERE `+where, args...).Scan(
		&st.ClientID, &st.Scopes, &st.Expires, &st.Done, &st.Denied, &st.Subject, &authTime,
	); err != nil {
		return nil, errors.New("postgres: device authorization not found")
	}
	if authTime != nil {
		st.AuthTime = *authTime
	}
	return &st, nil
}

// --- consent / device UI helpers (app-owned, not part of op.Storage) ---

// CompleteLogin attaches the subject and the approved (possibly narrowed)
// scopes to a pending authorization request. It is what the consent screen
// calls before the callback.
func (s *OIDCStore) CompleteLogin(ctx context.Context, id, subject string, scopes []string) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE oidc_auth_requests
		   SET subject = $2, scopes = $3, done = true, auth_time = now()
		 WHERE id = $1`, id, subject, oidcstore.NonNil(scopes))
	if err != nil {
		return fmt.Errorf("postgres: complete login: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return errors.New("postgres: auth request not found")
	}
	return nil
}

// DeviceByUserCode returns the pending device authorization for a user code.
func (s *OIDCStore) DeviceByUserCode(ctx context.Context, userCode string) (*op.DeviceAuthorizationState, error) {
	return s.deviceState(ctx, `upper(replace(user_code, '-', '')) = upper(replace($1, '-', ''))`, userCode)
}

// ApproveDevice marks a device authorization approved. A nil scopes slice keeps
// the requested scopes; an explicit slice narrows them.
func (s *OIDCStore) ApproveDevice(ctx context.Context, userCode, subject string, scopes []string) error {
	q := `UPDATE oidc_devices SET done = true, subject = $2, auth_time = now()
	       WHERE upper(replace(user_code, '-', '')) = upper(replace($1, '-', ''))`
	args := []any{userCode, subject}
	if scopes != nil {
		q = `UPDATE oidc_devices SET done = true, subject = $2, auth_time = now(), scopes = $3
		      WHERE upper(replace(user_code, '-', '')) = upper(replace($1, '-', ''))`
		args = append(args, scopes)
	}
	tag, err := s.pool.Exec(ctx, q, args...)
	if err != nil {
		return fmt.Errorf("postgres: approve device: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return errors.New("postgres: device authorization not found")
	}
	s.record(ctx, "oidc.device.approve", subject, "", audit.OutcomeOK)
	return nil
}

// DenyDevice marks a device authorization denied.
func (s *OIDCStore) DenyDevice(ctx context.Context, userCode string) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE oidc_devices SET denied = true
		 WHERE upper(replace(user_code, '-', '')) = upper(replace($1, '-', ''))`, userCode)
	if err != nil {
		return fmt.Errorf("postgres: deny device: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return errors.New("postgres: device authorization not found")
	}
	s.record(ctx, "oidc.device.deny", "", "", audit.OutcomeDenied)
	return nil
}

// --- engine-neutral business-plane surface (same shapes as oauth.Service) ---

// Grants lists what each client can still do as this subject, derived from the
// OP token tables. It is the OP-backed counterpart of oauth.Service.Grants.
func (s *OIDCStore) Grants(ctx context.Context, subject string) ([]oauth.Grant, error) {
	if subject == "" {
		return nil, errors.New("postgres: subject is required")
	}
	rows, err := s.pool.Query(ctx, `
		SELECT client_id, scopes, issued_at, expires_at, false
		  FROM oidc_access_tokens WHERE subject = $1 AND expires_at > now()
		UNION ALL
		SELECT client_id, scopes, issued_at, expires_at, true
		  FROM oidc_refresh_tokens WHERE subject = $1 AND expires_at > now()`, subject)
	if err != nil {
		return nil, fmt.Errorf("postgres: list grants: %w", err)
	}
	defer rows.Close()

	byClient := make(map[string]*oauth.Grant)
	for rows.Next() {
		var (
			clientID string
			scopes   []string
			issued   time.Time
			expires  time.Time
			hasRT    bool
		)
		if err := rows.Scan(&clientID, &scopes, &issued, &expires, &hasRT); err != nil {
			return nil, err
		}
		g, ok := byClient[clientID]
		if !ok {
			g = &oauth.Grant{ClientID: clientID, IssuedAt: issued, ExpiresAt: expires}
			if c, err := s.clients.Get(ctx, clientID); err == nil {
				g.ClientName = c.Name
			}
			byClient[clientID] = g
		}
		for _, sc := range scopes {
			if sc == oidc.ScopeOfflineAccess {
				continue
			}
			g.Scopes = appendScopeUnique(g.Scopes, oauth.Scope(sc))
		}
		if issued.Before(g.IssuedAt) {
			g.IssuedAt = issued
		}
		if expires.After(g.ExpiresAt) {
			g.ExpiresAt = expires
		}
		if hasRT {
			g.HasRefresh = true
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]oauth.Grant, 0, len(byClient))
	for _, g := range byClient {
		sort.Slice(g.Scopes, func(i, j int) bool { return g.Scopes[i] < g.Scopes[j] })
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ClientID < out[j].ClientID })
	return out, nil
}

// RevokeGrant removes every OP token a client holds for a subject. It is the
// local revocation and is idempotent.
func (s *OIDCStore) RevokeGrant(ctx context.Context, subject, clientID string) error {
	if subject == "" || clientID == "" {
		return errors.New("postgres: subject and client id are required")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `DELETE FROM oidc_access_tokens WHERE subject = $1 AND client_id = $2`, subject, clientID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM oidc_refresh_tokens WHERE subject = $1 AND client_id = $2`, subject, clientID); err != nil {
		return err
	}
	// A device authorization for this client and subject outlives its tokens:
	// leaving it would let the holder of the device_code mint a fresh pair after
	// the user revoked the grant.
	if _, err := tx.Exec(ctx, `DELETE FROM oidc_devices WHERE subject = $1 AND client_id = $2`, subject, clientID); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	s.record(ctx, "oidc.grant.revoke", subject, clientID, audit.OutcomeOK)
	return nil
}

// RevokeTokens implements oauth.TokenAdmin for the OP-managed token tables. It
// is what a suspended client, a compromised subject, or the Kill Switch call.
//
// Device authorizations are revoked alongside the tokens, on the same
// client/subject predicate (the table carries both columns). They are not counted
// in the result — that number is tokens — but they must go: a held device_code
// would otherwise re-mint what was just revoked, defeating the Kill Switch for
// the life of the code.
func (s *OIDCStore) RevokeTokens(ctx context.Context, f oauth.TokenFilter) (int, error) {
	total, err := revokeMatching(ctx, s.pool, []string{"oidc_access_tokens", "oidc_refresh_tokens"}, f)
	if err != nil {
		return total, err
	}
	// A pending authorization request whose code has not been redeemed is a
	// redeemable capability, not a token. Leaving it alive let a code issued
	// before the Kill Switch mint a fresh access/refresh pair after the switch
	// reported success.
	if _, err := revokePendingAuthorizations(ctx, s.pool, f); err != nil {
		return total, err
	}
	if _, err := revokeMatching(ctx, s.pool, []string{"oidc_devices"}, f); err != nil {
		return total, err
	}
	return total, nil
}

// revokePendingAuthorizations deletes auth requests selected by the filter and
// the codes minted from them. Codes are deleted first because their only link to
// the subject is request_id.
func revokePendingAuthorizations(ctx context.Context, pool *pgxpool.Pool, f oauth.TokenFilter) (int, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	removed := 0
	tag, err := tx.Exec(ctx, `
		DELETE FROM oidc_codes
		 WHERE request_id IN (
		       SELECT id FROM oidc_auth_requests
		        WHERE ($1 = '' OR client_id = $1) AND ($2 = '' OR subject = $2))`,
		f.ClientID, f.Subject)
	if err != nil {
		return removed, err
	}
	removed += int(tag.RowsAffected())

	tag, err = tx.Exec(ctx, `
		DELETE FROM oidc_auth_requests
		 WHERE ($1 = '' OR client_id = $1) AND ($2 = '' OR subject = $2)`,
		f.ClientID, f.Subject)
	if err != nil {
		return removed, err
	}
	removed += int(tag.RowsAffected())

	if err := tx.Commit(ctx); err != nil {
		return removed, err
	}
	return removed, nil
}

// PurgeSubject removes a subject's non-token OP state: the pending consent
// requests, any authorization codes minted from them, and the device
// authorizations it approved or started.
//
// It is the token-free half of account erasure. Issued tokens are rows in the
// token tables and are removed by RevokeTokens, not here — so a caller doing a
// full erasure calls both. Splitting them keeps each statement's intent legible:
// this one deletes work in flight, that one deletes access already granted.
//
// One transaction, because the codes are deleted by joining through the requests
// that are about to disappear.
func (s *OIDCStore) PurgeSubject(ctx context.Context, subject string) (int, error) {
	if subject == "" {
		return 0, errors.New("postgres: subject is required")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	total := 0
	// Codes first: their only link to the subject is request_id.
	tag, err := tx.Exec(ctx, `
		DELETE FROM oidc_codes
		 WHERE request_id IN (SELECT id FROM oidc_auth_requests WHERE subject = $1)`, subject)
	if err != nil {
		return total, err
	}
	total += int(tag.RowsAffected())

	for _, q := range []string{
		`DELETE FROM oidc_auth_requests WHERE subject = $1`,
		`DELETE FROM oidc_devices WHERE subject = $1`,
	} {
		tag, err := tx.Exec(ctx, q, subject)
		if err != nil {
			return total, err
		}
		total += int(tag.RowsAffected())
	}
	if err := tx.Commit(ctx); err != nil {
		return total, err
	}
	return total, nil
}

// DescribeDeviceAuthorization is the device verification page's view of a
// pending device grant (OP-backed counterpart of the same oauth.Service method).
func (s *OIDCStore) DescribeDeviceAuthorization(ctx context.Context, userCode string) (oauth.DeviceAuthorization, error) {
	st, err := s.DeviceByUserCode(ctx, userCode)
	if err != nil || st.Done || st.Denied || time.Now().After(st.Expires) {
		return oauth.DeviceAuthorization{}, oauth.ErrDeviceNotFound
	}
	client, err := s.clients.Get(ctx, st.ClientID)
	if err != nil {
		return oauth.DeviceAuthorization{}, oauth.ErrDeviceNotFound
	}
	descriptors, err := s.registry.Resolve(oidcstore.Scopes(st.Scopes), st.ClientID)
	if err != nil {
		return oauth.DeviceAuthorization{}, err
	}
	return oauth.DeviceAuthorization{
		UserCode:  userCode,
		Client:    client,
		Scopes:    descriptors,
		ExpiresAt: st.Expires,
	}, nil
}

// DecideDeviceAuthorization records the user's approval or denial, narrowing
// scopes and enforcing explicit consent exactly like the interactive flow.
func (s *OIDCStore) DecideDeviceAuthorization(ctx context.Context, userCode, subject string, approve bool, scopes, explicit []oauth.Scope) error {
	if subject == "" {
		return &oauth.Error{Code: "access_denied", Description: "user is not authenticated"}
	}
	st, err := s.DeviceByUserCode(ctx, userCode)
	if err != nil || st.Done || st.Denied || time.Now().After(st.Expires) {
		return oauth.ErrDeviceNotFound
	}
	if !approve {
		return s.DenyDevice(ctx, userCode)
	}

	granted, err := oidcstore.NarrowScopes(st.Scopes, scopes)
	if err != nil {
		return err
	}
	descriptors, err := s.registry.Resolve(oidcstore.Scopes(granted), st.ClientID)
	if err != nil {
		return err
	}
	if err := oidcstore.RequireExplicitConsent(descriptors, explicit); err != nil {
		return err
	}
	// ADR-0001 O-6 (revised): a device authorization always yields a refresh
	// token, so offline_access is granted implicitly.
	granted = oidcstore.WithOfflineAccess(granted)
	return s.ApproveDevice(ctx, userCode, subject, granted)
}

func appendScopeUnique(dst []oauth.Scope, s oauth.Scope) []oauth.Scope {
	for _, have := range dst {
		if have == s {
			return dst
		}
	}
	return append(dst, s)
}
