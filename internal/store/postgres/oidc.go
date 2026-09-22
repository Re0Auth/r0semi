package postgres

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/oauth"
)

// OIDCStore is the production op.Storage + op.DeviceAuthorizationStorage for the
// OpenID Provider (ADR-0001). It replaces the hand-rolled oauth.Store once the
// migration completes; until then both coexist.
//
// It owns the *policy* the OP cannot: which scopes exist (via the oauth.Registry
// in the client adapter), and an audit trail for every token it issues or
// revokes.
type OIDCStore struct {
	pool     *pgxpool.Pool
	clients  oauth.ClientRegistry
	registry *oauth.Registry
	login    func(ctx context.Context, authRequestID string) string
	signer   *OIDCSigner
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
	Signer *OIDCSigner
	// Audit records token issuance and revocation. Optional.
	Audit audit.Logger
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
		requestTTL: 30 * time.Minute,
	}, nil
}

// OIDC returns the OpenID Provider storage on the migrated database.
func (db *DB) OIDC(clients oauth.ClientRegistry, opts OIDCOptions) (*OIDCStore, error) {
	return NewOIDCStore(db.pool, clients, opts)
}

// OIDCSigner is the OP's RS256 signing key. Key material is injected by the
// composition root; the store never generates or persists it.
type OIDCSigner struct {
	id  string
	key *rsa.PrivateKey
}

// NewOIDCSigner wraps a private key.
func NewOIDCSigner(id string, key *rsa.PrivateKey) *OIDCSigner {
	return &OIDCSigner{id: id, key: key}
}

// ID implements op.SigningKey.
func (s *OIDCSigner) ID() string { return s.id }

// SignatureAlgorithm implements op.SigningKey.
func (s *OIDCSigner) SignatureAlgorithm() jose.SignatureAlgorithm { return jose.RS256 }

// Key implements op.SigningKey (private key).
func (s *OIDCSigner) Key() any { return s.key }

type oidcPublicKey struct{ *OIDCSigner }

func (p oidcPublicKey) Algorithm() jose.SignatureAlgorithm { return jose.RS256 }
func (p oidcPublicKey) Use() string                        { return "sig" }
func (p oidcPublicKey) Key() any                           { return &p.key.PublicKey }

// opClient adapts oauth.Client to op.Client. Secret verification stays in
// oauth.Client.Authenticate (SHA-256); the library never sees the hash.
type opClient struct {
	c        oauth.Client
	registry *oauth.Registry
	login    func(string) string
}

func (c opClient) GetID() string                    { return c.c.ID }
func (c opClient) RedirectURIs() []string           { return c.c.RedirectURIs }
func (c opClient) PostLogoutRedirectURIs() []string { return nil }
func (c opClient) AccessTokenType() op.AccessTokenType {
	return op.AccessTokenTypeBearer
}
func (c opClient) IDTokenLifetime() time.Duration       { return time.Hour }
func (c opClient) DevMode() bool                        { return false }
func (c opClient) IDTokenUserinfoClaimsAssertion() bool { return false }
func (c opClient) ClockSkew() time.Duration             { return 0 }
func (c opClient) RestrictAdditionalIdTokenScopes() func([]string) []string {
	return func(s []string) []string { return s }
}
func (c opClient) RestrictAdditionalAccessTokenScopes() func([]string) []string {
	return func(s []string) []string { return s }
}

func (c opClient) ApplicationType() op.ApplicationType {
	if c.c.Type == oauth.ClientPublic {
		return op.ApplicationTypeNative
	}
	return op.ApplicationTypeWeb
}

func (c opClient) AuthMethod() oidc.AuthMethod {
	if c.c.Type == oauth.ClientPublic {
		return oidc.AuthMethodNone
	}
	return oidc.AuthMethodBasic
}

func (c opClient) ResponseTypes() []oidc.ResponseType {
	return []oidc.ResponseType{oidc.ResponseTypeCode}
}

func (c opClient) GrantTypes() []oidc.GrantType {
	return []oidc.GrantType{oidc.GrantTypeCode, oidc.GrantTypeRefreshToken, oidc.GrantTypeDeviceCode}
}

func (c opClient) LoginURL(id string) string {
	if c.login == nil {
		return "/login?authRequestID=" + id
	}
	return c.login(id)
}

// IsScopeAllowed is the real scope gate: only scopes in the registry are legal.
// This is what makes the OP's own scope validation consult our catalog instead
// of silently dropping unknown scopes.
func (c opClient) IsScopeAllowed(scope string) bool {
	if c.registry == nil {
		return false
	}
	_, ok := c.registry.Get(oauth.Scope(scope))
	return ok
}

// oidcAuthRequest implements op.AuthRequest from a database row. It is the
// consent record, so scopes can be narrowed here before the code is issued.
type oidcAuthRequest struct {
	id            string
	clientID      string
	redirectURI   string
	responseType  oidc.ResponseType
	responseMode  oidc.ResponseMode
	scopes        []string
	state         string
	nonce         string
	codeChallenge *oidc.CodeChallenge
	subject       string
	done          bool
	authTime      *time.Time
}

func (a *oidcAuthRequest) GetID() string         { return a.id }
func (a *oidcAuthRequest) GetACR() string        { return "" }
func (a *oidcAuthRequest) GetAMR() []string      { return nil }
func (a *oidcAuthRequest) GetAudience() []string { return []string{a.clientID} }
func (a *oidcAuthRequest) GetAuthTime() time.Time {
	if a.authTime == nil {
		return time.Time{}
	}
	return *a.authTime
}
func (a *oidcAuthRequest) GetClientID() string                   { return a.clientID }
func (a *oidcAuthRequest) GetCodeChallenge() *oidc.CodeChallenge { return a.codeChallenge }
func (a *oidcAuthRequest) GetNonce() string                      { return a.nonce }
func (a *oidcAuthRequest) GetRedirectURI() string                { return a.redirectURI }
func (a *oidcAuthRequest) GetResponseType() oidc.ResponseType    { return a.responseType }
func (a *oidcAuthRequest) GetResponseMode() oidc.ResponseMode    { return a.responseMode }
func (a *oidcAuthRequest) GetScopes() []string                   { return a.scopes }
func (a *oidcAuthRequest) GetState() string                      { return a.state }
func (a *oidcAuthRequest) GetSubject() string                    { return a.subject }
func (a *oidcAuthRequest) Done() bool                            { return a.done }

// oidcRefreshRequest implements op.RefreshTokenRequest from a refresh row.
type oidcRefreshRequest struct {
	idHash   string
	clientID string
	subject  string
	scopes   []string
	amr      []string
	audience []string
	authTime *time.Time
}

func (r *oidcRefreshRequest) GetAMR() []string      { return r.amr }
func (r *oidcRefreshRequest) GetAudience() []string { return r.audience }
func (r *oidcRefreshRequest) GetAuthTime() time.Time {
	if r.authTime == nil {
		return time.Time{}
	}
	return *r.authTime
}
func (r *oidcRefreshRequest) GetClientID() string         { return r.clientID }
func (r *oidcRefreshRequest) GetScopes() []string         { return r.scopes }
func (r *oidcRefreshRequest) GetSubject() string          { return r.subject }
func (r *oidcRefreshRequest) SetCurrentScopes(s []string) { r.scopes = s }

func hashValue(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])
}

// nonNil keeps a text[] parameter from being sent as SQL NULL: every array
// column is NOT NULL, and "no scopes" is an empty array, not a missing one.
func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func randomValue() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func clientIDOf(request op.TokenRequest) string {
	if c, ok := request.(interface{ GetClientID() string }); ok {
		return c.GetClientID()
	}
	return ""
}

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
	id, err := randomValue()
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
		nonNil([]string(req.Scopes)), req.State, req.Nonce, challenge, method, userID, now, now.Add(s.requestTTL),
	); err != nil {
		return nil, fmt.Errorf("postgres: create auth request: %w", err)
	}
	return &oidcAuthRequest{
		id: id, clientID: req.ClientID, redirectURI: req.RedirectURI,
		responseType: req.ResponseType, responseMode: req.ResponseMode,
		scopes: append([]string(nil), req.Scopes...), state: req.State, nonce: req.Nonce,
		codeChallenge: codeChallenge(req.CodeChallenge, method),
		subject:       userID,
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
		a         oidcAuthRequest
		challenge string
		method    string
		authTime  *time.Time
	)
	if err := s.pool.QueryRow(ctx, query, args...).Scan(
		&a.id, &a.clientID, &a.redirectURI, &a.responseType, &a.responseMode, &a.scopes,
		&a.state, &a.nonce, &challenge, &method, &a.subject, &a.done, &authTime,
	); err != nil {
		return nil, fmt.Errorf("postgres: auth request: %w", err)
	}
	a.codeChallenge = codeChallenge(challenge, method)
	a.authTime = authTime
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
	id, err := randomValue()
	if err != nil {
		return "", time.Time{}, err
	}
	expires := time.Now().UTC().Add(s.accessTTL)
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO oidc_access_tokens (id_hash, client_id, subject, scopes, expires_at)
		VALUES ($1,$2,$3,$4,$5)`,
		hashValue(id), clientIDOf(request), request.GetSubject(), nonNil(request.GetScopes()), expires); err != nil {
		return "", time.Time{}, fmt.Errorf("postgres: create access token: %w", err)
	}
	s.record(ctx, "oidc.token", request.GetSubject(), clientIDOf(request), audit.OutcomeOK)
	return id, expires, nil
}

// CreateAccessAndRefreshTokens implements op.Storage. Refresh tokens rotate:
// presenting one consumes it and issues a new one.
func (s *OIDCStore) CreateAccessAndRefreshTokens(ctx context.Context, request op.TokenRequest, currentRefreshToken string) (string, string, time.Time, error) {
	accessID, expires, err := s.CreateAccessToken(ctx, request)
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
	scopes := nonNil(request.GetScopes())
	amr = nonNil(amr)
	audience = nonNil(audience)

	value, err := randomValue()
	if err != nil {
		return "", "", time.Time{}, err
	}
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO oidc_refresh_tokens
			(token_hash, id_hash, client_id, subject, scopes, amr, audience, auth_time, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		hashValue(value), hashValue(accessID), clientIDOf(request), request.GetSubject(),
		scopes, amr, audience, authTime, time.Now().UTC().Add(s.refreshTTL),
	); err != nil {
		return "", "", time.Time{}, fmt.Errorf("postgres: create refresh token: %w", err)
	}

	if currentRefreshToken != "" {
		if _, err := s.pool.Exec(ctx,
			`DELETE FROM oidc_refresh_tokens WHERE token_hash = $1`, hashValue(currentRefreshToken)); err != nil {
			return "", "", time.Time{}, fmt.Errorf("postgres: rotate refresh token: %w", err)
		}
	}
	return accessID, value, expires, nil
}

// TokenRequestByRefreshToken implements op.Storage.
func (s *OIDCStore) TokenRequestByRefreshToken(ctx context.Context, value string) (op.RefreshTokenRequest, error) {
	var (
		r        oidcRefreshRequest
		authTime *time.Time
	)
	if err := s.pool.QueryRow(ctx, `
		SELECT id_hash, client_id, subject, scopes, amr, audience, auth_time
		  FROM oidc_refresh_tokens WHERE token_hash = $1`, hashValue(value)).Scan(
		&r.idHash, &r.clientID, &r.subject, &r.scopes, &r.amr, &r.audience, &authTime,
	); err != nil {
		return nil, errors.New("postgres: invalid refresh token")
	}
	r.authTime = authTime
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
func (s *OIDCStore) GetRefreshTokenInfo(ctx context.Context, clientID, token string) (string, string, error) {
	var (
		subject string
		idHash  string
	)
	if err := s.pool.QueryRow(ctx, `
		SELECT subject, id_hash FROM oidc_refresh_tokens WHERE token_hash = $1 AND client_id = $2`,
		hashValue(token), clientID).Scan(&subject, &idHash); err != nil {
		return "", "", op.ErrInvalidRefreshToken
	}
	return subject, idHash, nil
}

// SigningKey implements op.Storage.
func (s *OIDCStore) SigningKey(context.Context) (op.SigningKey, error) { return s.signer, nil }

// SignatureAlgorithms implements op.Storage.
func (s *OIDCStore) SignatureAlgorithms(context.Context) ([]jose.SignatureAlgorithm, error) {
	return []jose.SignatureAlgorithm{jose.RS256}, nil
}

// KeySet implements op.Storage.
func (s *OIDCStore) KeySet(context.Context) ([]op.Key, error) {
	return []op.Key{oidcPublicKey{s.signer}}, nil
}

// --- op.OPStorage ---

// GetClientByClientID implements op.Storage. The login hook is bound to this
// request's context so it can touch the browser session while building the
// consent URL.
func (s *OIDCStore) GetClientByClientID(ctx context.Context, clientID string) (op.Client, error) {
	c, err := s.clients.Get(ctx, clientID)
	if err != nil {
		return nil, err
	}
	return opClient{c: c, registry: s.registry, login: func(id string) string {
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
		return err
	}
	if c.Type == oauth.ClientConfidential && !c.Authenticate(clientSecret) {
		return errors.New("postgres: invalid client secret")
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
func (s *OIDCStore) GetDeviceAuthorizatonState(ctx context.Context, clientID, deviceCode string) (*op.DeviceAuthorizationState, error) {
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
		 WHERE id = $1`, id, subject, nonNil(scopes))
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
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	s.record(ctx, "oidc.grant.revoke", subject, clientID, audit.OutcomeOK)
	return nil
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
	descriptors, err := s.registry.Resolve(stringsToScopes(st.Scopes), st.ClientID)
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

	granted := st.Scopes
	if len(scopes) > 0 {
		for _, sc := range scopes {
			if !containsStr(st.Scopes, sc.String()) {
				return &oauth.Error{Code: "invalid_scope", Description: "the decision cannot widen the requested scope"}
			}
		}
		granted = scopeStrings(scopes)
	}
	descriptors, err := s.registry.Resolve(stringsToScopes(granted), st.ClientID)
	if err != nil {
		return err
	}
	ticked := make(map[oauth.Scope]struct{}, len(explicit))
	for _, sc := range explicit {
		ticked[sc] = struct{}{}
	}
	for _, d := range descriptors {
		if d.ExplicitConsent {
			if _, ok := ticked[d.Scope]; !ok {
				return &oauth.Error{Code: "access_denied", Description: "explicit consent is required for " + d.Scope.String()}
			}
		}
	}
	return s.ApproveDevice(ctx, userCode, subject, granted)
}

func containsStr(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

func scopeStrings(scopes []oauth.Scope) []string {
	out := make([]string, len(scopes))
	for i, s := range scopes {
		out[i] = s.String()
	}
	return out
}

func stringsToScopes(in []string) []oauth.Scope {
	out := make([]oauth.Scope, len(in))
	for i, s := range in {
		out[i] = oauth.Scope(s)
	}
	return out
}

func appendScopeUnique(dst []oauth.Scope, s oauth.Scope) []oauth.Scope {
	for _, have := range dst {
		if have == s {
			return dst
		}
	}
	return append(dst, s)
}
