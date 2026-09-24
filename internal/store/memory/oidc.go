// Package memory provides the in-memory OpenID Provider store. It is the
// non-durable twin of internal/store/postgres.OIDCStore: the same op.Storage and
// op.DeviceAuthorizationStorage surface, the same business-plane helpers, but no
// database.
//
// ADR-0001 P4b made this necessary. Before it, a deployment without
// DATABASE_URL fell back to a hand-rolled authorization server; now every
// deployment runs the OpenID Provider, and the only thing that changes with a
// DSN is where the OP's state is kept. That removes an entire second engine and,
// with it, a second place for the consent and token rules to drift.
package memory

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/internal/oidcstore"
	"github.com/Re0Auth/r0semi/oauth"
)

// OIDCStore is an in-memory op.Storage + op.DeviceAuthorizationStorage, plus the
// business-plane helpers the HTTP layer and the operator plane call.
type OIDCStore struct {
	mu       sync.Mutex
	clients  oauth.ClientRegistry
	registry *oauth.Registry
	login    func(ctx context.Context, authRequestID string) string
	signer   *oidcstore.Signer
	audit    audit.Logger

	authRequests      map[string]*oidcstore.AuthRequest
	authRequestExpiry map[string]time.Time
	codes             map[string]codeRecord // by TokenHash(code)
	accessTokens      map[string]accessToken
	refreshTokens     map[string]refreshToken
	devices           map[string]deviceRecord // by TokenHash(device code)
	userCodes         map[string]string       // normalized user code -> TokenHash(device code)

	accessTTL  time.Duration
	refreshTTL time.Duration
	requestTTL time.Duration
	now        func() time.Time
}

// ErrRefreshTokenSpent reports a refresh token presented after it had already
// been rotated. It is a refusal, not a lookup miss: the caller asked to spend a
// token this store has already consumed, which is what a replayed (or stolen)
// refresh token looks like. Returning an error rather than minting a second
// generation is the whole point — it is the only thing that makes reuse visible.
var ErrRefreshTokenSpent = errors.New("memory: refresh token was already rotated")

type codeRecord struct {
	requestID string
	expiresAt time.Time
}

type accessToken struct {
	id        string
	clientID  string
	subject   string
	scopes    []string
	issuedAt  time.Time
	expiresAt time.Time
}

type refreshToken struct {
	valueHash string
	idHash    string
	clientID  string
	subject   string
	scopes    []string
	amr       []string
	audience  []string
	authTime  *time.Time
	issuedAt  time.Time
	expiresAt time.Time
}

type deviceRecord struct {
	deviceCodeHash string
	userCode       string
	clientID       string
	scopes         []string
	expiresAt      time.Time
	done           bool
	denied         bool
	subject        string
	authTime       time.Time
}

// OIDCOptions configures a memory OIDCStore.
type OIDCOptions struct {
	Clients  oauth.ClientRegistry
	Registry *oauth.Registry
	// Login builds the consent URL. It receives the request context, so the
	// composition root can bind the auth request to the browser session.
	Login  func(ctx context.Context, authRequestID string) string
	Signer *oidcstore.Signer
	Audit  audit.Logger
	// Now supplies the current time; tests inject a fake clock.
	Now func() time.Time
	// RequestTTL is how long a pending consent handle stays valid. Defaults to
	// 30 minutes.
	RequestTTL time.Duration
}

// NewOIDCStore builds an empty in-memory store.
func NewOIDCStore(opts OIDCOptions) (*OIDCStore, error) {
	switch {
	case opts.Clients == nil:
		return nil, errors.New("memory: OIDCStore: client registry is required")
	case opts.Registry == nil:
		return nil, errors.New("memory: OIDCStore: scope registry is required")
	case opts.Signer == nil:
		return nil, errors.New("memory: OIDCStore: signer is required")
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	ttl := opts.RequestTTL
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	return &OIDCStore{
		clients:           opts.Clients,
		registry:          opts.Registry,
		login:             opts.Login,
		signer:            opts.Signer,
		audit:             opts.Audit,
		authRequests:      make(map[string]*oidcstore.AuthRequest),
		authRequestExpiry: make(map[string]time.Time),
		codes:             make(map[string]codeRecord),
		accessTokens:      make(map[string]accessToken),
		refreshTokens:     make(map[string]refreshToken),
		devices:           make(map[string]deviceRecord),
		userCodes:         make(map[string]string),
		accessTTL:         time.Hour,
		refreshTTL:        30 * 24 * time.Hour,
		requestTTL:        ttl,
		now:               now,
	}, nil
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

func codeChallenge(challenge, method string) *oidc.CodeChallenge {
	if challenge == "" {
		return nil
	}
	return &oidc.CodeChallenge{Challenge: challenge, Method: oidc.CodeChallengeMethod(method)}
}

// --- op.AuthStorage ---

// CreateAuthRequest implements op.Storage.
func (s *OIDCStore) CreateAuthRequest(_ context.Context, req *oidc.AuthRequest, userID string) (op.AuthRequest, error) {
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
	s.mu.Lock()
	defer s.mu.Unlock()
	a := &oidcstore.AuthRequest{
		ID: id, ClientID: req.ClientID, RedirectURI: req.RedirectURI,
		ResponseType: req.ResponseType, ResponseMode: req.ResponseMode,
		Scopes: append([]string(nil), req.Scopes...), State: req.State, Nonce: req.Nonce,
		CodeChallenge: codeChallenge(challenge, method),
		Subject:       userID,
	}
	s.authRequests[id] = a
	s.authRequestExpiry[id] = s.now().Add(s.requestTTL)
	return a, nil
}

// AuthRequestByID implements op.Storage.
func (s *OIDCStore) AuthRequestByID(_ context.Context, id string) (op.AuthRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.authRequests[id]
	if !ok {
		return nil, errors.New("memory: auth request not found")
	}
	return cloneAuthRequest(a), nil
}

// AuthRequestByCode implements op.Storage.
func (s *OIDCStore) AuthRequestByCode(_ context.Context, code string) (op.AuthRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.codes[oauth.TokenHash(code)]
	if !ok || !s.now().Before(c.expiresAt) {
		return nil, errors.New("memory: authorization code is unknown or expired")
	}
	a, ok := s.authRequests[c.requestID]
	if !ok {
		return nil, errors.New("memory: auth request not found")
	}
	return cloneAuthRequest(a), nil
}

func cloneAuthRequest(a *oidcstore.AuthRequest) *oidcstore.AuthRequest {
	out := *a
	out.Scopes = append([]string(nil), a.Scopes...)
	return &out
}

// SaveAuthCode implements op.Storage.
func (s *OIDCStore) SaveAuthCode(_ context.Context, id, code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes[oauth.TokenHash(code)] = codeRecord{requestID: id, expiresAt: s.now().Add(s.requestTTL)}
	return nil
}

// DeleteAuthRequest implements op.Storage.
func (s *OIDCStore) DeleteAuthRequest(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.authRequests, id)
	delete(s.authRequestExpiry, id)
	for k, c := range s.codes {
		if c.requestID == id {
			delete(s.codes, k)
		}
	}
	return nil
}

// CreateAccessToken implements op.Storage.
func (s *OIDCStore) CreateAccessToken(_ context.Context, request op.TokenRequest) (string, time.Time, error) {
	id, err := oidcstore.RandomValue()
	if err != nil {
		return "", time.Time{}, err
	}
	now := s.now()
	expires := now.Add(s.accessTTL)
	t := accessToken{
		id: id, clientID: oidcstore.ClientIDOf(request), subject: request.GetSubject(),
		scopes:   oidcstore.NonNil(oidcstore.WithoutOfflineAccess(request.GetScopes())),
		issuedAt: now, expiresAt: expires,
	}
	s.mu.Lock()
	s.accessTokens[oauth.TokenHash(id)] = t
	s.mu.Unlock()
	s.record(context.Background(), "oidc.token", request.GetSubject(), t.clientID, audit.OutcomeOK)
	return id, expires, nil
}

// CreateAccessAndRefreshTokens implements op.Storage. Refresh tokens rotate:
// presenting one consumes it and issues a new one.
//
// The claim on the presented token and both writes happen under ONE lock. That
// is not tidiness: rotating as "read it now, delete it later" leaves a window in
// which two requests holding the same refresh token are both honoured, and the
// window is invisible to the race detector — the two critical sections never
// overlap, so there is no data race to find. The consequence is worse than one
// extra token: rotation never notices the reuse, so a stolen refresh token can be
// replayed indefinitely alongside the victim's own client, and nothing ever
// signals that it happened.
//
// The presented token is checked, not assumed. A request that arrives with a
// token this store no longer holds is refused rather than quietly minting a
// replacement, so a replay fails instead of succeeding twice.
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

	// Everything that can fail has failed by now, so the critical section below
	// cannot leave a claimed-but-unreplaced refresh token behind.
	now := s.now()
	expires := now.Add(s.accessTTL)
	access := accessToken{
		id: accessID, clientID: oidcstore.ClientIDOf(request), subject: request.GetSubject(),
		scopes:   oidcstore.NonNil(oidcstore.WithoutOfflineAccess(request.GetScopes())),
		issuedAt: now, expiresAt: expires,
	}
	refresh := refreshToken{
		valueHash: oauth.TokenHash(value),
		idHash:    oauth.TokenHash(accessID),
		clientID:  oidcstore.ClientIDOf(request),
		subject:   request.GetSubject(),
		scopes:    oidcstore.NonNil(oidcstore.WithoutOfflineAccess(request.GetScopes())),
		amr:       amr,
		audience:  audience,
		authTime:  authTime,
		issuedAt:  now,
		expiresAt: now.Add(s.refreshTTL),
	}

	s.mu.Lock()
	if currentRefreshToken != "" {
		spent := oauth.TokenHash(currentRefreshToken)
		if _, held := s.refreshTokens[spent]; !held {
			s.mu.Unlock()
			return "", "", time.Time{}, ErrRefreshTokenSpent
		}
		delete(s.refreshTokens, spent)
	}
	s.accessTokens[oauth.TokenHash(accessID)] = access
	s.refreshTokens[oauth.TokenHash(value)] = refresh
	s.mu.Unlock()

	s.record(ctx, "oidc.token", request.GetSubject(), access.clientID, audit.OutcomeOK)
	return accessID, value, expires, nil
}

// TokenRequestByRefreshToken implements op.Storage.
func (s *OIDCStore) TokenRequestByRefreshToken(_ context.Context, value string) (op.RefreshTokenRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.refreshTokens[oauth.TokenHash(value)]
	if !ok || !s.now().Before(r.expiresAt) {
		return nil, errors.New("memory: invalid refresh token")
	}
	return &oidcstore.RefreshRequest{
		IDHash: r.idHash, ClientID: r.clientID, Subject: r.subject,
		Scopes: append([]string(nil), r.scopes...), AMR: r.amr, Audience: r.audience, AuthTime: r.authTime,
	}, nil
}

// TerminateSession implements op.Storage.
func (s *OIDCStore) TerminateSession(_ context.Context, userID, clientID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, t := range s.accessTokens {
		if t.subject == userID && t.clientID == clientID {
			delete(s.accessTokens, k)
		}
	}
	for k, t := range s.refreshTokens {
		if t.subject == userID && t.clientID == clientID {
			delete(s.refreshTokens, k)
		}
	}
	return nil
}

// RevokeToken implements op.Storage. Access tokens arrive as the plaintext ID,
// refresh tokens as the plaintext value.
func (s *OIDCStore) RevokeToken(ctx context.Context, tokenOrTokenID, userID, clientID string) *oidc.Error {
	h := oauth.TokenHash(tokenOrTokenID)

	s.mu.Lock()
	if t, ok := s.accessTokens[h]; ok {
		if t.clientID != clientID {
			s.mu.Unlock()
			return oidc.ErrInvalidClient().WithDescription("token was not issued for this client")
		}
		delete(s.accessTokens, h)
		s.mu.Unlock()
		s.record(ctx, "oidc.revoke", userID, clientID, audit.OutcomeOK)
		return nil
	}
	if t, ok := s.refreshTokens[h]; ok {
		if t.clientID != clientID {
			s.mu.Unlock()
			return oidc.ErrInvalidClient().WithDescription("token was not issued for this client")
		}
		delete(s.refreshTokens, h)
		s.mu.Unlock()
		s.record(ctx, "oidc.revoke", userID, clientID, audit.OutcomeOK)
		return nil
	}
	s.mu.Unlock()
	// RFC 7009: revoking an unknown token is success.
	return nil
}

// GetRefreshTokenInfo implements op.Storage.
//
// The second return value is the identifier the library hands straight back to
// RevokeToken, which HASHES whatever it is given before looking it up (that is
// how a raw token from the wire is normally resolved). So the identifier has to
// be the raw refresh token value, not the row's hash — returning a hash made
// RevokeToken hash a hash, match nothing, and report success without deleting
// anything, so a refresh token could not be revoked at all.
//
// It is not a disclosure: this method is given the raw token as its argument.
func (s *OIDCStore) GetRefreshTokenInfo(_ context.Context, clientID, token string) (string, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.refreshTokens[oauth.TokenHash(token)]
	if !ok || t.clientID != clientID {
		return "", "", op.ErrInvalidRefreshToken
	}
	return t.subject, token, nil
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

// SetUserinfoFromToken implements op.Storage. Only `sub` is ever exposed
// (ADR-0001 O-3).
func (s *OIDCStore) SetUserinfoFromToken(_ context.Context, userinfo *oidc.UserInfo, _, subject, _ string) error {
	userinfo.Subject = subject
	return nil
}

// SetIntrospectionFromToken implements op.Storage.
func (s *OIDCStore) SetIntrospectionFromToken(_ context.Context, introspection *oidc.IntrospectionResponse, tokenID, subject, _ string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.accessTokens[oauth.TokenHash(tokenID)]
	if !ok || !s.now().Before(t.expiresAt) {
		return errors.New("memory: token not found")
	}
	introspection.Active = true
	introspection.Subject = subject
	introspection.ClientID = t.clientID
	introspection.Scope = append([]string(nil), t.scopes...)
	introspection.Expiration = oidc.FromTime(t.expiresAt)
	return nil
}

// GetPrivateClaimsFromScopes implements op.Storage.
func (s *OIDCStore) GetPrivateClaimsFromScopes(context.Context, string, string, []string) (map[string]any, error) {
	return nil, nil
}

// GetKeyByIDAndClientID implements op.Storage. JWT profile grant is not supported.
func (s *OIDCStore) GetKeyByIDAndClientID(context.Context, string, string) (*jose.JSONWebKey, error) {
	return nil, errors.New("memory: JWT profile grant is not supported")
}

// ValidateJWTProfileScopes implements op.Storage.
func (s *OIDCStore) ValidateJWTProfileScopes(_ context.Context, _ string, scopes []string) ([]string, error) {
	return scopes, nil
}

// Health implements op.Storage.
func (s *OIDCStore) Health(context.Context) error { return nil }

// --- op.DeviceAuthorizationStorage ---

func normalizeUserCode(code string) string {
	return strings.ToUpper(strings.ReplaceAll(code, "-", ""))
}

// StoreDeviceAuthorization implements op.Storage.
func (s *OIDCStore) StoreDeviceAuthorization(_ context.Context, clientID, deviceCode, userCode string, expires time.Time, scopes []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeExpiredDevicesLocked(s.now())
	if _, exists := s.userCodes[normalizeUserCode(userCode)]; exists {
		return op.ErrDuplicateUserCode
	}
	h := oauth.TokenHash(deviceCode)
	s.devices[h] = deviceRecord{
		deviceCodeHash: h, userCode: userCode, clientID: clientID,
		scopes: append([]string(nil), scopes...), expiresAt: expires,
	}
	s.userCodes[normalizeUserCode(userCode)] = h
	return nil
}

// GetDeviceAuthorizatonState implements op.Storage.
func (s *OIDCStore) GetDeviceAuthorizatonState(_ context.Context, clientID, deviceCode string) (*op.DeviceAuthorizationState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.devices[oauth.TokenHash(deviceCode)]
	if !ok || d.clientID != clientID {
		return nil, errors.New("memory: device authorization not found")
	}
	return d.state(), nil
}

func (d deviceRecord) state() *op.DeviceAuthorizationState {
	return &op.DeviceAuthorizationState{
		ClientID: d.clientID,
		Scopes:   append([]string(nil), d.scopes...),
		Expires:  d.expiresAt,
		Done:     d.done,
		Denied:   d.denied,
		Subject:  d.subject,
		AuthTime: d.authTime,
	}
}

// purgeExpiredDevicesLocked drops expired device authorizations. The caller
// holds the lock.
func (s *OIDCStore) purgeExpiredDevicesLocked(now time.Time) int {
	removed := 0
	for h, d := range s.devices {
		if now.After(d.expiresAt) {
			delete(s.devices, h)
			delete(s.userCodes, normalizeUserCode(d.userCode))
			removed++
		}
	}
	return removed
}

// SweepExpired removes every record whose deadline has passed and returns how
// many it removed.
//
// A lookup already refuses an expired record, but nothing removed it. That is
// the leak this closes: without a sweep the maps keep every token, code and
// pending request the deployment ever issued, for the life of the process. It
// matters twice over, because the calls that scan them under the store's single
// lock — Grants, RevokeGrant, RevokeTokens, DeleteAuthRequest — then get slower
// as the maps grow.
//
// No goroutine starts here, so a test can call it directly; the composition root
// runs it on a ticker. A record is removed only once a lookup would already
// refuse it, so a sweep can never revoke something still in use.
func (s *OIDCStore) SweepExpired() int {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()

	removed := 0
	for id, expires := range s.authRequestExpiry {
		if now.After(expires) {
			delete(s.authRequestExpiry, id)
			delete(s.authRequests, id)
			removed++
		}
	}
	for k, c := range s.codes {
		if now.After(c.expiresAt) {
			delete(s.codes, k)
			removed++
		}
	}
	for k, t := range s.accessTokens {
		if !now.Before(t.expiresAt) {
			delete(s.accessTokens, k)
			removed++
		}
	}
	for k, t := range s.refreshTokens {
		if !now.Before(t.expiresAt) {
			delete(s.refreshTokens, k)
			removed++
		}
	}
	removed += s.purgeExpiredDevicesLocked(now)
	return removed
}

// Counts is how many records each map currently holds.
type Counts struct {
	AuthRequests  int
	Codes         int
	AccessTokens  int
	RefreshTokens int
	Devices       int
}

// Records is the total number of records the store holds.
func (c Counts) Records() int {
	return c.AuthRequests + c.Codes + c.AccessTokens + c.RefreshTokens + c.Devices
}

// Counts reports the current size of each map. It exists so the sweep's effect
// is observable: a test asserts the maps stay bounded, and a benchmark reports
// the population it ran at rather than assuming it.
func (s *OIDCStore) Counts() Counts {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Counts{
		AuthRequests:  len(s.authRequests),
		Codes:         len(s.codes),
		AccessTokens:  len(s.accessTokens),
		RefreshTokens: len(s.refreshTokens),
		Devices:       len(s.devices),
	}
}

// --- consent / device UI helpers (app-owned, not part of op.Storage) ---

// CompleteLogin attaches the subject and the approved (possibly narrowed)
// scopes to a pending authorization request.
func (s *OIDCStore) CompleteLogin(_ context.Context, id, subject string, scopes []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.authRequests[id]
	if !ok {
		return errors.New("memory: auth request not found")
	}
	a.Subject = subject
	a.Scopes = append([]string(nil), scopes...)
	a.IsDone = true
	now := s.now()
	a.AuthTime = &now
	return nil
}

// DeviceByUserCode returns the pending device authorization for a user code.
func (s *OIDCStore) DeviceByUserCode(_ context.Context, userCode string) (*op.DeviceAuthorizationState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, ok := s.userCodes[normalizeUserCode(userCode)]
	if !ok {
		return nil, errors.New("memory: device authorization not found")
	}
	d, ok := s.devices[h]
	if !ok {
		return nil, errors.New("memory: device authorization not found")
	}
	return d.state(), nil
}

// ApproveDevice marks a device authorization approved. A nil scopes slice keeps
// the requested scopes; an explicit slice narrows them.
func (s *OIDCStore) ApproveDevice(_ context.Context, userCode, subject string, scopes []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, ok := s.userCodes[normalizeUserCode(userCode)]
	if !ok {
		return errors.New("memory: device authorization not found")
	}
	d := s.devices[h]
	d.done = true
	d.subject = subject
	d.authTime = s.now()
	if scopes != nil {
		d.scopes = append([]string(nil), scopes...)
	}
	s.devices[h] = d
	s.record(context.Background(), "oidc.device.approve", subject, d.clientID, audit.OutcomeOK)
	return nil
}

// DenyDevice marks a device authorization denied.
func (s *OIDCStore) DenyDevice(_ context.Context, userCode string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, ok := s.userCodes[normalizeUserCode(userCode)]
	if !ok {
		return errors.New("memory: device authorization not found")
	}
	d := s.devices[h]
	d.denied = true
	s.devices[h] = d
	s.record(context.Background(), "oidc.device.deny", "", d.clientID, audit.OutcomeDenied)
	return nil
}

// --- engine-neutral business-plane surface (same shapes as oauth.Service) ---

// Grants lists what each client can still do as this subject, derived from the
// live tokens. It mirrors postgres.OIDCStore.Grants.
func (s *OIDCStore) Grants(ctx context.Context, subject string) ([]oauth.Grant, error) {
	if subject == "" {
		return nil, errors.New("memory: subject is required")
	}
	s.mu.Lock()
	byClient := make(map[string]*oauth.Grant)
	collect := func(clientID string, scopes []string, issued, expires time.Time, refresh bool) {
		if !expires.After(s.now()) {
			return
		}
		g, ok := byClient[clientID]
		if !ok {
			g = &oauth.Grant{ClientID: clientID, IssuedAt: issued, ExpiresAt: expires}
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
		if refresh {
			g.HasRefresh = true
		}
	}
	for _, t := range s.accessTokens {
		if t.subject == subject {
			collect(t.clientID, t.scopes, t.issuedAt, t.expiresAt, false)
		}
	}
	for _, t := range s.refreshTokens {
		if t.subject == subject {
			collect(t.clientID, t.scopes, t.issuedAt, t.expiresAt, true)
		}
	}
	s.mu.Unlock()

	out := make([]oauth.Grant, 0, len(byClient))
	for _, g := range byClient {
		if c, err := s.clients.Get(ctx, g.ClientID); err == nil {
			g.ClientName = c.Name
		}
		sortScopes(g.Scopes)
		out = append(out, *g)
	}
	sortGrants(out)
	return out, nil
}

// RevokeGrant removes every token a client holds for a subject.
func (s *OIDCStore) RevokeGrant(ctx context.Context, subject, clientID string) error {
	if subject == "" || clientID == "" {
		return errors.New("memory: subject and client id are required")
	}
	s.mu.Lock()
	for k, t := range s.accessTokens {
		if t.subject == subject && t.clientID == clientID {
			delete(s.accessTokens, k)
		}
	}
	for k, t := range s.refreshTokens {
		if t.subject == subject && t.clientID == clientID {
			delete(s.refreshTokens, k)
		}
	}
	s.mu.Unlock()
	s.record(ctx, "oidc.grant.revoke", subject, clientID, audit.OutcomeOK)
	return nil
}

// RevokeTokens implements oauth.TokenAdmin. It counts both tables, so a Kill
// Switch report has a number an operator can act on.
func (s *OIDCStore) RevokeTokens(_ context.Context, f oauth.TokenFilter) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for k, t := range s.accessTokens {
		if f.Matches(t.clientID, t.subject) {
			delete(s.accessTokens, k)
			removed++
		}
	}
	for k, t := range s.refreshTokens {
		if f.Matches(t.clientID, t.subject) {
			delete(s.refreshTokens, k)
			removed++
		}
	}
	return removed, nil
}

// PurgeSubject removes a subject's non-token state: pending consent requests,
// the codes minted from them, and device authorizations. It is the in-memory twin
// of the Postgres store's method, and the same split applies — issued tokens are
// RevokeTokens' job, not this one.
func (s *OIDCStore) PurgeSubject(_ context.Context, subject string) (int, error) {
	if subject == "" {
		return 0, errors.New("memory: subject is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	purged := make(map[string]bool)
	for id, req := range s.authRequests {
		if req.Subject == subject {
			delete(s.authRequests, id)
			delete(s.authRequestExpiry, id)
			purged[id] = true
			removed++
		}
	}
	// Codes hang off their request, so they go with it rather than waiting for the
	// sweep to expire them. Leaving them behind would keep a usable authorization
	// code alive after the account it belongs to was erased.
	for k, c := range s.codes {
		if purged[c.requestID] {
			delete(s.codes, k)
			removed++
		}
	}
	for k, d := range s.devices {
		if d.subject == subject {
			delete(s.userCodes, normalizeUserCode(d.userCode))
			delete(s.devices, k)
			removed++
		}
	}
	return removed, nil
}

// DescribeDeviceAuthorization is the device verification page's view of a
// pending device grant.
func (s *OIDCStore) DescribeDeviceAuthorization(ctx context.Context, userCode string) (oauth.DeviceAuthorization, error) {
	st, err := s.DeviceByUserCode(ctx, userCode)
	if err != nil || st.Done || st.Denied || s.now().After(st.Expires) {
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
	if err != nil || st.Done || st.Denied || s.now().After(st.Expires) {
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

func sortScopes(scopes []oauth.Scope) {
	sort.Slice(scopes, func(i, j int) bool { return scopes[i] < scopes[j] })
}

func sortGrants(grants []oauth.Grant) {
	sort.Slice(grants, func(i, j int) bool { return grants[i].ClientID < grants[j].ClientID })
}
