package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Re0Auth/r0semi/audit"
)

type service struct {
	clients ClientRegistry
	tokens  Store
	devices DeviceStore
	audit   audit.Logger
	scopes  *Registry
	issuer  string

	atTTL        time.Duration
	rtTTL        time.Duration
	codeTTL      time.Duration
	deviceTTL    time.Duration
	pollInterval time.Duration
	verifyPath   string
	now          func() time.Time
}

func NewService(clients ClientRegistry, tokens Store, logger audit.Logger, cfg Config) (Service, error) {
	switch {
	case clients == nil:
		return nil, errors.New("oauth: ClientRegistry is required")
	case tokens == nil:
		return nil, errors.New("oauth: token Store is required")
	case logger == nil:
		return nil, errors.New("oauth: audit.Logger is required")
	case cfg.Issuer == "":
		return nil, errors.New("oauth: Config.Issuer is required")
	case cfg.Scopes == nil:
		return nil, errors.New("oauth: Config.Scopes registry is required")
	}
	if cfg.AccessTokenTTL <= 0 {
		cfg.AccessTokenTTL = defaultAccessTokenTTL
	}
	if cfg.RefreshTokenTTL <= 0 {
		cfg.RefreshTokenTTL = defaultRefreshTokenTTL
	}
	if cfg.CodeTTL <= 0 {
		cfg.CodeTTL = defaultCodeTTL
	}
	if cfg.Devices == nil {
		cfg.Devices = NewMemoryDeviceStore()
	}
	if cfg.DeviceCodeTTL <= 0 {
		cfg.DeviceCodeTTL = defaultDeviceCodeTTL
	}
	if cfg.DevicePollInterval <= 0 {
		cfg.DevicePollInterval = defaultDevicePollInterval
	}
	if cfg.VerificationPath == "" {
		cfg.VerificationPath = defaultVerificationPath
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &service{
		clients:      clients,
		tokens:       tokens,
		devices:      cfg.Devices,
		audit:        logger,
		scopes:       cfg.Scopes,
		issuer:       cfg.Issuer,
		atTTL:        cfg.AccessTokenTTL,
		rtTTL:        cfg.RefreshTokenTTL,
		codeTTL:      cfg.CodeTTL,
		deviceTTL:    cfg.DeviceCodeTTL,
		pollInterval: cfg.DevicePollInterval,
		verifyPath:   cfg.VerificationPath,
		now:          cfg.Now,
	}, nil
}

func (s *service) AuthenticateClient(ctx context.Context, clientID, clientSecret string) error {
	_, err := s.client(ctx, clientID, clientSecret, true)
	return err
}

// describe validates the parts of an authorization request that must hold
// before any consent is shown, and returns the client and scope descriptors.
func (s *service) describe(ctx context.Context, req AuthorizationRequest) (Client, []Descriptor, error) {
	client, err := s.client(ctx, req.ClientID, "", false)
	if err != nil {
		return Client{}, nil, err
	}
	if !client.AllowsRedirect(req.RedirectURI) {
		return Client{}, nil, protocolError("invalid_request", "redirect_uri is not registered")
	}
	if req.CodeChallenge == "" || req.CodeChallengeMethod != "S256" {
		return Client{}, nil, protocolError("invalid_request", "PKCE with S256 is required")
	}
	descriptors, err := s.scopes.Resolve(req.Scopes, client.ID)
	if err != nil {
		return Client{}, nil, protocolError("invalid_scope", err.Error())
	}
	for _, sc := range req.Scopes {
		if !client.AllowsScope(sc) {
			return Client{}, nil, protocolError("invalid_scope", "client is not registered for "+sc.String())
		}
	}
	return client, descriptors, nil
}

func (s *service) DescribeAuthorization(ctx context.Context, req AuthorizationRequest) (AuthorizationDetails, error) {
	client, descriptors, err := s.describe(ctx, req)
	if err != nil {
		return AuthorizationDetails{}, err
	}
	return AuthorizationDetails{Client: client, Scopes: descriptors}, nil
}

func (s *service) Authorize(ctx context.Context, req AuthorizationRequest) (AuthorizationResponse, error) {
	client, descriptors, err := s.describe(ctx, req)
	if err != nil {
		return AuthorizationResponse{}, err
	}
	if req.Subject == "" {
		return AuthorizationResponse{}, protocolError("access_denied", "user is not authenticated")
	}

	if err := checkExplicit(descriptors, req.Explicit); err != nil {
		return AuthorizationResponse{}, err
	}

	code, err := newToken()
	if err != nil {
		return AuthorizationResponse{}, err
	}
	rec := AuthorizationCode{
		ClientID:            client.ID,
		Subject:             req.Subject,
		Scopes:              append([]Scope(nil), req.Scopes...),
		RedirectURI:         req.RedirectURI,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		ExpiresAt:           s.now().Add(s.codeTTL),
	}
	if err := s.tokens.SaveCode(ctx, code, rec); err != nil {
		return AuthorizationResponse{}, err
	}
	s.record(ctx, "oauth.authorize", req.Subject, client.ID, audit.OutcomeOK)
	return AuthorizationResponse{Code: code, State: req.State, RedirectURI: req.RedirectURI}, nil
}

func (s *service) Exchange(ctx context.Context, req CodeExchangeRequest) (TokenResponse, error) {
	client, err := s.client(ctx, req.ClientID, req.ClientSecret, true)
	if err != nil {
		return TokenResponse{}, err
	}
	code, err := s.tokens.ConsumeCode(ctx, req.Code)
	if errors.Is(err, ErrTokenNotFound) {
		return TokenResponse{}, protocolError("invalid_grant", "authorization code is unknown or already used")
	}
	if err != nil {
		return TokenResponse{}, err
	}
	if !s.now().Before(code.ExpiresAt) {
		return TokenResponse{}, protocolError("invalid_grant", "authorization code has expired")
	}
	if code.ClientID != client.ID {
		return TokenResponse{}, protocolError("invalid_grant", "authorization code was issued to another client")
	}
	if code.RedirectURI != req.RedirectURI {
		return TokenResponse{}, protocolError("invalid_grant", "redirect_uri mismatch")
	}
	if !verifyPKCE(req.CodeVerifier, code.CodeChallenge, code.CodeChallengeMethod) {
		return TokenResponse{}, protocolError("invalid_grant", "PKCE verification failed")
	}
	return s.issue(ctx, client.ID, code.Subject, code.Scopes)
}

func (s *service) Refresh(ctx context.Context, req RefreshRequest) (TokenResponse, error) {
	client, err := s.client(ctx, req.ClientID, req.ClientSecret, true)
	if err != nil {
		return TokenResponse{}, err
	}
	rt, err := s.tokens.ConsumeRefresh(ctx, req.RefreshToken)
	if errors.Is(err, ErrTokenNotFound) {
		return TokenResponse{}, protocolError("invalid_grant", "refresh token is unknown or already used")
	}
	if err != nil {
		return TokenResponse{}, err
	}
	if !s.now().Before(rt.ExpiresAt) {
		return TokenResponse{}, protocolError("invalid_grant", "refresh token has expired")
	}
	if rt.ClientID != client.ID {
		return TokenResponse{}, protocolError("invalid_grant", "refresh token was issued to another client")
	}

	scopes := rt.Scopes
	if len(req.Scopes) > 0 {
		for _, sc := range req.Scopes {
			if !containsScope(rt.Scopes, sc) {
				return TokenResponse{}, protocolError("invalid_scope", "refresh cannot widen the granted scope")
			}
		}
		scopes = req.Scopes
	}
	return s.issue(ctx, client.ID, rt.Subject, scopes)
}

func (s *service) Revoke(ctx context.Context, req RevokeRequest) error {
	client, err := s.client(ctx, req.ClientID, req.ClientSecret, true)
	if err != nil {
		return err
	}
	// RFC 7009: revocation is idempotent, and the token may be either kind.
	if err := s.tokens.DeleteAccess(ctx, req.Token); err != nil {
		return err
	}
	if err := s.tokens.DeleteRefresh(ctx, req.Token); err != nil {
		return err
	}
	s.record(ctx, "oauth.revoke", "", client.ID, audit.OutcomeOK)
	return nil
}

func (s *service) Introspect(ctx context.Context, accessToken string) (TokenInfo, error) {
	at, err := s.tokens.GetAccess(ctx, accessToken)
	if errors.Is(err, ErrTokenNotFound) {
		return TokenInfo{Active: false}, nil
	}
	if err != nil {
		return TokenInfo{}, err
	}
	if !s.now().Before(at.ExpiresAt) {
		return TokenInfo{Active: false}, nil
	}
	return TokenInfo{
		Active:    true,
		Subject:   at.Subject,
		ClientID:  at.ClientID,
		Scopes:    at.Scopes,
		ExpiresAt: at.ExpiresAt,
	}, nil
}

func (s *service) issue(ctx context.Context, clientID, subject string, scopes []Scope) (TokenResponse, error) {
	at, err := newToken()
	if err != nil {
		return TokenResponse{}, err
	}
	rt, err := newToken()
	if err != nil {
		return TokenResponse{}, err
	}
	now := s.now()
	access := AccessToken{
		ClientID: clientID, Subject: subject,
		Scopes:   append([]Scope(nil), scopes...),
		IssuedAt: now, ExpiresAt: now.Add(s.atTTL),
	}
	refresh := RefreshToken{
		ClientID: clientID, Subject: subject,
		Scopes:   append([]Scope(nil), scopes...),
		IssuedAt: now, ExpiresAt: now.Add(s.rtTTL),
	}
	if err := s.tokens.SaveAccess(ctx, at, access); err != nil {
		return TokenResponse{}, err
	}
	if err := s.tokens.SaveRefresh(ctx, rt, refresh); err != nil {
		return TokenResponse{}, err
	}
	s.record(ctx, "oauth.token", subject, clientID, audit.OutcomeOK)
	return TokenResponse{
		AccessToken:  at,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.atTTL / time.Second),
		RefreshToken: rt,
		Scope:        joinScopes(scopes),
	}, nil
}

// client resolves a client and, when auth is set, authenticates a confidential
// one. Public clients have no secret; their code/refresh binding plus PKCE is
// what protects them.
func (s *service) client(ctx context.Context, id, secret string, auth bool) (Client, error) {
	c, err := s.clients.Get(ctx, id)
	if errors.Is(err, ErrClientNotFound) {
		return Client{}, protocolError("invalid_client", "unknown client")
	}
	if err != nil {
		return Client{}, err
	}
	if auth && c.Type == ClientConfidential && !c.Authenticate(secret) {
		return Client{}, protocolError("invalid_client", "invalid client credentials")
	}
	return c, nil
}

func (s *service) record(ctx context.Context, action, subject, clientID, outcome string) {
	_ = s.audit.Record(ctx, audit.Event{
		Action:   action,
		Subject:  subject,
		Provider: "oauth",
		Outcome:  outcome,
		Detail:   map[string]string{"client_id": clientID},
	})
}

func verifyPKCE(verifier, challenge, method string) bool {
	if verifier == "" || challenge == "" || method != "S256" {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	got := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(got), []byte(challenge)) == 1
}

func containsScope(scopes []Scope, want Scope) bool {
	for _, s := range scopes {
		if s == want {
			return true
		}
	}
	return false
}

func joinScopes(scopes []Scope) string {
	parts := make([]string, len(scopes))
	for i, s := range scopes {
		parts[i] = s.String()
	}
	return strings.Join(parts, " ")
}

func newToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("oauth: random: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
