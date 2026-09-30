package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
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
	if !validPKCEChallenge(req.CodeChallenge) || req.CodeChallengeMethod != "S256" {
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

	// Read first, spend second. ConsumeCode is a DELETE, so feeding it a request
	// whose bindings do not hold let anybody who merely came by a code — no
	// verifier, no client secret — burn it and deny the client that earned it
	// their tokens. That is a low-cost targeted denial of service, and it was
	// invisible: the refusal was identical to a replay and nothing was audited.
	//
	// GetCode is a read, so a caller that cannot prove it owns the code loses
	// nothing. Every binding is judged here, before anything is consumed, in the
	// order this endpoint has always judged them.
	code, err := s.tokens.GetCode(ctx, req.Code)
	if errors.Is(err, ErrTokenNotFound) {
		return TokenResponse{}, protocolError("invalid_grant", "authorization code is unknown or already used")
	}
	if err != nil {
		return TokenResponse{}, err
	}
	if err := s.checkCodeBinding(client, code, req); err != nil {
		// Failed but the code exists: the observability half of the finding. The
		// subject is the code's own, so an operator can see who was targeted; the
		// client is the authenticated caller, i.e. who tried.
		s.record(ctx, "oauth.exchange_failed", code.Subject, client.ID, audit.OutcomeDenied)
		return TokenResponse{}, err
	}

	// The atomic gate. ConsumeCode's DELETE is what decides single use: a
	// concurrent second request with the same valid code loses this race and is
	// refused below, so exactly one exchange can mint.
	claimed, err := s.tokens.ConsumeCode(ctx, req.Code)
	if errors.Is(err, ErrTokenNotFound) {
		// Never issued, or already spent — possibly by a request that won the
		// race between the read above and this claim.
		return TokenResponse{}, protocolError("invalid_grant", "authorization code is unknown or already used")
	}
	if err != nil {
		return TokenResponse{}, err
	}
	// Re-asserted on the record this request actually consumed. A code record is
	// immutable and the pre-check above already judged it, so this cannot fire
	// today; it is here so that only the record that won the claim may ever mint,
	// and so the bindings live in one helper applied to both reads.
	if err := s.checkCodeBinding(client, claimed, req); err != nil {
		s.record(ctx, "oauth.exchange_failed", claimed.Subject, client.ID, audit.OutcomeDenied)
		return TokenResponse{}, err
	}
	return s.issue(ctx, client.ID, claimed.Subject, claimed.Scopes, "")
}

// checkCodeBinding judges an authorization code record against the request about
// to redeem it, in the order the exchange has always used: expiry first, then the
// client, the redirect_uri and finally PKCE. Every failure is an invalid_grant
// (400), and the human-readable text each binding has always carried is kept so
// no client sees a change on the failure paths.
//
// It is one helper because it is applied twice: to the pre-flight read, whose
// failure must not spend the code, and to the record the atomic claim returned,
// which is the only record allowed to mint.
func (s *service) checkCodeBinding(client Client, code AuthorizationCode, req CodeExchangeRequest) error {
	if !s.now().Before(code.ExpiresAt) {
		return protocolError("invalid_grant", "authorization code has expired")
	}
	if code.ClientID != client.ID {
		return protocolError("invalid_grant", "authorization code was issued to another client")
	}
	if code.RedirectURI != req.RedirectURI {
		return protocolError("invalid_grant", "redirect_uri mismatch")
	}
	if !verifyPKCE(req.CodeVerifier, code.CodeChallenge, code.CodeChallengeMethod) {
		return protocolError("invalid_grant", "PKCE verification failed")
	}
	return nil
}

func (s *service) Refresh(ctx context.Context, req RefreshRequest) (TokenResponse, error) {
	client, err := s.client(ctx, req.ClientID, req.ClientSecret, true)
	if err != nil {
		return TokenResponse{}, err
	}

	// Ownership is judged BEFORE the value is spent, not after. ConsumeRefresh is
	// a DELETE: checking the client binding afterwards let any authenticated
	// client burn another client's refresh token simply by presenting it — the
	// refusal arrived, but the owner's token was already gone — and, now that a
	// spent value leaves a family tombstone, the owner's own retry was then
	// reported as a replay and revoked the whole family. TokenOwner is a read, so
	// a mismatch costs the caller nothing and takes nothing from the owner.
	//
	// An already-spent value is intentionally not resolvable this way (TokenOwner
	// reports ErrTokenNotFound for it, which keeps RFC 7009 revocation
	// idempotent); it falls through to ConsumeRefresh below, where the reuse
	// signal and its family revocation live.
	owner, err := s.tokens.TokenOwner(ctx, req.RefreshToken)
	switch {
	case err == nil && owner != client.ID:
		return TokenResponse{}, protocolError("invalid_grant", "refresh token was issued to another client")
	case err != nil && !errors.Is(err, ErrTokenNotFound):
		return TokenResponse{}, err
	}

	rt, err := s.tokens.ConsumeRefresh(ctx, req.RefreshToken)
	var reuse *RefreshReuseError
	switch {
	case errors.As(err, &reuse):
		// RFC 9700 §4.14.2: a token that is already spent means two parties hold
		// it, and the presentation is the theft signal. Revoke every generation of
		// the family before refusing, or the thief's current access and refresh
		// pair stays live for the rest of the refresh TTL.
		//
		// A failure here is returned as-is rather than swallowed into the refusal:
		// the caller must not be told "refused" while the family it asked to kill
		// is still alive. Failing closed is the only honest answer.
		if _, revErr := s.tokens.RevokeRefreshFamily(ctx, reuse.FamilyID); revErr != nil {
			return TokenResponse{}, revErr
		}
		// The spent record is gone, so there is no subject to name; the client is
		// known and is the half that can still be attributed. The outcome is denied
		// because this request was refused as a suspected replay.
		s.record(ctx, "oauth.reuse_detected", "", client.ID, audit.OutcomeDenied)
		return TokenResponse{}, protocolError("invalid_grant", "refresh token is unknown or already used")
	case errors.Is(err, ErrTokenNotFound):
		return TokenResponse{}, protocolError("invalid_grant", "refresh token is unknown or already used")
	case err != nil:
		return TokenResponse{}, err
	}
	if !s.now().Before(rt.ExpiresAt) {
		return TokenResponse{}, protocolError("invalid_grant", "refresh token has expired")
	}
	// Re-asserted on the record this request actually consumed. The pre-check
	// above already refused a foreign token and a record's owner cannot change,
	// but the binding is cheap and this is the value about to mint tokens.
	if rt.ClientID != client.ID {
		return TokenResponse{}, protocolError("invalid_grant", "refresh token was issued to another client")
	}

	scopes := rt.Scopes
	if len(req.Scopes) > 0 {
		for _, sc := range req.Scopes {
			if !slices.Contains(rt.Scopes, sc) {
				return TokenResponse{}, protocolError("invalid_scope", "refresh cannot widen the granted scope")
			}
		}
		scopes = req.Scopes
	}
	return s.issue(ctx, client.ID, rt.Subject, scopes, rt.FamilyID)
}

func (s *service) Revoke(ctx context.Context, req RevokeRequest) error {
	client, err := s.client(ctx, req.ClientID, req.ClientSecret, true)
	if err != nil {
		return err
	}
	// RFC 7009 §2.1: the server MUST verify that the token was issued to the
	// client making the request. Deleting by value alone let any registered client
	// revoke another client's tokens — and the refresh chain hanging off them —
	// simply by coming by the value.
	//
	// An unknown value and a value owned by somebody else are answered the same
	// way: the uniform, idempotent success. Confirming "that is not yours" would
	// turn this endpoint into an oracle for whether a stolen string is a live
	// token (G-8, docs/audit-7/findings/Z20-VERIFIED.md). The foreign branch
	// therefore revokes NOTHING — RFC 7009's verify, then do not advertise.
	owner, err := s.tokens.TokenOwner(ctx, req.Token)
	switch {
	case errors.Is(err, ErrTokenNotFound):
		return nil
	case err != nil:
		return err
	case owner != client.ID:
		return nil
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
	// A suspended or deleted client is reported as unknown by EVERY protocol
	// entrance (oauth/client.go ClientStatus): its token must not stay usable, or
	// the data plane keeps serving a client an operator has switched off. Consulted
	// after the expiry check so an already-dead token costs no lookup, and answered
	// as inactive rather than as an error so it is indistinguishable, to the caller,
	// from a token that never existed. `client()` is the same door every other
	// entrance (AuthenticateClient/Exchange/Refresh/Revoke) goes through.
	if _, err := s.clients.Get(ctx, at.ClientID); errors.Is(err, ErrClientNotFound) {
		return TokenInfo{Active: false}, nil
	} else if err != nil {
		return TokenInfo{}, err
	}
	return TokenInfo{
		Active:    true,
		Subject:   at.Subject,
		ClientID:  at.ClientID,
		Scopes:    at.Scopes,
		ExpiresAt: at.ExpiresAt,
	}, nil
}

// issue mints an access and refresh pair. familyID names the rotation family the
// pair joins: empty mints a new one (a first issuance — a code exchange or a
// device grant), and non-empty inherits the spent token's family (a rotation), so
// every generation descended from one authorization is revocable together.
//
// The same family goes on both records. The access token belongs to the chain
// too: it is minted alongside a refresh token and dies with the family when a
// replay is detected, otherwise the thief's current access token would outlive
// the revocation.
func (s *service) issue(ctx context.Context, clientID, subject string, scopes []Scope, familyID string) (TokenResponse, error) {
	at, err := newToken()
	if err != nil {
		return TokenResponse{}, err
	}
	rt, err := newToken()
	if err != nil {
		return TokenResponse{}, err
	}
	if familyID == "" {
		// A fresh generation is its own family. Drawn from the same CSPRNG as the
		// tokens: it is not a credential, but a guessable family id would let one
		// client's revocation name another's chain.
		if familyID, err = newToken(); err != nil {
			return TokenResponse{}, err
		}
	}
	now := s.now()
	access := AccessToken{
		ClientID: clientID, Subject: subject,
		Scopes:   append([]Scope(nil), scopes...),
		FamilyID: familyID,
		IssuedAt: now, ExpiresAt: now.Add(s.atTTL),
	}
	refresh := RefreshToken{
		ClientID: clientID, Subject: subject,
		Scopes:   append([]Scope(nil), scopes...),
		FamilyID: familyID,
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

// validPKCEChallenge reports whether challenge has the only shape an S256 PKCE
// challenge can have: the unpadded base64url encoding of a SHA-256 digest, which
// is exactly 43 characters drawn from [A-Za-z0-9_-] (RFC 7636 §4.2). It is shared
// by describe and verifyPKCE so the authorize-side admission and the
// exchange-side verification cannot drift apart: a challenge rejected at
// authorize must never have been acceptable at exchange, and vice versa.
//
// Known limit: §4.2 gives no way to refuse an upper-cased 43-character digest
// without the verifier, because uppercase letters are in the base64url alphabet.
// Such a challenge is shape-valid and is accepted here; it fails only at the
// exchange, where the constant-time comparison over the computed digest exposes
// it. That is a property of the format, not of this predicate.
func validPKCEChallenge(challenge string) bool {
	if len(challenge) != 43 {
		return false
	}
	for i := 0; i < len(challenge); i++ {
		c := challenge[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

func verifyPKCE(verifier, challenge, method string) bool {
	if verifier == "" || !validPKCEChallenge(challenge) || method != "S256" {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	got := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(got), []byte(challenge)) == 1
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
