package oauth

import (
	"context"
	"time"
)

// Error is an OAuth 2.0 protocol error (RFC 6749 §5.2).
type Error struct {
	Code        string
	Description string
}

func (e *Error) Error() string { return "oauth: " + e.Code + ": " + e.Description }

func protocolError(code, description string) *Error {
	return &Error{Code: code, Description: description}
}

// AuthorizationRequest carries an already-authenticated subject and the scopes
// the user approved on the consent screen.
type AuthorizationRequest struct {
	ClientID            string
	RedirectURI         string
	Subject             string
	Scopes              []Scope
	Explicit            []Scope // scopes the user individually ticked
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
}

// AuthorizationResponse is returned to the redirect URI.
type AuthorizationResponse struct {
	Code        string
	State       string
	RedirectURI string
}

// CodeExchangeRequest exchanges an authorization code for tokens.
type CodeExchangeRequest struct {
	ClientID     string
	ClientSecret string
	Code         string
	RedirectURI  string
	CodeVerifier string
}

// RefreshRequest rotates a refresh token.
type RefreshRequest struct {
	ClientID     string
	ClientSecret string
	RefreshToken string
	Scopes       []Scope // optional narrowing
}

// RevokeRequest revokes an access or refresh token.
type RevokeRequest struct {
	ClientID      string
	ClientSecret  string
	Token         string
	TokenTypeHint string
}

// TokenResponse is the token-endpoint payload.
type TokenResponse struct {
	AccessToken  string
	TokenType    string
	ExpiresIn    int64
	RefreshToken string
	Scope        string
}

// TokenInfo is the result of introspection.
type TokenInfo struct {
	Active    bool
	Subject   string
	ClientID  string
	Scopes    []Scope
	ExpiresAt time.Time
}

// AuthorizationDetails is the consent-screen view of a validated request. It
// carries no secret and issues nothing.
type AuthorizationDetails struct {
	Client Client
	Scopes []Descriptor
}

// Service is the oauth/as capability: the authorization server core.
//
// It is transport-agnostic. The HTTP layer is responsible for redirecting,
// rendering consent, and mapping *Error to the wire format; this service owns
// the protocol rules.
type Service interface {
	// DescribeAuthorization validates an authorization request without issuing
	// anything and returns what the consent screen must render.
	DescribeAuthorization(ctx context.Context, req AuthorizationRequest) (AuthorizationDetails, error)

	Authorize(ctx context.Context, req AuthorizationRequest) (AuthorizationResponse, error)
	Exchange(ctx context.Context, req CodeExchangeRequest) (TokenResponse, error)
	// BeginDeviceAuthorization starts an RFC 8628 device authorization.
	BeginDeviceAuthorization(ctx context.Context, req DeviceAuthorizationRequest) (DeviceAuthorizationResponse, error)
	// PollDeviceAuthorization is the token-endpoint half of the device grant.
	PollDeviceAuthorization(ctx context.Context, req DeviceCodeExchangeRequest) (TokenResponse, error)
	// DescribeDeviceAuthorization returns what the verification page renders.
	DescribeDeviceAuthorization(ctx context.Context, userCode string) (DeviceAuthorization, error)
	// DecideDeviceAuthorization records the user's approval or denial.
	DecideDeviceAuthorization(ctx context.Context, userCode, subject string, approve bool, scopes, explicit []Scope) error
	Refresh(ctx context.Context, req RefreshRequest) (TokenResponse, error)
	Revoke(ctx context.Context, req RevokeRequest) error
	Introspect(ctx context.Context, accessToken string) (TokenInfo, error)
	// AuthenticateClient checks client credentials. It is used by endpoints
	// that require a registered client but carry no grant, such as RFC 7662
	// introspection.
	AuthenticateClient(ctx context.Context, clientID, clientSecret string) error
}

// Config wires the authorization server.
type Config struct {
	// Issuer identifies this authorization server, e.g. "https://auth.r0semi.dev".
	Issuer string
	// Scopes is the scope catalog. Providers contribute descriptors to it.
	Scopes *Registry
	// AccessTokenTTL defaults to one hour.
	AccessTokenTTL time.Duration
	// RefreshTokenTTL defaults to thirty days.
	RefreshTokenTTL time.Duration
	// CodeTTL defaults to five minutes.
	CodeTTL time.Duration
	// Devices stores pending RFC 8628 device authorizations. Defaults to an
	// in-memory store.
	Devices DeviceStore
	// DeviceCodeTTL defaults to ten minutes.
	DeviceCodeTTL time.Duration
	// DevicePollInterval defaults to five seconds.
	DevicePollInterval time.Duration
	// Now supplies the current time; tests inject a fake clock.
	Now func() time.Time
}

const (
	defaultAccessTokenTTL  = time.Hour
	defaultRefreshTokenTTL = 30 * 24 * time.Hour
	defaultCodeTTL         = 5 * time.Minute
)
