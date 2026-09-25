// Package oidcstore holds the engine-neutral building blocks shared by every
// op.Storage adapter: the signing key, the op.Client adapter, the auth-request
// and refresh-request records, and the consent policy (scope narrowing and
// explicit consent).
//
// It exists so those pieces are written once. The Postgres adapter
// (internal/store/postgres) and the in-memory adapter (internal/store/memory)
// differ only in how they persist; a second copy of "can this decision widen
// the requested scope?" is exactly the kind of drift that would let one engine
// enforce a rule the other does not.
package oidcstore

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/Re0Auth/r0semi/oauth"
)

// Signer is the OP's RS256 signing key plus any retired public keys that must
// still verify previously issued id_tokens during a rotation. Key material is
// injected by the composition root; the adapter never generates or persists it.
type Signer struct {
	id      string
	key     *rsa.PrivateKey
	retired []RetiredSigningKey
}

// RetiredSigningKey is an old signing key kept for verification only.
type RetiredSigningKey struct {
	ID     string
	Public *rsa.PublicKey
}

// NewSigner wraps a private key.
func NewSigner(id string, key *rsa.PrivateKey) *Signer {
	return &Signer{id: id, key: key}
}

// WithRetired adds public keys that are published in the JWKS but never used to
// sign. They let a rotation overlap: new tokens use the current key, old ones
// still verify.
func (s *Signer) WithRetired(keys ...RetiredSigningKey) *Signer {
	s.retired = append(s.retired, keys...)
	return s
}

// ValidateSigner rejects a signing key set that could not produce verifiable
// id_tokens: no key, a key below 2048 bits, an empty or duplicate kid, or a kid
// reused between current and retired. A JWKS with duplicate kids is ambiguous,
// and a small RSA key is not a defensible signature at this tier.
func ValidateSigner(s *Signer) error {
	if s == nil || s.key == nil {
		return errors.New("oidcstore: signing key is required")
	}
	if s.id == "" {
		return errors.New("oidcstore: signing key id is required")
	}
	if s.key.N.BitLen() < 2048 {
		return fmt.Errorf("oidcstore: signing key must be at least 2048 bits, got %d", s.key.N.BitLen())
	}
	seen := map[string]bool{s.id: true}
	for _, r := range s.retired {
		if r.ID == "" {
			return errors.New("oidcstore: retired signing key id is required")
		}
		if r.Public == nil {
			return fmt.Errorf("oidcstore: retired signing key %q has no public key", r.ID)
		}
		if seen[r.ID] {
			return fmt.Errorf("oidcstore: duplicate signing key id %q", r.ID)
		}
		seen[r.ID] = true
	}
	return nil
}

// ID implements op.SigningKey.
func (s *Signer) ID() string { return s.id }

// SignatureAlgorithm implements op.SigningKey.
func (s *Signer) SignatureAlgorithm() jose.SignatureAlgorithm { return jose.RS256 }

// Key implements op.SigningKey (private key).
func (s *Signer) Key() any { return s.key }

// KeySet returns the current public key followed by every retired public key.
func (s *Signer) KeySet() []op.Key {
	out := make([]op.Key, 0, 1+len(s.retired))
	out = append(out, publicKey{s})
	for _, r := range s.retired {
		out = append(out, retiredPublicKey{id: r.ID, pub: r.Public})
	}
	return out
}

type publicKey struct{ *Signer }

func (p publicKey) Algorithm() jose.SignatureAlgorithm { return jose.RS256 }
func (p publicKey) Use() string                        { return "sig" }
func (p publicKey) Key() any                           { return &p.key.PublicKey }

type retiredPublicKey struct {
	id  string
	pub *rsa.PublicKey
}

func (k retiredPublicKey) ID() string                         { return k.id }
func (k retiredPublicKey) Algorithm() jose.SignatureAlgorithm { return jose.RS256 }
func (k retiredPublicKey) Use() string                        { return "sig" }
func (k retiredPublicKey) Key() any                           { return k.pub }

// ProviderClient adapts oauth.Client to op.Client. Secret verification stays in
// oauth.Client.Authenticate (SHA-256); the library never sees the hash.
type ProviderClient struct {
	Client   oauth.Client
	Registry *oauth.Registry
	// Login builds the consent URL for an auth request. It receives the raw id
	// and is bound to the request context by the adapter that built it.
	Login func(id string) string
}

func (c ProviderClient) GetID() string                    { return c.Client.ID }
func (c ProviderClient) RedirectURIs() []string           { return c.Client.RedirectURIs }
func (c ProviderClient) PostLogoutRedirectURIs() []string { return nil }
func (c ProviderClient) AccessTokenType() op.AccessTokenType {
	return op.AccessTokenTypeBearer
}
func (c ProviderClient) IDTokenLifetime() time.Duration       { return time.Hour }
func (c ProviderClient) DevMode() bool                        { return false }
func (c ProviderClient) IDTokenUserinfoClaimsAssertion() bool { return false }
func (c ProviderClient) ClockSkew() time.Duration             { return 0 }
func (c ProviderClient) RestrictAdditionalIdTokenScopes() func([]string) []string {
	return func(s []string) []string { return s }
}
func (c ProviderClient) RestrictAdditionalAccessTokenScopes() func([]string) []string {
	return func(s []string) []string { return s }
}

func (c ProviderClient) ApplicationType() op.ApplicationType {
	if c.Client.Type == oauth.ClientPublic {
		return op.ApplicationTypeNative
	}
	return op.ApplicationTypeWeb
}

func (c ProviderClient) AuthMethod() oidc.AuthMethod {
	if c.Client.Type == oauth.ClientPublic {
		return oidc.AuthMethodNone
	}
	return oidc.AuthMethodBasic
}

func (c ProviderClient) ResponseTypes() []oidc.ResponseType {
	return []oidc.ResponseType{oidc.ResponseTypeCode}
}

func (c ProviderClient) GrantTypes() []oidc.GrantType {
	return []oidc.GrantType{oidc.GrantTypeCode, oidc.GrantTypeRefreshToken, oidc.GrantTypeDeviceCode}
}

func (c ProviderClient) LoginURL(id string) string {
	if c.Login == nil {
		return "/login?authRequestID=" + id
	}
	return c.Login(id)
}

// IsScopeAllowed is the real scope gate: a scope is legal only if the catalog
// knows it AND the client was registered for it. This is what makes the OP's own
// scope validation consult our rules instead of silently dropping unknown
// scopes (ADR-0001 O-7).
func (c ProviderClient) IsScopeAllowed(scope string) bool {
	if c.Registry == nil {
		return false
	}
	s := oauth.Scope(scope)
	if _, ok := c.Registry.Get(s); !ok {
		return false
	}
	return c.Client.AllowsScope(s)
}

// AuthRequest implements op.AuthRequest. It is the consent record, so scopes can
// be narrowed here before the code is issued.
type AuthRequest struct {
	ID            string
	ClientID      string
	RedirectURI   string
	ResponseType  oidc.ResponseType
	ResponseMode  oidc.ResponseMode
	Scopes        []string
	State         string
	Nonce         string
	CodeChallenge *oidc.CodeChallenge
	Subject       string
	IsDone        bool
	AuthTime      *time.Time
}

func (a *AuthRequest) GetID() string                         { return a.ID }
func (a *AuthRequest) GetACR() string                        { return "" }
func (a *AuthRequest) GetAMR() []string                      { return nil }
func (a *AuthRequest) GetAudience() []string                 { return []string{a.ClientID} }
func (a *AuthRequest) GetClientID() string                   { return a.ClientID }
func (a *AuthRequest) GetCodeChallenge() *oidc.CodeChallenge { return a.CodeChallenge }
func (a *AuthRequest) GetNonce() string                      { return a.Nonce }
func (a *AuthRequest) GetRedirectURI() string                { return a.RedirectURI }
func (a *AuthRequest) GetResponseType() oidc.ResponseType    { return a.ResponseType }
func (a *AuthRequest) GetResponseMode() oidc.ResponseMode    { return a.ResponseMode }
func (a *AuthRequest) GetScopes() []string                   { return a.Scopes }
func (a *AuthRequest) GetState() string                      { return a.State }
func (a *AuthRequest) GetSubject() string                    { return a.Subject }
func (a *AuthRequest) GetAuthTime() time.Time {
	if a.AuthTime == nil {
		return time.Time{}
	}
	return *a.AuthTime
}
func (a *AuthRequest) Done() bool { return a.IsDone }

// RefreshRequest implements op.RefreshTokenRequest.
type RefreshRequest struct {
	IDHash   string
	ClientID string
	Subject  string
	Scopes   []string
	AMR      []string
	Audience []string
	AuthTime *time.Time
}

func (r *RefreshRequest) GetAMR() []string            { return r.AMR }
func (r *RefreshRequest) GetAudience() []string       { return r.Audience }
func (r *RefreshRequest) GetClientID() string         { return r.ClientID }
func (r *RefreshRequest) GetScopes() []string         { return r.Scopes }
func (r *RefreshRequest) GetSubject() string          { return r.Subject }
func (r *RefreshRequest) SetCurrentScopes(s []string) { r.Scopes = s }
func (r *RefreshRequest) GetAuthTime() time.Time {
	if r.AuthTime == nil {
		return time.Time{}
	}
	return *r.AuthTime
}

// SplitProtocolScopes partitions a scope set into the ones the catalogue
// describes and the OIDC-standard flags it deliberately does not.
//
// The catalogue is about data permissions. `openid` and `offline_access` are
// protocol flags, and `profile` / `email` / the other claim scopes are accepted
// as no-ops because userinfo returns only `sub` (O-3). The consent, device and
// token paths must all agree on this split, so it lives here rather than in one
// caller.
func SplitProtocolScopes(scopes []string) (described, protocol []string) {
	for _, s := range scopes {
		if StandardOIDCScope(s) {
			protocol = append(protocol, s)
			continue
		}
		described = append(described, s)
	}
	return described, protocol
}

// StandardOIDCScope reports whether scope is one the OP always accepts without
// consulting the catalogue (O-3, O-6).
func StandardOIDCScope(scope string) bool {
	switch scope {
	case oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail, oidc.ScopePhone, oidc.ScopeAddress, oidc.ScopeOfflineAccess:
		return true
	default:
		return false
	}
}

// DefaultDevicePollInterval is the minimum interval between device-code polls.
// It is the same value the OP advertises, so the protocol layer and the storage
// throttle cannot drift.
const DefaultDevicePollInterval = 5 * time.Second

// --- consent policy ---

// NarrowScopes validates that an approval only narrows the requested scope set.
// A nil approval means "everything requested" — the field was omitted. An
// explicit empty approval is refused rather than silently upgraded to the full
// request: "grant nothing" must not become "grant everything". Returning an error
// here (as a protocol error) is what keeps "approval can only narrow" true no
// matter which engine is running.
func NarrowScopes(requested []string, approved []oauth.Scope) ([]string, error) {
	if approved == nil {
		return requested, nil
	}
	if len(approved) == 0 {
		return nil, &oauth.Error{Code: "invalid_request", Description: "an approval must grant at least one scope; omit the field to grant the requested scopes"}
	}
	granted := make([]string, 0, len(approved))
	for _, s := range approved {
		if !HasScope(requested, s.String()) {
			return nil, &oauth.Error{Code: "invalid_scope", Description: "the decision cannot widen the requested scope"}
		}
		granted = append(granted, s.String())
	}
	return granted, nil
}

// RequireExplicitConsent rejects an approval that omitted a critical scope the
// user had to tick individually.
func RequireExplicitConsent(descriptors []oauth.Descriptor, explicit []oauth.Scope) error {
	ticked := make(map[oauth.Scope]struct{}, len(explicit))
	for _, s := range explicit {
		ticked[s] = struct{}{}
	}
	for _, d := range descriptors {
		if !d.ExplicitConsent {
			continue
		}
		if _, ok := ticked[d.Scope]; !ok {
			return &oauth.Error{Code: "access_denied", Description: "explicit consent is required for " + d.Scope.String()}
		}
	}
	return nil
}

// WithOfflineAccess appends the OIDC offline_access scope if absent, so the OP
// issues a refresh token (ADR-0001 O-6, revised).
func WithOfflineAccess(scopes []string) []string {
	if HasScope(scopes, oidc.ScopeOfflineAccess) {
		return scopes
	}
	return append(scopes, oidc.ScopeOfflineAccess)
}

// WithoutOfflineAccess removes offline_access before a scope list is stored or
// shown. Re0Auth always issues a refresh token, so offline_access is an internal
// trigger, not a scope the client should see (ADR-0001 O-6, revised).
func WithoutOfflineAccess(scopes []string) []string {
	out := make([]string, 0, len(scopes))
	for _, s := range scopes {
		if s != oidc.ScopeOfflineAccess {
			out = append(out, s)
		}
	}
	return out
}

// HasScope reports whether name is in the space-delimited-field list.
func HasScope(scopes []string, name string) bool {
	for _, s := range scopes {
		if s == name {
			return true
		}
	}
	return false
}

// ScopeStrings converts typed scopes to their wire form.
func ScopeStrings(scopes []oauth.Scope) []string {
	out := make([]string, len(scopes))
	for i, s := range scopes {
		out[i] = s.String()
	}
	return out
}

// Scopes converts wire-form scope strings to typed scopes.
func Scopes(in []string) []oauth.Scope {
	out := make([]oauth.Scope, len(in))
	for i, s := range in {
		out[i] = oauth.Scope(s)
	}
	return out
}

// NonNil keeps a nil slice from being persisted as SQL NULL; every array column
// is NOT NULL, and "no scopes" is an empty array, not a missing one.
func NonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// RandomValue returns a 256-bit opaque value, URL-safe and unpadded. It is how
// an adapter mints an id it will store only as a hash.
func RandomValue() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ClientIDOf returns the client id of a token request, for adapters that need
// to persist it. Token requests that carry no client id yield an empty string.
func ClientIDOf(request op.TokenRequest) string {
	if c, ok := request.(interface{ GetClientID() string }); ok {
		return c.GetClientID()
	}
	return ""
}

// ErrMissingSigner is returned when a store is built without a signing key.
var ErrMissingSigner = errors.New("oidcstore: signer is required")

// Trim is a tiny helper so callers do not each reimplement scope trimming.
func Trim(s string) string { return strings.TrimSpace(s) }
