package oauth

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Re0Auth/r0semi/audit"
)

// Device flow defaults. RFC 8628 §3.5 makes the interval a floor the client must
// respect, not a promise the server makes.
const (
	defaultDeviceCodeTTL      = 10 * time.Minute
	defaultDevicePollInterval = 5 * time.Second
	// defaultVerificationPath is the path a deployment with no separate frontend
	// serves the verification page at. A deployment that has one overrides it to
	// point at a real page.
	defaultVerificationPath = "/device"

	// userCodeLen is the number of significant characters in a user code.
	userCodeLen = 8
	// userCodeAlphabet omits vowels (no accidental words) and glyphs that are
	// easy to misread (0/O, 1/I/L, 2/Z, 5/S, 8/B).
	userCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ"
)

// ErrDeviceNotFound reports an unknown, already-decided or expired device
// authorization. The caller maps it to a 404 or to expired_token.
var ErrDeviceNotFound = errors.New("oauth: device authorization not found")

// DeviceStatus is the lifecycle of a device authorization.
type DeviceStatus string

const (
	DevicePending  DeviceStatus = "pending"
	DeviceApproved DeviceStatus = "approved"
	DeviceDenied   DeviceStatus = "denied"
)

// DeviceAuthorizationRequest starts an RFC 8628 device authorization.
type DeviceAuthorizationRequest struct {
	ClientID string
	Scopes   []Scope
}

// DeviceAuthorizationResponse is the RFC 8628 §3.2 payload handed to the client.
// It is the only time the device_code is ever transmitted.
type DeviceAuthorizationResponse struct {
	DeviceCode              string
	UserCode                string
	VerificationURI         string
	VerificationURIComplete string
	ExpiresIn               int64
	Interval                int64
}

// DeviceCodeExchangeRequest is the device_code grant at the token endpoint
// (RFC 8628 §3.4).
type DeviceCodeExchangeRequest struct {
	ClientID     string
	ClientSecret string
	DeviceCode   string
}

// DeviceAuthorization is a pending request as the verification page sees it. It
// carries no device code and issues nothing.
type DeviceAuthorization struct {
	UserCode  string
	Client    Client
	Scopes    []Descriptor
	ExpiresAt time.Time
}

// DeviceAuthorizationRecord is the persisted pending request.
type DeviceAuthorizationRecord struct {
	// DeviceCodeHash is the at-rest form of the device code, set by the store.
	// The plaintext device code is never persisted: like an access token it is
	// a bearer secret.
	DeviceCodeHash string
	UserCode       string
	ClientID       string
	Scopes         []Scope
	Status         DeviceStatus
	Subject        string // set on approval
	Explicit       []Scope
	ExpiresAt      time.Time
	LastPoll       time.Time
}

// DeviceStore persists pending device authorizations, keyed by device code and
// by user code. It is kept separate from Store so an implementation can adopt
// the device flow without touching its token storage.
//
// SaveDevice and GetDevice take the plaintext device code; the store keys on
// TokenHash(deviceCode) and stores only the hash. The user code is not a secret
// (it is displayed to the user), so it is stored as-is.
type DeviceStore interface {
	SaveDevice(ctx context.Context, deviceCode string, d DeviceAuthorizationRecord) error
	GetDevice(ctx context.Context, deviceCode string) (DeviceAuthorizationRecord, error)
	GetDeviceByUserCode(ctx context.Context, userCode string) (DeviceAuthorizationRecord, error)
	UpdateDevice(ctx context.Context, d DeviceAuthorizationRecord) error
}

// MemoryDeviceStore is a non-durable DeviceStore for development and tests.
type MemoryDeviceStore struct {
	mu     sync.Mutex
	byDev  map[string]DeviceAuthorizationRecord
	byUser map[string]string // normalized user code -> device code hash
}

// NewMemoryDeviceStore returns an empty store.
func NewMemoryDeviceStore() *MemoryDeviceStore {
	return &MemoryDeviceStore{
		byDev:  make(map[string]DeviceAuthorizationRecord),
		byUser: make(map[string]string),
	}
}

// SaveDevice implements DeviceStore.
func (s *MemoryDeviceStore) SaveDevice(_ context.Context, deviceCode string, d DeviceAuthorizationRecord) error {
	d.DeviceCodeHash = TokenHash(deviceCode)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.byDev[d.DeviceCodeHash] = d
	s.byUser[NormalizeUserCode(d.UserCode)] = d.DeviceCodeHash
	return nil
}

// GetDevice implements DeviceStore.
func (s *MemoryDeviceStore) GetDevice(_ context.Context, deviceCode string) (DeviceAuthorizationRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.byDev[TokenHash(deviceCode)]
	if !ok {
		return DeviceAuthorizationRecord{}, ErrDeviceNotFound
	}
	return d, nil
}

// GetDeviceByUserCode implements DeviceStore.
func (s *MemoryDeviceStore) GetDeviceByUserCode(_ context.Context, userCode string) (DeviceAuthorizationRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	hash, ok := s.byUser[NormalizeUserCode(userCode)]
	if !ok {
		return DeviceAuthorizationRecord{}, ErrDeviceNotFound
	}
	d, ok := s.byDev[hash]
	if !ok {
		return DeviceAuthorizationRecord{}, ErrDeviceNotFound
	}
	return d, nil
}

// UpdateDevice implements DeviceStore.
func (s *MemoryDeviceStore) UpdateDevice(_ context.Context, d DeviceAuthorizationRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byDev[d.DeviceCodeHash] = d
	s.byUser[NormalizeUserCode(d.UserCode)] = d.DeviceCodeHash
	return nil
}

// BeginDeviceAuthorization starts a device authorization. The scopes are
// validated here, exactly as the interactive flow validates them, so an
// unregistered client or scope fails before any user is bothered.
func (s *service) BeginDeviceAuthorization(ctx context.Context, req DeviceAuthorizationRequest) (DeviceAuthorizationResponse, error) {
	client, _, err := s.describeScopes(ctx, req.ClientID, req.Scopes)
	if err != nil {
		return DeviceAuthorizationResponse{}, err
	}

	deviceCode, err := newToken()
	if err != nil {
		return DeviceAuthorizationResponse{}, err
	}
	userCode, err := s.freeUserCode(ctx)
	if err != nil {
		return DeviceAuthorizationResponse{}, err
	}

	if err := s.devices.SaveDevice(ctx, deviceCode, DeviceAuthorizationRecord{
		UserCode:  userCode,
		ClientID:  client.ID,
		Scopes:    append([]Scope(nil), req.Scopes...),
		Status:    DevicePending,
		ExpiresAt: s.now().Add(s.deviceTTL),
	}); err != nil {
		return DeviceAuthorizationResponse{}, err
	}

	s.record(ctx, "oauth.device.begin", "", client.ID, audit.OutcomeOK)
	verify := strings.TrimRight(s.issuer, "/") + s.verifyPath
	// RFC 8628 §3.2: interval is in seconds and the client must respect it.
	interval := int64(s.pollInterval / time.Second)
	if interval < 1 {
		interval = 1
	}
	return DeviceAuthorizationResponse{
		DeviceCode:              deviceCode,
		UserCode:                userCode,
		VerificationURI:         verify,
		VerificationURIComplete: verify + "?user_code=" + url.QueryEscape(userCode),
		ExpiresIn:               int64(s.deviceTTL / time.Second),
		Interval:                interval,
	}, nil
}

// PollDeviceAuthorization is the token-endpoint half of the device grant: it
// reports pending, denial or expiry as RFC 8628 §3.5 errors, and issues tokens
// only once the user has approved.
func (s *service) PollDeviceAuthorization(ctx context.Context, req DeviceCodeExchangeRequest) (TokenResponse, error) {
	client, err := s.client(ctx, req.ClientID, req.ClientSecret, true)
	if err != nil {
		return TokenResponse{}, err
	}
	rec, err := s.devices.GetDevice(ctx, req.DeviceCode)
	if errors.Is(err, ErrDeviceNotFound) {
		return TokenResponse{}, protocolError("invalid_grant", "device code is unknown")
	}
	if err != nil {
		return TokenResponse{}, err
	}
	if rec.ClientID != client.ID {
		return TokenResponse{}, protocolError("invalid_grant", "device code was issued to another client")
	}

	now := s.now()
	if !now.Before(rec.ExpiresAt) {
		return TokenResponse{}, protocolError("expired_token", "the device code has expired")
	}
	// Polling faster than the advertised interval is not an error to hide: we
	// tell the client to slow down, and do not stamp LastPoll, so backing off
	// for the full interval converges.
	if !rec.LastPoll.IsZero() && now.Before(rec.LastPoll.Add(s.pollInterval)) {
		return TokenResponse{}, protocolError("slow_down", "polling faster than the advertised interval")
	}
	rec.LastPoll = now
	if err := s.devices.UpdateDevice(ctx, rec); err != nil {
		return TokenResponse{}, err
	}

	switch rec.Status {
	case DevicePending:
		return TokenResponse{}, protocolError("authorization_pending", "the user has not decided yet")
	case DeviceDenied:
		return TokenResponse{}, protocolError("access_denied", "the user denied the request")
	}
	return s.issue(ctx, client.ID, rec.Subject, rec.Scopes)
}

// DescribeDeviceAuthorization returns what the verification page must render.
func (s *service) DescribeDeviceAuthorization(ctx context.Context, userCode string) (DeviceAuthorization, error) {
	rec, err := s.devices.GetDeviceByUserCode(ctx, userCode)
	if errors.Is(err, ErrDeviceNotFound) {
		return DeviceAuthorization{}, ErrDeviceNotFound
	}
	if err != nil {
		return DeviceAuthorization{}, err
	}
	if !s.now().Before(rec.ExpiresAt) {
		return DeviceAuthorization{}, ErrDeviceNotFound
	}
	if rec.Status != DevicePending {
		return DeviceAuthorization{}, ErrDeviceNotFound
	}
	client, descriptors, err := s.describeScopes(ctx, rec.ClientID, rec.Scopes)
	if err != nil {
		return DeviceAuthorization{}, err
	}
	return DeviceAuthorization{
		UserCode:  rec.UserCode,
		Client:    client,
		Scopes:    descriptors,
		ExpiresAt: rec.ExpiresAt,
	}, nil
}

// DecideDeviceAuthorization records the user's approval or denial. An approval
// may only narrow the scopes and must individually tick every critical one,
// exactly like the interactive consent decision.
func (s *service) DecideDeviceAuthorization(ctx context.Context, userCode, subject string, approve bool, scopes, explicit []Scope) error {
	if subject == "" {
		return protocolError("access_denied", "user is not authenticated")
	}
	rec, err := s.devices.GetDeviceByUserCode(ctx, userCode)
	if errors.Is(err, ErrDeviceNotFound) {
		return ErrDeviceNotFound
	}
	if err != nil {
		return err
	}
	if !s.now().Before(rec.ExpiresAt) {
		return ErrDeviceNotFound
	}
	if rec.Status != DevicePending {
		return protocolError("invalid_request", "the request has already been decided")
	}

	if !approve {
		rec.Status = DeviceDenied
		if err := s.devices.UpdateDevice(ctx, rec); err != nil {
			return err
		}
		s.record(ctx, "oauth.device.deny", subject, rec.ClientID, audit.OutcomeDenied)
		return nil
	}

	granted := rec.Scopes
	if len(scopes) > 0 {
		for _, sc := range scopes {
			if !containsScope(rec.Scopes, sc) {
				return protocolError("invalid_scope", "the decision cannot widen the requested scope")
			}
		}
		granted = scopes
	}
	_, descriptors, err := s.describeScopes(ctx, rec.ClientID, granted)
	if err != nil {
		return err
	}
	if err := checkExplicit(descriptors, explicit); err != nil {
		return err
	}

	rec.Status = DeviceApproved
	rec.Subject = subject
	rec.Scopes = append([]Scope(nil), granted...)
	rec.Explicit = append([]Scope(nil), explicit...)
	if err := s.devices.UpdateDevice(ctx, rec); err != nil {
		return err
	}
	s.record(ctx, "oauth.device.approve", subject, rec.ClientID, audit.OutcomeOK)
	return nil
}

// describeScopes validates a client and its requested scopes without the
// redirect_uri/PKCE requirements of the interactive flow.
func (s *service) describeScopes(ctx context.Context, clientID string, scopes []Scope) (Client, []Descriptor, error) {
	client, err := s.client(ctx, clientID, "", false)
	if err != nil {
		return Client{}, nil, err
	}
	descriptors, err := s.scopes.Resolve(scopes, client.ID)
	if err != nil {
		return Client{}, nil, protocolError("invalid_scope", err.Error())
	}
	for _, sc := range scopes {
		if !client.AllowsScope(sc) {
			return Client{}, nil, protocolError("invalid_scope", "client is not registered for "+sc.String())
		}
	}
	return client, descriptors, nil
}

func (s *service) freeUserCode(ctx context.Context) (string, error) {
	for attempt := 0; attempt < 8; attempt++ {
		code, err := newUserCode()
		if err != nil {
			return "", err
		}
		if _, err := s.devices.GetDeviceByUserCode(ctx, code); errors.Is(err, ErrDeviceNotFound) {
			return code, nil
		}
	}
	return "", errors.New("oauth: could not allocate a unique user code")
}

// checkExplicit enforces that every critical scope was individually approved.
func checkExplicit(descriptors []Descriptor, explicit []Scope) error {
	ticked := make(map[Scope]struct{}, len(explicit))
	for _, sc := range explicit {
		ticked[sc] = struct{}{}
	}
	for _, d := range descriptors {
		if d.ExplicitConsent {
			if _, ok := ticked[d.Scope]; !ok {
				return protocolError("access_denied", "explicit consent is required for "+d.Scope.String())
			}
		}
	}
	return nil
}

// newUserCode returns a code like "BCDF-GHJK", drawn uniformly from
// userCodeAlphabet with rejection sampling so no character is favoured.
func newUserCode() (string, error) {
	max := byte(256 - 256%len(userCodeAlphabet))
	raw := make([]byte, 0, userCodeLen)
	buf := make([]byte, 1)
	for len(raw) < userCodeLen {
		if _, err := rand.Read(buf); err != nil {
			return "", fmt.Errorf("oauth: random: %w", err)
		}
		if buf[0] >= max {
			continue
		}
		raw = append(raw, userCodeAlphabet[int(buf[0])%len(userCodeAlphabet)])
	}
	return string(raw[:userCodeLen/2]) + "-" + string(raw[userCodeLen/2:]), nil
}

// normalizeUserCode makes user codes case- and separator-insensitive, because

func NormalizeUserCode(s string) string {
	return strings.ReplaceAll(strings.ToUpper(strings.TrimSpace(s)), "-", "")
}
