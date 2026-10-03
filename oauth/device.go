package oauth

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/url"
	"slices"
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

// ErrUserCodeConflict reports a device-authorization write refused because the
// canonical user code already names another live request.
//
// S04-5: uniqueness is the store's canonical unique constraint's job, not a
// check-then-insert in oauth. A DeviceStore's SaveDevice MUST return an error
// wrapping this sentinel when the write violates the canonical user-code
// uniqueness — the dash-stripped uppercase form GetDeviceByUserCode looks up —
// and MUST NOT wrap any other failure as a conflict. oauth treats
// exactly this as a collision (redraw the user code) and every other error as
// fatal, so an infrastructure fault can no longer masquerade as an exhausted code
// space and a genuine collision can no longer be lost to a race between the
// pre-flight read and the insert.
var ErrUserCodeConflict = errors.New("oauth: user code already in use")

// DeviceStatus is the lifecycle of a device authorization.
type DeviceStatus string

const (
	DevicePending  DeviceStatus = "pending"
	DeviceApproved DeviceStatus = "approved"
	DeviceDenied   DeviceStatus = "denied"
)

// DeviceAuthorizationRequest starts an RFC 8628 device authorization.
//
// ClientSecret is the confidential client's credential (RFC 8628 §3.1 applies
// RFC 6749 §3.2.1): it may be empty for a public client, which authenticates with
// PKCE at redemption rather than a shared secret.
type DeviceAuthorizationRequest struct {
	ClientID     string
	ClientSecret string
	Scopes       []Scope
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

// DeviceDecision is the terminal outcome of a verification page: the status plus
// everything that comes with it.
//
// It is a value of its own rather than a whole DeviceAuthorizationRecord because
// a decision must be unable to touch the request's own fields (client, user code,
// expiry) as a side effect — and, more importantly, because deciding is a
// transition, not a write: see RecordDecision.
type DeviceDecision struct {
	Status   DeviceStatus
	Subject  string  // set on approval
	Scopes   []Scope // the granted set; may narrow the requested one
	Explicit []Scope
}

// DeviceStore persists pending device authorizations, keyed by device code and
// by user code. It is kept separate from Store so an implementation can adopt
// the device flow without touching its token storage.
//
// SaveDevice and GetDevice take the plaintext device code; the store keys on
// TokenHash(deviceCode) and stores only the hash. The user code is not a secret
// (it is displayed to the user), so it is stored as-is.
//
// The two writes are deliberately narrow. A poll and a decision arrive
// concurrently by nature — the client polls every few seconds while the user is
// looking at the page — so a store that accepted whole records would let a poll
// that read before the decision write its stale copy back afterwards, erasing the
// decision. That is the bug these method shapes exist to make unrepresentable.
type DeviceStore interface {
	// SaveDevice persists a new request. It is the authoritative uniqueness gate:
	// when the canonical user code already names a live record it MUST return an
	// error wrapping ErrUserCodeConflict, and any other failure MUST be returned
	// as itself. The GET-then-INSERT that used to live in oauth left a window
	// between the lookup and this write; the canonical unique constraint does not
	// (S04-5).
	SaveDevice(ctx context.Context, deviceCode string, d DeviceAuthorizationRecord) error
	GetDevice(ctx context.Context, deviceCode string) (DeviceAuthorizationRecord, error)
	GetDeviceByUserCode(ctx context.Context, userCode string) (DeviceAuthorizationRecord, error)
	// RecordPoll stamps the last poll, which is what the throttling check reads.
	// It records nothing else: a poll is not a decision.
	RecordPoll(ctx context.Context, deviceCodeHash string, at time.Time) error
	// RecordDecision records the user's decision, and only if the request has not
	// been decided yet: the first decision is final, so a concurrent approval
	// cannot overwrite a denial (or the reverse). It reports whether the decision
	// applied — false means the store refused it, because the request is unknown
	// or has already been decided.
	RecordDecision(ctx context.Context, deviceCodeHash string, d DeviceDecision) (bool, error)
	// ConsumeDevice atomically redeems an approved authorization: it hands the
	// record to exactly one caller and removes it, so one consent can be spent on
	// exactly one token pair. It reports ok=false without an error when the code
	// is unknown, was never approved, has already been redeemed, or has expired —
	// all of which the poll answers the same way, because none of them may issue.
	//
	// The read and the removal are one step on purpose. A GetDevice followed by a
	// delete would let two polls that both read "approved" both mint tokens from a
	// single approval.
	ConsumeDevice(ctx context.Context, deviceCodeHash string) (DeviceAuthorizationRecord, bool, error)
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

// SaveDevice implements DeviceStore. It mirrors the canonical unique constraint
// the PG store carries (0033): a normalized user code that already names a live
// record is ErrUserCodeConflict, a duplicate device-code hash is refused rather
// than silently overwriting the earlier authorization.
func (s *MemoryDeviceStore) SaveDevice(_ context.Context, deviceCode string, d DeviceAuthorizationRecord) error {
	d.DeviceCodeHash = TokenHash(deviceCode)
	canonical := NormalizeUserCode(d.UserCode)

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.byDev[d.DeviceCodeHash]; exists {
		return fmt.Errorf("oauth: device code already stored")
	}
	if _, taken := s.byUser[canonical]; taken {
		return fmt.Errorf("%w: %s", ErrUserCodeConflict, canonical)
	}
	s.byDev[d.DeviceCodeHash] = d
	s.byUser[canonical] = d.DeviceCodeHash
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

// RecordPoll implements DeviceStore.
func (s *MemoryDeviceStore) RecordPoll(_ context.Context, deviceCodeHash string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.byDev[deviceCodeHash]
	if !ok {
		return ErrDeviceNotFound
	}
	d.LastPoll = at
	s.byDev[deviceCodeHash] = d
	return nil
}

// RecordDecision implements DeviceStore. The status check and the write happen
// under one lock, so exactly one of two concurrent decisions applies.
func (s *MemoryDeviceStore) RecordDecision(_ context.Context, deviceCodeHash string, dec DeviceDecision) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.byDev[deviceCodeHash]
	if !ok || d.Status != DevicePending {
		return false, nil
	}
	d.Status = dec.Status
	d.Subject = dec.Subject
	d.Scopes = append([]Scope(nil), dec.Scopes...)
	d.Explicit = append([]Scope(nil), dec.Explicit...)
	s.byDev[deviceCodeHash] = d
	return true, nil
}

// ConsumeDevice implements DeviceStore. The status check and the removal happen
// under one lock, so exactly one of two concurrent polls redeems an approval; the
// loser is told ok=false rather than being handed the same consent again.
func (s *MemoryDeviceStore) ConsumeDevice(_ context.Context, deviceCodeHash string) (DeviceAuthorizationRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.byDev[deviceCodeHash]
	if !ok || d.Status != DeviceApproved {
		return DeviceAuthorizationRecord{}, false, nil
	}
	// Drop the user-code index entry only if it still points at this record: a
	// user code can be reused once its old record is gone, and deleting a newer
	// request's mapping would make that request unreachable from the page.
	if key := NormalizeUserCode(d.UserCode); s.byUser[key] == deviceCodeHash {
		delete(s.byUser, key)
	}
	delete(s.byDev, deviceCodeHash)
	return d, true, nil
}

// SweepExpired drops every device record whose deadline has passed and reports
// how many. It is the device store's counterpart to MemoryStore.SweepExpired.
//
// Expiry is already enforced on read, so this is not what makes an expired
// request unusable — it is what keeps the two maps from holding every request
// the process ever started, which is a leak with no other bound in a store that
// has no database behind it.
//
// The byUser index is keyed by normalized user code, and a user code can be
// reused once its old record is gone, so the index entry is dropped only when it
// still points at the record being removed; otherwise a sweep would delete the
// mapping of a newer request that happens to carry the same user code.
//
// Nothing calls it on a timer from inside this package: a deployment that runs
// this store either calls it from its own loop or accepts the growth, and saying
// so here is better than starting a goroutine a caller cannot stop.
func (s *MemoryDeviceStore) SweepExpired(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	removed := 0
	for devHash, rec := range s.byDev {
		if now.Before(rec.ExpiresAt) {
			continue
		}
		if key := NormalizeUserCode(rec.UserCode); s.byUser[key] == devHash {
			delete(s.byUser, key)
		}
		delete(s.byDev, devHash)
		removed++
	}
	return removed
}

// BeginDeviceAuthorization starts a device authorization.
//
// Unlike the interactive authorize endpoint, this one authenticates a
// confidential client (S04-2): the device holder cannot redeem without the
// secret anyway (PollDeviceAuthorization authenticates), so an anonymous start
// buys nothing but a consent screen that presents a trusted client's registered
// name to whoever follows the user_code. A public client keeps the "none" method
// — it has no secret and is bound by PKCE at redemption.
//
// The scopes are validated here too, so an unregistered client or scope fails
// before any user is bothered, and a request with no scopes is refused rather
// than minting a scope-less token pair (S04-9).
func (s *service) BeginDeviceAuthorization(ctx context.Context, req DeviceAuthorizationRequest) (DeviceAuthorizationResponse, error) {
	if len(req.Scopes) == 0 {
		return DeviceAuthorizationResponse{}, protocolError("invalid_scope", "scope is required")
	}
	client, _, err := s.describeAuthenticatedScopes(ctx, req.ClientID, req.ClientSecret, req.Scopes)
	if err != nil {
		return DeviceAuthorizationResponse{}, err
	}

	deviceCode, err := newToken()
	if err != nil {
		return DeviceAuthorizationResponse{}, err
	}
	// The candidate user code and the save are retried together on a conflict:
	// uniqueness is the store's canonical unique constraint's decision, and only
	// that conflict means "redraw". Any other save failure is the request's answer
	// (S04-5).
	userCode, err := s.saveDeviceAuthorization(ctx, deviceCode, DeviceAuthorizationRecord{
		ClientID:  client.ID,
		Scopes:    append([]Scope(nil), req.Scopes...),
		Status:    DevicePending,
		ExpiresAt: s.now().Add(s.deviceTTL),
	})
	if err != nil {
		return DeviceAuthorizationResponse{}, err
	}

	s.record(ctx, "oauth.device.begin", "", client.ID, audit.OutcomeOK)
	verify := strings.TrimRight(s.issuer, "/") + s.verifyPath
	// RFC 8628 §3.2: interval is in seconds and the client must respect it. It is
	// rounded UP: a 2500ms interval advertised as 2 truncates a floor into a
	// promise the server then punishes with slow_down (S04-6).
	interval := int64((s.pollInterval + time.Second - 1) / time.Second)
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
	// A decided request reports its outcome even to a poll that came too soon.
	// Throttling it first hid a denial (or an approval) behind slow_down, so a
	// client polling on its own faster cadence never learned the terminal answer
	// the user had already given (S04-6). The pending case below still throttles.
	switch rec.Status {
	case DeviceDenied:
		return TokenResponse{}, protocolError("access_denied", "the user denied the request")
	case DevicePending:
		// Polling faster than the advertised interval is not an error to hide: we
		// tell the client to slow down, and do not stamp LastPoll, so backing off
		// for the full interval converges.
		if !rec.LastPoll.IsZero() && now.Before(rec.LastPoll.Add(s.pollInterval)) {
			return TokenResponse{}, protocolError("slow_down", "polling faster than the advertised interval")
		}
		// Stamp the poll — and only the stamp. Writing the record read above back
		// would erase a decision that landed in between, which is exactly what
		// DeviceStore.RecordPoll exists to make impossible.
		if err := s.devices.RecordPoll(ctx, rec.DeviceCodeHash, now); err != nil {
			return TokenResponse{}, err
		}
		return TokenResponse{}, protocolError("authorization_pending", "the user has not decided yet")
	}
	// The read above saw an approval; only the consume may act on it. Issuing on
	// the strength of the read alone would mint a fresh token pair on every poll,
	// and would also silently revive an approval the user revoked in between.
	//
	// The revocation generation is captured before the consume (R10-19): a
	// RevokeGrant landing while this poll is between its consume and its mint has
	// no approved record left to delete, so the post-issue re-check is what stops
	// it from being lost.
	epoch := s.grantEpoch(rec.Subject, client.ID)
	consumed, ok, err := s.devices.ConsumeDevice(ctx, rec.DeviceCodeHash)
	if err != nil {
		return TokenResponse{}, err
	}
	if !ok {
		return TokenResponse{}, protocolError("invalid_grant", "device code has already been redeemed")
	}
	return s.issueGuarded(ctx, client.ID, consumed.Subject, consumed.Scopes, "", epoch)
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
		applied, err := s.devices.RecordDecision(ctx, rec.DeviceCodeHash, DeviceDecision{
			Status: DeviceDenied,
		})
		if err != nil {
			return err
		}
		if !applied {
			return protocolError("invalid_request", "the request has already been decided")
		}
		s.record(ctx, "oauth.device.deny", subject, rec.ClientID, audit.OutcomeDenied)
		return nil
	}

	granted := rec.Scopes
	if scopes != nil {
		if len(scopes) == 0 {
			// An explicit empty approval is "grant nothing" and must not be
			// silently upgraded to the full request; omit the field for that.
			return protocolError("invalid_request", "an approval must grant at least one scope; omit scopes to grant the requested set")
		}
		for _, sc := range scopes {
			if !slices.Contains(rec.Scopes, sc) {
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

	// The transition decides: if another decision landed between the read above
	// and this write, the store refuses and the first decision stands.
	applied, err := s.devices.RecordDecision(ctx, rec.DeviceCodeHash, DeviceDecision{
		Status:   DeviceApproved,
		Subject:  subject,
		Scopes:   granted,
		Explicit: explicit,
	})
	if err != nil {
		return err
	}
	if !applied {
		return protocolError("invalid_request", "the request has already been decided")
	}
	s.record(ctx, "oauth.device.approve", subject, rec.ClientID, audit.OutcomeOK)
	return nil
}

// describeScopes validates a client and its requested scopes without the
// redirect_uri/PKCE requirements of the interactive flow. It does not
// authenticate: it is the verification page's and the decision's read of an
// already-created request, which carries no secret.
func (s *service) describeScopes(ctx context.Context, clientID string, scopes []Scope) (Client, []Descriptor, error) {
	client, err := s.client(ctx, clientID, "", false)
	if err != nil {
		return Client{}, nil, err
	}
	return s.resolveScopes(client, scopes)
}

// describeAuthenticatedScopes is describeScopes plus client authentication, for
// the device authorization endpoint (RFC 8628 §3.1). A public client passes with
// any secret — it has none — and a confidential one must prove its own.
func (s *service) describeAuthenticatedScopes(ctx context.Context, clientID, clientSecret string, scopes []Scope) (Client, []Descriptor, error) {
	client, err := s.client(ctx, clientID, clientSecret, true)
	if err != nil {
		return Client{}, nil, err
	}
	return s.resolveScopes(client, scopes)
}

// resolveScopes is the shared half of the two helpers: every requested scope must
// be known and registered to the client.
func (s *service) resolveScopes(client Client, scopes []Scope) (Client, []Descriptor, error) {
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

// saveDeviceAuthorization draws a user code and persists the request, retrying
// only while the store reports the canonical user code is taken.
//
// This is where uniqueness is decided (S04-5). The pre-flight read in freeUserCode
// is an optimisation; the authoritative answer is the store's canonical unique
// constraint, surfaced as ErrUserCodeConflict. A non-conflict save error is
// returned as itself: retrying it cannot help, and reporting it as "could not
// allocate a unique user code" would drop the cause an operator needs.
func (s *service) saveDeviceAuthorization(ctx context.Context, deviceCode string, base DeviceAuthorizationRecord) (string, error) {
	for attempt := 0; attempt < 8; attempt++ {
		userCode, err := s.freeUserCode(ctx)
		if err != nil {
			return "", err
		}
		base.UserCode = userCode
		switch err := s.devices.SaveDevice(ctx, deviceCode, base); {
		case err == nil:
			return userCode, nil
		case errors.Is(err, ErrUserCodeConflict):
			continue // canonical unique constraint says taken, redraw
		default:
			return "", err
		}
	}
	return "", errors.New("oauth: could not allocate a unique user code")
}

// freeUserCode draws a user code that the store does not already hold. It is a
// pre-flight read, not the uniqueness gate: only a store error that is not
// ErrDeviceNotFound and not an ErrUserCodeConflict is fatal, and the read and the
// later SaveDevice are still an unavoidable race that the canonical unique
// constraint closes (S04-5).
func (s *service) freeUserCode(ctx context.Context) (string, error) {
	for attempt := 0; attempt < 8; attempt++ {
		code, err := newUserCode()
		if err != nil {
			return "", err
		}
		// Only "not found" means the code is free. Every other error is a store
		// failure: retrying cannot fix it, and folding it into the loop turned an
		// infrastructure fault into "could not allocate a unique user code" with
		// the cause dropped (S04-5). A conflict reported by the read counts as a
		// collision, so a store that surfaces the constraint on lookup is handled
		// the same way as one that returns the record.
		switch _, err := s.devices.GetDeviceByUserCode(ctx, code); {
		case err == nil, errors.Is(err, ErrUserCodeConflict):
			continue // taken, redraw
		case errors.Is(err, ErrDeviceNotFound):
			return code, nil
		default:
			return "", err
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
