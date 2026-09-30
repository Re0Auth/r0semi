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
	"log/slog"
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
	// refreshTombstones is what is left of a spent refresh token, keyed by the
	// same value hash. It exists for one reason: RFC 9700 §4.14.2 says a replay
	// of a rotated refresh token is itself the theft signal, and the whole family
	// has to go with it. By the time the replay arrives the live row is gone, so
	// the tombstone is the only thing that still carries the family id and the
	// paired access token's id hash the revocation needs.
	refreshTombstones map[string]refreshTombstone
	devices           map[string]deviceRecord // by TokenHash(device code)
	userCodes         map[string]string       // normalized user code -> TokenHash(device code)

	// Subject indexes. The token maps are keyed by token hash, so every lookup by
	// subject — and every revocation by subject, which is what a Kill Switch sweep
	// and an account erasure do — used to scan the whole map under the store's
	// single lock. That made Grants and RevokeTokens slower as the deployment grew,
	// on the paths that exist to be fast during an incident.
	//
	// The indexes are maintained in the same critical section as the maps they
	// describe, through the put/delete helpers below rather than by hand, so the two
	// cannot drift; checkIndexes in the tests asserts that over a randomised
	// sequence of operations.
	accessBySubject  subjectIndex
	refreshBySubject subjectIndex
	requestBySubject subjectIndex

	accessTTL  time.Duration
	refreshTTL time.Duration
	requestTTL time.Duration
	now        func() time.Time
}

// subjectIndex maps a subject to the keys of the records belonging to it.
//
// A record with no subject (a token minted for an anonymous request) is not
// indexed: it can only be found by a full scan, which is what an unfiltered
// revocation does anyway.
type subjectIndex map[string]map[string]struct{}

func newSubjectIndex() subjectIndex { return make(subjectIndex) }

func (ix subjectIndex) add(subject, key string) {
	if subject == "" {
		return
	}
	keys, ok := ix[subject]
	if !ok {
		keys = make(map[string]struct{}, 4)
		ix[subject] = keys
	}
	keys[key] = struct{}{}
}

func (ix subjectIndex) remove(subject, key string) {
	keys, ok := ix[subject]
	if !ok {
		return
	}
	delete(keys, key)
	if len(keys) == 0 {
		delete(ix, subject)
	}
}

// keys returns the record keys indexed for a subject, or nil. The caller must not
// mutate the result.
func (ix subjectIndex) keys(subject string) map[string]struct{} { return ix[subject] }

// --- indexed writes. Every mutation of a token or auth-request map goes through
// one of these, so the index cannot be forgotten. The caller holds the lock.

func (s *OIDCStore) putAccessLocked(key string, t accessToken) {
	s.accessTokens[key] = t
	s.accessBySubject.add(t.subject, key)
}

func (s *OIDCStore) deleteAccessLocked(key string) bool {
	t, ok := s.accessTokens[key]
	if !ok {
		return false
	}
	delete(s.accessTokens, key)
	s.accessBySubject.remove(t.subject, key)
	return true
}

func (s *OIDCStore) putRefreshLocked(key string, t refreshToken) {
	s.refreshTokens[key] = t
	s.refreshBySubject.add(t.subject, key)
}

func (s *OIDCStore) deleteRefreshLocked(key string) bool {
	t, ok := s.refreshTokens[key]
	if !ok {
		return false
	}
	delete(s.refreshTokens, key)
	s.refreshBySubject.remove(t.subject, key)
	return true
}

func (s *OIDCStore) deleteRequestLocked(id string) bool {
	a, ok := s.authRequests[id]
	if !ok {
		return false
	}
	delete(s.authRequests, id)
	delete(s.authRequestExpiry, id)
	s.requestBySubject.remove(a.Subject, id)
	return true
}

// --- candidate sets for a filtered revocation. Each returns the keys to examine:
// the subject's indexed records when a subject is given, every key otherwise. The
// caller holds the lock and must not delete while ranging the result, which is why
// these copy.

func (s *OIDCStore) accessKeysLocked(subject string) []string {
	if subject == "" {
		out := make([]string, 0, len(s.accessTokens))
		for k := range s.accessTokens {
			out = append(out, k)
		}
		return out
	}
	indexed := s.accessBySubject.keys(subject)
	out := make([]string, 0, len(indexed))
	for k := range indexed {
		out = append(out, k)
	}
	return out
}

func (s *OIDCStore) refreshKeysLocked(subject string) []string {
	if subject == "" {
		out := make([]string, 0, len(s.refreshTokens))
		for k := range s.refreshTokens {
			out = append(out, k)
		}
		return out
	}
	indexed := s.refreshBySubject.keys(subject)
	out := make([]string, 0, len(indexed))
	for k := range indexed {
		out = append(out, k)
	}
	return out
}

func (s *OIDCStore) requestKeysLocked(subject string) []string {
	if subject == "" {
		out := make([]string, 0, len(s.authRequests))
		for k := range s.authRequests {
			out = append(out, k)
		}
		return out
	}
	indexed := s.requestBySubject.keys(subject)
	out := make([]string, 0, len(indexed))
	for k := range indexed {
		out = append(out, k)
	}
	return out
}

// ErrRefreshTokenSpent reports a refresh token presented after it had already
// been rotated. It is a refusal, not a lookup miss: the caller asked to spend a
// token this store has already consumed, which is what a replayed (or stolen)
// refresh token looks like. Returning an error rather than minting a second
// generation is the whole point — it is the only thing that makes reuse visible.
//
// It is an *oidc.Error carrying invalid_grant, not a bare error: the token
// endpoint maps a typed protocol error to 400, while an untyped one becomes a
// 500 server_error and hides the refusal from the client.
var ErrRefreshTokenSpent = oidc.ErrInvalidGrant().WithDescription("refresh token was already rotated")

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
	// nonce is the authorization request's nonce, carried so a rotated id_token can
	// repeat it (OIDC Core §12.2). Rotation inherits it from the token it spends.
	nonce string
	// familyID is shared by every generation descended from one authorization.
	// Rotation inherits it, so a replay that reaches a tombstone can name the
	// chain to revoke rather than only the value that was presented.
	familyID  string
	issuedAt  time.Time
	expiresAt time.Time
}

// refreshTombstone is the residue rotation leaves behind for the token it spent.
// It is not a credential: the value it stands for is already unusable, and the
// hash it is keyed by cannot be turned back into that value.
type refreshTombstone struct {
	familyID  string
	idHash    string
	clientID  string
	subject   string
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
	// lastPoll is when the device last asked. RFC 8628 §3.5 lets the server answer
	// slow_down when a client polls faster than the advertised interval; the
	// library maps context.DeadlineExceeded to exactly that error, so the throttle
	// lives here.
	lastPoll time.Time
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
		refreshTombstones: make(map[string]refreshTombstone),
		devices:           make(map[string]deviceRecord),
		userCodes:         make(map[string]string),
		accessBySubject:   newSubjectIndex(),
		refreshBySubject:  newSubjectIndex(),
		requestBySubject:  newSubjectIndex(),
		accessTTL:         time.Hour,
		refreshTTL:        30 * 24 * time.Hour,
		requestTTL:        ttl,
		now:               now,
	}, nil
}

// record writes one OP audit event. A failure is logged, not returned and not
// swallowed: the token or the device decision has already happened, so refusing
// now would not undo it — but an audit record that vanishes without a trace is
// the one outcome this project does not accept. The direction is the operator
// plane's (log and proceed), not the vault's (withhold the emission), because
// nothing irreversible is gated on this line.
//
// The subject is deliberately not logged: a raw `usr_…` belongs in the event
// field the sink pseudonymises, not in a log line that outlives the key.
func (s *OIDCStore) record(ctx context.Context, action, subject, clientID, outcome string) {
	if s.audit == nil {
		return
	}
	if err := s.audit.Record(ctx, audit.Event{
		Action: action, Subject: subject, Provider: "oidc", Outcome: outcome,
		Detail: map[string]string{"client_id": clientID},
	}); err != nil {
		slog.Error("oidc audit record failed",
			"action", action, "client_id", clientID, "outcome", outcome, "err", err)
	}
}

// recordConsent writes the audit event for a consent decision. It is separate
// from record() because the interesting detail here is which scopes were
// granted, not only which client was involved — that is the half the operator
// log was missing, and it is the question "what did this account authorize".
//
// scopes are space-joined: the audit detail is a flat string map, and the
// approved scope set is small and already a list on the wire.
func (s *OIDCStore) recordConsent(ctx context.Context, action, subject, clientID string, scopes []string, outcome string) {
	if s.audit == nil {
		return
	}
	detail := map[string]string{"client_id": clientID}
	if len(scopes) > 0 {
		detail["scopes"] = strings.Join(scopes, " ")
	}
	if err := s.audit.Record(ctx, audit.Event{
		Action: action, Subject: subject, Provider: "oidc", Outcome: outcome,
		Detail: detail,
	}); err != nil {
		slog.Error("oidc audit record failed",
			"action", action, "client_id", clientID, "outcome", outcome, "err", err)
	}
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
		// The library normalizes the freshness requirement before this call
		// (prompt=login becomes MaxAge=0), so it is recorded verbatim rather
		// than re-derived from the wire parameters.
		Prompt: append([]string(nil), req.Prompt...),
		MaxAge: cloneMaxAge(req.MaxAge),
	}
	s.authRequests[id] = a
	s.authRequestExpiry[id] = s.now().Add(s.requestTTL)
	s.requestBySubject.add(a.Subject, id)
	// Hand back a copy, like AuthRequestByID/AuthRequestByCode: the stored record
	// is mutated under s.mu by CompleteLogin/SetAuthTime, so returning the same
	// pointer let a caller's write race those and change the store (the -race
	// report in the audit). A copy-on-return keeps the write path as disciplined as
	// the read path.
	return cloneAuthRequest(a), nil
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

// AuthRequestByCode implements op.Storage. It consumes the code: a second
// exchange of the same value finds nothing. The library only deletes the request
// after it has minted tokens, so a read-then-delete left a window where two
// concurrent exchanges both succeeded. Treating the lookup itself as the claim is
// what makes the code single-use under concurrency; a failed exchange burns the
// code, which is the fail-closed direction.
func (s *OIDCStore) AuthRequestByCode(_ context.Context, code string) (op.AuthRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := oauth.TokenHash(code)
	c, ok := s.codes[key]
	if !ok || !s.now().Before(c.expiresAt) {
		return nil, errors.New("memory: authorization code is unknown or expired")
	}
	a, ok := s.authRequests[c.requestID]
	if !ok {
		return nil, errors.New("memory: auth request not found")
	}
	delete(s.codes, key)
	s.deleteRequestLocked(c.requestID)
	return cloneAuthRequest(a), nil
}

func cloneAuthRequest(a *oidcstore.AuthRequest) *oidcstore.AuthRequest {
	out := *a
	out.Scopes = append([]string(nil), a.Scopes...)
	out.Prompt = append([]string(nil), a.Prompt...)
	out.MaxAge = cloneMaxAge(a.MaxAge)
	return &out
}

// cloneMaxAge copies the pointed-to value, so a caller writing through one
// request's MaxAge cannot reach the stored record or another copy of it.
func cloneMaxAge(in *uint) *uint {
	if in == nil {
		return nil
	}
	v := *in
	return &v
}

// SaveAuthCode implements op.Storage.
func (s *OIDCStore) SaveAuthCode(_ context.Context, id, code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes[oauth.TokenHash(code)] = codeRecord{requestID: id, expiresAt: s.now().Add(s.requestTTL)}
	return nil
}

// DeleteAuthRequest implements op.Storage.
func (s *OIDCStore) DeleteAuthRequest(ctx context.Context, id string) error {
	s.mu.Lock()
	subject, clientID := "", ""
	if a, ok := s.authRequests[id]; ok {
		subject, clientID = a.Subject, a.ClientID
	}
	s.deleteRequestLocked(id)
	for k, c := range s.codes {
		if c.requestID == id {
			delete(s.codes, k)
		}
	}
	s.mu.Unlock()
	// A refused request leaves as much trace as an approved one: who was asked,
	// which client, and the answer no. The subject is empty for a request nobody
	// signed in for, which is itself the honest record.
	s.recordConsent(ctx, "oidc.consent.deny", subject, clientID, nil, audit.OutcomeDenied)
	return nil
}

// CreateAccessToken implements op.Storage.
func (s *OIDCStore) CreateAccessToken(ctx context.Context, request op.TokenRequest) (string, time.Time, error) {
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
	s.putAccessLocked(oauth.TokenHash(id), t)
	s.mu.Unlock()
	s.record(ctx, "oidc.token", request.GetSubject(), t.clientID, audit.OutcomeOK)
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
		nonce:     oidcstore.NonceOf(request),
		issuedAt:  now,
		expiresAt: now.Add(s.refreshTTL),
	}

	s.mu.Lock()
	familyID := ""
	if currentRefreshToken != "" {
		spent := oauth.TokenHash(currentRefreshToken)
		held, ok := s.refreshTokens[spent]
		if !ok {
			// The read path (TokenRequestByRefreshToken) is what normally turns a
			// replay into a family revocation. Reaching rotation with a token this
			// store no longer holds means that path was bypassed; if a tombstone
			// still names the family, revoke it here too rather than answering the
			// replay with a bare refusal and leaving the thief's generation alive.
			if ts, known := s.refreshTombstones[spent]; known {
				s.revokeFamilyLocked(ts.familyID)
			}
			s.mu.Unlock()
			return "", "", time.Time{}, ErrRefreshTokenSpent
		}
		// Read the spent record BEFORE deleting it: this is the only moment its
		// family id and paired access-token hash are still reachable. The
		// tombstone carries both forward for the replay.
		familyID = held.familyID
		if familyID == "" {
			// Unreachable through this store, which always mints a family id, but
			// a record with no family would otherwise make the replay a no-op.
			familyID = spent
		}
		s.refreshTombstones[spent] = refreshTombstone{
			familyID:  familyID,
			idHash:    held.idHash,
			clientID:  held.clientID,
			subject:   held.subject,
			expiresAt: held.expiresAt,
		}
		s.deleteRefreshLocked(spent)
	} else {
		id, err := oidcstore.RandomValue()
		if err != nil {
			s.mu.Unlock()
			return "", "", time.Time{}, err
		}
		familyID = id
	}
	refresh.familyID = familyID
	s.putAccessLocked(oauth.TokenHash(accessID), access)
	s.putRefreshLocked(oauth.TokenHash(value), refresh)
	s.mu.Unlock()

	s.record(ctx, "oidc.token", request.GetSubject(), access.clientID, audit.OutcomeOK)
	return accessID, value, expires, nil
}

// TokenRequestByRefreshToken implements op.Storage.
//
// A live, unexpired row is resolved as before. Anything else is the interesting
// case: if an unexpired tombstone names the presented hash, this is a replay of a
// token that was already rotated — the theft signal RFC 9700 §4.14.2 keys on — so
// the whole family is revoked before the refusal is returned. The library maps
// the error to invalid_grant, so the client still sees a 400.
func (s *OIDCStore) TokenRequestByRefreshToken(_ context.Context, value string) (op.RefreshTokenRequest, error) {
	spent := oauth.TokenHash(value)
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.refreshTokens[spent]
	if !ok || !s.now().Before(r.expiresAt) {
		if ts, known := s.refreshTombstones[spent]; known && s.now().Before(ts.expiresAt) {
			s.revokeFamilyLocked(ts.familyID)
			return nil, ErrRefreshTokenSpent
		}
		return nil, errors.New("memory: invalid refresh token")
	}
	// Copy every slice and the *time.Time: Scopes was already copied, but AMR,
	// Audience and AuthTime aliased the stored record, so a caller's write reached
	// the store and kept applying on every later refresh (verified finding).
	// Postgres is unaffected — it scans into fresh values.
	out := &oidcstore.RefreshRequest{
		IDHash: r.idHash, ClientID: r.clientID, Subject: r.subject,
		Scopes: append([]string(nil), r.scopes...),
		AMR:    append([]string(nil), r.amr...),
		Nonce:  r.nonce,
	}
	out.Audience = append([]string(nil), r.audience...)
	if r.authTime != nil {
		at := *r.authTime
		out.AuthTime = &at
	}
	return out, nil
}

// revokeFamilyLocked deletes every live generation of a family, every tombstone
// of that family, and the access token each of them was paired with. The caller
// holds the lock.
//
// It deletes by the family id rather than by subject or client on purpose: the
// family is exactly the set of tokens descended from one authorization, which is
// the unit RFC 9700 §4.14.2 revokes. The access token's key is the refresh row's
// idHash, which is why the tombstone carries that field at all — the live row
// that named it has already been consumed by the time a replay arrives.
//
// A family id is never empty for a record this store minted; the guard is here so
// a malformed record cannot turn the revocation into "delete everything with an
// empty family", which is every unset record.
func (s *OIDCStore) revokeFamilyLocked(familyID string) {
	if familyID == "" {
		return
	}
	for key, t := range s.refreshTokens {
		if t.familyID == familyID {
			s.deleteRefreshLocked(key)
			s.deleteAccessLocked(t.idHash)
		}
	}
	for key, ts := range s.refreshTombstones {
		if ts.familyID == familyID {
			s.deleteAccessLocked(ts.idHash)
			delete(s.refreshTombstones, key)
		}
	}
}

// TerminateSession implements op.Storage.
func (s *OIDCStore) TerminateSession(_ context.Context, userID, clientID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Only this subject's records are examined: the index is what keeps a session
	// termination from walking every token in the deployment.
	for key := range s.accessBySubject.keys(userID) {
		if t, ok := s.accessTokens[key]; ok && t.clientID == clientID {
			s.deleteAccessLocked(key)
		}
	}
	for key := range s.refreshBySubject.keys(userID) {
		if t, ok := s.refreshTokens[key]; ok && t.clientID == clientID {
			s.deleteRefreshLocked(key)
		}
	}
	// The spent generations of this subject's refresh tokens go with them: a
	// tombstone left behind is not a credential, but it is state about a session
	// that was just terminated, and its paired access row would be swept only by
	// the replay path.
	for key, ts := range s.refreshTombstones {
		if ts.subject == userID && ts.clientID == clientID {
			delete(s.refreshTombstones, key)
			s.deleteAccessLocked(ts.idHash)
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
		s.deleteAccessLocked(h)
		// RFC 7009 §2.1: revoking a token should revoke the whole grant. The
		// refresh token minted alongside this access token shares its id hash.
		//
		// This one lookup is by id hash rather than by subject, so it is a scan —
		// and it is left as one deliberately. A revocation is an operator or user
		// action, not a hot path, and a fourth index would have to be maintained on
		// every refresh rotation for it.
		for k, rt := range s.refreshTokens {
			if rt.idHash == h {
				s.deleteRefreshLocked(k)
			}
		}
		for k, ts := range s.refreshTombstones {
			if ts.idHash == h {
				delete(s.refreshTombstones, k)
			}
		}
		s.mu.Unlock()
		s.record(ctx, "oidc.revoke", userID, clientID, audit.OutcomeOK)
		return nil
	}
	// The access row can already be gone while its refresh half is not: the access
	// token expires after an hour, the refresh token after thirty days, and the
	// sweep removes each on its own. Without this lookup the presented access token
	// matches nothing, the call answers RFC 7009's "unknown token is success", and
	// the refresh token — the half that mints replacements — stays live.
	for k, rt := range s.refreshTokens {
		if rt.idHash != h {
			continue
		}
		if rt.clientID != clientID {
			s.mu.Unlock()
			return oidc.ErrInvalidClient().WithDescription("token was not issued for this client")
		}
		s.deleteRefreshLocked(k)
		s.deleteAccessLocked(h)
		for tk, ts := range s.refreshTombstones {
			if ts.idHash == h {
				delete(s.refreshTombstones, tk)
			}
		}
		s.mu.Unlock()
		s.record(ctx, "oidc.revoke", userID, clientID, audit.OutcomeOK)
		return nil
	}
	if t, ok := s.refreshTokens[h]; ok {
		if t.clientID != clientID {
			s.mu.Unlock()
			return oidc.ErrInvalidClient().WithDescription("token was not issued for this client")
		}
		s.deleteRefreshLocked(h)
		// The paired access token is keyed by the same id hash, and the spent
		// generations of this value share its hash.
		s.deleteAccessLocked(t.idHash)
		delete(s.refreshTombstones, h)
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

// SetUserinfoFromScopes implements op.Storage. Only `sub` is ever exposed
// (ADR-0001 O-3), and the subject is the whole of what it sets.
//
// It is NOT deprecated on this code path, whatever the upstream interface comment
// says. `op.CreateIDToken` fills a fresh `oidc.UserInfo` through this callback and
// then calls `claims.SetUserInfo`, which ASSIGNS `sub` from `UserInfo.Subject`
// rather than merging it (pkg/oidc/token.go). A no-op stub therefore did not mean
// "no extra claims": it meant `sub: ""` on every id_token minted by the
// authorization-code, refresh and device grants — the one claim OIDC Core §2 makes
// REQUIRED, and the identity an RP keys its session on. Both stores have to set it.
func (s *OIDCStore) SetUserinfoFromScopes(_ context.Context, userinfo *oidc.UserInfo, userID, _ string, _ []string) error {
	userinfo.Subject = userID
	return nil
}

// SetUserinfoFromRequest implements op.CanSetUserinfoFromRequest. It is the seam
// the library offers for claims that depend on the request rather than the scopes
// (op.CreateIDToken calls it right after SetUserinfoFromScopes and merges the
// claims into the id_token), and the nonce is exactly such a claim.
//
// OIDC Core §12.2: the id_token returned by a refresh MUST NOT carry a nonce
// unless it is the same nonce as in the original authorization request. The
// library reads the nonce only from an op.AuthRequest, and this store must not
// make RefreshRequest satisfy op.AuthRequest — `needsRefreshToken` switches on
// `case AuthRequest` before `case RefreshTokenRequest`, so doing that would break
// rotation and make CreateTokenResponse delete the auth request and emit a bogus
// consent denial. Setting the claim here is the sanctioned alternative. An empty
// nonce is left out: the claim has `omitempty`, and §12.2 forbids inventing one.
func (s *OIDCStore) SetUserinfoFromRequest(_ context.Context, userinfo *oidc.UserInfo, request op.IDTokenRequest, _ []string) error {
	nonce := oidcstore.NonceOf(request)
	if nonce == "" {
		return nil
	}
	if userinfo.Claims == nil {
		userinfo.Claims = make(map[string]any, 1)
	}
	userinfo.Claims["nonce"] = nonce
	return nil
}

// SetUserinfoFromToken implements op.Storage. Only `sub` is ever exposed
// (ADR-0001 O-3).
//
// The token is looked up rather than trusted. userinfo is a protected resource:
// the library reaches this method either by decrypting an opaque token into its
// ID, or — when decryption fails — by falling back to verifying the bearer as a
// signed JWT. Only the first shape can name an access token this store issued, so
// requiring `tokenID` to hit a LIVE row decides liveness (expiry, revocation and
// erasure all delete the row) and, in the same lookup, removes the fallback: a
// bearer that decrypts to nothing carries no ID that this store has ever seen.
func (s *OIDCStore) SetUserinfoFromToken(_ context.Context, userinfo *oidc.UserInfo, tokenID, subject, _ string) error {
	if tokenID == "" {
		return errNotAnAccessToken
	}
	h := oauth.TokenHash(tokenID)
	now := s.now()

	s.mu.Lock()
	t, ok := s.accessTokens[h]
	// The subject is compared against the record, not against the caller's
	// assertion: a decrypted pair is only meaningful together. What is published is
	// the record's subject, which is the same value when they agree.
	live := ok && t.subject == subject && now.Before(t.expiresAt)
	stored := t.subject
	s.mu.Unlock()
	if !live {
		return errNotAnAccessToken
	}
	userinfo.Subject = stored
	return nil
}

// errNotAnAccessToken is the userinfo refusal. It says nothing about WHICH check
// failed — an unparseable bearer, a revoked one, an expired one and an id_token
// all read the same — because the endpoint is reachable by anyone holding a
// string, and distinguishing the cases would turn it into an oracle.
var errNotAnAccessToken = errors.New("not a live access token")

// SetIntrospectionFromToken implements op.Storage.
//
// The hash, the clock read and the scope copy happen before the store's lock, not
// under it. They are pure functions of the arguments and of data the lock does not
// own, and holding the lock through them made this the store's slowest operation
// per unit of real work: the parallel benchmark ran at 227ns/op against 168ns/op
// serial, on twenty cores, for a lookup that is a map read.
func (s *OIDCStore) SetIntrospectionFromToken(_ context.Context, introspection *oidc.IntrospectionResponse, tokenID, subject, _ string) error {
	key := oauth.TokenHash(tokenID)
	now := s.now()

	s.mu.Lock()
	t, ok := s.accessTokens[key]
	if !ok {
		s.mu.Unlock()
		return errors.New("memory: token not found")
	}
	scopes := append([]string(nil), t.scopes...)
	clientID, expiresAt := t.clientID, t.expiresAt
	s.mu.Unlock()

	if !now.Before(expiresAt) {
		return errors.New("memory: token not found")
	}
	introspection.Active = true
	introspection.Subject = subject
	introspection.ClientID = clientID
	introspection.Scope = scopes
	introspection.Expiration = oidc.FromTime(expiresAt)
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
	h := oauth.TokenHash(deviceCode)
	d, ok := s.devices[h]
	if !ok || d.clientID != clientID {
		return nil, errors.New("memory: device authorization not found")
	}
	// RFC 8628 §3.5: a client that polls faster than the advertised interval is
	// told to slow down. The library turns context.DeadlineExceeded into that
	// error, so the store returns it for a premature poll. Only pending polls are
	// throttled: an approved record is consumed below and a denied one is final.
	if !d.done && !d.denied && !d.lastPoll.IsZero() &&
		s.now().Before(d.lastPoll.Add(oidcstore.DefaultDevicePollInterval)) {
		d.lastPoll = s.now()
		s.devices[h] = d
		return nil, context.DeadlineExceeded
	}
	st := d.state()
	if d.done && !d.denied {
		// Single use. The library reads this once, right before it mints the
		// tokens, and has no consume step of its own — so without this a device_code
		// kept minting fresh access/refresh pairs for the rest of its TTL, and a
		// revocation performed in between was undone by the next poll. A denied or
		// still-pending record is left in place for the library to answer.
		delete(s.devices, h)
		delete(s.userCodes, normalizeUserCode(d.userCode))
		return st, nil
	}
	d.lastPoll = s.now()
	s.devices[h] = d
	return st, nil
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
			s.deleteRequestLocked(id)
			removed++
		}
	}
	for k, c := range s.codes {
		if now.After(c.expiresAt) {
			delete(s.codes, k)
			removed++
		}
	}
	// The two token sweeps are scans by design: expiry is a property of the record,
	// not of its subject, so no index can narrow them. They run on a ticker, not on
	// a request.
	for k, t := range s.accessTokens {
		if !now.Before(t.expiresAt) {
			s.deleteAccessLocked(k)
			removed++
		}
	}
	for k, t := range s.refreshTokens {
		if !now.Before(t.expiresAt) {
			s.deleteRefreshLocked(k)
			removed++
		}
	}
	// A tombstone is swept on its own deadline, which is the spent token's: past
	// that point the value it stands for could not have been spent anyway, so the
	// family rule has nothing left to detect and the residue is pure memory.
	for k, ts := range s.refreshTombstones {
		if !now.Before(ts.expiresAt) {
			delete(s.refreshTombstones, k)
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
	Tombstones    int
	Devices       int
}

// Records is the total number of records the store holds.
func (c Counts) Records() int {
	return c.AuthRequests + c.Codes + c.AccessTokens + c.RefreshTokens + c.Tombstones + c.Devices
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
		Tombstones:    len(s.refreshTombstones),
		Devices:       len(s.devices),
	}
}

// --- consent / device UI helpers (app-owned, not part of op.Storage) ---

// SetAuthTime records when the human authenticated, so CompleteLogin does not
// overwrite it with the consent-decision time.
func (s *OIDCStore) SetAuthTime(_ context.Context, id string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.authRequests[id]
	if !ok {
		return errors.New("memory: auth request not found")
	}
	a.AuthTime = &at
	return nil
}

// CompleteLogin attaches the subject and the approved (possibly narrowed)
// scopes to a pending authorization request.
//
// An authorization request is created before anyone has signed in, so its subject
// is empty until this call — which means this is also where the subject index
// learns about it. Without the move, a revocation filtered by subject would look
// at the old (empty) set and miss the request and its code entirely, and a code
// that survives a Kill Switch is a live credential.
func (s *OIDCStore) CompleteLogin(ctx context.Context, id, subject string, scopes []string) error {
	s.mu.Lock()
	a, ok := s.authRequests[id]
	if !ok {
		s.mu.Unlock()
		return errors.New("memory: auth request not found")
	}
	previous := a.Subject
	a.Subject = subject
	a.Scopes = append([]string(nil), scopes...)
	a.IsDone = true
	if previous != subject {
		s.requestBySubject.remove(previous, id)
		s.requestBySubject.add(subject, id)
	}
	// Preserve the session's real authentication time when the login hook set it;
	// only fall back to the decision time when it did not. A request that asked
	// for a fresh authentication (`prompt=login` or an elapsed `max_age`) is the
	// exception: the recorded time is exactly what it asked not to accept, so
	// completing the interactive decision is the re-authentication and the
	// id_token must carry that moment, not the stale session's.
	if now := s.now(); a.RequiresReauthentication(now) || a.AuthTime == nil {
		a.AuthTime = &now
	}
	clientID := a.ClientID
	approved := a.Scopes
	s.mu.Unlock()
	// The consent decision itself is an authorization event: who granted which
	// client which scopes, and when. Recorded after the state change it describes.
	s.recordConsent(ctx, "oidc.consent.approve", subject, clientID, approved, audit.OutcomeOK)
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
//
// The state conditions are checked here, under the same lock the write takes, so
// a decision cannot land on a code that is already decided or expired — the
// postgres store carries the same predicate in its UPDATE (see C3-3 in
// docs/security-audit-3.md).
func (s *OIDCStore) ApproveDevice(ctx context.Context, userCode, subject string, scopes []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, ok := s.userCodes[normalizeUserCode(userCode)]
	if !ok {
		return oauth.ErrDeviceNotFound
	}
	d := s.devices[h]
	if d.done || d.denied || !s.now().Before(d.expiresAt) {
		return oauth.ErrDeviceNotFound
	}
	d.done = true
	d.subject = subject
	d.authTime = s.now()
	if scopes != nil {
		d.scopes = append([]string(nil), scopes...)
	}
	s.devices[h] = d
	s.record(ctx, "oidc.device.approve", subject, d.clientID, audit.OutcomeOK)
	return nil
}

// DenyDevice marks a device authorization denied.
//
// A denial only requires that none is recorded yet: `done` is deliberately not
// consulted, so denying still outranks an approval whichever write lands second.
func (s *OIDCStore) DenyDevice(ctx context.Context, userCode string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, ok := s.userCodes[normalizeUserCode(userCode)]
	if !ok {
		return oauth.ErrDeviceNotFound
	}
	d := s.devices[h]
	if d.denied {
		return oauth.ErrDeviceNotFound
	}
	d.denied = true
	s.devices[h] = d
	s.record(ctx, "oidc.device.deny", "", d.clientID, audit.OutcomeDenied)
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
	for key := range s.accessBySubject.keys(subject) {
		if t, ok := s.accessTokens[key]; ok {
			collect(t.clientID, t.scopes, t.issuedAt, t.expiresAt, false)
		}
	}
	for key := range s.refreshBySubject.keys(subject) {
		if t, ok := s.refreshTokens[key]; ok {
			collect(t.clientID, t.scopes, t.issuedAt, t.expiresAt, true)
		}
	}
	s.mu.Unlock()

	// Names resolved in one lookup for the whole page rather than one Get per
	// client from inside the scan above.
	ids := make([]string, 0, len(byClient))
	for id := range byClient {
		ids = append(ids, id)
	}
	names := oauth.LookupClientNames(ctx, s.clients, ids)

	out := make([]oauth.Grant, 0, len(byClient))
	for _, g := range byClient {
		g.ClientName = names[g.ClientID]
		sortScopes(g.Scopes)
		out = append(out, *g)
	}
	sortGrants(out)
	return out, nil
}

// RevokeGrant removes every token a client holds for a subject.
//
// It also removes what the client could still redeem: an authorization code
// minted but not yet exchanged, and an approved device authorization. Both are
// capabilities rather than tokens, so neither is counted, but leaving either
// alive let a client that withheld it obtain a fresh access/refresh pair after
// the user revoked the grant — revocation reported success while the access
// came back, and the refresh token made it indefinite. RevokeTokens and
// PurgeSubject clear the same state for the same reason.
func (s *OIDCStore) RevokeGrant(ctx context.Context, subject, clientID string) error {
	if subject == "" || clientID == "" {
		return errors.New("memory: subject and client id are required")
	}
	s.mu.Lock()
	for key := range s.accessBySubject.keys(subject) {
		if t, ok := s.accessTokens[key]; ok && t.clientID == clientID {
			s.deleteAccessLocked(key)
		}
	}
	for key := range s.refreshBySubject.keys(subject) {
		if t, ok := s.refreshTokens[key]; ok && t.clientID == clientID {
			s.deleteRefreshLocked(key)
		}
	}
	// Spent generations are removed with the live ones: the family is what the
	// grant names, and leaving a tombstone would leave the paired access row it
	// names reachable by the replay path after the grant was revoked.
	for key, ts := range s.refreshTombstones {
		if ts.subject == subject && ts.clientID == clientID {
			delete(s.refreshTombstones, key)
			s.deleteAccessLocked(ts.idHash)
		}
	}
	purged := make(map[string]bool)
	for id := range s.requestBySubject.keys(subject) {
		req, ok := s.authRequests[id]
		if !ok || req.ClientID != clientID {
			continue
		}
		s.deleteRequestLocked(id)
		purged[id] = true
	}
	// Codes hang off their request, so they go with it rather than waiting for
	// the sweep to expire them.
	for k, c := range s.codes {
		if purged[c.requestID] {
			delete(s.codes, k)
		}
	}
	// A device authorization for this client and subject is a capability that
	// outlives the tokens: leaving it would let the holder of the device_code mint
	// a fresh pair after the user just revoked the grant.
	for h, d := range s.devices {
		if d.clientID == clientID && d.subject == subject {
			delete(s.userCodes, normalizeUserCode(d.userCode))
			delete(s.devices, h)
		}
	}
	s.mu.Unlock()
	s.record(ctx, "oidc.grant.revoke", subject, clientID, audit.OutcomeOK)
	return nil
}

// RevokeTokens implements oauth.TokenAdmin. It counts both tables, so a Kill
// Switch report has a number an operator can act on.
//
// Pending authorization requests and their authorization codes are revoked with
// the tokens, though they are not counted as tokens. A code is a redeemable
// capability: an attacker holding one issued before the Kill Switch can exchange
// it for a fresh access/refresh pair after the switch returns success, which is
// exactly the "isolated but still reachable" state the endpoint exists to rule
// out. Device authorizations go for the same reason.
func (s *OIDCStore) RevokeTokens(_ context.Context, f oauth.TokenFilter) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	// A revocation filtered by subject only has to look at that subject's records;
	// the unfiltered one is the Kill Switch's "everything", and it must look at all
	// of them. The keys are copied out before anything is deleted, because the
	// delete helpers mutate the index being ranged.
	for _, k := range s.accessKeysLocked(f.Subject) {
		if t, ok := s.accessTokens[k]; ok && f.Matches(t.clientID, t.subject) {
			s.deleteAccessLocked(k)
			removed++
		}
	}
	for _, k := range s.refreshKeysLocked(f.Subject) {
		if t, ok := s.refreshTokens[k]; ok && f.Matches(t.clientID, t.subject) {
			s.deleteRefreshLocked(k)
			removed++
		}
	}
	// Tombstones are not tokens, so they are not counted — but a revocation that
	// named the family has to clear its spent generations too, and the paired
	// access row each one names. They are removed on the same client/subject
	// filter, because that is what a tombstone carries.
	for k, ts := range s.refreshTombstones {
		if !f.Matches(ts.clientID, ts.subject) {
			continue
		}
		delete(s.refreshTombstones, k)
		s.deleteAccessLocked(ts.idHash)
	}
	purged := make(map[string]bool)
	for _, id := range s.requestKeysLocked(f.Subject) {
		req, ok := s.authRequests[id]
		if !ok || !f.Matches(req.ClientID, req.Subject) {
			continue
		}
		s.deleteRequestLocked(id)
		purged[id] = true
	}
	for k, c := range s.codes {
		if purged[c.requestID] {
			delete(s.codes, k)
		}
	}
	// Device authorizations are capabilities, not tokens, so they are not counted
	// here — but they are revoked with the rest: a held device_code would
	// otherwise re-mint what was just revoked, defeating the Kill Switch for the
	// life of the code.
	for h, d := range s.devices {
		if f.Matches(d.clientID, d.subject) {
			delete(s.userCodes, normalizeUserCode(d.userCode))
			delete(s.devices, h)
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
	for _, id := range s.requestKeysLocked(subject) {
		req, ok := s.authRequests[id]
		if !ok || req.Subject != subject {
			continue
		}
		s.deleteRequestLocked(id)
		purged[id] = true
		removed++
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
	// The page shows data permissions; `openid`/`profile`/... are protocol flags
	// the catalogue deliberately does not describe. Resolving the full request
	// here made a standard OIDC device request fail.
	described, _ := oidcstore.SplitProtocolScopes(st.Scopes)
	descriptors, err := s.registry.Resolve(oidcstore.Scopes(described), st.ClientID)
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
	// Re-attach the protocol scopes the client requested: the consent UI renders
	// only catalogue scopes, so a decision must not silently downgrade an OpenID
	// device authorization to a plain OAuth one.
	_, protocol := oidcstore.SplitProtocolScopes(st.Scopes)
	for _, s := range protocol {
		if !oidcstore.HasScope(granted, s) {
			granted = append(granted, s)
		}
	}
	described, _ := oidcstore.SplitProtocolScopes(granted)
	descriptors, err := s.registry.Resolve(oidcstore.Scopes(described), st.ClientID)
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
