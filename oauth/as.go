package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
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

	// refreshLocks serializes the claim-and-act step of Refresh per rotation
	// family (S14-5), so a replay's family revocation cannot interleave with a
	// rotation's mint. refreshLocksMu guards the map itself, not the families:
	// entries are created and dropped under it and each family's own mutex is
	// held only for the step. See lockRefreshFamily.
	refreshLocksMu sync.Mutex
	refreshLocks   map[string]*refreshFamilyLock

	// grantEpochs is the per-(subject, client) revocation generation (R10-19).
	// RevokeGrant bumps it before it deletes; each issuing entry point captures it
	// before its destructive claim and re-checks it after the pair is written, so a
	// revocation that landed while this request was between its claim and its mint
	// is never lost. grantEpochsMu is a leaf lock: it is held only for map
	// operations, never across a store call and never nested inside a family lock.
	grantEpochsMu sync.Mutex
	grantEpochs   map[string]uint64
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
	// The memory store has no clock of its own, but its refresh tombstones carry a
	// deadline the contract says they expire on. Hand it the same clock the
	// service judges every other deadline with, so a defaulted clock and an
	// injected one agree. Other Store implementations are left untouched.
	if ms, ok := tokens.(*MemoryStore); ok {
		ms.now = cfg.Now
	}
	// The in-memory pair. A client registry that keeps no tokens cannot revoke
	// them on its own, and this is the one place both halves are in hand: publish
	// the token engine to the registry so ClientAdmin.Delete removes the client's
	// tokens with its registration (KIT-10). A registry or store that does not
	// implement the two interfaces — a durable one that owns its tokens, a test
	// double — is left exactly as it was.
	if setter, ok := clients.(TokenRevokerSetter); ok {
		if revoker, ok := tokens.(TokenAdmin); ok {
			setter.SetTokenRevoker(revoker)
		}
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
		refreshLocks: make(map[string]*refreshFamilyLock),
		grantEpochs:  make(map[string]uint64),
	}, nil
}

// AuthenticateClient checks that the caller is a registered, authenticating
// client. It goes through client() — the same door Exchange/Refresh/Revoke use —
// but then requires the client to actually authenticate: client() lets a public
// client through with any secret because those endpoints bind authorization to
// PKCE and the code/refresh record instead. That leniency is wrong here, where
// the caller's identity IS the check (RFC 7662 introspection, upstreamkit's
// cascade revocation). Accepting any secret for a ClientPublic made this gate
// admit an unauthenticated caller: registration was the only requirement, and
// "any registered public client" would pass a credential check it failed. A
// public client is refused with invalid_client.
func (s *service) AuthenticateClient(ctx context.Context, clientID, clientSecret string) error {
	c, err := s.client(ctx, clientID, clientSecret, true)
	if err != nil {
		return err
	}
	if c.Type != ClientConfidential {
		return protocolError("invalid_client", "public clients cannot authenticate")
	}
	return nil
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

	// Capture the revocation generation before the code is spent. A RevokeGrant
	// that lands while this exchange is between its claim and its mint has nothing
	// left to delete (the code is already gone), so the post-issue re-check in
	// issueGuarded is the only thing that can catch it (R10-19).
	epoch := s.grantEpoch(code.Subject, client.ID)

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
	return s.issueGuarded(ctx, client.ID, claimed.Subject, claimed.Scopes, "", epoch)
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

	// Capture the revocation generation before the destructive claim (R10-19).
	// GetRefresh is the non-destructive read peer of ConsumeRefresh; a spent or
	// unknown value reports ErrTokenNotFound, and the claim below then mints
	// nothing, so there is no live pair for the guard to protect.
	var epoch uint64
	if held, getErr := s.tokens.GetRefresh(ctx, req.RefreshToken); getErr == nil {
		epoch = s.grantEpoch(held.Subject, client.ID)
	}

	// S14-5: the claim and the step that follows it are one act per family. The
	// reuse branch below revokes the family; the rotation branch below mints into
	// it. Without a family-wide turnstile a replay can revoke between the
	// winner's ConsumeRefresh and its issue, and the mint then repopulates a
	// family that was just reported dead — the thief keeps a live generation for
	// the rest of the refresh TTL. Everything from the claim to the mint or the
	// revocation runs under this lock, so the two steps can only run whole, one
	// after the other: a rotation that goes first is followed by a detection that
	// revokes the generation it just minted, and a detection that goes first has
	// already deleted the record the rotation would claim, so that claim finds
	// nothing and mints nothing. The key is the family itself, so unrelated
	// chains never wait on each other.
	key, err := s.refreshFamilyKey(ctx, req.RefreshToken)
	if err != nil {
		return TokenResponse{}, err
	}
	unlock := s.lockRefreshFamily(key)
	defer unlock()

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
	// The store hands back a retained row even if its deadline has passed
	// (S09-4): the caller, with its injected clock, is the only place expiry is
	// judged, so the claim above cannot be treated as proof the value was live.
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
	return s.issueGuarded(ctx, client.ID, rt.Subject, scopes, rt.FamilyID, epoch)
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
	//
	// The owner read also resolves a SPENT refresh value from its tombstone
	// (SpentRefreshOwner), which is what makes DeleteRefresh's documented
	// tombstone-clear reachable at all: TokenOwner answers only for a live value,
	// so before this the request returned the uniform success above and the
	// tombstone outlived the revocation that claimed to have cleared it (S01-8).
	owner, err := s.revocableOwner(ctx, req.Token)
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

// revocableOwner names the client a value belongs to for RFC 7009's ownership
// check. TokenOwner answers for a live access or refresh value; a spent refresh
// value has only a tombstone left, so its owner comes from the optional
// SpentRefreshOwner extension when the store offers one. A store that does not
// keeps the old answer (ErrTokenNotFound), and the revocation stays the uniform
// success that clears nothing.
func (s *service) revocableOwner(ctx context.Context, value string) (string, error) {
	owner, err := s.tokens.TokenOwner(ctx, value)
	if err == nil {
		return owner, nil
	}
	if !errors.Is(err, ErrTokenNotFound) {
		return "", err
	}
	if spent, ok := s.tokens.(SpentRefreshOwner); ok {
		return spent.SpentRefreshOwner(ctx, value)
	}
	return "", ErrTokenNotFound
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

// grantEpochKey names one (subject, client) revocation generation. NUL cannot
// occur in either component, so the two cannot be confused for one another.
func grantEpochKey(subject, clientID string) string { return subject + "\x00" + clientID }

// grantEpoch reads the current revocation generation for a grant.
func (s *service) grantEpoch(subject, clientID string) uint64 {
	s.grantEpochsMu.Lock()
	defer s.grantEpochsMu.Unlock()
	return s.grantEpochs[grantEpochKey(subject, clientID)]
}

// bumpGrantEpoch advances the generation. RevokeGrant calls it BEFORE its delete,
// which is the ordering that makes the post-issue re-check complete: a revocation
// whose delete could have preceded the pair is guaranteed to have bumped before
// the issuance captured its epoch, and one that bumps after the capture is caught
// by the re-check.
func (s *service) bumpGrantEpoch(subject, clientID string) {
	s.grantEpochsMu.Lock()
	defer s.grantEpochsMu.Unlock()
	s.grantEpochs[grantEpochKey(subject, clientID)]++
}

// issueGuarded mints a pair and then re-checks the grant's revocation generation.
// A bump between the capture (before the destructive claim) and this point means
// a RevokeGrant reported success while this request was in flight; the freshly
// written pair is rolled back and the caller is refused (R10-19).
func (s *service) issueGuarded(ctx context.Context, clientID, subject string, scopes []Scope, familyID string, epoch uint64) (TokenResponse, error) {
	resp, err := s.issue(ctx, clientID, subject, scopes, familyID)
	if err != nil {
		return resp, err
	}
	if s.grantEpoch(subject, clientID) == epoch {
		return resp, nil
	}
	accessErr := s.tokens.DeleteAccess(ctx, resp.AccessToken)
	refreshErr := s.tokens.DeleteRefresh(ctx, resp.RefreshToken)
	if accessErr != nil || refreshErr != nil {
		return TokenResponse{}, fmt.Errorf(
			"oauth: grant revoked during issuance; rolling the pair back failed: access=%v refresh=%v",
			accessErr, refreshErr)
	}
	s.record(ctx, "oauth.issue_revoked", subject, clientID, audit.OutcomeDenied)
	return TokenResponse{}, protocolError("invalid_grant",
		"the grant was revoked while this request was in flight")
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
		// The access record is already live but the pair can never be delivered:
		// the response is this error. Leaving it behind mints a usable bearer
		// token nobody can name or revoke, so the write is undone. A rollback
		// failure is reported alongside the original error, because a leaked
		// access token must not be hidden behind the cleaner-looking save error
		// (S01-4).
		if delErr := s.tokens.DeleteAccess(ctx, at); delErr != nil {
			return TokenResponse{}, fmt.Errorf("oauth: save refresh token: %w (access-token rollback also failed: %v)", err, delErr)
		}
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

// dummyClientSecretHash is the verifier the unknown-client branch recomputes
// against. It is not a credential: it exists so the refusal spends the same
// salted slow-hash work a real secret check does, instead of returning after a
// single map miss and letting an attacker time client-id enumeration (S01-5).
// Recomparing a stored verifier (not hashing the presented secret afresh) is what
// keeps this branch the same shape as Authenticate's.
var dummyClientSecretHash = NewSecretHash("oauth:no-such-client")

// client resolves a client and, when auth is set, authenticates a confidential
// one. Public clients have no secret; their code/refresh binding plus PKCE is
// what protects them.
//
// An unknown client and a wrong secret answer with the SAME description and the
// same comparison work. The kit's contract (upstreamkit/server.go) is that an
// unauthenticated caller must not be able to tell an unknown client from a bad
// secret; different text — or a path that skips the digest comparison — is a
// client-id oracle (S01-5). The distinction stays server-side, in the audit
// plane.
func (s *service) client(ctx context.Context, id, secret string, auth bool) (Client, error) {
	c, err := s.clients.Get(ctx, id)
	if errors.Is(err, ErrClientNotFound) {
		if auth {
			verifySecretHash(dummyClientSecretHash, secret)
		}
		return Client{}, protocolError("invalid_client", "invalid client credentials")
	}
	if err != nil {
		return Client{}, err
	}
	if auth && c.Type == ClientConfidential && !c.Authenticate(secret) {
		return Client{}, protocolError("invalid_client", "invalid client credentials")
	}
	return c, nil
}

// record writes one OAuth audit event. A failure is logged, not swallowed: the
// token or the revocation has already happened, so refusing now would not undo it,
// but an audit record that vanishes without a trace is the outcome this project
// does not accept. The direction is the OP store's (log and proceed); the raw
// subject is deliberately not logged, so it cannot outlive its pseudonymisation
// key (S01-9/N-03).
func (s *service) record(ctx context.Context, action, subject, clientID, outcome string) {
	if err := s.audit.Record(ctx, audit.Event{
		Action:   action,
		Subject:  subject,
		Provider: "oauth",
		Outcome:  outcome,
		Detail:   map[string]string{"client_id": clientID},
	}); err != nil {
		slog.Error("oauth audit record failed",
			"action", action, "client_id", clientID, "outcome", outcome, "err", err)
	}
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

// refreshFamilyLock is one rotation family's turnstile. refs counts the callers
// that hold or are waiting for it, so the map entry can be dropped once the last
// one leaves; without the count the service's lock map would keep one entry for
// every family it ever saw, which is the same unbounded growth the tombstones
// are swept to avoid.
type refreshFamilyLock struct {
	mu   sync.Mutex
	refs int
}

// lockRefreshFamily serializes every state change of one rotation family and
// returns the release. The key is the family when the store can name it, the
// presented value when the store reports it unknown, and one service-wide key
// when the store cannot name families at all (coarser, but still atomic).
//
// It never blocks unrelated families: the map is consulted under refreshLocksMu
// only long enough to find or create the family's own mutex, which is then taken
// outside that guard.
func (s *service) lockRefreshFamily(key string) func() {
	s.refreshLocksMu.Lock()
	l := s.refreshLocks[key]
	if l == nil {
		l = &refreshFamilyLock{}
		s.refreshLocks[key] = l
	}
	l.refs++
	s.refreshLocksMu.Unlock()

	l.mu.Lock()
	return func() {
		l.mu.Unlock()

		s.refreshLocksMu.Lock()
		l.refs--
		if l.refs == 0 {
			delete(s.refreshLocks, key)
		}
		s.refreshLocksMu.Unlock()
	}
}

// refreshFamilyKey names the serialization key for a presented refresh value. A
// store that implements RefreshFamilyResolver answers for a live value from its
// record and for a spent one from its tombstone, so a replay and the rotation it
// races share one key. A store that cannot answer is not a Store failure: the
// service falls back to a single key, which serializes every refresh but keeps
// the claim-and-act step atomic on any implementation. An unknown value gets the
// value's own key — nothing can be revoked for it, so it needs no family-wide
// wait, but two concurrent presentations of the same unknown value still must not
// interleave.
func (s *service) refreshFamilyKey(ctx context.Context, value string) (string, error) {
	resolver, ok := s.tokens.(RefreshFamilyResolver)
	if !ok {
		return "refresh:global", nil
	}
	family, err := resolver.RefreshFamily(ctx, value)
	switch {
	case err == nil && family != "":
		return "refresh:family:" + family, nil
	case err != nil && !errors.Is(err, ErrTokenNotFound):
		// A store that cannot answer must not paint over its failure with an
		// unserialized claim: fail closed, the same way a failed family
		// revocation does.
		return "", err
	}
	return "refresh:value:" + TokenHash(value), nil
}
