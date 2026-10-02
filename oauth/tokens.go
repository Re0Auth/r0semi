package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

// ErrTokenNotFound reports a token value this issuer never handed out, or one a
// plain revocation removed. It is NOT what a replayed rotated refresh token
// reports: that is ErrRefreshTokenReused, because the two demand opposite
// responses (RFC 9700 §4.14.2).
var ErrTokenNotFound = errors.New("oauth: token not found")

// ErrRefreshTokenReused reports a refresh token presented after this store
// already rotated it. It is the theft signal RFC 9700 §4.14.2 keys on: the
// legitimate client and whoever stole the token both hold a copy, so the second
// presentation is a replay, and the whole rotation family must be revoked.
//
// It is distinct from ErrTokenNotFound on purpose. "Never issued" is an ordinary
// invalid_grant; "already spent" is evidence of compromise, and a store that
// folded the two together would refuse the replay while leaving the thief's
// current generation live.
var ErrRefreshTokenReused = errors.New("oauth: refresh token reused after rotation")

// RefreshReuseError is the typed form of ErrRefreshTokenReused. It carries the
// family the presented token belonged to so the caller can revoke it — the token
// row itself is gone by the time this is returned, so the family id is the only
// surviving handle on the chain the thief is holding.
//
// Unwrap reports ErrRefreshTokenReused, so a caller can key on either the type
// (for the family) or the sentinel (with errors.Is).
type RefreshReuseError struct {
	FamilyID string
}

func (e *RefreshReuseError) Error() string {
	return "oauth: refresh token reused after rotation (family " + e.FamilyID + ")"
}

// Unwrap makes errors.Is(err, ErrRefreshTokenReused) true.
func (e *RefreshReuseError) Unwrap() error { return ErrRefreshTokenReused }

// AccessToken is a short-lived bearer token's record. It deliberately does NOT
// carry the token value: the store keys records by TokenHash(value), so a dump
// of the store yields no usable token.
type AccessToken struct {
	ClientID string
	Subject  string
	Scopes   []Scope
	// FamilyID is the rotation family this record belongs to; a detected replay
	// revokes every record with the same FamilyID.
	FamilyID  string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// RefreshToken is a long-lived token used to obtain new access tokens. It is
// rotated on every use.
type RefreshToken struct {
	ClientID string
	Subject  string
	Scopes   []Scope
	// FamilyID is the rotation family this record belongs to; a detected replay
	// revokes every record with the same FamilyID.
	FamilyID  string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// AuthorizationCode is a one-time code bound to a client, redirect URI and PKCE
// challenge.
type AuthorizationCode struct {
	ClientID            string
	Subject             string
	Scopes              []Scope
	RedirectURI         string
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           time.Time
}

// Store persists authorization codes and token records.
//
// The opaque value (code or token) is passed alongside the record. It is used
// only as a lookup key and is never persisted: an implementation MUST key on
// TokenHash(value) and MUST NOT store the value itself. That way a leaked store
// is not a leaked credential.
//
// Expiry is enforced by the service, not the store, so a store stays a dumb map.
//
// BREAKING CHANGE for Store implementers: this interface gained
// RevokeRefreshFamily, GetCode, GetRefresh and redefined ConsumeRefresh, and
// AccessToken/RefreshToken gained a FamilyID field. An implementation in another
// module must add all three methods, keep each spent refresh value's family
// reachable (tombstone) so a replay is reported as a *RefreshReuseError rather
// than ErrTokenNotFound, and record the family on both token kinds. The service
// relies on them to satisfy RFC 9700 §4.14.2, to keep a failed code exchange from
// spending the code, and to let a caller resolve a session read-only before a
// fallible upstream call; a store that only implements the old single-use consume
// silently keeps a detected replay from killing the thief's generation, one
// without GetCode cannot serve the exchange's pre-flight read at all, and one
// without GetRefresh forces the caller to spend a refresh token just to learn
// whose session it names.
//
// ConsumeCode and ConsumeRefresh must be atomic: a code is single-use and a
// refresh token is single-use because it rotates.
//
// Refresh-token rotation is what makes reuse detectable, and detection is only
// worth anything if it can be acted on: RFC 9700 §4.14.2 requires the whole
// rotation family to be revoked when a spent token is presented again. The
// contract therefore has two parts beyond the plain single-use consume:
//
//   - ConsumeRefresh of a value this store already consumed MUST return a
//     *RefreshReuseError carrying that value's FamilyID — never ErrTokenNotFound,
//     which would report a replay as an ordinary unknown token.
//   - The family MUST stay reachable after consumption for at least the spent
//     token's own lifetime. A store that forgets the family at rotation makes the
//     replay unrecognisable, which is the failure this contract exists to stop.
//     Implementations keep a tombstone (the spent hash mapped to its family);
//     RevokeRefreshFamily is what clears the chain.
//
// ListBySubject and DeleteBySubjectClient exist for the grants view, and they are
// what make "the tokens are the grant" true rather than merely stated: revoking a
// client is deleting its rows, so a revoked grant cannot survive in a table that
// the next request does not consult.
type Store interface {
	SaveCode(ctx context.Context, value string, c AuthorizationCode) error
	// GetCode returns the record a code value names WITHOUT consuming it, or
	// ErrTokenNotFound when this store never issued it (or a consume or a
	// revocation already removed it). It is the read peer of GetAccess, and the
	// read half of the exchange's two-step claim: the service judges the client,
	// redirect_uri and PKCE bindings on this record BEFORE it spends anything, so
	// a failed exchange refuses the caller instead of costing the code's owner
	// their tokens. Whoever merely knows a code can no longer deny it to the
	// client that earned it.
	//
	// It must return the same record ConsumeCode would return for a value no one
	// has claimed: GetCode is a pre-flight read, never the claim. Single use is
	// still decided by ConsumeCode's atomic delete, and only the record that wins
	// that delete may mint tokens. Expiry, like every other deadline in this
	// interface, is judged by the service, not the store.
	GetCode(ctx context.Context, value string) (AuthorizationCode, error)
	ConsumeCode(ctx context.Context, value string) (AuthorizationCode, error)

	SaveAccess(ctx context.Context, value string, t AccessToken) error
	GetAccess(ctx context.Context, value string) (AccessToken, error)
	DeleteAccess(ctx context.Context, value string) error

	SaveRefresh(ctx context.Context, value string, t RefreshToken) error
	// GetRefresh returns the record a refresh value names WITHOUT consuming it, or
	// ErrTokenNotFound when this store never issued it (or a consume or a
	// revocation already removed it). It is the read peer of ConsumeRefresh, the
	// same way GetCode is the read peer of ConsumeCode: a caller that only needs to
	// resolve which account or session a token belongs to and then attempt a
	// fallible side effect upstream must not have to spend the token to do it.
	//
	// A value already spent by ConsumeRefresh reports ErrTokenNotFound here, not a
	// *RefreshReuseError: this read is never where a replay is judged, and treating
	// an unknown and a spent value the same keeps the destructive claim — the one
	// that rotates the family and arms the reuse tombstone — the single place a
	// replay can be recognised. It mirrors GetAccess, and, like every other
	// deadline in this interface, expiry is judged by the service, not the store.
	GetRefresh(ctx context.Context, value string) (RefreshToken, error)
	// ConsumeRefresh claims a live refresh value atomically and retires it. A
	// live value returns its record; a value this store already consumed returns
	// a *RefreshReuseError carrying that value's FamilyID; only a value never
	// issued returns ErrTokenNotFound.
	ConsumeRefresh(ctx context.Context, value string) (RefreshToken, error)
	DeleteRefresh(ctx context.Context, value string) error

	// RevokeRefreshFamily deletes every live and retired refresh record of one
	// rotation family, plus every access record minted with it, and reports how
	// many token records went away. It is idempotent, and an empty familyID
	// revokes nothing — never "all": a caller that lost the family must not be
	// able to turn a detection into a global token wipe.
	RevokeRefreshFamily(ctx context.Context, familyID string) (int, error)

	// ListBySubject returns every token record for a subject, expired ones
	// included: the store has no clock, so the service decides what is still live.
	ListBySubject(ctx context.Context, subject string) ([]GrantRecord, error)
	// DeleteBySubjectClient removes every token one client holds for one subject,
	// plus any authorization code it was issued and has not spent. Codes go with
	// the tokens because an unspent code is a redeemable capability: withholding
	// it and redeeming after the revocation hands the client a fresh token pair.
	DeleteBySubjectClient(ctx context.Context, subject, clientID string) error

	// TokenOwner returns the client a presented token value was issued to, or
	// ErrTokenNotFound. The value may name an access token or a refresh token.
	//
	// It is a READ, not a consume, and it exists because RFC 7009 §2.1 requires
	// revocation to check that the token belongs to the client asking: deleting by
	// value alone let any registered client revoke another's tokens — and with
	// them the refresh chain — if it ever came by the value.
	TokenOwner(ctx context.Context, value string) (string, error)
}

// RefreshFamilyResolver is an OPTIONAL Store extension: it names the rotation
// family a refresh value belongs to, live or already spent, WITHOUT claiming it.
//
// The service needs the family *before* it consumes, because the claim and the
// step that follows it must be one atomic act per family (S14-5): on the reuse
// branch a replay revokes the family, on the rotation branch it mints into it,
// and if those two can interleave the revocation can land before the mint and
// leave a live generation behind. A store that can answer this lets the service
// take a per-family lock across the whole step, so generations of one chain
// serialize while unrelated chains do not.
//
// It is deliberately not part of Store: an implementation that cannot answer it
// is not broken and does not fail to compile. The service falls back to a single
// service-wide lock, which is coarser but still atomic. A value the store never
// issued reports ErrTokenNotFound, and the service then serializes on the value
// alone — nothing can be revoked for it, but two presentations of the same value
// still must not overlap. Like GetRefresh, a value already spent is *resolved*
// here (from its tombstone), not reported as a replay: judging a replay stays
// ConsumeRefresh's job.
type RefreshFamilyResolver interface {
	RefreshFamily(ctx context.Context, value string) (string, error)
}

// TokenFilter selects tokens for bulk revocation. An empty filter matches every
// token; when both fields are set they combine with AND.
type TokenFilter struct {
	ClientID string
	Subject  string
}

// Matches reports whether a token's owner is selected by the filter.
func (f TokenFilter) Matches(clientID, subject string) bool {
	return (f.ClientID == "" || f.ClientID == clientID) &&
		(f.Subject == "" || f.Subject == subject)
}

// TokenAdmin is the management side of a token store: bulk revocation, for an
// operator disabling a client, containing a compromised account, or throwing the
// Kill Switch. It is separate from Store so the request path depends only on the
// operations it actually performs.
type TokenAdmin interface {
	// RevokeTokens deletes every matching token and reports how many rows went
	// away. Removing zero is success: revocation is idempotent.
	RevokeTokens(ctx context.Context, f TokenFilter) (int, error)
}

// TokenAdmins fans a revocation out across several stores, because a deployment
// can run more than one token engine: the OpenID Provider, and — for one
// migrated from the retired hand-rolled engine — the token tables that engine
// left behind. Revoking in only one of them would report success while leaving
// tokens alive in the other.
type TokenAdmins []TokenAdmin

// RevokeTokens implements TokenAdmin. Every store is asked even when one fails: a
// store that holds nothing must not hide one that errored. The removed counts are
// summed and the first error is returned, so the caller still learns that
// something went wrong and — revocation being idempotent — can retry.
func (a TokenAdmins) RevokeTokens(ctx context.Context, f TokenFilter) (int, error) {
	total := 0
	var firstErr error
	for _, store := range a {
		n, err := store.RevokeTokens(ctx, f)
		total += n
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return total, firstErr
}

// refreshTombstone is what a spent refresh token leaves behind in MemoryStore.
//
// The live record is deleted at rotation, so by the time a replay arrives the
// only surviving pointer to the family is this: the spent token's hash mapped to
// its family and the owner fields the lifecycle revocations match on. It stores
// no token value — only the hash the record was already keyed by — and it expires
// on the spent token's own deadline, because after that a replay could not have
// produced a usable token anyway.
type refreshTombstone struct {
	FamilyID  string
	ClientID  string
	Subject   string
	ExpiresAt time.Time
}

// MemoryStore is a non-durable Store for development and tests.
type MemoryStore struct {
	mu      sync.Mutex
	codes   map[string]AuthorizationCode
	access  map[string]AccessToken
	refresh map[string]RefreshToken
	// tombstones hold the family of every spent refresh value, keyed the same way
	// the live maps are. Without them a replay is indistinguishable from a value
	// that was never issued.
	tombstones map[string]refreshTombstone
	// now judges the tombstone deadline in ConsumeRefresh. The store has no clock
	// of its own — expiry is the service's judgment everywhere else — so the
	// service injects its clock at construction (NewService). A nil now keeps the
	// tombstone alive forever, which is the old, never-expiring behaviour.
	now func() time.Time
}

// NewMemoryStore returns an empty store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		codes:      make(map[string]AuthorizationCode),
		access:     make(map[string]AccessToken),
		refresh:    make(map[string]RefreshToken),
		tombstones: make(map[string]refreshTombstone),
	}
}

// SweepExpired drops every record whose deadline has passed and reports how many.
//
// Expiry is already enforced on read, so this is not what makes an expired token
// unusable — it is what keeps the maps from holding every token the process ever
// issued, which is a leak with no other bound in a store that has no database
// behind it. Tombstones are swept on the same rule: a spent token past its own
// deadline can no longer be replayed into anything, and keeping the residue would
// make the tombstone map grow without bound in a deployment that never rotates a
// family.
//
// Nothing calls it on a timer from inside this package: a deployment that runs
// this store either calls it from its own loop or accepts the growth, and saying
// so here is better than starting a goroutine a caller cannot stop.
func (s *MemoryStore) SweepExpired(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	removed := 0
	for k, c := range s.codes {
		if !now.Before(c.ExpiresAt) {
			delete(s.codes, k)
			removed++
		}
	}
	for k, t := range s.access {
		if !now.Before(t.ExpiresAt) {
			delete(s.access, k)
			removed++
		}
	}
	for k, t := range s.refresh {
		if !now.Before(t.ExpiresAt) {
			delete(s.refresh, k)
			removed++
		}
	}
	for k, tomb := range s.tombstones {
		if !now.Before(tomb.ExpiresAt) {
			delete(s.tombstones, k)
			removed++
		}
	}
	return removed
}

// SaveCode implements Store.
func (s *MemoryStore) SaveCode(_ context.Context, value string, c AuthorizationCode) error {
	s.mu.Lock()
	s.codes[TokenHash(value)] = c
	s.mu.Unlock()
	return nil
}

// GetCode implements Store. It is a read under the same mutex the claim takes,
// so the exchange can judge every binding before ConsumeCode decides whether the
// code is spent. A failed binding therefore costs the caller nothing.
func (s *MemoryStore) GetCode(_ context.Context, value string) (AuthorizationCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.codes[TokenHash(value)]
	if !ok {
		return AuthorizationCode{}, ErrTokenNotFound
	}
	return c, nil
}

// ConsumeCode implements Store.
func (s *MemoryStore) ConsumeCode(_ context.Context, value string) (AuthorizationCode, error) {
	key := TokenHash(value)

	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.codes[key]
	if !ok {
		return AuthorizationCode{}, ErrTokenNotFound
	}
	delete(s.codes, key)
	return c, nil
}

// SaveAccess implements Store.
func (s *MemoryStore) SaveAccess(_ context.Context, value string, t AccessToken) error {
	s.mu.Lock()
	s.access[TokenHash(value)] = t
	s.mu.Unlock()
	return nil
}

// GetAccess implements Store.
func (s *MemoryStore) GetAccess(_ context.Context, value string) (AccessToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.access[TokenHash(value)]
	if !ok {
		return AccessToken{}, ErrTokenNotFound
	}
	return t, nil
}

// DeleteAccess implements Store. Deleting an absent token is not an error, so
// revocation stays idempotent.
func (s *MemoryStore) DeleteAccess(_ context.Context, value string) error {
	s.mu.Lock()
	delete(s.access, TokenHash(value))
	s.mu.Unlock()
	return nil
}

// TokenOwner implements Store.
func (s *MemoryStore) TokenOwner(_ context.Context, value string) (string, error) {
	key := TokenHash(value)
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.access[key]; ok {
		return t.ClientID, nil
	}
	if t, ok := s.refresh[key]; ok {
		return t.ClientID, nil
	}
	return "", ErrTokenNotFound
}

// SaveRefresh implements Store.
func (s *MemoryStore) SaveRefresh(_ context.Context, value string, t RefreshToken) error {
	s.mu.Lock()
	s.refresh[TokenHash(value)] = t
	s.mu.Unlock()
	return nil
}

// GetRefresh implements Store. It is a read under the same mutex ConsumeRefresh
// claims under, with nothing deleted: a caller resolving which account a token
// names can therefore try again after a failure. A spent value is only a
// tombstone here, and a tombstone is not returned as a live record — the reuse
// signal belongs to ConsumeRefresh, whose claim is what makes presenting the
// value again a theft report.
func (s *MemoryStore) GetRefresh(_ context.Context, value string) (RefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.refresh[TokenHash(value)]
	if !ok {
		return RefreshToken{}, ErrTokenNotFound
	}
	return t, nil
}

// ConsumeRefresh implements Store. A live value is claimed and retired in one
// step; a value already spent leaves a tombstone its family can be read from, and
// presenting it again is the replay the caller must revoke the family for.
func (s *MemoryStore) ConsumeRefresh(_ context.Context, value string) (RefreshToken, error) {
	key := TokenHash(value)

	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.refresh[key]
	if !ok {
		if tomb, spent := s.tombstones[key]; spent {
			// The tombstone expires on the spent token's own deadline: after it,
			// a replay could not have produced a usable token anyway, so it is an
			// ordinary unknown value rather than a theft signal. Without this the
			// family would be revoked for a value that is already dead — the PG
			// store filters the same way with `expires_at > clock()`.
			if s.now != nil && !s.now().Before(tomb.ExpiresAt) {
				return RefreshToken{}, ErrTokenNotFound
			}
			return RefreshToken{}, &RefreshReuseError{FamilyID: tomb.FamilyID}
		}
		return RefreshToken{}, ErrTokenNotFound
	}
	delete(s.refresh, key)
	s.tombstones[key] = refreshTombstone{
		FamilyID: t.FamilyID, ClientID: t.ClientID, Subject: t.Subject, ExpiresAt: t.ExpiresAt,
	}
	return t, nil
}

// DeleteRefresh implements Store. The value's tombstone goes with it: an explicit
// revocation of a spent token says the replay signal is no longer wanted for that
// value, and leaving the tombstone behind would keep reporting a reuse for a
// token the caller just revoked.
func (s *MemoryStore) DeleteRefresh(_ context.Context, value string) error {
	key := TokenHash(value)
	s.mu.Lock()
	delete(s.refresh, key)
	delete(s.tombstones, key)
	s.mu.Unlock()
	return nil
}

// RevokeRefreshFamily implements Store. It deletes every generation of the family
// — live refresh records, the tombstones of spent ones, and the access record
// each generation was minted with — and reports the token records removed. An
// empty familyID is a no-op rather than a match-everything predicate.
func (s *MemoryStore) RevokeRefreshFamily(_ context.Context, familyID string) (int, error) {
	if familyID == "" {
		return 0, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	removed := 0
	for key, t := range s.refresh {
		if t.FamilyID == familyID {
			delete(s.refresh, key)
			removed++
		}
	}
	for key, t := range s.access {
		if t.FamilyID == familyID {
			delete(s.access, key)
			removed++
		}
	}
	// Tombstones are residue, not token records, so they are cleared but not
	// counted: the caller is told how many credentials died.
	for key, tomb := range s.tombstones {
		if tomb.FamilyID == familyID {
			delete(s.tombstones, key)
		}
	}
	return removed, nil
}

// RefreshFamily implements RefreshFamilyResolver. It is the non-destructive read
// peer of ConsumeRefresh's family answer: a live value names the family on its
// record, and a value already spent names it on the tombstone it left, so the
// service can serialize a replay's revocation and a rotation's mint on the same
// family. The tombstone deadline is judged exactly as ConsumeRefresh judges it,
// with the clock the service injected: past it the value is an ordinary unknown,
// because a replay there could not produce a usable token and the family must not
// be locked or revoked for it.
func (s *MemoryStore) RefreshFamily(_ context.Context, value string) (string, error) {
	key := TokenHash(value)

	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.refresh[key]; ok {
		return t.FamilyID, nil
	}
	if tomb, spent := s.tombstones[key]; spent {
		if s.now != nil && !s.now().Before(tomb.ExpiresAt) {
			return "", ErrTokenNotFound
		}
		return tomb.FamilyID, nil
	}
	return "", ErrTokenNotFound
}

// TokenHash is the at-rest form of an opaque token. Store implementations MUST
// key on it and MUST NOT persist the token itself.
//
// A plain SHA-256 is the right tool here, unlike for passwords: these tokens are
// 32 bytes from crypto/rand, so there is nothing to brute force and no need for
// a slow KDF. The store is a lookup table, not a verifier.
func TokenHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
