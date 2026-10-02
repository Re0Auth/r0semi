package oauth

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/Re0Auth/r0semi/audit"
)

// TokenKind distinguishes the two records a grant can be made of.
type TokenKind string

const (
	TokenKindAccess  TokenKind = "access"
	TokenKindRefresh TokenKind = "refresh"
)

// GrantRecord is one stored token row, without its value.
//
// It exists so a subject's tokens can be enumerated. That is what makes both
// halves of the grants view possible: listing what a client can still do, and
// revoking it by removing the tokens themselves.
type GrantRecord struct {
	Kind      TokenKind
	ClientID  string
	Scopes    []Scope
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// Grant is what one client can currently do as one subject.
//
// It is **derived from live tokens, not stored separately.** That is a decision
// with a consequence worth stating plainly: a grant exists exactly as long as the
// client holds a usable token, so revoking one is just deleting them, and there
// is no second source of truth that could disagree with what the tokens actually
// allow. The price is that the list shows *current access* rather than *historic
// consent* — a client whose last refresh token has expired drops off it, because
// it can no longer do anything. A stored consent record would keep showing it;
// this does not, and the difference is deliberate.
type Grant struct {
	ClientID   string
	ClientName string
	Scopes     []Scope
	// HasRefresh reports whether the client can renew without asking again. It is
	// the difference between "this will lapse" and "this will keep working", which
	// is the thing a user looking at this list actually wants to know.
	HasRefresh bool
	IssuedAt   time.Time
	// ExpiresAt is the furthest-out token, so it is when access finally lapses.
	ExpiresAt time.Time
}

// Grants lists what each client can still do as this subject.
func (s *service) Grants(ctx context.Context, subject string) ([]Grant, error) {
	if subject == "" {
		return nil, errors.New("oauth: subject is required")
	}
	records, err := s.tokens.ListBySubject(ctx, subject)
	if err != nil {
		return nil, err
	}

	now := s.now()
	byClient := make(map[string]*Grant)
	for _, r := range records {
		// Expiry is enforced here rather than in the store, which stays a dumb
		// map: an expired token is a token that grants nothing, so it does not
		// make a client appear.
		if !r.ExpiresAt.After(now) {
			continue
		}
		g, ok := byClient[r.ClientID]
		if !ok {
			g = &Grant{ClientID: r.ClientID, IssuedAt: r.IssuedAt, ExpiresAt: r.ExpiresAt}
			byClient[r.ClientID] = g
		}
		g.Scopes = unionScopes(g.Scopes, r.Scopes)
		if r.IssuedAt.Before(g.IssuedAt) {
			g.IssuedAt = r.IssuedAt
		}
		if r.ExpiresAt.After(g.ExpiresAt) {
			g.ExpiresAt = r.ExpiresAt
		}
		if r.Kind == TokenKindRefresh {
			g.HasRefresh = true
		}
	}

	// Names resolved in one lookup for the whole page rather than one Get per
	// client from inside the loop above.
	ids := make([]string, 0, len(byClient))
	for id := range byClient {
		ids = append(ids, id)
	}
	names := LookupClientNames(ctx, s.clients, ids)

	out := make([]Grant, 0, len(byClient))
	for _, g := range byClient {
		g.ClientName = names[g.ClientID]
		out = append(out, *g)
	}
	// Sorted, because a map is not. A list that reorders itself between two loads
	// of the same page is a list nobody trusts.
	sort.Slice(out, func(i, j int) bool { return out[i].ClientID < out[j].ClientID })
	return out, nil
}

// RevokeGrant removes every token a client holds for a subject.
//
// This is the local revocation from the threat model's §7: it touches no
// binding and no upstream credential, so the user's other devices and other
// clients keep working, and nothing at the data source changes. The client's
// next call fails with `invalid_token` and it must ask again.
//
// It is idempotent: revoking a client that holds nothing is a no-op, which is
// what lets the endpoint answer 204 either way.
//
// It also removes an authorization code issued but not yet exchanged. Who holds
// that code decides how much it is worth: a client is untrusted, and it can
// withhold the code precisely to spend it after the user revokes — the exchange
// returns an access *and* a refresh token, so the revocation would be undone for
// as long as the client keeps refreshing. (An earlier note here called the gap
// bounded because "the client already has its tokens"; the refresh token is what
// made that wrong.)
func (s *service) RevokeGrant(ctx context.Context, subject, clientID string) error {
	if subject == "" || clientID == "" {
		return errors.New("oauth: subject and client id are required")
	}
	if err := s.tokens.DeleteBySubjectClient(ctx, subject, clientID); err != nil {
		return err
	}
	s.record(ctx, "oauth.grant.revoke", subject, clientID, audit.OutcomeOK)
	return nil
}

// unionScopes merges two scope sets, keeping the result sorted so that a grant
// built from the same records always reads the same way.
func unionScopes(a, b []Scope) []Scope {
	seen := make(map[Scope]bool, len(a)+len(b))
	for _, s := range a {
		seen[s] = true
	}
	for _, s := range b {
		seen[s] = true
	}
	out := make([]Scope, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// ListBySubject implements Store by scanning both tables.
//
// The scan runs under the read lock, so it no longer serialises with the token
// reads an account page's other requests perform (S01-11/S04-4), and every
// returned record's Scopes are a copy so a caller cannot rewrite stored grants
// through the slice it was handed (Z18v-1).
func (s *MemoryStore) ListBySubject(_ context.Context, subject string) ([]GrantRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var out []GrantRecord
	for _, t := range s.access {
		if t.Subject == subject {
			out = append(out, GrantRecord{
				Kind: TokenKindAccess, ClientID: t.ClientID, Scopes: cloneScopes(t.Scopes),
				IssuedAt: t.IssuedAt, ExpiresAt: t.ExpiresAt,
			})
		}
	}
	for _, t := range s.refresh {
		if t.Subject == subject {
			out = append(out, GrantRecord{
				Kind: TokenKindRefresh, ClientID: t.ClientID, Scopes: cloneScopes(t.Scopes),
				IssuedAt: t.IssuedAt, ExpiresAt: t.ExpiresAt,
			})
		}
	}
	return out, nil
}

// DeleteBySubjectClient implements Store. It reports nothing about what it
// removed: revoking is idempotent, so "there was nothing there" is success.
//
// Unspent authorization codes go with the tokens. A code is a redeemable
// capability, not a record of something already handed over: a client that asked
// for authorization and withheld the code could exchange it after the subject
// revoked the grant, and the exchange returns a refresh token, so the revocation
// it just reported came undone for good. RevokeTokens clears codes for the same
// reason; this is the per-client path.
func (s *MemoryStore) DeleteBySubjectClient(_ context.Context, subject, clientID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for key, t := range s.access {
		if t.Subject == subject && t.ClientID == clientID {
			delete(s.access, key)
		}
	}
	for key, t := range s.refresh {
		if t.Subject == subject && t.ClientID == clientID {
			delete(s.refresh, key)
		}
	}
	for key, c := range s.codes {
		if c.Subject == subject && c.ClientID == clientID {
			delete(s.codes, key)
		}
	}
	// Spent tokens' tombstones carry the same owner fields, so they are dropped
	// too. They are not credentials, but a tombstone outliving the revocation of
	// the grant it belonged to would keep reporting that grant's family as
	// replayable — and would keep it revocable — after the user was told it was
	// gone.
	for key, tomb := range s.tombstones {
		if tomb.Subject == subject && tomb.ClientID == clientID {
			delete(s.tombstones, key)
		}
	}
	return nil
}

// RevokeTokens implements TokenAdmin. It returns how many records it removed,
// because a Kill Switch report with no number is not something an operator can
// act on.
//
// Authorization codes are removed with the tokens even though they are not
// counted: an unredeemed code is a redeemable capability, so a Kill Switch that
// left one alive could still mint fresh tokens afterwards.
func (s *MemoryStore) RevokeTokens(_ context.Context, f TokenFilter) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	removed := 0
	for key, t := range s.access {
		if f.Matches(t.ClientID, t.Subject) {
			delete(s.access, key)
			removed++
		}
	}
	for key, t := range s.refresh {
		if f.Matches(t.ClientID, t.Subject) {
			delete(s.refresh, key)
			removed++
		}
	}
	for key, c := range s.codes {
		if f.Matches(c.ClientID, c.Subject) {
			delete(s.codes, key)
		}
	}
	// Matching tombstones are cleared but not counted: they are the residue of
	// spent tokens, not tokens a client can still use. Leaving one behind would
	// keep the revoked family's replay signal armed, which is the opposite of what
	// a Kill Switch promises.
	for key, tomb := range s.tombstones {
		if f.Matches(tomb.ClientID, tomb.Subject) {
			delete(s.tombstones, key)
		}
	}
	return removed, nil
}
