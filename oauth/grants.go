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
			if client, err := s.clients.Get(ctx, r.ClientID); err == nil {
				g.ClientName = client.Name
			}
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

	out := make([]Grant, 0, len(byClient))
	for _, g := range byClient {
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
// Known and bounded gap: an authorization code issued before the revocation and
// not yet exchanged is left alone, so it can still be exchanged. Codes are
// single-use, PKCE-bound, bound to the client that requested them, and expire in
// minutes; closing the window would mean enumerating and deleting codes too, for
// a case where the client already has its tokens. Recorded rather than papered
// over.
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
func (s *MemoryStore) ListBySubject(_ context.Context, subject string) ([]GrantRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var out []GrantRecord
	for _, t := range s.access {
		if t.Subject == subject {
			out = append(out, GrantRecord{
				Kind: TokenKindAccess, ClientID: t.ClientID, Scopes: t.Scopes,
				IssuedAt: t.IssuedAt, ExpiresAt: t.ExpiresAt,
			})
		}
	}
	for _, t := range s.refresh {
		if t.Subject == subject {
			out = append(out, GrantRecord{
				Kind: TokenKindRefresh, ClientID: t.ClientID, Scopes: t.Scopes,
				IssuedAt: t.IssuedAt, ExpiresAt: t.ExpiresAt,
			})
		}
	}
	return out, nil
}

// DeleteBySubjectClient implements Store. It reports nothing about what it
// removed: revoking is idempotent, so "there was nothing there" is success.
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
	return nil
}
