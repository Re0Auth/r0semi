package federation

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"

	"github.com/Re0Auth/r0semi/internal/account"
)

var (
	// ErrUnknownBind reports a missing or already-consumed bind request.
	ErrUnknownBind = errors.New("federation: unknown or expired bind request")
	// ErrBindUser reports a bind request that belongs to another user.
	ErrBindUser = errors.New("federation: bind request belongs to another user")
	// ErrBindUnavailable reports a source that cannot be bound.
	ErrBindUnavailable = errors.New("federation: source cannot be bound")
	// ErrBindSuperseded reports a bind whose binding was removed or replaced
	// after the flow began: an Unbind, a CascadeRevoke, a Kill Switch shred or an
	// account erasure completed first, or another writer claimed the row. The
	// bind is refused rather than allowed to re-create the credential.
	ErrBindSuperseded = errors.New("federation: the binding was removed or changed while this bind was in progress")
)

// BindFlow is a pending source binding.
type BindFlow struct {
	ID        string
	User      account.UserID
	Game      string
	Source    string
	Verifier  string
	State     string
	ReturnTo  string
	ExpiresAt time.Time

	// Bound reports whether a binding existed when this flow began, and
	// BoundVersion is its Version at that moment (meaningful only when Bound).
	// CompleteBind re-checks them with PutIfVersion / Create, so a flow begun
	// against a live binding cannot re-create one that a completed Unbind,
	// CascadeRevoke, Kill Switch shred or account erasure removed (S14-2). Those
	// are single store operations, unlike the process-local keyedMutex, so the
	// check also holds across Postgres replicas.
	Bound        bool
	BoundVersion uint64
}

// BindChallenge is what the browser needs to start binding.
type BindChallenge struct {
	ID           string
	AuthorizeURL string
}

// BindFlowStore persists pending bind flows, keyed by state.
type BindFlowStore interface {
	Put(ctx context.Context, f BindFlow) error
	// Consume returns and removes the flow for state.
	Consume(ctx context.Context, state string) (BindFlow, error)
	// PurgeUserFlows removes every pending flow one account has started and
	// reports how many. It is the account-erasure path: a pending flow holds a
	// PKCE verifier for a person, and an erasure must not leave it behind.
	PurgeUserFlows(ctx context.Context, user account.UserID) (int, error)
}

// MemoryBindFlowStore is a non-durable BindFlowStore for development and tests.
type MemoryBindFlowStore struct {
	mu sync.Mutex
	m  map[string]BindFlow
}

// NewMemoryBindFlowStore returns an empty store.
func NewMemoryBindFlowStore() *MemoryBindFlowStore {
	return &MemoryBindFlowStore{m: make(map[string]BindFlow)}
}

// Put implements BindFlowStore.
func (s *MemoryBindFlowStore) Put(_ context.Context, f BindFlow) error {
	s.mu.Lock()
	s.m[f.State] = f
	s.mu.Unlock()
	return nil
}

// Consume implements BindFlowStore. It is single-use.
func (s *MemoryBindFlowStore) Consume(_ context.Context, state string) (BindFlow, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.m[state]
	if !ok {
		return BindFlow{}, ErrUnknownBind
	}
	delete(s.m, state)
	return f, nil
}

// PurgeUserFlows implements BindFlowStore.
func (s *MemoryBindFlowStore) PurgeUserFlows(_ context.Context, user account.UserID) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for state, f := range s.m {
		if f.User == user {
			delete(s.m, state)
			n++
		}
	}
	return n, nil
}

// SweepExpired drops flows whose deadline has passed and reports how many it
// removed.
//
// Expiry is enforced on Consume, so this is not what makes an expired flow
// unusable — it is what keeps the map from holding every flow the process ever
// started. A flow is written by BeginBind and read only if the browser comes back;
// an abandoned one (a closed tab, a QR scan the user never finished) has no other
// bound, and in memory mode there is no durable sweep behind it. The composition
// root runs this on the same ticker as the other sweeps.
func (s *MemoryBindFlowStore) SweepExpired() int {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for state, f := range s.m {
		if !now.Before(f.ExpiresAt) {
			delete(s.m, state)
			removed++
		}
	}
	return removed
}

// BeginBind starts binding a source for a user and returns the upstream
// authorization URL to redirect the browser to.
func (s *service) BeginBind(ctx context.Context, user account.UserID, game, source, returnTo string) (BindChallenge, error) {
	src, ok := s.registry.Get(game, source)
	if !ok {
		return BindChallenge{}, ErrUnknownSource
	}
	if src.ClientID == "" || s.baseURL == "" {
		return BindChallenge{}, ErrBindUnavailable
	}

	id, err := newBindID()
	if err != nil {
		return BindChallenge{}, err
	}
	verifier := oauth2.GenerateVerifier()
	flow := BindFlow{
		ID: id, User: user, Game: game, Source: source,
		Verifier: verifier, State: id, ReturnTo: returnTo,
		ExpiresAt: s.now().Add(s.bindTTL),
	}
	// Record what the account was bound to when this flow began. The read is
	// deliberately taken without the lock: it is a precondition to re-check under
	// the lock in CompleteBind, not a lock itself, and a stale read only makes the
	// later claim fail closed.
	if current, gerr := s.bindings.Get(ctx, user, game, source); gerr == nil {
		flow.Bound = true
		flow.BoundVersion = current.Version
	} else if !errors.Is(gerr, ErrNotBound) {
		return BindChallenge{}, gerr
	}
	if err := s.flows.Put(ctx, flow); err != nil {
		return BindChallenge{}, err
	}

	authURL := s.oauthConfig(src).AuthCodeURL(id, oauth2.S256ChallengeOption(verifier))
	return BindChallenge{ID: id, AuthorizeURL: authURL}, nil
}

// CompleteBind finishes a binding: it consumes the flow, exchanges the code for
// an upstream token, and stores the binding. The flow is returned even on error
// so the caller can redirect the browser back to where it came from.
func (s *service) CompleteBind(ctx context.Context, user account.UserID, state, code string) (Binding, BindFlow, error) {
	flow, err := s.flows.Consume(ctx, state)
	if err != nil {
		return Binding{}, BindFlow{}, err
	}
	switch {
	case flow.User != user:
		return Binding{}, flow, ErrBindUser
	case !s.now().Before(flow.ExpiresAt):
		return Binding{}, flow, ErrUnknownBind
	case code == "":
		return Binding{}, flow, errors.New("federation: authorization was refused")
	}

	// The per-binding keyed lock, held for the whole exchange-and-store sequence,
	// exactly like every other writer of one binding's credential (Unbind,
	// refreshBinding, CascadeRevoke, shredBinding). It orders a bind against a
	// CONCURRENT removal within this process. A removal that already finished is
	// caught by the claim below, not by the lock: the flow remembers the Version
	// the account was bound to, and a row that moved or vanished loses the CAS.
	unlock := s.locks.lock(bindingKey(user, flow.Game, flow.Source))
	defer unlock()

	src, ok := s.registry.Get(flow.Game, flow.Source)
	if !ok {
		return Binding{}, flow, ErrUnknownSource
	}
	token, err := s.oauthConfig(src).Exchange(s.oauthContext(ctx), code, oauth2.VerifierOption(flow.Verifier))
	if err != nil {
		return Binding{}, flow, fmt.Errorf("federation: bind exchange: %w", err)
	}

	generation, err := newBindingGeneration()
	if err != nil {
		return Binding{}, flow, err
	}
	binding := Binding{
		User: user, Game: flow.Game, Source: flow.Source,
		TokenType:  token.TokenType,
		Expiry:     token.Expiry,
		HasRefresh: token.RefreshToken != "",
		Version:    generation,
	}
	// Claim the row BEFORE the vault write, the order refreshBinding uses
	// (refresh.go) and for the same reason: a writer that loses the claim must not
	// have touched the vault. The claim is also where the BeginBind precondition
	// is enforced — PutIfVersion refuses a row that moved or vanished, Create
	// refuses one that appeared — so a removal that completed before this flow
	// reached the lock still cannot be undone, in this process or another replica.
	var won bool
	if flow.Bound {
		won, err = s.bindings.PutIfVersion(ctx, binding, flow.BoundVersion)
	} else {
		won, err = s.bindings.Create(ctx, binding)
	}
	if err != nil {
		return Binding{}, flow, err
	}
	if !won {
		// Fail closed, and do not touch the vault: there is no secret to roll back
		// because the vault write has not happened yet.
		return Binding{}, flow, ErrBindSuperseded
	}
	// The token goes into the vault; the binding store keeps only metadata. The
	// row is already claimed, so a vault failure cannot strand a decryptable
	// secret with no row pointing at it; it leaves the row for the next call or an
	// Unbind, the same trade refreshBinding documents.
	if err := s.storeBindingSecret(ctx, binding, bindingSecret{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
	}); err != nil {
		return Binding{}, flow, err
	}
	return binding, flow, nil
}

func (s *service) oauthConfig(src Source) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     src.ClientID,
		ClientSecret: src.ClientSecret,
		Endpoint:     oauth2.Endpoint{AuthURL: src.AuthorizationEndpoint, TokenURL: src.TokenEndpoint},
		RedirectURL:  s.redirectURL(src),
		Scopes:       src.bindScopes(),
	}
}

func (s *service) oauthContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, oauth2.HTTPClient, s.httpClient)
}

func (s *service) redirectURL(src Source) string {
	return strings.TrimRight(s.baseURL, "/") + "/auth/upstream/" + src.Game + "/" + src.Name + "/callback"
}

func newBindID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", errors.New("federation: random source failed")
	}
	return "bnd_" + hex.EncodeToString(b), nil
}
