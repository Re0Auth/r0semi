package federation

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
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
	// The token goes into the vault; the binding store keeps only metadata.
	if err := s.storeBindingSecret(ctx, binding, bindingSecret{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
	}); err != nil {
		return Binding{}, flow, err
	}
	if err := s.bindings.Put(ctx, binding); err != nil {
		// Do not leave an orphaned secret behind. A rollback that fails is reported
		// alongside the original error rather than swallowed: the residue is a
		// decryptable upstream token with no row pointing at it, which no endpoint
		// can reach and only an account erasure would clear.
		if rerr := s.vault.Revoke(ctx, BindingIdentity(binding)); rerr != nil {
			// Logged as well as returned. No endpoint can reach the residue and only
			// an account erasure clears it, so the caller seeing this error is not
			// enough on its own: an operator has to learn that a decryptable upstream
			// token is stranded.
			slog.ErrorContext(ctx, "could not roll back a bind's vault secret; a secret is left with no binding",
				"user", string(binding.User), "game", binding.Game, "source", binding.Source, "err", rerr)
			return Binding{}, flow, errors.Join(err,
				fmt.Errorf("federation: a secret is left in the vault with no binding: %w", rerr))
		}
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
