package referencesource

import (
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/idp"
)

// SocialConfig tunes the source's OAuth social login.
type SocialConfig struct {
	// Now injects a clock. Defaults to time.Now.
	Now func() time.Time
	// StateTTL is how long an in-flight authorization stays valid. Defaults to
	// 10 minutes.
	StateTTL time.Duration
}

// SocialDeps are the pieces the social login drives.
type SocialDeps struct {
	Registry *idp.Registry
	Logger   audit.Logger
}

// SocialLogin logs a visitor in through a standard OAuth 2.0 identity provider
// (Google, GitHub, ...).
//
// It is the cleanest demonstration of the Authenticator seam: the source's own
// login is itself OAuth, and Re0Auth still only ever sees the subject. The
// subject is namespaced by provider ("google:12345") so two providers cannot
// collide on a bare account id.
type SocialLogin struct {
	registry *idp.Registry
	logger   audit.Logger
	now      func() time.Time
	stateTTL time.Duration

	mu     sync.Mutex
	states map[string]socialState
}

type socialState struct {
	provider  idp.Provider
	verifier  string
	nonce     string
	returnTo  string
	expiresAt time.Time
}

// NewSocialLogin wires the source's social login.
func NewSocialLogin(cfg SocialConfig, deps SocialDeps) (*SocialLogin, error) {
	if deps.Registry == nil {
		return nil, errors.New("referencesource: SocialDeps.Registry is required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.StateTTL <= 0 {
		cfg.StateTTL = 10 * time.Minute
	}
	if deps.Logger == nil {
		deps.Logger = audit.NewMemoryLogger()
	}
	return &SocialLogin{
		registry: deps.Registry,
		logger:   deps.Logger,
		now:      cfg.Now,
		stateTTL: cfg.StateTTL,
		states:   make(map[string]socialState),
	}, nil
}

// Mount registers the social login routes: one start/callback pair per enabled
// provider.
func (l *SocialLogin) Mount(mux *http.ServeMux, establish Establish) {
	mux.HandleFunc("GET /login/{provider}/start", l.handleStart)
	mux.HandleFunc("GET /login/{provider}/callback", func(w http.ResponseWriter, r *http.Request) {
		l.handleCallback(w, r, establish)
	})
}

func (l *SocialLogin) handleStart(w http.ResponseWriter, r *http.Request) {
	provider := idp.Provider(r.PathValue("provider"))
	client, ok := l.registry.Get(provider)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "unknown_provider"})
		return
	}
	state, err := randomLoginID("soc_")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal_error"})
		return
	}
	verifier := client.NewVerifier()
	nonce := client.NewNonce()

	l.mu.Lock()
	l.sweepLocked()
	l.states[state] = socialState{
		provider:  provider,
		verifier:  verifier,
		nonce:     nonce,
		returnTo:  r.URL.Query().Get("return_to"),
		expiresAt: l.now().Add(l.stateTTL),
	}
	l.mu.Unlock()

	http.Redirect(w, r, client.AuthCodeURL(state, verifier, nonce), http.StatusFound)
}

func (l *SocialLogin) handleCallback(w http.ResponseWriter, r *http.Request, establish Establish) {
	provider := idp.Provider(r.PathValue("provider"))
	state := r.URL.Query().Get("state")

	l.mu.Lock()
	st, ok := l.states[state]
	delete(l.states, state)
	l.mu.Unlock()

	switch {
	case !ok || !l.now().Before(st.expiresAt):
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_state"})
		return
	case st.provider != provider:
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "provider_mismatch"})
		return
	case r.URL.Query().Get("error") != "":
		writeJSON(w, http.StatusForbidden, map[string]any{
			"error": "access_denied", "message": r.URL.Query().Get("error"),
		})
		return
	}

	client, ok := l.registry.Get(provider)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "unknown_provider"})
		return
	}
	token, err := client.Exchange(r.Context(), r.URL.Query().Get("code"), st.verifier)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": "upstream_unavailable", "message": err.Error()})
		return
	}
	identity, err := client.Identity(r.Context(), token, st.nonce)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": "upstream_unavailable", "message": err.Error()})
		return
	}

	credential, err := json.Marshal(map[string]string{
		"access_token":  token.AccessToken,
		"token_type":    token.TokenType,
		"refresh_token": token.RefreshToken,
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal_error"})
		return
	}
	defer zeroize(credential)

	subject := string(identity.Provider) + ":" + identity.Subject
	if err := establish(r.Context(), Principal{
		Subject: subject, Display: identity.DisplayName, Credential: credential,
		Meta: map[string]string{"provider": string(identity.Provider)},
	}); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal_error"})
		return
	}
	_ = l.logger.Record(r.Context(), audit.Event{
		Action:   "referencesource.login",
		Subject:  subject,
		Provider: string(identity.Provider),
		Outcome:  audit.OutcomeOK,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"state": "confirmed", "subject": subject, "return_to": st.returnTo,
	})
}

func (l *SocialLogin) sweepLocked() {
	now := l.now()
	for state, st := range l.states {
		if !now.Before(st.expiresAt) {
			delete(l.states, state)
		}
	}
}
