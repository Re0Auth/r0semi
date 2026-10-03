package referencesource

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/idp"
	"github.com/Re0Auth/r0semi/safeurl"
	"github.com/Re0Auth/r0semi/vault"
)

// maxInFlightStates caps the number of concurrently pending OAuth
// authorization states a SocialLogin will hold. The start route is
// unauthenticated by design, so without a cap the states map grows with the
// request rate times StateTTL and every start pays an O(n) sweep. Reaching the
// cap is a capacity signal, not an error in the caller's request.
const maxInFlightStates = 4096

// socialBindCookiePrefix names the per-provider bind cookie. The cookie is the
// second factor the OAuth `state` cannot be: the state alone is a bearer token,
// so whoever presents it is treated as the browser that started the login. The
// callback writes the IdP's subject into the PRESENTER's session and vault, so
// without a browser-bound proof an attacker can start a login, hand the callback
// URL to a victim, and bind the attacker's upstream account to the victim
// (login CSRF / forced login). TapTap's login in this package already carries the
// same second factor (R10-08).
const socialBindCookiePrefix = "refsrc_social_bind_"

func socialBindCookieName(provider idp.Provider) string {
	return socialBindCookiePrefix + string(provider)
}

// SocialConfig tunes the source's OAuth social login.
type SocialConfig struct {
	// Now injects a clock. Defaults to time.Now.
	Now func() time.Time
	// StateTTL is how long an in-flight authorization stays valid. Defaults to
	// 10 minutes.
	StateTTL time.Duration
	// Secure sets the Secure flag on the bind cookie. It must be true whenever
	// the source is served over https (the composition root refuses to start an
	// https issuer with it false).
	Secure bool
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
	secure   bool

	mu     sync.Mutex
	states map[string]socialState
}

type socialState struct {
	provider idp.Provider
	verifier string
	nonce    string
	// bind is the secret the initiating browser was given as a cookie and must
	// present on the callback. It never leaves the server in a response body.
	bind      string
	returnTo  string
	expiresAt time.Time
}

// boundTo reports whether the browser presenting bind is the one the login was
// started for. The comparison is constant-time; the values are random 128-bit
// tokens, so this is belt to the token's suspenders rather than the defence
// itself. A state with no binding is never satisfied.
func (st socialState) boundTo(bind string) bool {
	if st.bind == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(st.bind), []byte(bind)) == 1
}

// bindCookieFor builds the Set-Cookie that ties a login to the browser that
// started it. The path is the login prefix, so the value is not offered anywhere
// else, and there is no MaxAge: it dies with the browser session and is
// worthless once the state is gone.
func (l *SocialLogin) bindCookieFor(provider idp.Provider, bind string) *http.Cookie {
	return &http.Cookie{
		Name:     socialBindCookieName(provider),
		Value:    bind,
		Path:     "/login/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   l.secure,
	}
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
		secure:   cfg.Secure,
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
	// The browser binding. It is issued as a cookie below and required on the
	// callback, which is what makes the state a proof of browser continuity
	// rather than a bearer token (R10-08).
	bind, err := randomLoginID("bind_")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal_error"})
		return
	}

	l.mu.Lock()
	l.sweepLocked()
	if len(l.states) >= maxInFlightStates {
		l.mu.Unlock()
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "too_many_pending_authorizations"})
		return
	}
	l.states[state] = socialState{
		provider: provider,
		verifier: verifier,
		nonce:    nonce,
		bind:     bind,
		// return_to arrives on an unauthenticated GET and is echoed back in the
		// callback JSON, so it is held to the same same-origin rule as every other
		// request-supplied redirect parameter (the guard lives in safeurl).
		returnTo:  safeurl.RelativePath(r.URL.Query().Get("return_to")),
		expiresAt: l.now().Add(l.stateTTL),
	}
	l.mu.Unlock()

	authURL, err := client.AuthCodeURL(r.Context(), state, verifier, nonce)
	if err != nil {
		http.Error(w, "could not start the authorization", http.StatusBadGateway)
		return
	}
	// Only after the authorize URL is built: a failed start hands out no cookie.
	http.SetCookie(w, l.bindCookieFor(provider, bind))
	// authURL is the registered provider's authorize endpoint, assembled by the
	// OIDC client from discovery plus the random state, verifier and nonce;
	// return_to is carried in the session, not this URL.
	http.Redirect(w, r, authURL, http.StatusFound) //nolint:gosec // G710: authURL is the registered provider's authorize endpoint
}

func (l *SocialLogin) handleCallback(w http.ResponseWriter, r *http.Request, establish Establish) {
	provider := idp.Provider(r.PathValue("provider"))
	state := r.URL.Query().Get("state")

	// The browser binding is read before the lock. It must match the state's
	// binding exactly; presenting the state is not enough (R10-08).
	bind := ""
	if c, err := r.Cookie(socialBindCookieName(provider)); err == nil {
		bind = c.Value
	}

	l.mu.Lock()
	st, ok := l.states[state]
	switch {
	case !ok || !l.now().Before(st.expiresAt):
		l.mu.Unlock()
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_state"})
		return
	case st.provider != provider:
		l.mu.Unlock()
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "provider_mismatch"})
		return
	case !st.boundTo(bind):
		// The same answer as an unknown state, so a stranger learns nothing, and
		// the state is deliberately NOT deleted: a request that cannot prove it
		// started the login must not be able to burn the owner's in-flight flow.
		l.mu.Unlock()
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_state"})
		return
	}
	// All checks passed: the state is single-use.
	delete(l.states, state)
	l.mu.Unlock()

	if r.URL.Query().Get("error") != "" {
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
	defer vault.Scrub(credential)

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
		"state": "confirmed", "subject": subject, "return_to": safeurl.RelativePath(st.returnTo),
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
