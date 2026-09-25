// Package auth implements the /auth plane: r0semi signing a human in through
// an external IdP, plus the same-origin browser session that results.
//
// It is deliberately separate from both /oauth (r0semi as authorization server)
// and /v1 (the business API). See docs/account-model.md §5–§6.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/alexedwards/scs/v2/memstore"

	"github.com/Re0Auth/r0semi/idp"
	"github.com/Re0Auth/r0semi/internal/account"
	"github.com/Re0Auth/r0semi/internal/safeurl"
)

// Session keys. Flow state is stored server-side, so mode and return_to cannot
// be tampered with by the browser.
const (
	keyUser         = "usr"
	keyCSRF         = "csrf"
	keyAuthTime     = "auth_time"
	keyFlowState    = "flow_state"
	keyFlowProvider = "flow_provider"
	keyFlowMode     = "flow_mode"
	keyFlowReturnTo = "flow_return_to"
	keyFlowVerifier = "flow_verifier"
	keyFlowNonce    = "flow_nonce"
)

var flowKeys = []string{keyFlowState, keyFlowProvider, keyFlowMode, keyFlowReturnTo, keyFlowVerifier}

// Options configures the session manager.
type Options struct {
	Lifetime    time.Duration
	IdleTimeout time.Duration
	// Secure toggles the Secure cookie attribute (and the __Host- name prefix).
	// Tests over plain HTTP set it to false.
	Secure     bool
	CookieName string
	Store      scs.Store
	// Index maps a session token to the account it belongs to. Optional: without
	// it, the Kill Switch can sign the whole deployment out but not one account.
	Index SessionIndex
}

// SessionIndex maps a session token to the account it belongs to.
//
// scs has no such notion: a session is an opaque cookie and the store sees only
// encoded bytes. Keeping the mapping here is what lets an operator revoke every
// session one account holds, rather than everyone's.
type SessionIndex interface {
	Remember(ctx context.Context, token, subject string) error
	Forget(ctx context.Context, token string) error
}

// Manager owns the browser session.
type Manager struct {
	sessions *scs.SessionManager
	index    SessionIndex
}

// NewManager builds a session manager with secure cookie defaults.
func NewManager(opts Options) *Manager {
	sm := scs.New()
	if opts.Store != nil {
		sm.Store = opts.Store
	} else {
		sm.Store = memstore.New()
	}
	if opts.Lifetime > 0 {
		sm.Lifetime = opts.Lifetime
	} else {
		sm.Lifetime = 24 * time.Hour
	}
	if opts.IdleTimeout > 0 {
		sm.IdleTimeout = opts.IdleTimeout
	} else {
		sm.IdleTimeout = 2 * time.Hour
	}

	name := opts.CookieName
	if name == "" {
		if opts.Secure {
			name = "__Host-r0semi_session"
		} else {
			name = "r0semi_session"
		}
	}
	sm.Cookie.Name = name
	sm.Cookie.HttpOnly = true
	sm.Cookie.Secure = opts.Secure
	sm.Cookie.SameSite = http.SameSiteLaxMode
	sm.Cookie.Path = "/"
	sm.Cookie.Persist = true

	return &Manager{sessions: sm, index: opts.Index}
}

// LoadAndSave is the session middleware. It must wrap every browser-facing
// route (/auth and the session endpoints of /v1).
func (m *Manager) LoadAndSave(next http.Handler) http.Handler {
	return m.sessions.LoadAndSave(next)
}

// User returns the signed-in account, if any.
func (m *Manager) User(ctx context.Context) (account.UserID, bool) {
	v := m.sessions.GetString(ctx, keyUser)
	if v == "" {
		return "", false
	}
	return account.UserID(v), true
}

// AuthenticatedAt returns when this session signed in. It is what the OP records
// as auth_time instead of the later consent decision.
func (m *Manager) AuthenticatedAt(ctx context.Context) (time.Time, bool) {
	v := m.sessions.GetString(ctx, keyAuthTime)
	if v == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, v)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// SignIn stores the account and rotates the session id, so a pre-login session
// cannot be fixated onto the authenticated user.
//
// When a SessionIndex is configured, the new token is recorded against the
// account. A session that cannot be recorded is destroyed rather than left to
// exist: an operator must be able to reach every session a subject holds, and a
// session outside the index would be one they cannot.
func (m *Manager) SignIn(ctx context.Context, user account.UserID) error {
	// RenewToken deletes the pre-login token; drop its index entry first so it
	// cannot linger as an orphan.
	if m.index != nil {
		if old := m.sessions.Token(ctx); old != "" {
			_ = m.index.Forget(ctx, old)
		}
	}
	m.sessions.Put(ctx, keyUser, string(user))
	// auth_time is when the human actually authenticated, not when a later
	// authorization decision happens. The OP's ID token must carry the former, so
	// it is recorded at sign-in and read back by the login hook.
	m.sessions.Put(ctx, keyAuthTime, time.Now().UTC().Format(time.RFC3339Nano))
	if err := m.sessions.RenewToken(ctx); err != nil {
		return err
	}
	if m.index == nil {
		return nil
	}
	token := m.sessions.Token(ctx)
	if token == "" {
		_ = m.sessions.Destroy(ctx)
		return errors.New("auth: no session token after renewal")
	}
	if err := m.index.Remember(ctx, token, string(user)); err != nil {
		_ = m.sessions.Destroy(ctx)
		return err
	}
	return nil
}

// SignOut destroys the session.
func (m *Manager) SignOut(ctx context.Context) error {
	if m.index != nil {
		if token := m.sessions.Token(ctx); token != "" {
			_ = m.index.Forget(ctx, token)
		}
	}
	return m.sessions.Destroy(ctx)
}

// CSRFToken returns the session's CSRF token, creating one if needed. The
// frontend reads it (e.g. from /v1/sessions/current) and echoes it in
// X-CSRF-Token on writes.
func (m *Manager) CSRFToken(ctx context.Context) string {
	if tok := m.sessions.GetString(ctx, keyCSRF); tok != "" {
		return tok
	}
	tok := randomToken(32)
	m.sessions.Put(ctx, keyCSRF, tok)
	return tok
}

// ValidCSRF reports whether the request carries the session's CSRF token.
func (m *Manager) ValidCSRF(r *http.Request) bool {
	want := m.sessions.GetString(r.Context(), keyCSRF)
	got := r.Header.Get("X-CSRF-Token")
	if want == "" || got == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(want), []byte(got)) == 1
}

// handleKey namespaces a browser-bound handle inside the session. Each handle
// gets its own key so gob never has to encode a slice.
func handleKey(kind, id string) string { return "handle_" + kind + "_" + id }

// ownerKey namespaces the account a handle was created for. It is a different
// prefix from handleKey so the two can never collide, and the kind is spelled the
// same on both sides by construction — Bind writes both.
func ownerKey(kind, id string) string { return "owner_" + kind + "_" + id }

// Bind scopes a server-side handle (an authorization request, an enrollment,
// ...) to this browser session. Only the session that created it may read or
// decide it, which prevents one user's handle from being acted on in another
// browser.
//
// When an account is already signed in, the handle is tagged with it as well.
// That is what stops a handle created by account A from being approved by account
// B after B signs in on the same browser. Rotating the session id on sign-in
// preserves the session's values, deliberately — the consent flow depends on a
// handle surviving the sign-in it triggers — so without this tag the handle would
// follow the browser rather than the account.
//
// A handle created before anyone signed in carries no owner, and any signed-in
// account may use it. That is the flow as designed rather than a gap: there was
// nobody to bind it to. See OwnerMatches.
func (m *Manager) Bind(ctx context.Context, kind, id string) {
	m.sessions.Put(ctx, handleKey(kind, id), "1")
	if user, ok := m.User(ctx); ok {
		m.sessions.Put(ctx, ownerKey(kind, id), string(user))
	}
}

// Bound reports whether this browser created the handle.
func (m *Manager) Bound(ctx context.Context, kind, id string) bool {
	return m.sessions.GetString(ctx, handleKey(kind, id)) == "1"
}

// OwnerMatches reports whether the signed-in account may act on a handle.
//
// True when no owner was recorded — the handle was created before anyone signed
// in, so there was nobody to bind it to — and true when the recorded owner is the
// caller. False when a different account holds the session now.
//
// Callers must report false as "not found" rather than "forbidden": a handle that
// answers "forbidden" has confirmed that it exists and belongs to somebody else.
func (m *Manager) OwnerMatches(ctx context.Context, kind, id string, user account.UserID) bool {
	owner := m.sessions.GetString(ctx, ownerKey(kind, id))
	return owner == "" || owner == string(user)
}

// Unbind forgets a handle once it has been consumed.
func (m *Manager) Unbind(ctx context.Context, kind, id string) {
	m.sessions.Remove(ctx, handleKey(kind, id))
	m.sessions.Remove(ctx, ownerKey(kind, id))
}

// requireSafeMethod reports whether a method is exempt from CSRF checks.
func requireSafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}

// Handler serves the /auth plane.
type Handler struct {
	manager  *Manager
	registry *idp.Registry
	accounts account.Store
}

// NewHandler builds the /auth handler.
func NewHandler(m *Manager, registry *idp.Registry, accounts account.Store) (*Handler, error) {
	switch {
	case m == nil:
		return nil, errors.New("auth: session Manager is required")
	case registry == nil:
		return nil, errors.New("auth: idp Registry is required")
	case accounts == nil:
		return nil, errors.New("auth: account Store is required")
	}
	return &Handler{manager: m, registry: registry, accounts: accounts}, nil
}

// Register mounts the routes on mux.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /auth/{provider}/start", h.handleStart)
	mux.HandleFunc("GET /auth/{provider}/callback", h.handleCallback)
}

// Providers lists the identity providers this deployment offers, so a frontend can
// render one login button per configured provider instead of guessing at a fixed
// set. A deployment that enables only GitHub must not show a Google button that
// leads to "unknown provider".
func (h *Handler) Providers() []idp.Provider {
	return h.registry.Providers()
}

// ProviderLabel is the label a sign-in button should show for a provider. It
// comes from the deployment's configuration, so a custom OIDC provider is named
// without a frontend release.
func (h *Handler) ProviderLabel(p idp.Provider) string {
	if client, ok := h.registry.Get(p); ok {
		return client.DisplayName()
	}
	return string(p)
}

func (h *Handler) handleStart(w http.ResponseWriter, r *http.Request) {
	provider := idp.Provider(r.PathValue("provider"))
	client, ok := h.registry.Get(provider)
	if !ok {
		http.Error(w, "unknown provider", http.StatusNotFound)
		return
	}

	mode := r.URL.Query().Get("mode")
	if mode == "" {
		mode = "login"
	}
	if mode != "login" && mode != "link" {
		http.Error(w, "invalid mode", http.StatusBadRequest)
		return
	}
	if !requireSafeMethod(r.Method) {
		http.Error(w, "invalid method", http.StatusMethodNotAllowed)
		return
	}
	if mode == "link" {
		if _, ok := h.manager.User(r.Context()); !ok {
			http.Error(w, "sign in required to link an identity", http.StatusUnauthorized)
			return
		}
	}

	ctx := r.Context()
	state := randomToken(24)
	verifier := client.NewVerifier()
	nonce := client.NewNonce()
	returnTo := safeurl.RelativePath(r.URL.Query().Get("return_to"))
	h.manager.sessions.Put(ctx, keyFlowState, state)
	h.manager.sessions.Put(ctx, keyFlowProvider, string(provider))
	h.manager.sessions.Put(ctx, keyFlowMode, mode)
	h.manager.sessions.Put(ctx, keyFlowReturnTo, returnTo)
	h.manager.sessions.Put(ctx, keyFlowVerifier, verifier)
	h.manager.sessions.Put(ctx, keyFlowNonce, nonce)

	authURL, err := client.AuthCodeURL(ctx, state, verifier, nonce)
	if err != nil {
		// A provider whose discovery is unreachable, or that is misconfigured, is a
		// deployment problem the person cannot see. Send them back with a reason
		// rather than a dead-end 502 page they can do nothing with.
		redirectError(w, r, returnTo, "provider_unavailable")
		return
	}
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (h *Handler) handleCallback(w http.ResponseWriter, r *http.Request) {
	provider := idp.Provider(r.PathValue("provider"))
	client, ok := h.registry.Get(provider)
	if !ok {
		http.Error(w, "unknown provider", http.StatusNotFound)
		return
	}

	ctx := r.Context()
	state := r.URL.Query().Get("state")
	want := h.manager.sessions.GetString(ctx, keyFlowState)
	if want == "" || subtle.ConstantTimeCompare([]byte(state), []byte(want)) != 1 {
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}
	mode := h.manager.sessions.GetString(ctx, keyFlowMode)
	returnTo := safeurl.RelativePath(h.manager.sessions.GetString(ctx, keyFlowReturnTo))
	verifier := h.manager.sessions.GetString(ctx, keyFlowVerifier)
	nonce := h.manager.sessions.GetString(ctx, keyFlowNonce)
	flowProvider := h.manager.sessions.GetString(ctx, keyFlowProvider)
	h.clearFlow(ctx)

	if flowProvider != string(provider) {
		http.Error(w, "provider mismatch", http.StatusBadRequest)
		return
	}
	if denied := r.URL.Query().Get("error"); denied != "" {
		redirectError(w, r, returnTo, denied)
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		redirectError(w, r, returnTo, "invalid_request")
		return
	}

	token, err := client.Exchange(ctx, code, verifier)
	if err != nil {
		redirectError(w, r, returnTo, "exchange_failed")
		return
	}
	ident, err := client.Identity(ctx, token, nonce)
	if err != nil {
		redirectError(w, r, returnTo, "identity_failed")
		return
	}

	if mode == "link" {
		user, ok := h.manager.User(ctx)
		if !ok {
			redirectError(w, r, returnTo, "not_signed_in")
			return
		}
		if _, err := h.accounts.LinkIdentity(ctx, user, ident); err != nil {
			if errors.Is(err, account.ErrIdentityTaken) {
				redirectError(w, r, returnTo, "identity_taken")
				return
			}
			redirectError(w, r, returnTo, "link_failed")
			return
		}
		http.Redirect(w, r, returnTo, http.StatusSeeOther)
		return
	}

	user, err := h.accounts.FindByIdentity(ctx, ident.Provider, ident.Subject)
	switch {
	case errors.Is(err, account.ErrNotFound):
		created, _, cerr := h.accounts.CreateWithIdentity(ctx, ident)
		if cerr != nil {
			redirectError(w, r, returnTo, "signup_failed")
			return
		}
		user = created.ID
	case err != nil:
		redirectError(w, r, returnTo, "lookup_failed")
		return
	default:
		_ = h.accounts.TouchLogin(ctx, ident.Provider, ident.Subject)
	}

	if err := h.manager.SignIn(ctx, user); err != nil {
		redirectError(w, r, returnTo, "session_failed")
		return
	}
	http.Redirect(w, r, returnTo, http.StatusSeeOther)
}

func (h *Handler) clearFlow(ctx context.Context) {
	for _, k := range flowKeys {
		h.manager.sessions.Remove(ctx, k)
	}
}

func redirectError(w http.ResponseWriter, r *http.Request, returnTo, code string) {
	u, err := url.Parse(returnTo)
	if err != nil {
		http.Error(w, "authentication failed", http.StatusBadRequest)
		return
	}
	q := u.Query()
	q.Set("error", code)
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusSeeOther)
}

func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("auth: random source failed")
	}
	return hex.EncodeToString(b)
}
