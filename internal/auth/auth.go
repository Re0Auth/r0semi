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
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/alexedwards/scs/v2/memstore"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/idp"
	"github.com/Re0Auth/r0semi/internal/account"
	"github.com/Re0Auth/r0semi/internal/observability"
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
	// Audit, when set, receives sign-out events. Optional; a nil logger records
	// nothing, the same contract the metrics option has.
	Audit audit.Logger
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
	auditLog audit.Logger
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

	return &Manager{sessions: sm, index: opts.Index, auditLog: opts.Audit}
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

// SignOut destroys the session and records the event. A write failure is logged,
// not returned: the session is already gone, and refusing to admit it would leave
// the user signed out with no record, which is the opposite of what the log is for.
func (m *Manager) SignOut(ctx context.Context) error {
	subject := ""
	if user, ok := m.User(ctx); ok {
		subject = string(user)
	}
	err := m.EndSession(ctx)
	outcome := audit.OutcomeOK
	if err != nil {
		outcome = audit.OutcomeError
	}
	recordAudit(ctx, m.auditLog, audit.Event{Action: "auth.logout", Subject: subject, Outcome: outcome})
	return err
}

// EndSession destroys the session without recording auth.logout.
//
// It exists for a caller that has its own audit event: account erasure writes
// `account.delete`, and it runs *after* the erasure destroyed the account's
// pseudonym key. A logout event written there would carry a raw `usr_…` into a
// sink whose key no longer exists, which mints a fresh one and re-links exactly
// the account the erasure just made unlinkable — so the erasure path tears the
// session down with this instead. Every other caller uses SignOut, which records
// the event the log is for.
func (m *Manager) EndSession(ctx context.Context) error {
	if m.index != nil {
		if token := m.sessions.Token(ctx); token != "" {
			_ = m.index.Forget(ctx, token)
		}
	}
	return m.sessions.Destroy(ctx)
}

// recordAudit writes one authentication event. A write failure is logged, not
// returned: unlike the vault, nothing irreversible is gated on the record, so
// refusing a sign-in over an audit gap would trade availability for a missing
// line — the same trade admin.record makes. A nil logger records nothing.
func recordAudit(ctx context.Context, l audit.Logger, e audit.Event) {
	if l == nil {
		return
	}
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	if err := l.Record(ctx, e); err != nil {
		// No raw subject: the process log must not carry an account identifier the
		// pseudonym key cannot reach (G-23). The action says what failed.
		slog.Error("auth audit record failed", "action", e.Action, "err", err)
	}
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
// prefix from handleKey so the two can never collide, and the kind is spelled
// the same on both sides by construction — Bind writes both.
func ownerKey(kind, id string) string { return "owner_" + kind + "_" + id }

// queueKey namespaces the FIFO of ids a session has bound for one kind. It is the
// eviction order for the cap below, and it is a single joined string rather than
// a slice for the same reason handleKey is per-handle: session values stay the
// types gob can encode without registration.
func queueKey(kind string) string { return "boundq_" + kind }

// maxBoundHandlesPerKind bounds how many handles one session may hold for one
// kind. Handles are created by links a user can be sent to — a consent screen, a
// device verification, a bind start — and each one used to live until it was
// consumed. Nothing consumed an undecided one, so a browser that was made to
// visit many of them accumulated state without bound, and a session is read and
// rewritten on every request. The oldest entry is evicted past the cap.
const maxBoundHandlesPerKind = 32

// maxBoundHandleBytes is the longest id Bind will track. A bound id is stored in
// the session and rewritten on every request, and some callers derive it from
// request input (the device verification page binds the user code it looked up),
// so the byte length is otherwise priced by whoever sends the request. The
// service's own handles are far shorter (a user code is 9 bytes, an
// authorization id is base64 of 16); the cap exists to make "caller-chosen
// length" impossible rather than to accommodate one (Z07-3).
const maxBoundHandleBytes = 128

// handleSep separates the ids in a kind's queue. It is the ASCII unit separator,
// which cannot occur in a handle id: every id in this service is an opaque token
// the service minted — a base64 value, a device user code, a bind state.
const handleSep = '\x1f'

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
//
// Binding is idempotent, and the session keeps at most maxBoundHandlesPerKind
// handles per kind: binding one more evicts the oldest, which is the only way a
// session cannot be grown without bound by sending a browser to links.
func (m *Manager) Bind(ctx context.Context, kind, id string) {
	if id == "" || len(id) > maxBoundHandleBytes || strings.ContainsRune(id, handleSep) {
		// An id that could not be tracked is not bound at all. Binding it without
		// a queue entry would put state in the session that nothing can evict,
		// which is the failure this cap exists to prevent; an over-long id is
		// refused for the same reason — a session is rewritten whole, so its
		// bytes must not be caller-chosen (Z07-3).
		return
	}
	if m.sessions.GetString(ctx, handleKey(kind, id)) == "1" {
		return
	}
	m.enqueue(ctx, kind, id)
	m.sessions.Put(ctx, handleKey(kind, id), "1")
	if user, ok := m.User(ctx); ok {
		m.sessions.Put(ctx, ownerKey(kind, id), string(user))
	}
}

// enqueue records id as the newest handle of its kind, evicting the oldest while
// the kind is over its cap.
func (m *Manager) enqueue(ctx context.Context, kind, id string) {
	ids := append(m.boundQueue(ctx, kind), id)
	for len(ids) > maxBoundHandlesPerKind {
		m.release(ctx, kind, ids[0])
		ids = ids[1:]
	}
	m.sessions.Put(ctx, queueKey(kind), strings.Join(ids, string(handleSep)))
}

// boundQueue returns the ids this session has bound for kind, oldest first.
func (m *Manager) boundQueue(ctx context.Context, kind string) []string {
	raw := m.sessions.GetString(ctx, queueKey(kind))
	if raw == "" {
		return nil
	}
	return strings.Split(raw, string(handleSep))
}

// release drops the keys that make a handle usable. The queue is the caller's
// business: enqueue is mid-eviction when it calls this.
func (m *Manager) release(ctx context.Context, kind, id string) {
	m.sessions.Remove(ctx, handleKey(kind, id))
	m.sessions.Remove(ctx, ownerKey(kind, id))
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

// Unbind forgets a handle once it has been consumed, and takes it out of its
// kind's queue so the cap counts live handles rather than every handle the
// session has ever seen.
func (m *Manager) Unbind(ctx context.Context, kind, id string) {
	m.release(ctx, kind, id)

	ids := m.boundQueue(ctx, kind)
	kept := ids[:0]
	for _, v := range ids {
		if v != id {
			kept = append(kept, v)
		}
	}
	if len(kept) == 0 {
		m.sessions.Remove(ctx, queueKey(kind))
		return
	}
	m.sessions.Put(ctx, queueKey(kind), strings.Join(kept, string(handleSep)))
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
	// metrics observes sign-in outcomes. Optional; a nil *observability.Metrics
	// records nothing (its methods are nil-safe).
	metrics *observability.Metrics
	// auditLog records authentication events. Optional; a nil logger records
	// nothing.
	auditLog audit.Logger
}

// HandlerOption tunes a Handler.
type HandlerOption func(*Handler)

// WithMetrics attaches business metrics to the login plane. It is optional.
func WithMetrics(m *observability.Metrics) HandlerOption {
	return func(h *Handler) { h.metrics = m }
}

// WithAudit attaches the audit log. It is optional, but a deployment with a
// durable log should pass it: who authenticated as whom, and when, is the
// question the log exists to answer.
func WithAudit(l audit.Logger) HandlerOption {
	return func(h *Handler) { h.auditLog = l }
}

// NewHandler builds the /auth handler.
func NewHandler(m *Manager, registry *idp.Registry, accounts account.Store, opts ...HandlerOption) (*Handler, error) {
	switch {
	case m == nil:
		return nil, errors.New("auth: session Manager is required")
	case registry == nil:
		return nil, errors.New("auth: idp Registry is required")
	case accounts == nil:
		return nil, errors.New("auth: account Store is required")
	}
	h := &Handler{manager: m, registry: registry, accounts: accounts}
	for _, opt := range opts {
		opt(h)
	}
	return h, nil
}

// observeLogin records one sign-in attempt that reached a terminal outcome. The
// provider label is a configured name or "unknown"; the result is a short code,
// never a raw value from the request (the identity provider's own `error`
// parameter is reflected, so it is deliberately not passed through).
func (h *Handler) observeLogin(provider, result string) {
	h.metrics.ObserveLogin(provider, result)
}

// recordAuth writes one authentication event. code, when set, is the same bounded
// failure code the metric uses — never a request value.
func (h *Handler) recordAuth(ctx context.Context, action string, provider idp.Provider, subject, outcome, code string) {
	var detail map[string]string
	if code != "" {
		detail = map[string]string{"code": code}
	}
	recordAudit(ctx, h.auditLog, audit.Event{
		Action: action, Subject: subject, Provider: string(provider), Outcome: outcome, Detail: detail,
	})
}

// denyLogin records a sign-in that the request or the provider refused: the
// metric and the audit line, with no subject because none is known yet.
func (h *Handler) denyLogin(ctx context.Context, provider, code string) {
	h.observeLogin(provider, code)
	h.recordAuth(ctx, "auth.login", idp.Provider(provider), "", audit.OutcomeDenied, code)
}

// failLogin records the failure and hands the browser back with the reason, the
// two halves a failed callback has to do.
func (h *Handler) failLogin(w http.ResponseWriter, r *http.Request, provider idp.Provider, returnTo, code string) {
	h.observeLogin(string(provider), code)
	h.recordAuth(r.Context(), "auth.login", provider, "", outcomeFor(code), code)
	redirectError(w, r, returnTo, code)
}

// The login plane's failure codes.
//
// They are a contract with the SPA: each one is redirected back as `?error=<code>`
// and turned into a sentence by web/src/routes/+page.svelte. They are constants so
// that TestLoginFailureCodesAreExplainedByTheFrontend can iterate them instead of
// comparing two hand-copied lists — which is how the two drifted: this package
// redirected `denied` while the SPA's map, the documented contract
// (docs/account-model.md) and the browser suite all read `access_denied`.
const (
	codeAccessDenied        = "access_denied"
	codeProviderUnavailable = "provider_unavailable"
	codeInvalidRequest      = "invalid_request"
	codeExchangeFailed      = "exchange_failed"
	codeIdentityFailed      = "identity_failed"
	codeNotSignedIn         = "not_signed_in"
	codeIdentityTaken       = "identity_taken"
	codeLinkFailed          = "link_failed"
	codeSignupFailed        = "signup_failed"
	codeLookupFailed        = "lookup_failed"
	codeSessionFailed       = "session_failed"
	codeUnknownProvider     = "unknown_provider"
	codeInvalidState        = "invalid_state"
	codeProviderMismatch    = "provider_mismatch"
)

// loginCodes classifies every code this handler can emit: a refusal the provider or
// the request caused is "denied", anything else is this service failing to complete
// the flow. The value is what the audit record and the login metric carry, so a new
// code that is not added here is reported as an error rather than quietly counted as
// a denial.
var loginCodes = map[string]string{
	codeAccessDenied:        audit.OutcomeDenied,
	codeIdentityTaken:       audit.OutcomeDenied,
	codeUnknownProvider:     audit.OutcomeDenied,
	codeInvalidState:        audit.OutcomeDenied,
	codeProviderMismatch:    audit.OutcomeDenied,
	codeInvalidRequest:      audit.OutcomeDenied,
	codeNotSignedIn:         audit.OutcomeDenied,
	codeProviderUnavailable: audit.OutcomeError,
	codeExchangeFailed:      audit.OutcomeError,
	codeIdentityFailed:      audit.OutcomeError,
	codeLinkFailed:          audit.OutcomeError,
	codeSignupFailed:        audit.OutcomeError,
	codeLookupFailed:        audit.OutcomeError,
	codeSessionFailed:       audit.OutcomeError,
}

// redirectCodes are the codes the SPA can see: the ones failLogin puts in `?error=`.
// The rest (an unknown provider, a forged state, a provider mismatch) end at a 400
// page with no redirect, so the frontend has no sentence for them and needs none —
// the distinction is what keeps the two lists comparable rather than merely equal.
var redirectCodes = []string{
	codeAccessDenied, codeProviderUnavailable, codeInvalidRequest, codeExchangeFailed,
	codeIdentityFailed, codeNotSignedIn, codeIdentityTaken, codeLinkFailed,
	codeSignupFailed, codeLookupFailed, codeSessionFailed,
}

// outcomeFor maps a login failure code to its audit outcome. A code that is not
// classified is reported as an error: guessing "denied" would let a bug look like a
// user's decision in the audit log.
func outcomeFor(code string) string {
	if outcome, ok := loginCodes[code]; ok {
		return outcome
	}
	return audit.OutcomeError
}

// Register mounts the routes on mux.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /auth/{provider}/start", h.handleStart)
	mux.HandleFunc("GET /auth/{provider}/callback", h.handleCallback)
	mux.HandleFunc("GET /auth/reauth", h.handleReauth)
}

// handleReauth sends a signed-in browser back through its identity provider so a
// request that demanded a fresh authentication gets one.
//
// It exists because the OP's login boundary cannot name the provider: only the
// account store knows which identities the signed-in user has. The caller passes
// the page to return to after the new sign-in; this resolves the primary
// identity's provider and starts an ordinary login flow pointed at it (S02-1). A
// user who cannot be resolved is refused rather than sent to a consent screen
// that would have to fabricate an authentication.
func (h *Handler) handleReauth(w http.ResponseWriter, r *http.Request) {
	user, ok := h.manager.User(r.Context())
	if !ok {
		http.Error(w, "sign in required", http.StatusUnauthorized)
		return
	}
	returnTo := safeurl.RelativePath(r.URL.Query().Get("return_to"))

	u, err := h.accounts.GetUser(r.Context(), user)
	if err != nil {
		http.Error(w, "cannot resolve your account", http.StatusInternalServerError)
		return
	}
	identities, err := h.accounts.Identities(r.Context(), user)
	if err != nil || len(identities) == 0 {
		http.Error(w, "no identity to re-authenticate with", http.StatusBadRequest)
		return
	}
	provider := identityProvider(identities, u.PrimaryIdentity)
	if _, ok := h.registry.Get(provider); !ok {
		http.Error(w, "the identity provider is no longer configured", http.StatusBadRequest)
		return
	}
	target := "/auth/" + url.PathEscape(string(provider)) + "/start?mode=login&return_to=" + url.QueryEscape(returnTo)
	// The target is a same-origin path: the provider is a validated registry key and
	// return_to went through safeurl.RelativePath. No request value becomes an origin.
	// nosemgrep: go.lang.security.injection.open-redirect.open-redirect
	http.Redirect(w, r, target, http.StatusFound)
}

// identityProvider picks the identity the account names as primary, or the first
// one. Primary is display-only (I-1), so any identity re-authenticates the same
// account.
func identityProvider(identities []account.Identity, primary account.IdentityID) idp.Provider {
	for _, in := range identities {
		if in.ID == primary {
			return in.Provider
		}
	}
	return identities[0].Provider
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
		h.denyLogin(r.Context(), "unknown", codeUnknownProvider)
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
		h.failLogin(w, r, provider, returnTo, codeProviderUnavailable)
		return
	}
	// authURL is assembled by the OIDC client from the provider's registered
	// discovery document plus the random state, verifier and nonce above: it is
	// the provider's own authorize endpoint, never a caller-chosen destination.
	http.Redirect(w, r, authURL, http.StatusFound) //nolint:gosec // G710: authURL is the registered provider's authorize endpoint
}

func (h *Handler) handleCallback(w http.ResponseWriter, r *http.Request) {
	provider := idp.Provider(r.PathValue("provider"))
	client, ok := h.registry.Get(provider)
	if !ok {
		h.denyLogin(r.Context(), "unknown", codeUnknownProvider)
		http.Error(w, "unknown provider", http.StatusNotFound)
		return
	}

	ctx := r.Context()
	state := r.URL.Query().Get("state")
	want := h.manager.sessions.GetString(ctx, keyFlowState)
	if want == "" || subtle.ConstantTimeCompare([]byte(state), []byte(want)) != 1 {
		h.denyLogin(ctx, string(provider), codeInvalidState)
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
		h.denyLogin(ctx, string(provider), codeProviderMismatch)
		http.Error(w, "provider mismatch", http.StatusBadRequest)
		return
	}
	if denied := r.URL.Query().Get("error"); denied != "" {
		// The provider's own `error` value is reflected input, so it is not used
		// as a label: the bounded fact is that the provider refused.
		//
		// The code is `access_denied`, not `denied`: the SPA's message map, the
		// account model's documented `error=access_denied`, and the browser suite
		// all read that name, and a value only this file knew left a refusal
		// showing the generic "login did not finish" fallback.
		h.failLogin(w, r, provider, returnTo, "access_denied")
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		h.failLogin(w, r, provider, returnTo, codeInvalidRequest)
		return
	}

	token, err := client.Exchange(ctx, code, verifier)
	if err != nil {
		h.failLogin(w, r, provider, returnTo, codeExchangeFailed)
		return
	}
	ident, err := client.Identity(ctx, token, nonce)
	if err != nil {
		h.failLogin(w, r, provider, returnTo, codeIdentityFailed)
		return
	}

	if mode == "link" {
		user, ok := h.manager.User(ctx)
		if !ok {
			h.failLogin(w, r, provider, returnTo, codeNotSignedIn)
			return
		}
		if _, err := h.accounts.LinkIdentity(ctx, user, ident); err != nil {
			if errors.Is(err, account.ErrIdentityTaken) {
				h.failLogin(w, r, provider, returnTo, codeIdentityTaken)
				return
			}
			h.failLogin(w, r, provider, returnTo, codeLinkFailed)
			return
		}
		h.observeLogin(string(provider), observability.LoginSuccess)
		h.recordAuth(ctx, "auth.identity.link", provider, string(user), audit.OutcomeOK, "")
		http.Redirect(w, r, returnTo, http.StatusSeeOther)
		return
	}

	user, err := h.accounts.FindByIdentity(ctx, ident.Provider, ident.Subject)
	switch {
	case errors.Is(err, account.ErrNotFound):
		created, _, cerr := h.accounts.CreateWithIdentity(ctx, ident)
		if cerr != nil {
			h.failLogin(w, r, provider, returnTo, codeSignupFailed)
			return
		}
		h.recordAuth(ctx, "auth.signup", provider, string(created.ID), audit.OutcomeOK, "")
		user = created.ID
	case err != nil:
		h.failLogin(w, r, provider, returnTo, codeLookupFailed)
		return
	default:
		_ = h.accounts.TouchLogin(ctx, ident.Provider, ident.Subject)
	}

	if err := h.manager.SignIn(ctx, user); err != nil {
		h.failLogin(w, r, provider, returnTo, codeSessionFailed)
		return
	}
	h.observeLogin(string(provider), observability.LoginSuccess)
	h.recordAuth(ctx, "auth.login", provider, string(user), audit.OutcomeOK, "")
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
	// returnTo reached this point through safeurl.RelativePath, which returns a
	// same-origin absolute path or "/", so the redirect cannot name another
	// host (G710 cannot follow that sanitiser through the helper boundary).
	http.Redirect(w, r, u.String(), http.StatusSeeOther) //nolint:gosec // G710: returnTo is sanitised by safeurl.RelativePath
}

func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("auth: random source failed")
	}
	return hex.EncodeToString(b)
}
