package referencesource

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/tapsign"
	"github.com/Re0Auth/r0semi/taptapoauth"
	"github.com/Re0Auth/r0semi/vault"
)

// maxTapTapAttempts caps the number of concurrently pending device
// authorizations a TapTapLogin will hold. The challenge route is
// unauthenticated by design, so without a cap the attempts map grows with the
// request rate times the device-code lifetime and every challenge pays an O(n)
// sweep.
const maxTapTapAttempts = 1024

// errTooManyAttempts reports that the pending-attempt cap is reached. It is a
// capacity signal, not an upstream failure.
var errTooManyAttempts = errors.New("referencesource: too many pending login attempts")

// taptapBindCookie names the cookie that binds a device-login attempt to the
// browser that started it.
//
// The challenge hands the attempt id to the initiator's own frontend, because
// that is how the frontend polls; the poll then establishes whatever subject the
// upstream approved into the CALLER's session (source.establish). Nothing in
// that pair says the two requests came from the same browser, so an attempt id —
// which travels in a URL the initiator can hand to anyone — was the whole
// capability: whoever loaded GET /login/taptap/poll?id=<id> became the approved
// account. That is session fixation / login CSRF, and its victim is usually the
// person the attacker wants to log in *as someone else*.
//
// The fix is a second, non-URL secret: the challenge sets it as an HttpOnly
// cookie for the initiating browser and the poll must present the same value.
// It is not readable by script, and a page on another origin cannot set it for
// this one, so a browser that never started the attempt cannot satisfy it. The
// session cookie is SameSite=Lax, which a top-level cross-site GET still sends;
// that is why the defence is the value check and not the SameSite attribute.
const taptapBindCookie = "refsrc_taptap_bind"

// TapTapConfig tunes the source's TapTap login.
type TapTapConfig struct {
	// Provider is recorded in audit events. Defaults to "taptap".
	Provider string
	// Now injects a clock. Defaults to time.Now.
	Now func() time.Time
}

// TapTapDeps are the pieces the TapTap login drives.
type TapTapDeps struct {
	Enroller taptapoauth.Enroller
	Redeem   tapsign.Service
	Logger   audit.Logger
}

// TapTapLogin is the source's own login backed by TapTap's device-code (QR)
// flow. It is one of the Login implementations behind the Authenticator seam:
// the Kit's Consent hook reads the session it establishes, and Re0Auth never
// sees TapTap.
//
// It is a deliberate rewrite of the pattern in Re0Auth's former
// internal/enrollment, adapted so the subject is the *source's* account (the
// TapTap openid) rather than a Re0Auth usr_ id.
type TapTapLogin struct {
	enroller taptapoauth.Enroller
	redeem   tapsign.Service
	logger   audit.Logger
	provider string
	now      func() time.Time

	mu       sync.Mutex
	attempts map[string]*attempt
}

type attempt struct {
	auth     taptapoauth.DeviceAuth
	nextPoll time.Time
	// bind is the secret the initiating browser was given as a cookie and must
	// present when it polls. It never leaves the server in a response body.
	bind string
}

// boundTo reports whether the browser presenting bind is the one the attempt
// was started for. The comparison is constant-time; the values are random
// 128-bit tokens, so this is belt to the token's suspenders rather than the
// defence itself. An attempt with no binding is never satisfied.
func (a *attempt) boundTo(bind string) bool {
	if a.bind == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a.bind), []byte(bind)) == 1
}

// bindCookie builds the Set-Cookie that ties an attempt to its browser. The
// path is the poll's own prefix, so the value is not offered anywhere else, and
// there is no Expires: it dies with the browser session, and it is worthless
// once the attempt is gone.
func bindCookie(bind string) *http.Cookie {
	return &http.Cookie{
		Name:     taptapBindCookie,
		Value:    bind,
		Path:     "/login/taptap",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}

// LoginChallenge is what the user must act on: render VerificationURL as a QR
// code, or open it and enter UserCode.
type LoginChallenge struct {
	ID              string    `json:"id"`
	VerificationURL string    `json:"verification_url"`
	UserCode        string    `json:"user_code,omitempty"`
	IntervalSeconds int       `json:"interval_seconds"`
	ExpiresAt       time.Time `json:"expires_at"`

	// bind is the per-attempt secret the challenge sets as a cookie. It is
	// unexported and has no JSON tag on purpose: the challenge body goes back to
	// the initiator, and putting the binding in it would hand the attacker the
	// thing the binding exists to withhold.
	bind string
}

// LoginProgress is the state of a login attempt.
type LoginProgress struct {
	State             string `json:"state"` // pending | confirmed | expired | failed
	Subject           string `json:"subject,omitempty"`
	Message           string `json:"message,omitempty"`
	RetryAfterSeconds int    `json:"retry_after_seconds,omitempty"`
}

// NewTapTapLogin wires the source's TapTap login.
func NewTapTapLogin(cfg TapTapConfig, deps TapTapDeps) (*TapTapLogin, error) {
	switch {
	case deps.Enroller == nil:
		return nil, errors.New("referencesource: TapTapDeps.Enroller is required")
	case deps.Redeem == nil:
		return nil, errors.New("referencesource: TapTapDeps.Redeem is required")
	}
	if cfg.Provider == "" {
		cfg.Provider = "taptap"
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if deps.Logger == nil {
		deps.Logger = audit.NewMemoryLogger()
	}
	return &TapTapLogin{
		enroller: deps.Enroller,
		redeem:   deps.Redeem,
		logger:   deps.Logger,
		provider: cfg.Provider,
		now:      cfg.Now,
		attempts: make(map[string]*attempt),
	}, nil
}

// Mount registers the TapTap login routes. The QR code is the VerificationURL,
// which a frontend renders; this reference implementation speaks JSON.
func (l *TapTapLogin) Mount(mux *http.ServeMux, establish Establish) {
	mux.HandleFunc("POST /login/taptap/challenge", l.handleChallenge)
	mux.HandleFunc("GET /login/taptap/poll", func(w http.ResponseWriter, r *http.Request) {
		l.handlePoll(w, r, establish)
	})
}

// begin starts a TapTap device authorization for an anonymous visitor.
func (l *TapTapLogin) begin(ctx context.Context) (LoginChallenge, error) {
	auth, err := l.enroller.Start(ctx)
	if err != nil {
		return LoginChallenge{}, fmt.Errorf("referencesource: start tap tap login: %w", err)
	}
	id, err := randomLoginID("lgn_")
	if err != nil {
		return LoginChallenge{}, err
	}
	bind, err := randomLoginID("bind_")
	if err != nil {
		return LoginChallenge{}, err
	}

	l.mu.Lock()
	l.sweepLocked()
	if len(l.attempts) >= maxTapTapAttempts {
		l.mu.Unlock()
		return LoginChallenge{}, errTooManyAttempts
	}
	l.attempts[id] = &attempt{auth: auth, nextPoll: l.now(), bind: bind}
	l.mu.Unlock()

	return LoginChallenge{
		ID:              id,
		VerificationURL: auth.VerificationURL,
		UserCode:        auth.UserCode,
		IntervalSeconds: int(auth.Interval.Seconds()),
		ExpiresAt:       auth.ExpiresAt,
		bind:            bind,
	}, nil
}

// poll advances a login attempt. On success it hands the TapTap account and its
// credential to establish, which stores them under the source's own account id.
//
// bind is the cookie value the caller presented; it must match the value the
// challenge put in the initiating browser, or the attempt is not the caller's
// (see taptapBindCookie).
func (l *TapTapLogin) poll(ctx context.Context, id, bind string, establish Establish) (LoginProgress, error) {
	now := l.now()

	l.mu.Lock()
	a, ok := l.attempts[id]
	if !ok || !a.boundTo(bind) {
		l.mu.Unlock()
		// One answer for "no such attempt" and "not this browser's attempt":
		// telling them apart would confirm to a caller holding only an id
		// whether the attempt exists. The attempt is left in place, because a
		// mismatched caller is not necessarily its owner (an attacker is the
		// likely one) and must not be able to make the real browser lose it.
		return LoginProgress{State: "expired", Message: "login not found or expired"}, nil
	}
	if !now.Before(a.auth.ExpiresAt) {
		delete(l.attempts, id)
		l.mu.Unlock()
		return LoginProgress{State: "expired", Message: "login expired"}, nil
	}
	// Never hammer the upstream: honour the recommended poll interval.
	if now.Before(a.nextPoll) {
		wait := a.nextPoll.Sub(now)
		l.mu.Unlock()
		return LoginProgress{State: "pending", RetryAfterSeconds: int(wait.Seconds()) + 1}, nil
	}
	a.nextPoll = now.Add(a.auth.Interval)
	auth := a.auth
	l.mu.Unlock()

	token, err := l.enroller.Poll(ctx, auth)
	switch {
	case errors.Is(err, taptapoauth.ErrAuthorizationPending):
		return LoginProgress{State: "pending", RetryAfterSeconds: int(auth.Interval.Seconds())}, nil
	case err != nil:
		l.finish(id)
		return LoginProgress{State: "failed", Message: err.Error()}, nil
	}

	credential, err := l.redeem.Redeem(ctx, token)
	if err != nil {
		l.finish(id)
		return LoginProgress{State: "failed", Message: err.Error()}, nil
	}
	payload, err := credential.Encode()
	if err != nil {
		l.finish(id)
		return LoginProgress{State: "failed", Message: "encode credential"}, nil
	}
	defer vault.Scrub(payload)

	subject := token.OpenID
	if subject == "" {
		subject = token.UnionID
	}
	if subject == "" {
		l.finish(id)
		return LoginProgress{State: "failed", Message: "upstream returned no account id"}, nil
	}

	meta := map[string]string{"provider": l.provider, "object_id": credential.ObjectID}
	if token.UnionID != "" {
		meta["unionid"] = token.UnionID
	}
	if err := establish(ctx, Principal{
		Subject: subject, Display: subject, Credential: payload, Meta: meta,
	}); err != nil {
		l.finish(id)
		return LoginProgress{State: "failed", Message: "store credential"}, nil
	}

	l.finish(id)
	l.record(ctx, subject, audit.OutcomeOK)
	return LoginProgress{State: "confirmed", Subject: subject}, nil
}

func (l *TapTapLogin) handleChallenge(w http.ResponseWriter, r *http.Request) {
	challenge, err := l.begin(r.Context())
	switch {
	case errors.Is(err, errTooManyAttempts):
		// Capacity, not an upstream fault: tell the caller to back off rather
		// than reporting a bad gateway.
		w.Header().Set("Retry-After", "30")
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "too_many_pending_login_attempts"})
		return
	case err != nil:
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": "upstream_unavailable"})
		return
	}
	// The binding goes out as a cookie, not in the body: the body is returned to
	// the page that started the challenge, and only the browser itself may hold
	// the value the poll is checked against.
	http.SetCookie(w, bindCookie(challenge.bind))
	writeJSON(w, http.StatusOK, challenge)
}

func (l *TapTapLogin) handlePoll(w http.ResponseWriter, r *http.Request, establish Establish) {
	bind := ""
	if c, err := r.Cookie(taptapBindCookie); err == nil {
		bind = c.Value
	}
	progress, err := l.poll(r.Context(), r.URL.Query().Get("id"), bind, establish)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_request", "message": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, progress)
}

// RevokeUpstream implements UpstreamRevoker.
//
// Rotating the session token *is* the revocation: from the moment this succeeds,
// the old token is dead everywhere and every device holding it is signed out.
//
// The replacement is discarded on purpose. Keeping it would leave this source
// holding a live session while the person's own devices were signed out, which is
// the exact opposite of what they asked for — a silent hijack dressed up as a
// logout. tapsign.Revoke already does the rotate-and-discard; what only the login
// knows is the credential's format.
func (l *TapTapLogin) RevokeUpstream(ctx context.Context, subject string, credential []byte) error {
	cred, err := tapsign.DecodeCredential(credential)
	if err != nil {
		l.record(ctx, subject, audit.OutcomeError)
		return fmt.Errorf("referencesource: cascade revocation: %w", err)
	}
	if err := l.redeem.Revoke(ctx, cred); err != nil {
		l.record(ctx, subject, audit.OutcomeError)
		return err
	}
	l.record(ctx, subject, audit.OutcomeOK)
	return nil
}

func (l *TapTapLogin) finish(id string) {
	l.mu.Lock()
	delete(l.attempts, id)
	l.mu.Unlock()
}

func (l *TapTapLogin) sweepLocked() {
	now := l.now()
	for id, a := range l.attempts {
		if !now.Before(a.auth.ExpiresAt) {
			delete(l.attempts, id)
		}
	}
}

func (l *TapTapLogin) record(ctx context.Context, subject, outcome string) {
	_ = l.logger.Record(ctx, audit.Event{
		Action:   "referencesource.login",
		Subject:  subject,
		Provider: l.provider,
		Outcome:  outcome,
	})
}

func randomLoginID(prefix string) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("referencesource: random: %w", err)
	}
	return prefix + hex.EncodeToString(b), nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
