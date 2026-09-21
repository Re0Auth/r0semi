package referencesource

import (
	"context"
	"crypto/rand"
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
)

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
}

// LoginChallenge is what the user must act on: render VerificationURL as a QR
// code, or open it and enter UserCode.
type LoginChallenge struct {
	ID              string    `json:"id"`
	VerificationURL string    `json:"verification_url"`
	UserCode        string    `json:"user_code,omitempty"`
	IntervalSeconds int       `json:"interval_seconds"`
	ExpiresAt       time.Time `json:"expires_at"`
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

	l.mu.Lock()
	l.sweepLocked()
	l.attempts[id] = &attempt{auth: auth, nextPoll: l.now()}
	l.mu.Unlock()

	return LoginChallenge{
		ID:              id,
		VerificationURL: auth.VerificationURL,
		UserCode:        auth.UserCode,
		IntervalSeconds: int(auth.Interval.Seconds()),
		ExpiresAt:       auth.ExpiresAt,
	}, nil
}

// poll advances a login attempt. On success it hands the TapTap account and its
// credential to establish, which stores them under the source's own account id.
func (l *TapTapLogin) poll(ctx context.Context, id string, establish Establish) (LoginProgress, error) {
	now := l.now()

	l.mu.Lock()
	a, ok := l.attempts[id]
	if !ok {
		l.mu.Unlock()
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
	defer zeroize(payload)

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
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": "upstream_unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, challenge)
}

func (l *TapTapLogin) handlePoll(w http.ResponseWriter, r *http.Request, establish Establish) {
	progress, err := l.poll(r.Context(), r.URL.Query().Get("id"), establish)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_request", "message": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, progress)
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

// zeroize overwrites a buffer that held credential material.
//
//go:noinline
func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
