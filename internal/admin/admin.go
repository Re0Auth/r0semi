// Package admin is the operator plane: reviewing and revoking downstream client
// registrations, and the Kill Switch.
//
// It is deliberately thin and storage-agnostic. It owns the decisions (what
// suspension means, what the Kill Switch does and does not touch) and the audit
// trail; the actual rows live behind two narrow ports, so the same logic runs
// against Postgres and against the in-memory stores used in development.
//
// It does NOT own authentication. Who may call it is the HTTP layer's question,
// answered from an allowlist of account subjects there. See docs/admin.md.
package admin

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/oauth"
)

// ErrNotFound reports an unknown client id.
var ErrNotFound = oauth.ErrClientNotFound

// ErrInvalidTarget reports a Kill Switch request that names no target, or more
// than one.
var ErrInvalidTarget = errors.New("admin: the kill switch needs exactly one target")

// Clients is the registration store the operator plane manages: the request-path
// methods plus the administrative ones.
type Clients interface {
	oauth.ClientRegistry
	oauth.ClientAdmin
}

// SessionRevoker drops every browser session. It is optional: the in-memory
// development store cannot enumerate sessions, and a deployment that has no
// durable sessions says so by leaving this nil rather than pretending.
type SessionRevoker interface {
	RevokeAllSessions(ctx context.Context) (int64, error)
}

// Config wires the service.
type Config struct {
	Clients Clients
	// Tokens removes issued tokens in bulk.
	Tokens Revoker
	// Sessions, when set, lets the Kill Switch sign everyone out.
	Sessions SessionRevoker
	// Audit is required: an operator action with no durable record is not one
	// this project is willing to take.
	Audit audit.Logger
	Now   func() time.Time
}

// Revoker is the token side of the store (declared here so the service does not
// import a concrete store).
type Revoker interface {
	oauth.TokenAdmin
}

// Service is the operator capability.
type Service interface {
	ListClients(ctx context.Context) ([]oauth.Client, error)
	Register(ctx context.Context, actor string, req RegisterRequest) (Registration, error)
	SuspendClient(ctx context.Context, actor, clientID string) error
	ActivateClient(ctx context.Context, actor, clientID string) error
	DeleteClient(ctx context.Context, actor, clientID string) error
	KillSwitch(ctx context.Context, actor string, target Target) (Report, error)
}

// RegisterRequest is one downstream application being registered by an operator.
type RegisterRequest struct {
	Name          string
	Type          oauth.ClientType
	RedirectURIs  []string
	AllowedScopes []oauth.Scope
}

// Registration is the result of Register. Secret is the plaintext client secret,
// returned exactly once and only for a confidential client; nothing persists it,
// so losing it means registering again with a new secret.
type Registration struct {
	Client oauth.Client
	Secret string
}

// Target selects what the Kill Switch acts on. Exactly one field must be set.
type Target struct {
	All      bool
	ClientID string
	Subject  string
}

// Report is what the Kill Switch actually did. A number, not an assurance: the
// whole point of the endpoint is to be able to tell an incident responder how
// much was cut.
type Report struct {
	TokensRevoked    int   `json:"tokens_revoked"`
	SessionsRevoked  int64 `json:"sessions_revoked"`
	ClientsSuspended int   `json:"clients_suspended"`
}

type service struct {
	clients  Clients
	tokens   Revoker
	sessions SessionRevoker
	audit    audit.Logger
	now      func() time.Time
}

// New validates cfg and returns the service.
func New(cfg Config) (Service, error) {
	switch {
	case cfg.Clients == nil:
		return nil, errors.New("admin: Clients is required")
	case cfg.Tokens == nil:
		return nil, errors.New("admin: Tokens is required")
	case cfg.Audit == nil:
		return nil, errors.New("admin: Audit is required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &service{
		clients:  cfg.Clients,
		tokens:   cfg.Tokens,
		sessions: cfg.Sessions,
		audit:    cfg.Audit,
		now:      cfg.Now,
	}, nil
}

// ListClients implements Service.
func (s *service) ListClients(ctx context.Context) ([]oauth.Client, error) {
	return s.clients.List(ctx)
}

// Register implements Service. The new client is active immediately: only
// operators can call this, and a registration an operator just made does not
// need a second operator to confirm it.
func (s *service) Register(ctx context.Context, actor string, req RegisterRequest) (Registration, error) {
	id, err := newClientID()
	if err != nil {
		return Registration{}, err
	}
	secret := ""
	if req.Type == oauth.ClientConfidential {
		if secret, err = newSecret(); err != nil {
			return Registration{}, err
		}
	}
	client, err := oauth.NewClient(id, req.Name, req.Type, secret, req.RedirectURIs, req.AllowedScopes)
	if err != nil {
		return Registration{}, err
	}
	if err := s.clients.Create(ctx, client); err != nil {
		return Registration{}, err
	}
	s.record(ctx, actor, "admin.client.register", id, audit.OutcomeOK, map[string]string{
		"type": string(client.Type),
	})
	return Registration{Client: client, Secret: secret}, nil
}

// SuspendClient implements Service. Suspension happens before the token purge so
// that a failure in the purge cannot leave the client able to mint new tokens.
func (s *service) SuspendClient(ctx context.Context, actor, clientID string) error {
	if err := s.clients.SetStatus(ctx, clientID, oauth.ClientSuspended); err != nil {
		s.record(ctx, actor, "admin.client.suspend", clientID, audit.OutcomeError, nil)
		return err
	}
	removed, err := s.tokens.RevokeTokens(ctx, oauth.TokenFilter{ClientID: clientID})
	s.record(ctx, actor, "admin.client.suspend", clientID, outcome(err), map[string]string{
		"tokens_revoked": strconv.Itoa(removed),
	})
	return err
}

// ActivateClient implements Service.
func (s *service) ActivateClient(ctx context.Context, actor, clientID string) error {
	err := s.clients.SetStatus(ctx, clientID, oauth.ClientActive)
	s.record(ctx, actor, "admin.client.activate", clientID, outcome(err), nil)
	return err
}

// DeleteClient implements Service. The registration goes first; the tokens are
// purged regardless of whether it existed, so a retry still cuts live access.
func (s *service) DeleteClient(ctx context.Context, actor, clientID string) error {
	deleteErr := s.clients.Delete(ctx, clientID)
	removed, revokeErr := s.tokens.RevokeTokens(ctx, oauth.TokenFilter{ClientID: clientID})
	s.record(ctx, actor, "admin.client.delete", clientID, outcome(errors.Join(deleteErr, revokeErr)), map[string]string{
		"tokens_revoked": strconv.Itoa(removed),
	})
	return errors.Join(deleteErr, revokeErr)
}

// KillSwitch implements Service.
//
// Scope, stated precisely because "kill switch" invites over-claiming:
//
//   - all:    every issued token, and (with a session revoker) every browser
//     session. It cannot reach an upstream credential; re0auth does not
//     hold one.
//   - client: every token that client holds, and the client is suspended so it
//     cannot immediately mint more.
//   - subject: every token that account holds. Its browser sessions are NOT
//     dropped, because sessions are opaque cookies with no subject index;
//     the account is still able to sign in again.
//
// The data-source bindings are a separate plane and are NOT touched here. That
// half of the design (threat-model D5) is not implemented yet.
func (s *service) KillSwitch(ctx context.Context, actor string, target Target) (Report, error) {
	var (
		rep    Report
		filter oauth.TokenFilter
	)
	switch {
	case target.All && target.ClientID == "" && target.Subject == "":
	case target.ClientID != "" && !target.All && target.Subject == "":
		filter.ClientID = target.ClientID
	case target.Subject != "" && !target.All && target.ClientID == "":
		filter.Subject = target.Subject
	default:
		return rep, ErrInvalidTarget
	}

	if filter.ClientID != "" {
		if err := s.clients.SetStatus(ctx, filter.ClientID, oauth.ClientSuspended); err != nil {
			s.record(ctx, actor, "admin.kill_switch", filter.ClientID, audit.OutcomeError, nil)
			return rep, err
		}
		rep.ClientsSuspended = 1
	}

	removed, err := s.tokens.RevokeTokens(ctx, filter)
	rep.TokensRevoked = removed
	if err != nil {
		s.record(ctx, actor, "admin.kill_switch", killSubject(filter), audit.OutcomeError, nil)
		return rep, err
	}

	if target.All && s.sessions != nil {
		n, err := s.sessions.RevokeAllSessions(ctx)
		rep.SessionsRevoked = n
		if err != nil {
			s.record(ctx, actor, "admin.kill_switch", "all", audit.OutcomeError, map[string]string{
				"tokens_revoked": strconv.Itoa(removed),
			})
			return rep, err
		}
	}

	detail := map[string]string{
		"tokens_revoked":   strconv.Itoa(rep.TokensRevoked),
		"sessions_revoked": strconv.FormatInt(rep.SessionsRevoked, 10),
		"scope":            killScope(target),
	}
	s.record(ctx, actor, "admin.kill_switch", killSubject(filter), audit.OutcomeOK, detail)
	return rep, nil
}

func killScope(t Target) string {
	switch {
	case t.All:
		return "all"
	case t.ClientID != "":
		return "client"
	default:
		return "subject"
	}
}

func killSubject(f oauth.TokenFilter) string {
	if f.Subject != "" {
		return f.Subject
	}
	return f.ClientID
}

// record writes one audit row. A failure is logged, not returned: the safety
// action has already happened, and refusing to admit it would leave the operator
// without the action *and* without the record. The log line is the alarm.
func (s *service) record(ctx context.Context, actor, action, subject, outcome string, detail map[string]string) {
	merged := make(map[string]string, len(detail)+1)
	for k, v := range detail {
		merged[k] = v
	}
	merged["actor"] = actor
	if err := s.audit.Record(ctx, audit.Event{
		Time:     s.now().UTC(),
		Action:   action,
		Subject:  subject,
		Provider: "admin",
		Outcome:  outcome,
		Detail:   merged,
	}); err != nil {
		slog.Error("admin audit record failed", "action", action, "subject", subject, "err", err)
	}
}

func outcome(err error) string {
	if err != nil {
		return audit.OutcomeError
	}
	return audit.OutcomeOK
}

func newClientID() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("admin: generate client id: %w", err)
	}
	return "cli_" + hex.EncodeToString(b[:]), nil
}

func newSecret() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("admin: generate client secret: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}
