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

// ErrBindingsUnavailable reports a request to revoke data-source bindings by a
// deployment that has no data sources wired. Answering with a silent zero would
// claim an action that never happened.
var ErrBindingsUnavailable = errors.New("admin: this deployment cannot revoke data-source bindings")

// ErrInvalidRegistration reports a registration request the caller got wrong — a
// bad client type, a missing or unparseable redirect URI — as opposed to a failure
// to persist it. The handler maps it, and only it, to a 400; anything else is an
// internal error.
var ErrInvalidRegistration = errors.New("admin: invalid registration")

// Clients is the registration store the operator plane manages: the request-path
// methods plus the administrative ones.
type Clients interface {
	oauth.ClientRegistry
	oauth.ClientAdmin
}

// SessionRevoker drops browser sessions. It is optional: the in-memory
// development store cannot enumerate sessions, and a deployment that has no
// durable sessions says so by leaving this nil rather than pretending.
type SessionRevoker interface {
	RevokeAllSessions(ctx context.Context) (int64, error)
	// RevokeSubjectSessions drops every session belonging to one account. It needs
	// the session→subject index; without one the deployment can only sign everyone
	// out at once, and this method is what makes signing one account out possible.
	RevokeSubjectSessions(ctx context.Context, subject string) (int64, error)
}

// Bindings revokes data-source bindings in bulk. It is optional: a deployment
// with no data sources leaves it nil, and the kill switch then does not touch
// bindings (a dedicated `bindings` target is refused rather than answered with a
// hollow zero).
type Bindings interface {
	RevokeAllBindings(ctx context.Context) (BindingOutcome, error)
	RevokeSubjectBindings(ctx context.Context, subject string) (BindingOutcome, error)
}

// FlowPurger removes an account's in-flight bind flows. It is optional, like
// Bindings, and is the same capability the erasure path uses
// (lifecycle.FlowPurger): a pending flow is a capability that outlives the
// binding, because completing it creates a new binding and a new upstream token.
// A `subject` sweep must remove it for the same reason an erasure does.
//
// The subject is a plain string, not account.UserID, so this package keeps its
// distance from the account store the way Bindings does.
type FlowPurger interface {
	PurgeUserFlows(ctx context.Context, subject string) (int, error)
}

// Config wires the service.
type Config struct {
	Clients Clients
	// Tokens removes issued tokens in bulk.
	Tokens Revoker
	// Sessions, when set, lets the Kill Switch sign everyone out.
	Sessions SessionRevoker
	// Bindings, when set, lets the Kill Switch disconnect data sources.
	Bindings Bindings
	// Flows, when set, lets a `subject`-scoped Kill Switch remove the account's
	// in-flight bind flows. Nil for a deployment with no bind-flow store; a
	// pending flow it cannot reach is not cut.
	Flows FlowPurger
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
	// RotateClientSecret issues a new secret for a confidential client and returns
	// it once. The old secret stops working immediately; the client id and its
	// grants survive, which is the point — a leak used to mean delete-and-re-register.
	RotateClientSecret(ctx context.Context, actor, clientID string) (string, error)
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
	// Bindings revokes every data-source binding without touching tokens or
	// sessions. It is the narrow form of D5: cut data access, stay signed in.
	Bindings bool
}

// BindingOutcome is how much of the binding set a sweep cut.
type BindingOutcome struct {
	Total       int `json:"total"`
	Revoked     int `json:"revoked"`
	Cascade     int `json:"cascade"`
	Unsupported int `json:"unsupported"`
	Unavailable int `json:"unavailable"`
	Orphaned    int `json:"orphaned"`
	Failed      int `json:"failed"`
}

// Report is what the Kill Switch actually did. A number, not an assurance: the
// whole point of the endpoint is to be able to tell an incident responder how
// much was cut. Bindings is nil when no binding sweep ran; BindingsUnavailable,
// SessionsUnavailable and FlowsUnavailable say the target had that dimension but
// this deployment has no port able to sweep it — so "there was nothing there" and
// "this deployment cannot reach it" never look identical. FlowsPurged counts the
// in-flight bind flows a `subject` sweep removed.
type Report struct {
	TokensRevoked    int             `json:"tokens_revoked"`
	SessionsRevoked  int64           `json:"sessions_revoked"`
	ClientsSuspended int             `json:"clients_suspended"`
	FlowsPurged      int             `json:"flows_purged"`
	Bindings         *BindingOutcome `json:"bindings,omitempty"`
	// BindingsUnavailable is set when the target includes a binding dimension but
	// the deployment has no Bindings port. It is a field rather than an error so
	// that `all` — which must still cut tokens and sessions — is not refused by a
	// missing binding port, while the responder can still tell the two cases apart.
	BindingsUnavailable bool `json:"bindings_unavailable,omitempty"`
	// SessionsUnavailable is set when the target includes a session dimension but
	// the deployment has no session revoker. Without it `sessions_revoked: 0`
	// reads as "nobody was signed in" when it means "this deployment cannot sign
	// anyone out" (S11-2, Z10-4).
	SessionsUnavailable bool `json:"sessions_unavailable,omitempty"`
	// FlowsUnavailable is set when the target includes an in-flight-flow dimension
	// that this deployment cannot sweep: `all` has no port to enumerate accounts
	// with, and a deployment with no flow port has none at all. A pending bind
	// flow outlives the binding and can create a new one, so a sweep that leaves
	// it alive has to say so (S11-3).
	FlowsUnavailable bool `json:"flows_unavailable,omitempty"`
}

type service struct {
	clients  Clients
	tokens   Revoker
	sessions SessionRevoker
	bindings Bindings
	flows    FlowPurger
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
		bindings: cfg.Bindings,
		flows:    cfg.Flows,
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
		return Registration{}, fmt.Errorf("%w: %w", ErrInvalidRegistration, err)
	}
	if err := s.clients.Create(ctx, client); err != nil {
		return Registration{}, err
	}
	s.record(ctx, actor, "admin.client.register", id, audit.OutcomeOK, map[string]string{
		"type": string(client.Type),
		// The subject is stored as a keyed pseudonym, so the row names the client
		// it is about explicitly (Z10-8).
		"client_id": id,
	})
	return Registration{Client: client, Secret: secret}, nil
}

// RotateClientSecret implements Service. A new secret is generated and its digest
// stored; the plaintext is returned once and never persisted. The old secret stops
// authenticating the moment RotateSecret returns, so a caller must be ready to use
// the new one.
func (s *service) RotateClientSecret(ctx context.Context, actor, clientID string) (string, error) {
	secret, err := newSecret()
	if err != nil {
		return "", err
	}
	err = s.clients.RotateSecret(ctx, clientID, oauth.NewSecretHash(secret))
	s.record(ctx, actor, "admin.client.rotate_secret", clientID, outcome(err), map[string]string{
		"client_id": clientID,
	})
	if err != nil {
		return "", err
	}
	return secret, nil
}

// SuspendClient implements Service. Suspension happens before the token purge so
// that a failure in the purge cannot leave the client able to mint new tokens.
func (s *service) SuspendClient(ctx context.Context, actor, clientID string) error {
	if err := s.clients.SetStatus(ctx, clientID, oauth.ClientSuspended); err != nil {
		s.record(ctx, actor, "admin.client.suspend", clientID, audit.OutcomeError, map[string]string{
			"client_id": clientID,
		})
		return err
	}
	removed, err := s.tokens.RevokeTokens(ctx, oauth.TokenFilter{ClientID: clientID})
	s.record(ctx, actor, "admin.client.suspend", clientID, outcome(err), map[string]string{
		"tokens_revoked": strconv.Itoa(removed),
		"client_id":      clientID,
	})
	return err
}

// ActivateClient implements Service.
func (s *service) ActivateClient(ctx context.Context, actor, clientID string) error {
	err := s.clients.SetStatus(ctx, clientID, oauth.ClientActive)
	s.record(ctx, actor, "admin.client.activate", clientID, outcome(err), map[string]string{
		"client_id": clientID,
	})
	return err
}

// DeleteClient implements Service. The registration goes first; the tokens are
// purged regardless of whether it existed, so a retry still cuts live access.
func (s *service) DeleteClient(ctx context.Context, actor, clientID string) error {
	deleteErr := s.clients.Delete(ctx, clientID)
	removed, revokeErr := s.tokens.RevokeTokens(ctx, oauth.TokenFilter{ClientID: clientID})
	s.record(ctx, actor, "admin.client.delete", clientID, outcome(errors.Join(deleteErr, revokeErr)), map[string]string{
		"tokens_revoked": strconv.Itoa(removed),
		"client_id":      clientID,
	})
	return errors.Join(deleteErr, revokeErr)
}

// KillSwitch implements Service.
//
// Scope, stated precisely because "kill switch" invites over-claiming. Exactly
// one target may be set, and each one cuts:
//
//   - all:      every issued token, every browser session (where the deployment
//     has a session revoker), and every data-source binding.
//   - client:   every token that client holds, and the client is suspended so it
//     cannot immediately mint more. A binding belongs to a person, not to a
//     client, so this target leaves bindings alone.
//   - subject:  every token that account holds, every browser session it holds
//     (where a session subject index exists; see SessionRevoker), and every
//     binding it holds.
//   - bindings: every binding, and nothing else. The narrow form: cut data
//     access while everyone stays signed in.
//
// What it still cannot do: reach an upstream credential by itself. Re0Auth holds
// no platform credential, and the token a source issued is only ever used to ask
// that source to act on its own. A source that cannot revoke, or cannot be
// reached, is reported in Report.Bindings rather than folded into a success.
func (s *service) KillSwitch(ctx context.Context, actor string, target Target) (Report, error) {
	var rep Report
	if target.setCount() != 1 {
		return rep, ErrInvalidTarget
	}
	if target.Bindings && s.bindings == nil {
		return rep, ErrBindingsUnavailable
	}

	// Suspension happens before the token purge, so a failure in the purge cannot
	// leave the client able to mint more tokens.
	if target.ClientID != "" {
		if err := s.clients.SetStatus(ctx, target.ClientID, oauth.ClientSuspended); err != nil {
			s.recordKill(ctx, actor, target, audit.OutcomeError, rep)
			return rep, err
		}
		rep.ClientsSuspended = 1
	}

	// The bindings-only target deliberately leaves tokens and sessions alone: it is
	// "cut data access, stay signed in".
	if !target.Bindings {
		removed, err := s.tokens.RevokeTokens(ctx, oauth.TokenFilter{
			ClientID: target.ClientID,
			Subject:  target.Subject,
		})
		rep.TokensRevoked = removed
		if err != nil {
			s.recordKill(ctx, actor, target, audit.OutcomeError, rep)
			return rep, err
		}
	}

	// Sessions. `all` clears everyone; `subject` clears one account, which works
	// only where a session index exists. `client` and `bindings` never touch a
	// session: a session belongs to a person, not to a client.
	if s.sessions != nil && (target.All || target.Subject != "") {
		var (
			n   int64
			err error
		)
		if target.All {
			n, err = s.sessions.RevokeAllSessions(ctx)
		} else {
			n, err = s.sessions.RevokeSubjectSessions(ctx, target.Subject)
		}
		if err != nil {
			s.recordKill(ctx, actor, target, audit.OutcomeError, rep)
			return rep, err
		}
		rep.SessionsRevoked = n
	} else if target.All || target.Subject != "" {
		// The target has a session dimension and this deployment has no revoker to
		// serve it. Saying so is what keeps `sessions_revoked: 0` — "nobody was
		// signed in" — apart from "this deployment cannot sign anyone out"
		// (S11-2, Z10-4), the same distinction BindingsUnavailable draws.
		rep.SessionsUnavailable = true
	}

	// Bindings. `all` and the dedicated `bindings` target sweep the deployment;
	// `subject` sweeps one account. `client` has no binding dimension: a binding
	// belongs to a person, not to a client.
	//
	// When the target has a binding dimension but the deployment has no port, the
	// answer is a marker, not silence: `all` must still cut tokens and sessions, so
	// it cannot be refused, but an incident responder must be able to tell "no
	// bindings existed" from "this deployment cannot sweep bindings".
	if s.bindings != nil && (target.All || target.Bindings || target.Subject != "") {
		var (
			outcome BindingOutcome
			err     error
		)
		if target.Subject != "" && !target.All && !target.Bindings {
			outcome, err = s.bindings.RevokeSubjectBindings(ctx, target.Subject)
		} else {
			outcome, err = s.bindings.RevokeAllBindings(ctx)
		}
		if err != nil {
			s.recordKill(ctx, actor, target, audit.OutcomeError, rep)
			return rep, err
		}
		rep.Bindings = &outcome
	} else if target.All || target.Bindings || target.Subject != "" {
		rep.BindingsUnavailable = true
	}

	// In-flight bind flows. Only a `subject` sweep: a pending flow is a capability
	// that outlives the binding — completing it creates a new binding and a new
	// upstream token — so a sweep that cuts one account's bindings must remove it,
	// exactly as an erasure does. `all` has no per-account flow port, so it cannot
	// reach them; either way, a sweep that leaves them alive has to say so rather
	// than report a zero that reads as "there were none" (S11-3).
	if target.Subject != "" && s.flows != nil {
		purged, err := s.flows.PurgeUserFlows(ctx, target.Subject)
		if err != nil {
			s.recordKill(ctx, actor, target, audit.OutcomeError, rep)
			return rep, err
		}
		rep.FlowsPurged = purged
	} else if target.All || target.Subject != "" {
		rep.FlowsUnavailable = true
	}

	s.recordKill(ctx, actor, target, audit.OutcomeOK, rep)
	return rep, nil
}

// recordKill writes the Kill Switch's audit row from the report on every path,
// success and failure alike. A failure row that carried only some of the counts
// discarded work that had already happened: the durable record has to describe
// the partial sweep the same way the success row describes a complete one
// (S11-4, Z10V-1).
func (s *service) recordKill(ctx context.Context, actor string, target Target, outcome string, rep Report) {
	s.record(ctx, actor, "admin.kill_switch", target.auditSubject(), outcome, killDetail(rep, target))
}

// setCount is how many targets are named. Exactly one is required, so a request
// cannot mean two things at once.
func (t Target) setCount() int {
	n := 0
	if t.All {
		n++
	}
	if t.ClientID != "" {
		n++
	}
	if t.Subject != "" {
		n++
	}
	if t.Bindings {
		n++
	}
	return n
}

// auditSubject is what the audit row is about.
func (t Target) auditSubject() string {
	if t.ClientID != "" {
		return t.ClientID
	}
	if t.Subject != "" {
		return t.Subject
	}
	return "all"
}

func (t Target) scope() string {
	switch {
	case t.All:
		return "all"
	case t.ClientID != "":
		return "client"
	case t.Subject != "":
		return "subject"
	default:
		return "bindings"
	}
}

func killDetail(rep Report, target Target) map[string]string {
	detail := map[string]string{
		"scope":            target.scope(),
		"tokens_revoked":   strconv.Itoa(rep.TokensRevoked),
		"sessions_revoked": strconv.FormatInt(rep.SessionsRevoked, 10),
	}
	// The client id is the subject of a client-scoped row, and the audit sink
	// stores every subject as a keyed pseudonym — so a reader of the log cannot
	// answer "which client" without this compensating field (Z10-8). oidc.token
	// already carries one.
	if target.ClientID != "" {
		detail["client_id"] = target.ClientID
	}
	if rep.FlowsPurged != 0 {
		detail["flows_purged"] = strconv.Itoa(rep.FlowsPurged)
	}
	if rep.BindingsUnavailable {
		detail["bindings_unavailable"] = "true"
	}
	if rep.SessionsUnavailable {
		detail["sessions_unavailable"] = "true"
	}
	if rep.FlowsUnavailable {
		detail["flows_unavailable"] = "true"
	}
	if rep.Bindings != nil {
		detail["bindings_total"] = strconv.Itoa(rep.Bindings.Total)
		detail["bindings_revoked"] = strconv.Itoa(rep.Bindings.Revoked)
		detail["bindings_failed"] = strconv.Itoa(rep.Bindings.Failed)
	}
	return detail
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
		// The subject is deliberately absent: a raw usr_… in the process log is
		// exactly what the erasure's pseudonym-key destruction cannot reach (G-23).
		// action identifies what failed; the audit sink is where a subject is
		// correlated, and it is the sink that just failed.
		slog.Error("admin audit record failed", "action", action, "err", err)
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
