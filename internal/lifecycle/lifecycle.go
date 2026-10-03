// Package lifecycle owns account erasure: what "delete my account" actually
// means across every store, in what order, and what is reported back.
//
// It exists because deletion is not one write. An account's data is spread over
// a dozen tables that mostly have no foreign key to the account row, so a bare
// DELETE FROM accounts_users would silently orphan tokens, bindings, credentials
// and pending requests. Something has to name every store, in a deliberate order,
// and that sequencing is the whole value of this package.
//
// It deliberately owns no storage of its own: every dependency is a narrow port,
// injected by the composition root. That keeps the ordering testable against
// fakes, and keeps this package importing no concrete backend.
package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/internal/account"
	"github.com/Re0Auth/r0semi/oauth"
)

// VaultWiper destroys every credential one subject holds. Deleting the rows is
// what crypto-shreds them: the wrapped DEK lives in the row, so the ciphertext
// cannot be recovered once the row is gone.
type VaultWiper interface {
	DeleteSubject(ctx context.Context, subject string) (int, error)
}

// SubjectPurger removes an account's OP state that is not a token: pending
// consent requests, their authorization codes, and device authorizations.
type SubjectPurger interface {
	PurgeSubject(ctx context.Context, subject string) (int, error)
}

// FlowPurger removes an account's pending bind flows.
type FlowPurger interface {
	PurgeUserFlows(ctx context.Context, user account.UserID) (int, error)
}

// LegacyPurger removes an account's rows from the retired hand-rolled engine's
// non-token tables (authorization codes, device authorizations). It is only
// non-empty for a deployment migrated from that engine; see
// postgres.Tokens.PurgeLegacySubject.
type LegacyPurger interface {
	PurgeLegacySubject(ctx context.Context, subject string) (int, error)
}

// PseudonymDestroyer removes the key that ties an account to its audit history.
//
// It is the one step that does not delete rows from the account: the audit log is
// append-only and chained, so erasure there means destroying the ability to
// resolve a pseudonym back to an account, not removing the record. After this, the
// rows remain and still verify; they simply describe nobody.
type PseudonymDestroyer interface {
	Destroy(ctx context.Context, subject string) error
}

// TokenRevoker is the quota of oauth.TokenAdmin this package needs.
type TokenRevoker interface {
	RevokeTokens(ctx context.Context, f oauth.TokenFilter) (int, error)
}

// SessionRevoker drops an account's browser sessions. It mirrors
// admin.SessionRevoker: optional, because the in-memory development store cannot
// enumerate sessions.
type SessionRevoker interface {
	RevokeSubjectSessions(ctx context.Context, subject string) (int64, error)
}

// BindingRevoker disconnects an account's data-source bindings, which also
// shreds their vault entries. It is the federation service's shape.
type BindingRevoker interface {
	RevokeUserBindings(ctx context.Context, user account.UserID) (BindingOutcome, error)
}

// BindingOutcome is the fraction of a binding sweep that did something. Only the
// counts this package reports are here; the federation summary has more.
type BindingOutcome struct {
	Total   int
	Revoked int
	Failed  int
}

// Accounts is the account store, narrowed to what erasure needs.
type Accounts interface {
	DeleteUser(ctx context.Context, user account.UserID) error
}

// Config wires a Deleter. Required: Accounts, Tokens, Vault, Audit.
type Config struct {
	Accounts Accounts
	Tokens   TokenRevoker
	Vault    VaultWiper
	// Bindings, Sessions, OIDC and Flows are optional: a deployment without data
	// sources, durable sessions, or the OP seam simply has nothing to clear there.
	// Leaving one nil is the honest answer, not an oversight — but it means that
	// part of the account is not touched, which Result records.
	Bindings BindingRevoker
	Sessions SessionRevoker
	OIDC     SubjectPurger
	Flows    FlowPurger
	// Legacy, when set, clears the retired engine's non-token tables. Nil for a
	// deployment that never ran that engine.
	Legacy LegacyPurger
	// Pseudonyms, when set, is the last step: it destroys the key that makes the
	// account's audit history linkable. Nil for a deployment whose audit log does
	// not pseudonymise.
	Pseudonyms PseudonymDestroyer
	// Audit is required: an erasure nobody can later prove happened is not one
	// this project is willing to perform. A failure to record it fails the erasure.
	Audit audit.Logger
}

// Result is what an erasure removed, per store. It is returned to the caller and
// written to the audit trail, because "the account is gone" is not something a
// person can check for themselves.
type Result struct {
	Bindings BindingOutcome
	Vault    int
	Tokens   int
	Sessions int64
	Flows    int
	OIDC     int
	Legacy   int
	// SessionScoped is false when the deployment had no session revoker, meaning
	// the account's sessions were NOT cleared. It is surfaced rather than folded
	// into a zero, because zero sessions cleared and "could not clear any" look
	// identical otherwise.
	SessionScoped bool
	// PseudonymDestroyed is true only when a PseudonymDestroyer was wired and the
	// key destruction succeeded. It is the same shape as SessionScoped and exists
	// for the same reason: without it, "the account's audit history is unlinkable"
	// and "the step that delivers that promise was skipped" are indistinguishable
	// in a result that otherwise reports success.
	//
	// It is set only on the successful path, AFTER Destroy has run. The audit
	// record does NOT carry a true: it is written before Destroy (the ordering the
	// destroy depends on), so it reports pseudonym=pending / pseudonym_destroyed=
	// false, and success is read from the absence of a later error record for the
	// subject. This field is the returned result's truth, not the record's.
	PseudonymDestroyed bool
}

// Deleter performs account erasure.
type Deleter struct {
	cfg Config
}

// New validates cfg and returns a Deleter.
func New(cfg Config) (*Deleter, error) {
	switch {
	case cfg.Accounts == nil:
		return nil, errors.New("lifecycle: Accounts is required")
	case cfg.Tokens == nil:
		return nil, errors.New("lifecycle: Tokens is required")
	case cfg.Vault == nil:
		return nil, errors.New("lifecycle: Vault is required")
	case cfg.Audit == nil:
		return nil, errors.New("lifecycle: Audit is required")
	}
	return &Deleter{cfg: cfg}, nil
}

// DeleteAccount erases one account's data across every store.
//
// Order is load-bearing, and runs outward-in:
//
//  1. Bindings first. Each binding's secret is shredded and the upstream is asked
//     to forget the token while Re0Auth still holds it. Delete the local records
//     first and there is nothing left to tell the source with.
//  2. Vault. Any credential left after the binding sweep — a leftover from an
//     already-unbound source, or a provider that is not a federation binding —
//     goes here. This is the crypto-shred proper.
//  3. Tokens. Issued access and refresh tokens stop working.
//  4. Sessions. The browser sessions stop working.
//  5. Pending flows and OP state. Work in flight is discarded, including the
//     retired engine's tables where a deployment was migrated from it.
//  6. The account row last, with its identities.
//  7. The audit pseudonym key. The log is append-only and chained, so it is not
//     deleted from; destroying this key is what makes its rows unlinkable. It
//     goes last, after the record of the deletion itself has been written.
//
// Every step is idempotent, so a repeat is safe *at the store level*: the error
// names the step that stopped, and running it again re-does nothing already done.
// The audit event is written last, once the stores are clear, so it can state what
// was removed rather than promise it, and a failure to write it fails the request.
//
// The caveat, and the reason the HTTP layer no longer promises a retry: this
// endpoint is session-scoped, and step 4 revokes the account's sessions. A failure
// from that step on therefore cannot be retried through the endpoint — the caller
// has no session left — even though DeleteAccount itself would be safe to re-run.
// Making the retry real would need a retry credential that survives the erasure;
// until then the honest answer is that an operator has to finish it. That is
// deliberately the opposite of the operator plane, which logs and proceeds: here an
// unprovable erasure is worse than a failed one.
func (d *Deleter) DeleteAccount(ctx context.Context, actor, subject account.UserID) (Result, error) {
	if subject == "" {
		return Result{}, errors.New("lifecycle: subject is required")
	}
	var res Result

	if d.cfg.Bindings != nil {
		outcome, err := d.cfg.Bindings.RevokeUserBindings(ctx, subject)
		if err != nil {
			return d.fail(ctx, actor, subject, "bindings", err, res)
		}
		res.Bindings = outcome
		// The federation sweep reports a per-binding failure by folding it into
		// Failed rather than returning an error, so err == nil above does not mean
		// every binding was disconnected locally. A binding that could not be
		// removed locally still holds the account's credential, so treating this
		// step as done would erase the account and report outcome=ok while a
		// secret it was supposed to shred survives — the one thing this package
		// exists to prevent. res.Bindings is assigned first so the failure record
		// still carries bindings_revoked/bindings_failed and failed_at=bindings.
		if outcome.Failed > 0 {
			return d.fail(ctx, actor, subject, "bindings", fmt.Errorf(
				"lifecycle: %d of %d bindings could not be removed locally", outcome.Failed, outcome.Total), res)
		}
	}

	n, err := d.cfg.Vault.DeleteSubject(ctx, string(subject))
	if err != nil {
		return d.fail(ctx, actor, subject, "vault", err, res)
	}
	res.Vault = n

	tokens, err := d.cfg.Tokens.RevokeTokens(ctx, oauth.TokenFilter{Subject: string(subject)})
	if err != nil {
		return d.fail(ctx, actor, subject, "tokens", err, res)
	}
	res.Tokens = tokens

	if d.cfg.Sessions != nil {
		sessions, err := d.cfg.Sessions.RevokeSubjectSessions(ctx, string(subject))
		if err != nil {
			return d.fail(ctx, actor, subject, "sessions", err, res)
		}
		res.Sessions = sessions
		res.SessionScoped = true
	}

	if d.cfg.Flows != nil {
		flows, err := d.cfg.Flows.PurgeUserFlows(ctx, subject)
		if err != nil {
			return d.fail(ctx, actor, subject, "bind flows", err, res)
		}
		res.Flows = flows
	}

	if d.cfg.OIDC != nil {
		oidcRows, err := d.cfg.OIDC.PurgeSubject(ctx, string(subject))
		if err != nil {
			return d.fail(ctx, actor, subject, "OP state", err, res)
		}
		res.OIDC = oidcRows
	}

	if d.cfg.Legacy != nil {
		legacyRows, err := d.cfg.Legacy.PurgeLegacySubject(ctx, string(subject))
		if err != nil {
			return d.fail(ctx, actor, subject, "legacy state", err, res)
		}
		res.Legacy = legacyRows
	}

	if err := d.cfg.Accounts.DeleteUser(ctx, subject); err != nil {
		return d.fail(ctx, actor, subject, "account", err, res)
	}

	// The unlinkability step is the one thing the record below cannot state as
	// fact, because it has not run yet: the record comes first (see the ordering
	// note under Destroy, below). So the Result does not claim the destroy here —
	// it is set only once Destroy has actually succeeded — and the record carries
	// the three-state "pseudonym" field (pending / not_configured / failed)
	// alongside pseudonym_destroyed=false.
	res.PseudonymDestroyed = false

	// The record is written after every store is clear, so it can state the result
	// rather than a promise for those stores. A failure to write it fails the
	// erasure: the account row is already gone, and DeleteUser is idempotent, so a
	// repeat of the whole call would produce the record — though see the caveat on
	// DeleteAccount about the session the erasure revokes, which is what the
	// endpoint's caller loses.
	//
	// How to read this record for the pseudonym step: it is the ONLY account.delete
	// record on a successful run, and it says "pending" (when a destroyer is wired)
	// or "not_configured" — never "destroyed", because the key is still there when
	// the line is written. A run whose Destroy succeeded is therefore the run whose
	// record says pending and has NO later error record naming this subject. A
	// failed Destroy appends exactly that later record via fail
	// (outcome=error, failed_at=pseudonym, pseudonym=failed).
	if err := d.record(ctx, actor, subject, audit.OutcomeOK, res, ""); err != nil {
		return res, err
	}

	// Only then is the pseudonym key destroyed, and the order is not cosmetic: the
	// record just written is itself an audit event about this account, so destroying
	// the key first would make the log mint a fresh subject key in order to write it
	// — re-creating precisely the link this step exists to remove.
	if d.cfg.Pseudonyms != nil {
		if err := d.cfg.Pseudonyms.Destroy(ctx, string(subject)); err != nil {
			// The record written above cannot be rewritten (the sink is append-only):
			// it states the run reached the last step with the unlinkability promise
			// intact, which the failed Destroy has just falsified. So the failure is
			// recorded as a second, truthful account.delete — outcome=error, naming
			// "pseudonym" as the step that stopped — instead of being swallowed. The
			// success record is deliberately NOT moved below Destroy: recording is
			// itself an audit event about this account, so writing it after the key is
			// gone would make the sink mint a fresh key, re-creating the very link the
			// destroy exists to remove (see TestDeleteAccountDestroysThePseudonymKeyLast).
			// The failure record is the last word on the run; fail joins it if it
			// cannot even be written.
			res.PseudonymDestroyed = false
			return d.fail(ctx, actor, subject, "pseudonym", fmt.Errorf(
				"lifecycle: the account was erased but its audit history is still linkable: %w", err), res)
		}
		// The key is gone, so only now does the returned result say so. No record is
		// written: the sink would have to mint a fresh subject key to write one.
		res.PseudonymDestroyed = true
	}
	return res, nil
}

// fail records the failed attempt and returns the error.
//
// The caller already has an error to act on, so the cause it passed in is always
// returned. The record write, though, is not allowed to vanish: if it fails, that
// second error is joined into the returned one. errors.Is still reaches the
// original cause, and a caller that wants to know the trail could not be corrected
// reaches the record failure the same way. This matters most for the pseudonym
// step, where the failure record is the only thing that can contradict the
// outcome=ok record written before Destroy; discarding this error would leave a
// false success as the subject's last word with nothing naming the loss.
func (d *Deleter) fail(ctx context.Context, actor, subject account.UserID, step string, cause error, res Result) (Result, error) {
	if rerr := d.record(ctx, actor, subject, audit.OutcomeError, res, step); rerr != nil {
		return res, errors.Join(cause, fmt.Errorf("lifecycle: could not record the failure: %w", rerr))
	}
	return res, cause
}

// pseudonymState is the three-state label a record carries for the unlinkability
// step; see the "pseudonym" detail comment in record for what each value means and
// why "destroyed" is not one of them.
func (d *Deleter) pseudonymState(failedAt string) string {
	switch {
	case d.cfg.Pseudonyms == nil:
		return "not_configured"
	case failedAt == "pseudonym":
		return "failed"
	default:
		return "pending"
	}
}

func (d *Deleter) record(ctx context.Context, actor, subject account.UserID, outcome string, res Result, failedAt string) error {
	// No account id goes in Detail. The Subject field is the only place an account
	// is named, and the sink pseudonymises it; a raw `usr_…` in a detail value
	// would survive the pseudonymisation AND the key destruction, sitting in the one
	// row guaranteed to describe the erased account.
	//
	// So the actor is recorded as a shape, not an identity: whether the account
	// erased itself. That is what an operator reading the log needs, and it is the
	// only fact the raw id was carrying.
	detail := map[string]string{
		"bindings_revoked":    strconv.Itoa(res.Bindings.Revoked),
		"bindings_failed":     strconv.Itoa(res.Bindings.Failed),
		"vault_removed":       strconv.Itoa(res.Vault),
		"tokens_revoked":      strconv.Itoa(res.Tokens),
		"sessions_revoked":    strconv.FormatInt(res.Sessions, 10),
		"flows_removed":       strconv.Itoa(res.Flows),
		"oidc_removed":        strconv.Itoa(res.OIDC),
		"legacy_removed":      strconv.Itoa(res.Legacy),
		"session_scoped":      strconv.FormatBool(res.SessionScoped),
		"pseudonym_destroyed": strconv.FormatBool(res.PseudonymDestroyed),
		// pseudonym is the three-state view of the unlinkability step. It exists
		// because pseudonym_destroyed alone cannot tell "no destroyer is wired"
		// from "a destroyer is wired and has not run yet": both are false. It is
		// one of
		//   "not_configured" — no PseudonymDestroyer is wired;
		//   "pending"        — one is wired and the key still exists at record time;
		//   "failed"         — the destroy ran and failed (the fail record, step
		//                      "pseudonym", also carries failed_at=pseudonym).
		// There is deliberately no "destroyed": the record is written before
		// Destroy runs and none is written after (writing one would make the sink
		// mint a fresh subject key, re-creating the link the destroy removes). A
		// successful run is the one whose record says "pending" and which has no
		// later error record for this subject.
		"pseudonym": d.pseudonymState(failedAt),
		"self":      strconv.FormatBool(actor == subject),
	}
	if failedAt != "" {
		detail["failed_at"] = failedAt
	}
	return d.cfg.Audit.Record(ctx, audit.Event{
		Action:   "account.delete",
		Subject:  string(subject),
		Provider: "account",
		Outcome:  outcome,
		Detail:   detail,
	})
}
