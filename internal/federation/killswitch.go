package federation

import (
	"context"
	"errors"

	"github.com/Re0Auth/r0semi/internal/account"
)

// BindingRevocationSummary reports a bulk disconnect. Every count is here because
// a kill switch that answers only "done" is not something an incident responder
// can act on.
type BindingRevocationSummary struct {
	Total int
	// Revoked is bindings removed locally. The upstream outcomes below do not
	// change it: the local cut always happens, because a source that is down must
	// not be able to keep a binding alive.
	Revoked int
	// Cascade is bindings whose upstream session was ended outright.
	Cascade int
	// Unsupported is sources that declared they cannot revoke per client.
	Unsupported int
	// Unavailable is sources that could not be reached.
	Unavailable int
	// Orphaned is bindings whose source is no longer in the registry. They were
	// cut locally; there was no source left to tell.
	Orphaned int
	// Failed is bindings whose local removal did not complete.
	Failed int
}

// RevokeAllBindings disconnects every binding in the deployment.
func (s *service) RevokeAllBindings(ctx context.Context) (BindingRevocationSummary, error) {
	all, err := s.bindings.ListAll(ctx)
	if err != nil {
		return BindingRevocationSummary{}, err
	}
	return s.revokeBindings(ctx, all), nil
}

// RevokeUserBindings disconnects every binding one account holds.
func (s *service) RevokeUserBindings(ctx context.Context, user account.UserID) (BindingRevocationSummary, error) {
	if user == "" {
		return BindingRevocationSummary{}, errors.New("federation: user is required")
	}
	list, err := s.bindings.List(ctx, user)
	if err != nil {
		return BindingRevocationSummary{}, err
	}
	return s.revokeBindings(ctx, list), nil
}

// revokeBindings cuts every binding locally and asks each source to end what it
// can. It never stops on a single failure: a source that is down must not keep
// the other bindings alive. Per-binding outcomes are counted, never returned;
// only being unable to enumerate the bindings is an error.
func (s *service) revokeBindings(ctx context.Context, bindings []Binding) BindingRevocationSummary {
	var summary BindingRevocationSummary
	for _, b := range bindings {
		summary.Total++

		src, ok := s.registry.Get(b.Game, b.Source)
		if !ok {
			// The source is no longer configured. There is nothing to ask, but the
			// binding row and its secret still exist and must go.
			if err := s.shredBinding(ctx, b); err != nil {
				summary.Failed++
				continue
			}
			summary.Revoked++
			summary.Orphaned++
			continue
		}

		// A cascade ends the whole upstream session, the loudest thing Re0Auth can
		// ask for; try it first where the source advertises it. Cascade fails
		// closed, so a refusal falls through to Unbind, which cuts locally anyway.
		if src.CascadeRevocationEndpoint != "" {
			if _, err := s.CascadeRevoke(ctx, b.User, b.Game, b.Source); err == nil {
				summary.Revoked++
				summary.Cascade++
				continue
			}
		}

		result, err := s.Unbind(ctx, b.User, b.Game, b.Source)
		if err != nil {
			summary.Failed++
			continue
		}
		summary.Revoked++
		switch result.Upstream {
		case RevocationUnsupported:
			summary.Unsupported++
		case RevocationUnavailable:
			summary.Unavailable++
		}
	}
	return summary
}

// shredBinding removes a binding whose source is gone. Order mirrors Unbind: the
// secret first, because it is the part that could still be used, then the row.
//
// It takes the same per-binding lock the other removal paths take, for the same
// reason: a refresh in flight must not be able to write a fresh secret back after
// this has shredded the old one and deleted the row.
func (s *service) shredBinding(ctx context.Context, b Binding) error {
	unlock := s.locks.lock(bindingKey(b.User, b.Game, b.Source))
	defer unlock()

	if err := s.vault.Revoke(ctx, BindingIdentity(b)); err != nil {
		return err
	}
	return s.bindings.Delete(ctx, b.User, b.Game, b.Source)
}
