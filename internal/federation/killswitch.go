package federation

import (
	"context"
	"errors"
	"sync"

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
//
// The sweep is paged and its upstream calls run in a bounded pool. Both are
// load-shape decisions rather than correctness ones: a deployment with many
// accounts would otherwise materialise every binding in one slice, and ask each
// source one after another, inside a single request that has to answer before the
// server's write timeout. Per-binding outcomes are unchanged — every one of them
// is counted.
func (s *service) RevokeAllBindings(ctx context.Context) (BindingRevocationSummary, error) {
	var summary BindingRevocationSummary

	pager, ok := s.bindings.(BindingPager)
	if !ok {
		// A store that cannot page: the whole set at once, which is what every
		// store did before paging existed.
		all, err := s.bindings.ListAll(ctx)
		if err != nil {
			return BindingRevocationSummary{}, err
		}
		s.revokeBindings(ctx, all, &summary)
		return summary, nil
	}

	var afterUser, afterGame, afterSource string
	for {
		page, err := pager.ListAllPage(ctx, afterUser, afterGame, afterSource, s.sweepPage)
		if err != nil {
			// The pages already swept are reported as what they are: this returns
			// the summary with the error, so a partial sweep is never presented as
			// a complete one.
			return summary, err
		}
		if len(page) == 0 {
			return summary, nil
		}
		s.revokeBindings(ctx, page, &summary)
		if len(page) < s.sweepPage {
			return summary, nil
		}
		last := page[len(page)-1]
		afterUser, afterGame, afterSource = string(last.User), last.Game, last.Source
	}
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
	var summary BindingRevocationSummary
	s.revokeBindings(ctx, list, &summary)
	return summary, nil
}

// killSwitchPageSize is how many bindings one page of the sweep holds, and
// killSwitchWorkers is how many of them are being disconnected at once.
//
// The workers are bounded because each one is a vault operation plus an upstream
// HTTP call: unbounded fan-out over a large deployment would exhaust the outbound
// bulkhead and hammer the sources, which is the opposite of what a kill switch is
// for.
const (
	killSwitchPageSize = 500
	killSwitchWorkers  = 8
)

// bindingOutcome is what removing one binding contributed. It is a value rather
// than five counters written straight into the summary so the workers can hand
// their result to one merge point.
type bindingOutcome struct {
	revoked     int
	cascade     int
	unsupported int
	unavailable int
	orphaned    int
	failed      int
}

// revokeBindings cuts every binding locally and asks each source to end what it
// can. It never stops on a single failure: a source that is down must not keep
// the other bindings alive. Per-binding outcomes are counted into summary, never
// returned; only being unable to enumerate the bindings is an error.
func (s *service) revokeBindings(ctx context.Context, bindings []Binding, summary *BindingRevocationSummary) {
	if len(bindings) == 0 {
		return
	}
	workers := killSwitchWorkers
	if len(bindings) < workers {
		workers = len(bindings)
	}

	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		queue = make(chan Binding)
	)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for b := range queue {
				outcome := s.revokeBinding(ctx, b)
				mu.Lock()
				summary.Total += outcome.revoked + outcome.failed
				summary.Revoked += outcome.revoked
				summary.Cascade += outcome.cascade
				summary.Unsupported += outcome.unsupported
				summary.Unavailable += outcome.unavailable
				summary.Orphaned += outcome.orphaned
				summary.Failed += outcome.failed
				mu.Unlock()
			}
		}()
	}
	for _, b := range bindings {
		queue <- b
	}
	close(queue)
	wg.Wait()
}

// revokeBinding removes one binding, ending the upstream session where the source
// can, and reports what that took.
func (s *service) revokeBinding(ctx context.Context, b Binding) bindingOutcome {
	src, ok := s.registry.Get(b.Game, b.Source)
	if !ok {
		// The source is no longer configured. There is nothing to ask, but the
		// binding row and its secret still exist and must go.
		if err := s.shredBinding(ctx, b); err != nil {
			return bindingOutcome{failed: 1}
		}
		return bindingOutcome{revoked: 1, orphaned: 1}
	}

	// A cascade ends the whole upstream session, the loudest thing Re0Auth can
	// ask for; try it first where the source advertises it. Cascade fails
	// closed, so a refusal falls through to Unbind, which cuts locally anyway.
	if src.CascadeRevocationEndpoint != "" {
		if _, err := s.CascadeRevoke(ctx, b.User, b.Game, b.Source); err == nil {
			return bindingOutcome{revoked: 1, cascade: 1}
		}
	}

	result, err := s.Unbind(ctx, b.User, b.Game, b.Source)
	if err != nil {
		return bindingOutcome{failed: 1}
	}
	outcome := bindingOutcome{revoked: 1}
	switch result.Upstream {
	case RevocationUnsupported:
		outcome.unsupported = 1
	case RevocationUnavailable:
		outcome.unavailable = 1
	}
	return outcome
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
