package federation

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"golang.org/x/oauth2"

	"github.com/Re0Auth/r0semi/internal/observability"
)

// refreshSkew refreshes a little before actual expiry, to absorb clock skew.
const refreshSkew = 30 * time.Second

// ErrNoRefreshToken reports a binding that cannot be refreshed.
var ErrNoRefreshToken = errors.New("federation: binding has no refresh token")

// errRefreshRejected marks a refresh grant the upstream definitively rejected,
// as opposed to a transient network failure.
var errRefreshRejected = errors.New("federation: refresh grant rejected")

// needsRefresh reports whether a binding should be refreshed proactively.
func (s *service) needsRefresh(b Binding) bool {
	if !b.HasRefresh || b.Expiry.IsZero() {
		return false
	}
	return s.now().Add(refreshSkew).After(b.Expiry)
}

// refreshBinding refreshes a binding's upstream token and stores the result.
// force ignores the expiry check, which is how a 401 is handled. The work is
// serialized per binding, so a rotating refresh token is never spent twice
// concurrently.
func (s *service) refreshBinding(ctx context.Context, src Source, current Binding, force bool) (Binding, error) {
	unlock := s.locks.lock(bindingKey(current.User, current.Game, current.Source))
	defer unlock()

	fresh, err := s.bindings.Get(ctx, current.User, current.Game, current.Source)
	if err != nil {
		return Binding{}, err
	}
	// Another request already rotated the token while we waited for the lock.
	if fresh.Version != current.Version {
		return fresh, nil
	}
	if !force && !s.needsRefresh(fresh) {
		return fresh, nil
	}
	if !fresh.HasRefresh {
		s.metrics.ObserveUpstreamRefresh(observability.RefreshNoToken)
		return Binding{}, ErrNoRefreshToken
	}

	updated := fresh
	var rotated bindingSecret
	// The refresh token is read inside the vault's plaintext window, and the
	// replacement pair is collected here to be written once the window closes.
	err = s.useBindingSecret(ctx, fresh, func(secret *bindingSecret) error {
		if secret.RefreshToken == "" {
			return ErrNoRefreshToken
		}
		token, err := s.oauthConfig(src).
			TokenSource(s.oauthContext(ctx), &oauth2.Token{RefreshToken: secret.RefreshToken}).
			Token()
		if err != nil {
			if isRefreshRejected(err) {
				return errRefreshRejected
			}
			return fmt.Errorf("federation: refresh %s: %w", src.Name, err)
		}
		rotated.AccessToken = token.AccessToken
		rotated.RefreshToken = secret.RefreshToken // kept unless rotated
		if token.RefreshToken != "" {
			rotated.RefreshToken = token.RefreshToken // rotated
		}
		updated.TokenType = token.TokenType
		updated.Expiry = token.Expiry
		updated.HasRefresh = rotated.RefreshToken != ""
		updated.Version = fresh.Version + 1
		return nil
	})
	if err != nil {
		switch {
		case errors.Is(err, errRefreshRejected):
			s.metrics.ObserveUpstreamRefresh(observability.RefreshRejected)
			return s.refreshRejected(ctx, fresh)
		case errors.Is(err, ErrNoRefreshToken):
			s.metrics.ObserveUpstreamRefresh(observability.RefreshNoToken)
			return Binding{}, err
		default:
			s.metrics.ObserveUpstreamRefresh(observability.RefreshTransient)
			return Binding{}, err
		}
	}

	// Claim the version FIRST, and write the secret only if the claim held.
	//
	// The reverse order was wrong in two ways that only showed up under concurrency.
	// A writer that lost the race had already overwritten the winner's token in the
	// vault while the winner's row described a different one — the two stores
	// disagreeing about which upstream token is live. And a refresh racing an
	// Unbind resurrected the secret of a binding that had just been removed: the
	// row was gone so the swap failed, but the vault write had already happened,
	// leaving a decryptable token that ListAll cannot see, the Kill Switch cannot
	// reach again, and only an account erasure clears.
	won, err := s.bindings.PutIfVersion(ctx, updated, fresh.Version)
	if err != nil {
		return Binding{}, err
	}
	if !won {
		// Another process — or an unbind — got there first. Its row is the truth,
		// and we must not touch the vault.
		s.metrics.ObserveUpstreamRefresh(observability.RefreshLost)
		return s.bindings.Get(ctx, fresh.User, fresh.Game, fresh.Source)
	}
	if err := s.storeBindingSecret(ctx, updated, rotated); err != nil {
		// The row now describes a rotation whose secret was not stored. That is a
		// broken binding rather than a silent divergence: the next call presents
		// the old token, is rejected, and the rejection path cleans up. Worth
		// stating plainly — this is the one case the ordering trade buys.
		s.metrics.ObserveUpstreamRefresh(observability.RefreshTransient)
		return Binding{}, err
	}
	s.metrics.ObserveUpstreamRefresh(observability.RefreshOK)
	return updated, nil
}

// refreshRejected decides what a definitively rejected refresh grant means.
//
// A one-time refresh token makes invalid_grant ambiguous: if another process
// rotated this binding while we were calling the source, our call loses the race
// and is rejected for a token that is not dead, only spent. Deleting the binding
// then would destroy one the other process just renewed. So re-read first — a
// version that moved past the one we spent means somebody else won, and their
// token is the live one. Only a version that did not move means the grant is
// genuinely gone and the user must bind again.
func (s *service) refreshRejected(ctx context.Context, spent Binding) (Binding, error) {
	if latest, err := s.bindings.Get(ctx, spent.User, spent.Game, spent.Source); err == nil && latest.Version != spent.Version {
		return latest, nil
	}
	// The grant is genuinely gone. Remove the secret before the row, mirroring
	// shredBinding: the secret is the part that could still be used, and a secret
	// that outlives its row is a decryptable upstream token no endpoint can reach.
	// This path already holds the per-binding lock a refresh took, so it cannot
	// call shredBinding itself — that would re-enter the same lock.
	if err := s.vault.Revoke(ctx, BindingIdentity(spent)); err != nil {
		// Keep the row so the secret stays reachable by Unbind or the kill switch,
		// and retryable on the next refresh. Logged, because an unrecorded orphan
		// here is exactly what the rest of this package treats as a defect.
		slog.ErrorContext(ctx, "could not revoke a rejected binding's secret; leaving the binding in place",
			"user", string(spent.User), "game", spent.Game, "source", spent.Source, "err", err)
		return Binding{}, &NotBoundError{Game: spent.Game, Source: spent.Source}
	}
	if err := s.bindings.Delete(ctx, spent.User, spent.Game, spent.Source); err != nil {
		slog.ErrorContext(ctx, "could not delete a rejected binding",
			"user", string(spent.User), "game", spent.Game, "source", spent.Source, "err", err)
	}
	return Binding{}, &NotBoundError{Game: spent.Game, Source: spent.Source}
}

// isRefreshRejected reports a token endpoint that definitively rejected the
// refresh grant, as opposed to a transient network failure.
func isRefreshRejected(err error) bool {
	var re *oauth2.RetrieveError
	if !errors.As(err, &re) {
		return false
	}
	if re.ErrorCode == "invalid_grant" {
		return true
	}
	if re.Response != nil {
		switch re.Response.StatusCode {
		case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden:
			return true
		}
	}
	return false
}

func isUnauthorized(err error) bool {
	var se *SourceError
	return errors.As(err, &se) && se.Status == http.StatusUnauthorized
}

// callWithRefresh runs fn with a valid token, refreshing once if fn reports a
// 401. fn must return a *SourceError with status 401 for that to trigger. The
// access token only exists inside the vault's plaintext window.
func (s *service) callWithRefresh(ctx context.Context, src Source, binding Binding, fn func(token string) error) error {
	if s.needsRefresh(binding) {
		refreshed, err := s.refreshBinding(ctx, src, binding, false)
		if err != nil {
			return err
		}
		binding = refreshed
	}
	err := s.withAccessToken(ctx, binding, fn)
	if !isUnauthorized(err) || !binding.HasRefresh {
		return err
	}
	refreshed, rerr := s.refreshBinding(ctx, src, binding, true)
	if rerr != nil {
		return rerr
	}
	return s.withAccessToken(ctx, refreshed, fn)
}

// keyedMutex serializes work per key without leaking mutexes.
type keyedMutex struct {
	mu sync.Mutex
	m  map[string]*keyedEntry
}

type keyedEntry struct {
	mu   sync.Mutex
	refs int
}

func (k *keyedMutex) lock(key string) func() {
	k.mu.Lock()
	if k.m == nil {
		k.m = make(map[string]*keyedEntry)
	}
	e := k.m[key]
	if e == nil {
		e = &keyedEntry{}
		k.m[key] = e
	}
	e.refs++
	k.mu.Unlock()

	e.mu.Lock()
	return func() {
		e.mu.Unlock()
		k.mu.Lock()
		e.refs--
		if e.refs == 0 {
			delete(k.m, key)
		}
		k.mu.Unlock()
	}
}
