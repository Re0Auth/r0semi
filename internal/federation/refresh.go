package federation

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"golang.org/x/oauth2"
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
		if errors.Is(err, errRefreshRejected) {
			// The grant is dead; the user must bind the source again. Drop both
			// the metadata and the encrypted secret.
			_ = s.bindings.Delete(ctx, fresh.User, fresh.Game, fresh.Source)
			_ = s.vault.Revoke(ctx, BindingIdentity(fresh))
			return Binding{}, &NotBoundError{Game: fresh.Game, Source: fresh.Source}
		}
		return Binding{}, err
	}

	if err := s.storeBindingSecret(ctx, updated, rotated); err != nil {
		return Binding{}, err
	}
	if err := s.bindings.Put(ctx, updated); err != nil {
		return Binding{}, err
	}
	return updated, nil
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
