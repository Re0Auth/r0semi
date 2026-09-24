package federation

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/Re0Auth/r0semi/internal/account"
)

// UpstreamRevocation says what happened at the data source.
type UpstreamRevocation string

const (
	// RevocationDone: the source did it.
	RevocationDone UpstreamRevocation = "done"
	// RevocationUnsupported: the source cannot do it. For a token that means it
	// declared `token_class: long_lived`; for a session it means it does not
	// advertise the capability at all.
	RevocationUnsupported UpstreamRevocation = "unsupported"
	// RevocationUnavailable: the source could not be reached, or refused.
	RevocationUnavailable UpstreamRevocation = "unavailable"
	// RevocationNothingToDo: there was nothing to revoke.
	RevocationNothingToDo UpstreamRevocation = "nothing"
)

// tokenClassLongLived marks a source credential that cannot be revoked per client.
const tokenClassLongLived = "long_lived"

// ErrCascadeUnsupported reports a source that cannot end an upstream session.
var ErrCascadeUnsupported = errors.New("federation: the source cannot revoke the upstream session")

// RevocationResult reports what a revocation managed to undo.
//
// The upstream half is best effort for a disconnection and the whole point for a
// cascade, so carrying it back is what lets each caller say something true. Only
// the server knows whether "removed here, still live there" happened, and that is
// a different sentence from "done".
type RevocationResult struct {
	Upstream UpstreamRevocation
	// UpstreamError is the source's own failure when Upstream is unavailable. It
	// is diagnostic, never a secret, and never the reason a local removal failed —
	// that would have come back as an error instead.
	UpstreamError string
}

// preferredToken picks which token identifies the authorization.
//
// The refresh token when there is one: it names the durable authorization rather
// than an hour of it, and access tokens expire. Ending a session that outlives
// the token is the whole point, so a token that may already be dead is the wrong
// thing to send.
func preferredToken(secret bindingSecret) (token, hint string) {
	if secret.RefreshToken != "" {
		return secret.RefreshToken, "refresh_token"
	}
	if secret.AccessToken != "" {
		return secret.AccessToken, "access_token"
	}
	return "", ""
}

// postRevocation posts RFC 7009-shaped form data to one of a source's revocation
// endpoints, with the client's credentials.
//
// Factored out because token revocation and cascade revocation differ in the URL
// and in what the source does with it, and in nothing else. Two copies of the
// encoding rules would eventually disagree about one of them.
func (s *service) postRevocation(ctx context.Context, src Source, endpoint string, form url.Values) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// RFC 6749 §2.3.1: credentials going into the Basic header are urlencoded first.
	req.SetBasicAuth(url.QueryEscape(src.ClientID), url.QueryEscape(src.ClientSecret))

	resp, err := s.doer.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("the source answered %d", resp.StatusCode)
	}
	return nil
}

// CascadeRevoke ends the subject's whole upstream session at a source, and then
// removes the binding.
//
// This is the loudest thing Re0Auth can ask for. The source rotates or destroys
// the underlying login, so the person is signed out of every device — including
// the one in their hand — and the credential Re0Auth holds dies with it.
//
// It fails closed in the way Unbind deliberately does not: **nothing is removed
// unless the source confirmed**. Unbind removes locally whatever the source says,
// because the goal there is to cut a source off from this account, and a source
// that is down must not be able to hold that hostage. Here the goal *is* the
// upstream action, and the credential in the vault is the only means of
// attempting it again — so shredding it after a failure would leave the person
// permanently unable to do the thing they asked for.
func (s *service) CascadeRevoke(ctx context.Context, user account.UserID, game, source string) (RevocationResult, error) {
	if user == "" || game == "" || source == "" {
		return RevocationResult{}, errors.New("federation: user, game and source are required")
	}
	src, ok := s.registry.Get(game, source)
	if !ok {
		return RevocationResult{}, ErrUnknownSource
	}
	if src.CascadeRevocationEndpoint == "" {
		return RevocationResult{}, ErrCascadeUnsupported
	}
	// Same per-binding lock a refresh and an unbind take. A cascade must not
	// interleave with a refresh either: the refresh would rotate the token out from
	// under the request that is telling the source to kill the session, or write a
	// fresh secret back after this call shredded it.
	unlock := s.locks.lock(bindingKey(user, game, source))
	defer unlock()

	binding, err := s.bindings.Get(ctx, user, game, source)
	if err != nil {
		return RevocationResult{}, err
	}

	var secret bindingSecret
	if err := s.useBindingSecret(ctx, binding, func(sec *bindingSecret) error {
		secret = *sec
		return nil
	}); err != nil {
		return RevocationResult{}, fmt.Errorf("federation: read binding secret: %w", err)
	}

	token, hint := preferredToken(secret)
	if token == "" {
		return RevocationResult{}, errors.New("federation: the binding holds no token to identify the session")
	}
	form := url.Values{"token": {token}, "token_type_hint": {hint}}
	if err := s.postRevocation(ctx, src, src.CascadeRevocationEndpoint, form); err != nil {
		return RevocationResult{}, fmt.Errorf("federation: cascade revocation: %w", err)
	}

	// Only now. The session is gone, so there is nothing left to retry and the
	// binding's reason to exist went with it.
	if err := s.vault.Revoke(ctx, BindingIdentity(binding)); err != nil {
		return RevocationResult{}, fmt.Errorf("federation: shred binding secret: %w", err)
	}
	if err := s.bindings.Delete(ctx, user, game, source); err != nil {
		return RevocationResult{}, fmt.Errorf("federation: delete binding: %w", err)
	}
	return RevocationResult{Upstream: RevocationDone}, nil
}
