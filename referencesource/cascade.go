package referencesource

import (
	"context"
	"errors"

	"github.com/Re0Auth/r0semi/oauth"
	"github.com/Re0Auth/r0semi/upstreamkit"
	"github.com/Re0Auth/r0semi/vault"
)

// upstreamRevoker returns the first login that can end the upstream session.
//
// The capability is a property of a login rather than of the source, because only
// the login knows what "the upstream session" means for its provider: TapTap
// rotates a session token, someone else might call a logout endpoint. A source
// with no such login simply does not offer it.
func (s *Source) upstreamRevoker() UpstreamRevoker {
	for _, login := range s.logins {
		if revoker, ok := login.(UpstreamRevoker); ok {
			return revoker
		}
	}
	return nil
}

// cascadeRevoke ends the upstream session behind a token Re0Auth holds.
//
// This is the loudest thing this source can do. It signs the person out of every
// device, including the phone in their hand, and it is why the capability is
// advertised rather than assumed: Re0Auth offers it only where a source has said
// it can, and says out loud what it will do.
//
// The order matters, and it is the opposite of disconnecting a binding. Here
// nothing local is given up unless the upstream call succeeded, because the
// credential in the vault is the *only* means of trying again: shredding it after
// a failure would leave the person permanently unable to do the thing they asked
// for. Re0Auth's own rule for disconnecting is the mirror image — see
// internal/federation/unbind.go — and the difference is which half is the goal.
func (s *Source) cascadeRevoke(ctx context.Context, req upstreamkit.CascadeRevocationRequest) error {
	revoker := s.upstreamRevoker()
	if revoker == nil {
		// Unreachable through the kit, which does not advertise the endpoint
		// without the hook. Kept because silently succeeding would be worse.
		return errors.New("referencesource: this source cannot revoke an upstream session")
	}
	// Re0Auth is a registered client; this is not an open endpoint.
	if err := s.as.AuthenticateClient(ctx, req.ClientID, req.ClientSecret); err != nil {
		return err
	}

	subject, refresh, err := s.tokenSubject(ctx, req)
	if err != nil {
		return err
	}
	identity := vault.Identity{Subject: subject, Provider: s.provider}

	// Read the credential, call upstream, and only then let it go.
	if err := s.vault.Use(ctx, identity, func(credential []byte) error {
		return revoker.RevokeUpstream(ctx, subject, credential)
	}); err != nil {
		// Nothing local happened, and nothing may: the binding, the vault
		// credential and the presented token all stay usable so Re0Auth's retry can
		// name the session again. Spending the token in tokenSubject — the shape
		// this used to have — made the retry impossible.
		return err
	}
	// The upstream session is over, so the presented refresh token is now spent.
	// ConsumeRefresh is what rotates it and leaves the reuse tombstone, so a later
	// replay of this value is the theft signal rather than "never issued"; the
	// read that resolved the subject cost the token nothing. An access token is
	// deliberately left alone: it is a short-lived handle, not the durable
	// authorization, and the branch that resolved it must stay non-destructive.
	if refresh {
		if _, err := s.tokens.ConsumeRefresh(ctx, req.Token); err != nil {
			return err
		}
	}
	// The session is gone, so the stored credential's reason to exist is too.
	return s.vault.Revoke(ctx, identity)
}

// tokenSubject resolves which account a token belongs to, and whether that token
// is a refresh token (so the caller knows what it may spend once the upstream
// call has succeeded).
//
// The token was issued by this source, so this source is the only party that can
// answer — which is why the request carries a token rather than a subject Re0Auth
// would be asking to be trusted about. The resolution is READ-ONLY: GetRefresh and
// GetAccess are the read peers of the destructive claims, so a request whose
// upstream call then fails has taken nothing from the token's owner and can be
// retried with the same value.
func (s *Source) tokenSubject(ctx context.Context, req upstreamkit.CascadeRevocationRequest) (string, bool, error) {
	if req.Token == "" {
		return "", false, errors.New("referencesource: cascade revocation carried no token")
	}

	// The hint is a hint. Try what it names first and the other second, because a
	// source that refuses over a wrong guess is a source that gets blamed for it.
	byRefresh := func() (string, bool) {
		tok, err := s.tokens.GetRefresh(ctx, req.Token)
		if err != nil {
			return "", false
		}
		return tok.Subject, true
	}
	byAccess := func() (string, bool) {
		tok, err := s.tokens.GetAccess(ctx, req.Token)
		if err != nil {
			return "", false
		}
		return tok.Subject, true
	}

	first, second := byRefresh, byAccess
	refreshFirst := true
	if req.TokenTypeHint == "access_token" {
		first, second = byAccess, byRefresh
		refreshFirst = false
	}
	if subject, ok := first(); ok {
		return subject, refreshFirst, nil
	}
	if subject, ok := second(); ok {
		return subject, !refreshFirst, nil
	}
	return "", false, oauth.ErrTokenNotFound
}
