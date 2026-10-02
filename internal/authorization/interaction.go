// Package authorization defines the consent interaction: the engine-neutral
// contract between the /v1 consent screen and whichever authorization engine is
// running (the hand-rolled one or the OpenID Provider).
//
// It exists so the HTTP layer can offer the consent screen without importing an
// engine, and so both engines can implement one interface.
package authorization

import (
	"context"
	"errors"

	"github.com/Re0Auth/r0semi/oauth"
)

// ErrRequestExpired reports an authorization request this engine no longer holds:
// it was never issued, the user already decided it, or its deadline passed.
//
// It is a sentinel rather than "any error" because the HTTP layer has to answer
// two very different situations differently (S04-7). An expired request is the
// client's situation and gets a 4xx; a store outage, a context deadline or a
// serialization failure is the server's and gets a 5xx and an audit row. Before
// this sentinel every one of them was reported to the browser as an expired
// request, which turned an outage into a lie. Implementations must return
// ErrRequestExpired (wrapped is fine) for the unknown/expired case and leave every
// other error as itself.
var ErrRequestExpired = errors.New("authorization: the authorization request is unknown or expired")

// View is the consent screen's view of a pending authorization. It carries no
// secret.
type View struct {
	ID         string
	ClientID   string
	ClientName string
	Scopes     []oauth.Scope
}

// Interaction is the consent screen's engine seam.
type Interaction interface {
	// ValidID reports whether id is structurally plausible for this engine,
	// letting the HTTP layer reject garbage before a store lookup.
	ValidID(id string) bool
	// DescribeAuthorization returns the pending request for the consent screen.
	// It returns ErrRequestExpired when the request is unknown or expired and any
	// other error for an engine fault.
	DescribeAuthorization(ctx context.Context, id string) (View, error)
	// ApproveAuthorization completes the request and returns the browser's next
	// URL. It may only narrow the requested scopes. A request the engine no longer
	// holds is ErrRequestExpired; protocol refusals stay *oauth.Error.
	ApproveAuthorization(ctx context.Context, id, subject string, scopes, explicit []oauth.Scope) (string, error)
	// DenyAuthorization cancels the request and returns the browser's next URL.
	// It returns ErrRequestExpired for a request the engine no longer holds.
	DenyAuthorization(ctx context.Context, id string) (string, error)
}
