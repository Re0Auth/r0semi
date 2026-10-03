package oidcstore

import "context"

// RevocationEpochs carries the revocation generation a token request observed
// when it resolved its credential, from the resolve step (which consumes the
// code, refreshes the device record or reads the refresh row) to the mint
// (CreateAccessAndRefreshTokens).
//
// It exists because resolution and minting are separate storage calls in the
// library, and the source row is gone by the time the mint runs (R10-59). A
// Kill Switch that commits in that window has nothing left to delete, so
// without this carrier it reports success and then a live pair appears behind
// it. The epochs are read from the store's durable counters, so a revocation
// that landed after the capture makes the mint's re-check fail closed.
type RevocationEpochs struct {
	Global  int64
	Client  int64
	Subject int64

	captured bool
}

type revocationEpochsKey struct{}

// WithRevocationEpochs installs an empty carrier. The HTTP boundary does this on
// every OpenID Provider request, so the resolve step and the mint share one.
func WithRevocationEpochs(ctx context.Context) context.Context {
	return context.WithValue(ctx, revocationEpochsKey{}, &RevocationEpochs{})
}

// RevocationEpochsFromContext returns the carrier, if the request has one.
func RevocationEpochsFromContext(ctx context.Context) (*RevocationEpochs, bool) {
	b, ok := ctx.Value(revocationEpochsKey{}).(*RevocationEpochs)
	return b, ok
}

// CaptureRevocationEpochs records what the store's counters were at resolve time.
// It is a no-op when the request has no carrier, so a direct store caller keeps
// its old behaviour.
func CaptureRevocationEpochs(ctx context.Context, global, client, subject int64) {
	if b, ok := RevocationEpochsFromContext(ctx); ok {
		b.Global, b.Client, b.Subject = global, client, subject
		b.captured = true
	}
}

// RevocationUnchanged reports whether the counters still match the capture. A
// request with no carrier, or one that never went through a resolve step, is
// reported unchanged: there is nothing for this guard to compare against.
func RevocationUnchanged(ctx context.Context, global, client, subject int64) bool {
	b, ok := RevocationEpochsFromContext(ctx)
	if !ok || !b.captured {
		return true
	}
	return b.Global == global && b.Client == client && b.Subject == subject
}
