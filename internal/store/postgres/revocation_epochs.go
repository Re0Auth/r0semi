package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"
	oidc "github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/Re0Auth/r0semi/internal/oidcstore"
)

// ErrGrantRevokedInFlight is returned by CreateAccessAndRefreshTokens when the
// grant's revocation generation moved between the resolve step and the mint
// (R10-59). It is a typed invalid_grant, so the token endpoint answers 400 and
// the client re-runs the grant instead of seeing a 500.
var ErrGrantRevokedInFlight = oidc.ErrInvalidGrant().
	WithDescription("the grant was revoked while this request was in flight")

// revocationScopeKeys names the epoch rows a revocation or a mint covers. An
// empty filter is the global scope: the Kill Switch's "everything". The "*" key
// is seeded by migration 0036 and always present, which is what makes the mint's
// FOR SHARE read a reliable lock anchor.
func revocationScopeKeys(clientID, subject string) []string {
	if clientID == "" && subject == "" {
		return []string{"*"}
	}
	keys := make([]string, 0, 2)
	if clientID != "" {
		keys = append(keys, "client:"+clientID)
	}
	if subject != "" {
		keys = append(keys, "subject:"+subject)
	}
	return keys
}

// bumpRevocationEpochs advances the generation of the scope a revocation names,
// BEFORE its deletes (R10-59). It runs inside the revocation's own transaction,
// so the bump and the deletes commit together: a separately committed bump would
// let a mint that captured the post-bump value survive the deletes.
func bumpRevocationEpochs(ctx context.Context, tx pgx.Tx, clientID, subject string) error {
	for _, key := range revocationScopeKeys(clientID, subject) {
		if key == "*" {
			if _, err := tx.Exec(ctx,
				`UPDATE oidc_revocation_epochs SET epoch = epoch + 1, revoked_at = now() WHERE scope_key = '*'`); err != nil {
				return err
			}
			continue
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO oidc_revocation_epochs (scope_key, epoch, revoked_at)
			VALUES ($1, 1, now())
			ON CONFLICT (scope_key) DO UPDATE
			  SET epoch = oidc_revocation_epochs.epoch + 1, revoked_at = now()`, key); err != nil {
			return err
		}
	}
	return nil
}

// readRevocationEpochs reads the three generations for a grant. lock adds FOR
// SHARE, which the mint uses: the share lock makes a concurrent revocation's
// UPDATE wait until the mint commits, so the ordering is established in both
// directions without a second transaction.
func readRevocationEpochs(ctx context.Context, q querier, clientID, subject string, lock bool) (global, client, sub int64, err error) {
	stmt := `SELECT scope_key, epoch FROM oidc_revocation_epochs WHERE scope_key = ANY($1)`
	if lock {
		stmt += ` FOR SHARE`
	}
	rows, err := q.Query(ctx, stmt, revocationScopeKeys(clientID, subject))
	if err != nil {
		return 0, 0, 0, err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			key   string
			epoch int64
		)
		if err := rows.Scan(&key, &epoch); err != nil {
			return 0, 0, 0, err
		}
		switch {
		case key == "*":
			global = epoch
		case clientID != "" && key == "client:"+clientID:
			client = epoch
		case subject != "" && key == "subject:"+subject:
			sub = epoch
		}
	}
	return global, client, sub, rows.Err()
}

// captureRevocationEpochs records the generations the resolve step observed. It
// is a no-op when the request has no carrier (a direct store caller, a test).
func captureRevocationEpochs(ctx context.Context, q querier, clientID, subject string) error {
	global, client, sub, err := readRevocationEpochs(ctx, q, clientID, subject, false)
	if err != nil {
		return err
	}
	oidcstore.CaptureRevocationEpochs(ctx, global, client, sub)
	return nil
}

// checkRevocationEpochs reads the generations under FOR SHARE and fails closed
// when they moved since the resolve step (R10-59).
func checkRevocationEpochs(ctx context.Context, q querier, clientID, subject string) error {
	global, client, sub, err := readRevocationEpochs(ctx, q, clientID, subject, true)
	if err != nil {
		return err
	}
	if !oidcstore.RevocationUnchanged(ctx, global, client, sub) {
		return ErrGrantRevokedInFlight
	}
	return nil
}
