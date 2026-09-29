//go:build audit6

package z04pgstore

// The RFC 7009 revocation path's error classification, executed for real.
//
// The store is built on a pgxpool whose DSN points at 127.0.0.1:1 — a port
// where no Postgres will ever answer — so every statement fails with a
// connection error, which is exactly the failure shape a fail-open check has to
// survive: a database that cannot answer must not be mistaken for "the token
// does not exist".
//
// Why this is runnable without a database: pgxpool connects lazily, so
// constructing it never dials; the first QueryRow performs the (refused)
// connect, bounded by a short ConnectTimeout. The premise — that the pool
// genuinely cannot reach a database — is asserted before every claim, so a
// machine where something answers on that port fails loudly rather than passing
// vacuously.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/Re0Auth/r0semi/internal/store/postgres"
	"github.com/Re0Auth/r0semi/oauth"
)

// unreachablePool returns a pool bound to an address nothing will answer on,
// with a short connect budget so the probes fail fast rather than hang.
func unreachablePool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	cfg, err := pgxpool.ParseConfig("postgres://re0auth@127.0.0.1:1/re0auth?sslmode=disable")
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	cfg.MaxConns = 1
	cfg.MinConns = 0
	cfg.ConnConfig.ConnectTimeout = 250 * time.Millisecond
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("build pool: %v", err)
	}
	t.Cleanup(pool.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := pool.Ping(ctx); err == nil {
		t.Fatal("the premise is broken: something answered on 127.0.0.1:1 — pick another unreachable " +
			"port before trusting any result from this file")
	}
	return pool
}

// storeOnUnreachableDB builds a postgres.OIDCStore over a pool that cannot
// reach any database. The client registry is real but in memory; nothing on the
// RevokeToken / GetRefreshTokenInfo paths consults it, and the signer is only
// required to exist.
func storeOnUnreachableDB(t *testing.T) *postgres.OIDCStore {
	t.Helper()
	clients := oauth.NewMemoryClientRegistry()
	c, err := oauth.NewClient("probe-cli", "Probe", oauth.ClientConfidential, "s3cret",
		[]string{"https://client.example/cb"}, []oauth.Scope{oauth.ScopeAccountID})
	if err != nil {
		t.Fatalf("build probe client: %v", err)
	}
	if err := clients.Create(context.Background(), c); err != nil {
		t.Fatalf("register probe client: %v", err)
	}
	store, err := postgres.NewOIDCStore(unreachablePool(t), clients, postgres.OIDCOptions{
		Registry: oauth.DefaultRegistry(),
		Signer:   testSigner(t),
	})
	if err != nil {
		t.Fatalf("build store: %v", err)
	}
	return store
}

// TestRevokeTokenDoesNotReportSuccessWhenTheDatabaseCannotAnswer is the finding.
//
// OIDCStore.RevokeToken resolves the presented value's owner with three
// lookups, each gated on `err == nil`. Any error that is NOT "no rows" — a
// broken connection, a failover, a statement timeout, a cancelled request
// context — falls through all three and lands on the final `return nil`,
// which the token endpoint answers as RFC 7009's "unknown token is success":
// HTTP 200, nothing revoked, and no audit record (the audit write only happens
// on the branches that found the token).
//
// The probe holds the invariant the failure direction requires: a revocation
// that could not check the database must come back as an error (server_error,
// which tells the client to retry), never as success.
func TestRevokeTokenDoesNotReportSuccessWhenTheDatabaseCannotAnswer(t *testing.T) {
	store := storeOnUnreachableDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err := store.RevokeToken(ctx, "a-token-value-the-database-never-saw", "usr_probe", "probe-cli")
	if err == nil {
		t.Fatal("RevokeToken reported success (nil) while every lookup failed with a connection error: " +
			"the endpoint answers RFC 7009 success for a revocation that checked nothing, revoked nothing " +
			"and audited nothing. Only pgx.ErrNoRows may fall through to 'unknown token is success'")
	}
}

// TestRevokeTokenClassifiesOnlyNoRowsAsUnknownToken is the source half of the
// same finding, plus the contrast that makes it a classification gap rather
// than a policy: TokenOwner, one file over, on the same RFC 7009 path, does
// classify its lookup errors — RevokeToken never consults the helper.
func TestRevokeTokenClassifiesOnlyNoRowsAsUnknownToken(t *testing.T) {
	code := stripGoComments(readShipped(t, adapterDir+"/oidc.go"))
	body := methodBodyOf(t, code, "RevokeToken")

	if got := strings.Count(body, "QueryRow"); got < 3 {
		t.Fatalf("found %d QueryRow calls in RevokeToken; the extraction is broken (there are three)", got)
	}
	if !strings.Contains(body, "noRows(") && !strings.Contains(body, "errors.Is(err, pgx.ErrNoRows)") {
		t.Error("RevokeToken never classifies its lookup errors: every error — connection refused, " +
			"failover, statement timeout, cancelled context — falls through to `return nil`, which the " +
			"token endpoint answers as RFC 7009 success. TokenOwner (oauth.go) shows the shape: only " +
			"pgx.ErrNoRows means 'unknown token'; every other error must surface as server_error")
	}

	oauthCode := stripGoComments(readShipped(t, adapterDir+"/oauth.go"))
	if !strings.Contains(methodBodyOf(t, oauthCode, "TokenOwner"), "noRows(") {
		t.Fatal("TokenOwner no longer classifies noRows either; the probe's premise about the " +
			"established shape is stale — re-read the adapter")
	}
}

// TestGetRefreshTokenInfoDistinguishesDBFailureFromUnknownToken is the second
// half of the same hole.
//
// The library's revocation handler (zitadel/oidc v3 pkg/op/token_revocation.go,
// func Revoke) maps errors from GetRefreshTokenInfo explicitly:
//
//	only errors.Is(err, op.ErrInvalidRefreshToken)  -> try the other token shapes
//	any other error                                  -> 500 server_error, stop
//
// The store returns op.ErrInvalidRefreshToken for EVERY error, including a
// connection failure, so the library's 500 branch is unreachable and a
// database outage instead walks into the decrypt path and calls RevokeToken
// with a value it cannot resolve — landing in the finding above's 200.
//
// The probe holds the contract: a lookup that failed because the database
// could not answer must NOT be reported as "this refresh token is unknown".
func TestGetRefreshTokenInfoDistinguishesDBFailureFromUnknownToken(t *testing.T) {
	store := storeOnUnreachableDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, _, err := store.GetRefreshTokenInfo(ctx, "probe-cli", "a-refresh-token-the-database-never-saw")
	if err == nil {
		t.Fatal("GetRefreshTokenInfo returned success against an unreachable database; the premise is broken")
	}
	if errors.Is(err, op.ErrInvalidRefreshToken) {
		t.Fatal("GetRefreshTokenInfo reported a connection failure as op.ErrInvalidRefreshToken: the library " +
			"treats that sentinel as 'try the other token shapes' and reserves every other error for a 500 " +
			"(pkg/op/token_revocation.go, func Revoke). Collapse it — noRows may map to the sentinel, a " +
			"database failure must surface as itself so the outage answers server_error instead of walking " +
			"into a revocation that answers success")
	}
}
