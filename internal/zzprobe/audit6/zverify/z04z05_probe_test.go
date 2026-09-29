//go:build audit6

// Adversarial verification of claims 9 and 10, both of them Postgres-side.
//
// There is no local Postgres and no Docker on this machine (BRIEF.md's
// environment section), so a real end-to-end database test is UNREACHABLE here.
// What IS reachable is the failure SHAPE, which is what the claims are about:
// the store is built on a pgxpool pointed at a port nothing answers on, so every
// statement fails with a connection error — and then the store's own methods are
// called for real. That distinguishes "the code swallows a database failure"
// (executable here) from "the query would have found the row" (not executable).
package zverify

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/Re0Auth/r0semi/internal/oidcstore"
	"github.com/Re0Auth/r0semi/internal/store/postgres"
	"github.com/Re0Auth/r0semi/oauth"
)

// vUnreachablePort is a port nothing on this machine should answer on.
const vUnreachablePort = "127.0.0.1:1"

// unreachablePool returns a pool that cannot reach any database. pgxpool
// connects lazily, so building it never dials; the premise is asserted before
// any result is trusted.
func unreachablePool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	cfg, err := pgxpool.ParseConfig("postgres://re0auth@" + vUnreachablePort + "/re0auth?sslmode=disable")
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
		t.Fatalf("premise broken: something answered on %s — pick another unreachable port", vUnreachablePort)
	}
	return pool
}

func vSigner(t *testing.T) *oidcstore.Signer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	return oidcstore.NewSigner("vfy-pg", key)
}

// storeOnUnreachableDB builds a real postgres.OIDCStore over the dead pool.
func storeOnUnreachableDB(t *testing.T) *postgres.OIDCStore {
	t.Helper()
	clients := oauth.NewMemoryClientRegistry()
	c, err := oauth.NewClient("vfy-cli", "Vfy", oauth.ClientConfidential, "s3cret",
		[]string{"https://app.example/cb"}, []oauth.Scope{oauth.ScopeAccountID})
	if err != nil {
		t.Fatalf("build client: %v", err)
	}
	if err := clients.Create(context.Background(), c); err != nil {
		t.Fatalf("register client: %v", err)
	}
	store, err := postgres.NewOIDCStore(unreachablePool(t), clients, postgres.OIDCOptions{
		Registry: oauth.DefaultRegistry(),
		Signer:   vSigner(t),
	})
	if err != nil {
		t.Fatalf("build store: %v", err)
	}
	return store
}

// TestV09RevokeTokenReportsSuccessWhileTheDatabaseCannotAnswer is claim 9's
// executable half. RFC 7009's "an unknown token is success" is a statement
// about a token the server KNOWS it never issued; it is not a licence to answer
// success when no lookup could be performed.
func TestV09RevokeTokenReportsSuccessWhileTheDatabaseCannotAnswer(t *testing.T) {
	store := storeOnUnreachableDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err := store.RevokeToken(ctx, "a-value-the-database-never-saw", "usr_vfy", "vfy-cli")
	if err == nil {
		t.Errorf("CONFIRMED: RevokeToken returned nil (success) while every lookup failed with a " +
			"connection error — the endpoint answers RFC 7009 success for a revocation that checked " +
			"nothing, revoked nothing and audited nothing")
		return
	}
	t.Logf("FALSIFIED: RevokeToken surfaced the database failure: %v", err)
}

// TestV09GetRefreshTokenInfoCollapsesEveryErrorIntoTheSentinel is claim 9's
// second half. The library maps ONLY op.ErrInvalidRefreshToken to "try the other
// token shapes" and reserves every other error for a 500
// (pkg/op/token_revocation.go, func Revoke), so a collapsed error makes the 500
// branch unreachable.
func TestV09GetRefreshTokenInfoCollapsesEveryErrorIntoTheSentinel(t *testing.T) {
	store := storeOnUnreachableDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, _, err := store.GetRefreshTokenInfo(ctx, "vfy-cli", "a-refresh-token-the-database-never-saw")
	if err == nil {
		t.Fatalf("premise broken: GetRefreshTokenInfo succeeded against an unreachable database")
	}
	if errors.Is(err, op.ErrInvalidRefreshToken) {
		t.Errorf("CONFIRMED: GetRefreshTokenInfo reported a connection failure as "+
			"op.ErrInvalidRefreshToken (%v) — the library treats that sentinel as \"try the other token "+
			"shapes\" and reserves every other error for a 500, so a database outage walks into "+
			"RevokeToken with a value it cannot resolve and lands in the 200 above", err)
		return
	}
	t.Logf("FALSIFIED: the error is distinguishable: %v", err)
}

// TestV09UnreachableDatabaseErrorIsNotNoRows pins the premise that makes the
// two findings above about CLASSIFICATION rather than about policy: the error a
// dead pool produces is not pgx.ErrNoRows, so `err == nil` gating is the only
// thing deciding whether the caller learns about it.
func TestV09UnreachableDatabaseErrorIsNotNoRows(t *testing.T) {
	pool := unreachablePool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var owner string
	err := pool.QueryRow(ctx, `SELECT client_id FROM oidc_access_tokens WHERE id_hash = $1`, "x").Scan(&owner)
	if err == nil {
		t.Fatal("premise broken: a query against the dead pool succeeded")
	}
	if errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("the dead-pool error IS pgx.ErrNoRows (%v): the classification question is vacuous", err)
	}
	t.Logf("dead-pool error: %v (not pgx.ErrNoRows)", err)
}

// TestV09SourceShapeIsAsClaimed reads the shipped adapter and asserts the three
// lookups really are `err == nil`-gated (claim 9's mechanism), so the executable
// result above is not an artifact of the probe's own plumbing.
func TestV09SourceShapeIsAsClaimed(t *testing.T) {
	src := readShippedGo(t, "internal/store/postgres/oidc.go")
	body := funcBody(t, src, "func (s *OIDCStore) RevokeToken(")
	if got := strings.Count(body, "QueryRow"); got != 3 {
		t.Fatalf("found %d QueryRow calls in RevokeToken; the extraction is broken (there are three)", got)
	}
	if strings.Contains(body, "errors.Is(err, pgx.ErrNoRows)") || strings.Contains(body, "noRows(err)") {
		t.Errorf("RevokeToken now classifies its lookup errors, so claim 9's mechanism no longer holds " +
			"of this revision — re-derive the finding")
	}
	t.Logf("RevokeToken gates all three lookups on err == nil and never classifies pgx.ErrNoRows: " +
		"the final `return nil` is reachable for a connection error")

	// The contrast the original probe cites must be real, or the "classification
	// gap" framing is wrong.
	oauthSrc := readShippedGo(t, "internal/store/postgres/oauth.go")
	if !strings.Contains(oauthSrc, "noRows(err)") {
		t.Errorf("TokenOwner no longer classifies noRows either; the \"this is a gap, not a policy\" " +
			"framing is stale")
	} else {
		t.Logf("TokenOwner in oauth.go does classify noRows: the same package answers the same " +
			"question both ways")
	}
}

// ---------------------------------------------------------------------------
// 10 · Postgres refresh-token expiry is not adjudicated on the read path
// ---------------------------------------------------------------------------

// TestV10PostgresRefreshLookupHasNoExpiryPredicate is claim 10's mechanism,
// pinned against the shipped SQL. The memory store's equivalent line does carry
// `!s.now().Before(r.expiresAt)`; Postgres carries nothing.
func TestV10PostgresRefreshLookupHasNoExpiryPredicate(t *testing.T) {
	src := readShippedGo(t, "internal/store/postgres/oidc.go")
	body := funcBody(t, src, "func (s *OIDCStore) TokenRequestByRefreshToken(")
	if !strings.Contains(body, "FROM oidc_refresh_tokens WHERE token_hash = $1") {
		t.Fatalf("the lookup shape changed; re-read TokenRequestByRefreshToken:\n%s", body)
	}
	if strings.Contains(body, "expires_at") {
		t.Logf("FALSIFIED: the Postgres refresh lookup now filters on expires_at")
		return
	}
	if !strings.Contains(body, "return nil, errors.New(\"postgres: invalid refresh token\")") {
		t.Errorf("the not-found branch changed; re-read the method")
	}
	t.Errorf("CONFIRMED: Postgres's TokenRequestByRefreshToken selects from oidc_refresh_tokens with " +
		"no expires_at predicate, so a 31-day-old refresh token row still resolves; the only thing " +
		"that removes it is the 15-minute sweep (cmd/re0auth/main.go:405), and the memory store's " +
		"equivalent lookup DOES judge expiry on the read path (internal/store/memory/oidc.go:573)")
}

// TestV10MemoryStoreDoesAdjudicateExpiry is the contrast that makes claim 10 a
// backend divergence rather than a general gap. Executable: the memory store's
// clock is moved.
func TestV10MemoryStoreDoesAdjudicateExpiry(t *testing.T) {
	clock := newVClock()
	e := newVEnv(t, clock, nil)

	tokens := e.codeFlow(t, e.webID, e.webSec, []string{"account.id", "offline_access"}, "usr_vfy", time.Time{})
	if tokens.RefreshToken == "" {
		t.Fatal("no refresh token")
	}
	// Live now.
	if _, err := e.store.TokenRequestByRefreshToken(context.Background(), tokens.RefreshToken); err != nil {
		t.Fatalf("the fresh refresh token does not resolve: %v", err)
	}
	// Past the 30-day TTL, with no sweep run.
	clock.Advance(31 * 24 * time.Hour)
	if _, err := e.store.TokenRequestByRefreshToken(context.Background(), tokens.RefreshToken); err == nil {
		t.Errorf("the memory store resolved a refresh token past its TTL — the memory/Postgres " +
			"divergence in claim 10 does not hold")
		return
	}
	t.Logf("memory store refuses the expired token on the read path with no sweep: the two backends " +
		"really do differ, and Postgres is the later one")
}

// TestV10PostgresRevokeAndLookupIgnoreExpiryToo records the full extent of the
// missing predicate, so the severity discussion is not based on one query.
func TestV10PostgresRevokeAndLookupIgnoreExpiryToo(t *testing.T) {
	src := readShippedGo(t, "internal/store/postgres/oidc.go")

	// The three RevokeToken lookups and all three deletions.
	revoke := funcBody(t, src, "func (s *OIDCStore) RevokeToken(")
	if strings.Contains(revoke, "expires_at") {
		t.Logf("FALSIFIED: RevokeToken now mentions expires_at")
		return
	}
	// The device consume path.
	device := funcBody(t, src, "func (s *OIDCStore) GetDeviceAuthorizatonState(")
	if strings.Contains(device, "expires_at > ") || strings.Contains(device, "expires_at >=") {
		t.Logf("FALSIFIED: the Postgres device consume path now filters on expires_at")
	} else if !strings.Contains(device, "done = true AND denied = false") {
		t.Errorf("the Postgres device consume predicate changed; re-read it")
	} else {
		t.Logf("the Postgres device consume predicate is \"done = true AND denied = false\" with no " +
			"expires_at (internal/store/postgres/oidc.go:751): claim 2's mechanism holds on the " +
			"Postgres backend at the SQL level too, though only the table's own clock is available here")
	}
}

// ---------------------------------------------------------------------------
// source-reading helpers
// ---------------------------------------------------------------------------

// readShippedGo reads a tracked production file relative to the module root.
func readShippedGo(t *testing.T, rel string) string {
	t.Helper()
	root := moduleRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(raw)
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	// `go test` runs each package with its own directory as the working
	// directory, so walking up for go.mod works without assuming a depth.
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("no go.mod found above %s", dir)
		}
		dir = parent
	}
}

// funcBody returns the text of a top-level function from its signature line to
// the first line that is a lone closing brace at column 0.
func funcBody(t *testing.T, src, signature string) string {
	t.Helper()
	i := strings.Index(src, signature)
	if i < 0 {
		t.Fatalf("signature %q not found", signature)
	}
	rest := src[i:]
	end := strings.Index(rest, "\n}\n")
	if end < 0 {
		t.Fatalf("no function end found for %q", signature)
	}
	return rest[:end+3]
}
