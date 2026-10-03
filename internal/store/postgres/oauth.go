package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Re0Auth/r0semi/oauth"
)

// Tokens implements oauth.Store on Postgres.
//
// Every row is keyed by oauth.TokenHash(value): the opaque code or token is used
// only to compute the key and is never written. Single-use operations are a
// one-statement DELETE ... RETURNING, so two concurrent callers cannot both win.
//
// Refresh rotation also leaves a tombstone (oauth_refresh_tombstones) carrying the
// spent token's family, so a replay of a spent value is recognised as reuse and
// its whole family can be revoked (RFC 9700 §4.14.2). The tombstone is what lets
// ConsumeRefresh distinguish "already spent" from "never issued"; see the method.
type Tokens struct {
	pool *pgxpool.Pool
	// now judges the tombstone's own deadline. It is the store clock, not the
	// database's, for the reason postgres.go's single-clock policy states: a
	// deadline written by this process is judged by the process that wrote it.
	now func() time.Time
}

// Tokens must satisfy the public oauth.Store contract, tombstone obligations
// included. Asserted at compile time so a method dropped from the interface's
// shape fails here rather than at the composition root.
var _ oauth.Store = (*Tokens)(nil)

// clock reads the store clock, tolerating a Tokens built without one (the
// zero-value handle) rather than dereferencing a nil function.
func (s *Tokens) clock() time.Time {
	if s.now == nil {
		return time.Now()
	}
	return s.now()
}

// SaveCode implements oauth.Store.
func (s *Tokens) SaveCode(ctx context.Context, value string, c oauth.AuthorizationCode) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO oauth_codes
			(token_hash, client_id, subject, scopes, redirect_uri, code_challenge, code_challenge_method, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		oauth.TokenHash(value), c.ClientID, c.Subject, scopeArray(c.Scopes),
		c.RedirectURI, c.CodeChallenge, c.CodeChallengeMethod, c.ExpiresAt)
	return err
}

// authorizationCodeRow is the RETURNING shape of a consumed oauth_codes row.
type authorizationCodeRow struct {
	ClientID            string    `db:"client_id"`
	Subject             string    `db:"subject"`
	Scopes              []string  `db:"scopes"`
	RedirectURI         string    `db:"redirect_uri"`
	CodeChallenge       string    `db:"code_challenge"`
	CodeChallengeMethod string    `db:"code_challenge_method"`
	ExpiresAt           time.Time `db:"expires_at"`
}

func (r authorizationCodeRow) code() oauth.AuthorizationCode {
	return oauth.AuthorizationCode{
		ClientID:            r.ClientID,
		Subject:             r.Subject,
		Scopes:              scopesFrom(r.Scopes),
		RedirectURI:         r.RedirectURI,
		CodeChallenge:       r.CodeChallenge,
		CodeChallengeMethod: r.CodeChallengeMethod,
		ExpiresAt:           r.ExpiresAt,
	}
}

// GetCode implements oauth.Store. A SELECT, never a DELETE: the exchange reads
// the record to judge its client/redirect/PKCE bindings, and only the atomic
// ConsumeCode delete spends it. A failed binding therefore leaves the row for
// its rightful owner. Expiry is the service's judgment, so an expired code is
// returned here rather than hidden.
func (s *Tokens) GetCode(ctx context.Context, value string) (oauth.AuthorizationCode, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT client_id, subject, scopes, redirect_uri, code_challenge, code_challenge_method, expires_at
		  FROM oauth_codes WHERE token_hash = $1`, oauth.TokenHash(value))
	if err != nil {
		return oauth.AuthorizationCode{}, err
	}
	row, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[authorizationCodeRow])
	if noRows(err) {
		return oauth.AuthorizationCode{}, oauth.ErrTokenNotFound
	}
	if err != nil {
		return oauth.AuthorizationCode{}, err
	}
	return row.code(), nil
}

// ConsumeCode implements oauth.Store. Expiry is checked by the service, so an
// expired code is still returned (once) rather than swallowed.
func (s *Tokens) ConsumeCode(ctx context.Context, value string) (oauth.AuthorizationCode, error) {
	rows, err := s.pool.Query(ctx, `
		DELETE FROM oauth_codes
		 WHERE token_hash = $1
		RETURNING client_id, subject, scopes, redirect_uri, code_challenge, code_challenge_method, expires_at`,
		oauth.TokenHash(value))
	if err != nil {
		return oauth.AuthorizationCode{}, err
	}
	row, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[authorizationCodeRow])
	if noRows(err) {
		return oauth.AuthorizationCode{}, oauth.ErrTokenNotFound
	}
	if err != nil {
		return oauth.AuthorizationCode{}, err
	}
	return row.code(), nil
}

// SaveAccess implements oauth.Store.
func (s *Tokens) SaveAccess(ctx context.Context, value string, t oauth.AccessToken) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO oauth_access_tokens (token_hash, client_id, subject, scopes, family_id, issued_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		oauth.TokenHash(value), t.ClientID, t.Subject, scopeArray(t.Scopes),
		t.FamilyID, t.IssuedAt, t.ExpiresAt)
	return err
}

// tokenRow is the column shape shared by the access- and refresh-token tables.
type tokenRow struct {
	ClientID  string    `db:"client_id"`
	Subject   string    `db:"subject"`
	Scopes    []string  `db:"scopes"`
	FamilyID  string    `db:"family_id"`
	IssuedAt  time.Time `db:"issued_at"`
	ExpiresAt time.Time `db:"expires_at"`
}

func (r tokenRow) accessToken() oauth.AccessToken {
	return oauth.AccessToken{
		ClientID: r.ClientID, Subject: r.Subject, Scopes: scopesFrom(r.Scopes),
		FamilyID: r.FamilyID, IssuedAt: r.IssuedAt, ExpiresAt: r.ExpiresAt,
	}
}

func (r tokenRow) refreshToken() oauth.RefreshToken {
	return oauth.RefreshToken{
		ClientID: r.ClientID, Subject: r.Subject, Scopes: scopesFrom(r.Scopes),
		FamilyID: r.FamilyID, IssuedAt: r.IssuedAt, ExpiresAt: r.ExpiresAt,
	}
}

// GetAccess implements oauth.Store.
func (s *Tokens) GetAccess(ctx context.Context, value string) (oauth.AccessToken, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT client_id, subject, scopes, family_id, issued_at, expires_at
		  FROM oauth_access_tokens WHERE token_hash = $1`, oauth.TokenHash(value))
	if err != nil {
		return oauth.AccessToken{}, err
	}
	row, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[tokenRow])
	if noRows(err) {
		return oauth.AccessToken{}, oauth.ErrTokenNotFound
	}
	if err != nil {
		return oauth.AccessToken{}, err
	}
	return row.accessToken(), nil
}

// DeleteAccess implements oauth.Store. Deleting an absent token is not an error,
// which keeps RFC 7009 revocation idempotent.
func (s *Tokens) DeleteAccess(ctx context.Context, value string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM oauth_access_tokens WHERE token_hash = $1`, oauth.TokenHash(value))
	return err
}

// SaveRefresh implements oauth.Store.
func (s *Tokens) SaveRefresh(ctx context.Context, value string, t oauth.RefreshToken) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO oauth_refresh_tokens (token_hash, client_id, subject, scopes, family_id, issued_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		oauth.TokenHash(value), t.ClientID, t.Subject, scopeArray(t.Scopes),
		t.FamilyID, t.IssuedAt, t.ExpiresAt)
	return err
}

// GetRefresh implements oauth.Store. A SELECT, never a DELETE, mirroring GetCode
// and GetAccess: a caller resolving which account a token names, before a
// fallible upstream call, must be able to try again, and only ConsumeRefresh's
// atomic claim may rotate the token and leave the reuse tombstone.
//
// A value already spent has no live row left, so it reports ErrTokenNotFound here
// exactly like one this deployment never issued. That is deliberate: the
// *RefreshReuseError theft signal belongs to ConsumeRefresh, the destructive
// claim, and a read must never be the thing that judges a replay.
func (s *Tokens) GetRefresh(ctx context.Context, value string) (oauth.RefreshToken, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT client_id, subject, scopes, family_id, issued_at, expires_at
		  FROM oauth_refresh_tokens WHERE token_hash = $1`, oauth.TokenHash(value))
	if err != nil {
		return oauth.RefreshToken{}, err
	}
	row, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[tokenRow])
	if noRows(err) {
		return oauth.RefreshToken{}, oauth.ErrTokenNotFound
	}
	if err != nil {
		return oauth.RefreshToken{}, err
	}
	return row.refreshToken(), nil
}

// ConsumeRefresh implements oauth.Store. Rotation makes the token single-use, and
// the claim leaves a tombstone so a later replay of the same value is recognised
// as reuse rather than mistaken for a value that was never issued.
//
// The DELETE and the tombstone INSERT share one transaction: the row is the only
// place the family is recorded before it is gone, and a crash between the two
// would leave the family unrecoverable — a replay could then only be refused, not
// traced to the thief's generation.
//
// On no rows the replay branch runs: an unexpired tombstone for this hash names
// the family the presented token belonged to, and that is the RFC 9700 §4.14.2
// theft signal. A database error is returned as an error and never folded into
// either "unknown" or "reused": a store that cannot tell must fail closed.
func (s *Tokens) ConsumeRefresh(ctx context.Context, value string) (oauth.RefreshToken, error) {
	hash := oauth.TokenHash(value)

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return oauth.RefreshToken{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	rows, err := tx.Query(ctx, `
		DELETE FROM oauth_refresh_tokens
		 WHERE token_hash = $1
		RETURNING client_id, subject, scopes, family_id, issued_at, expires_at`, hash)
	if err != nil {
		return oauth.RefreshToken{}, err
	}
	row, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[tokenRow])
	switch {
	case err == nil:
		if _, err := tx.Exec(ctx, `
			INSERT INTO oauth_refresh_tombstones (token_hash, family_id, client_id, subject, expires_at)
			VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (token_hash) DO UPDATE
			   SET family_id = EXCLUDED.family_id, client_id = EXCLUDED.client_id,
			       subject = EXCLUDED.subject, expires_at = EXCLUDED.expires_at`,
			hash, row.FamilyID, row.ClientID, row.Subject, row.ExpiresAt); err != nil {
			return oauth.RefreshToken{}, fmt.Errorf("postgres: record spent refresh token: %w", err)
		}
		if err := tx.Commit(ctx); err != nil {
			return oauth.RefreshToken{}, err
		}
		return row.refreshToken(), nil
	case !noRows(err):
		return oauth.RefreshToken{}, err
	}

	// The live row is gone. The tombstone rotation left for this hash is the only
	// surviving pointer to the family.
	var familyID string
	err = tx.QueryRow(ctx, `
		SELECT family_id FROM oauth_refresh_tombstones
		 WHERE token_hash = $1 AND expires_at > $2`, hash, s.clock()).Scan(&familyID)
	switch {
	case err == nil:
		return oauth.RefreshToken{}, &oauth.RefreshReuseError{FamilyID: familyID}
	case noRows(err):
		// No tombstone: this value was never issued here, or its spent generation
		// has passed the point where a replay could mint anything.
		return oauth.RefreshToken{}, oauth.ErrTokenNotFound
	default:
		return oauth.RefreshToken{}, fmt.Errorf("postgres: look up spent refresh token: %w", err)
	}
}

// DeleteRefresh implements oauth.Store. The value's tombstone goes with it: an
// explicit revocation of a spent token says the replay signal is no longer wanted
// for that value.
//
// The two deletes share one transaction. Apart, a failure between them left the
// live row removed and the tombstone armed: the value then reads as "already
// spent", and the reuse path revoked the whole family of a token the caller had
// just explicitly revoked (S09-8).
func (s *Tokens) DeleteRefresh(ctx context.Context, value string) error {
	hash := oauth.TokenHash(value)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `DELETE FROM oauth_refresh_tokens WHERE token_hash = $1`, hash); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM oauth_refresh_tombstones WHERE token_hash = $1`, hash); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// RevokeRefreshFamily implements oauth.Store. One transaction removes the whole
// chain: every live refresh generation, every tombstone of the family, and every
// access record minted with it. Sharing a transaction is what makes the report
// honest — a family revocation that applied half of itself and errored is not a
// state a retry can distinguish from success.
//
// An empty familyID revokes nothing: it is the caller's "I have no family" case,
// and matching it would delete every row whose id was left empty by a malformed
// insert.
func (s *Tokens) RevokeRefreshFamily(ctx context.Context, familyID string) (int, error) {
	if familyID == "" {
		return 0, nil
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	total := 0
	for _, q := range []string{
		`DELETE FROM oauth_access_tokens WHERE family_id = $1`,
		`DELETE FROM oauth_refresh_tokens WHERE family_id = $1`,
	} {
		tag, err := tx.Exec(ctx, q, familyID)
		if err != nil {
			return total, err
		}
		total += int(tag.RowsAffected())
	}
	// Tombstones are residue, not token records: cleared, but not counted.
	if _, err := tx.Exec(ctx, `DELETE FROM oauth_refresh_tombstones WHERE family_id = $1`, familyID); err != nil {
		return total, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return total, nil
}

// grantRecordRow is one row of the access/refresh UNION ListBySubject reads.
type grantRecordRow struct {
	ClientID  string    `db:"client_id"`
	Scopes    []string  `db:"scopes"`
	IssuedAt  time.Time `db:"issued_at"`
	ExpiresAt time.Time `db:"expires_at"`
	IsRefresh bool      `db:"is_refresh"`
}

func (r grantRecordRow) record() oauth.GrantRecord {
	rec := oauth.GrantRecord{
		ClientID: r.ClientID, Scopes: scopesFrom(r.Scopes),
		IssuedAt: r.IssuedAt, ExpiresAt: r.ExpiresAt,
		Kind: oauth.TokenKindAccess,
	}
	if r.IsRefresh {
		rec.Kind = oauth.TokenKindRefresh
	}
	return rec
}

// ListBySubject implements oauth.Store.
//
// Expired rows are returned as well: the service owns the clock, and filtering
// here would put "is this still live" in two places, which is how the two
// answers eventually differ.
func (s *Tokens) ListBySubject(ctx context.Context, subject string) ([]oauth.GrantRecord, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT client_id, scopes, issued_at, expires_at, is_refresh FROM (
			SELECT client_id, scopes, issued_at, expires_at, false AS is_refresh
			  FROM oauth_access_tokens WHERE subject = $1
			UNION ALL
			SELECT client_id, scopes, issued_at, expires_at, true AS is_refresh
			  FROM oauth_refresh_tokens WHERE subject = $1
		) AS tokens`, subject)
	if err != nil {
		return nil, err
	}
	scanned, err := pgx.CollectRows(rows, pgx.RowToStructByName[grantRecordRow])
	if err != nil {
		return nil, err
	}

	var out []oauth.GrantRecord
	for _, r := range scanned {
		out = append(out, r.record())
	}
	return out, nil
}

// DeleteBySubjectClient implements oauth.Store.
//
// All three statements run even if an earlier one removes nothing, and none asks
// how many rows went away: revoking is idempotent, so the count is not
// information anyone acts on.
//
// They run in one transaction because "every token this client holds" is the
// claim the endpoint answers for: a half-applied revocation that errored still
// reports a failure the caller may retry, but the retry has no way to know which
// half landed. Unspent authorization codes are deleted with the tokens for the
// reason oauth.Store documents: an unspent code is a redeemable capability, and
// redeeming it after the revocation returns a fresh access *and* refresh token.
func (s *Tokens) DeleteBySubjectClient(ctx context.Context, subject, clientID string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	for _, q := range []string{
		`DELETE FROM oauth_access_tokens WHERE subject = $1 AND client_id = $2`,
		`DELETE FROM oauth_refresh_tokens WHERE subject = $1 AND client_id = $2`,
		// The spent generations' tombstones carry the same owner fields. They are
		// not credentials, but leaving one behind would keep the revoked grant's
		// family reported as replayable — and revocable — after the user was told
		// it was gone.
		`DELETE FROM oauth_refresh_tombstones WHERE subject = $1 AND client_id = $2`,
	} {
		if _, err := tx.Exec(ctx, q, subject, clientID); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM oauth_codes WHERE subject = $1 AND client_id = $2`, subject, clientID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// TokenOwner implements oauth.Store: which client a presented value belongs to,
// for the ownership check RFC 7009 §2.1 requires of revocation. A read, not a
// consume — revocation must be able to ask without spending the token.
func (s *Tokens) TokenOwner(ctx context.Context, value string) (string, error) {
	hash := oauth.TokenHash(value)
	var clientID string
	err := s.pool.QueryRow(ctx,
		`SELECT client_id FROM oauth_access_tokens WHERE token_hash = $1`, hash).Scan(&clientID)
	if err == nil {
		return clientID, nil
	}
	if !noRows(err) {
		return "", err
	}
	err = s.pool.QueryRow(ctx,
		`SELECT client_id FROM oauth_refresh_tokens WHERE token_hash = $1`, hash).Scan(&clientID)
	if noRows(err) {
		return "", oauth.ErrTokenNotFound
	}
	if err != nil {
		return "", err
	}
	return clientID, nil
}

// RevokeTokens implements oauth.TokenAdmin on the hand-rolled engine's tables.
// In durable deployments the OpenID Provider owns the tokens; this covers the
// in-memory engine's Postgres store, which shares the same seam.
//
// Authorization codes are removed with the tokens: a code that was never
// redeemed is a redeemable capability, and leaving it behind after a Kill Switch
// would let it mint fresh tokens.
//
// Spent generations' tombstones are cleared too but are NOT added to the count:
// they are residue no client can use, and inflating a Kill Switch report with
// them would tell an operator it revoked credentials it did not. Leaving them
// would keep each revoked family's replay signal armed after the switch.
//
// All of it runs in one transaction and the count is zero when any step fails,
// matching OIDCStore.RevokeTokens: a bulk revocation that applied half of itself
// and reported a count would be indistinguishable, to the retry, from success.
func (s *Tokens) RevokeTokens(ctx context.Context, f oauth.TokenFilter) (int, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	total, err := revokeMatching(ctx, tx, []string{"oauth_access_tokens", "oauth_refresh_tokens"}, f)
	if err != nil {
		return 0, err
	}
	clause, args := revokePredicate(f)
	for _, table := range []string{"oauth_codes", "oauth_refresh_tombstones"} {
		if _, err := deleteMatchingBatched(ctx, tx, table, clause, args); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return total, nil
}

// PurgeLegacySubject removes a subject's non-token rows from the retired engine's
// tables: its authorization codes and device authorizations.
//
// This exists for deployments that were migrated from the hand-rolled engine,
// where those tables may still hold rows for a live account. The current binary
// never writes them, so for a fresh deployment this deletes nothing — but an
// erasure that skipped them would silently leave a migrated account's data
// behind, which is the failure this whole path exists to prevent.
//
// The legacy token tables (oauth_access_tokens, oauth_refresh_tokens) are NOT
// touched here; they are covered by RevokeTokens, which the same erasure calls.
// The spent generations' tombstones (oauth_refresh_tombstones) go with them
// there, so an erasure cannot leave a subject's family residue behind — the
// integration guard TestAccountDeletionLeavesNoOrphans sees the table through
// information_schema and would fail if that step were dropped.
// The two deletes share one transaction. An erasure that removed the codes but
// not the device authorizations (or the reverse) leaves a redeemable capability
// for an account whose data is supposed to be gone; the count is zero when any
// statement fails, because the rollback leaves nothing removed (S09-8).
func (s *Tokens) PurgeLegacySubject(ctx context.Context, subject string) (int, error) {
	if subject == "" {
		return 0, errors.New("postgres: subject is required")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	total := 0
	for _, q := range []string{
		`DELETE FROM oauth_codes WHERE subject = $1`,
		`DELETE FROM oauth_device_authorizations WHERE subject = $1`,
	} {
		tag, err := tx.Exec(ctx, q, subject)
		if err != nil {
			return 0, err
		}
		total += int(tag.RowsAffected())
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return total, nil
}

// revokeBatchSize bounds one statement of one bulk revocation. It matches the
// session sweep's bound: a single statement can never outlive the pool's
// per-statement statement_timeout, so a large table is worked off in batches
// instead of being cancelled and rolling the whole revocation back (R10-121).
const revokeBatchSize = 1000

// deleteMatchingBatched removes every row matching clause, one bounded statement
// at a time, on the caller's handle.
//
// It carries the same predicate and the same transaction as the unbounded DELETE
// it replaces — only the LIMIT changes what one statement can do — so the summed
// count and the all-or-nothing semantics are unchanged. The ctid subquery is the
// bounded form used by the dated sweep and the session sweep.
func deleteMatchingBatched(ctx context.Context, db querier, table, clause string, args []any) (int, error) {
	stmt := fmt.Sprintf(
		`DELETE FROM %s WHERE ctid IN (SELECT ctid FROM %s%s LIMIT $%d)`,
		table, table, clause, len(args)+1)
	queryArgs := make([]any, 0, len(args)+1)
	queryArgs = append(queryArgs, args...)
	queryArgs = append(queryArgs, revokeBatchSize)
	return execBatched(ctx, db, stmt, queryArgs)
}

// execBatched runs one already-bounded statement repeatedly until a batch removes
// fewer rows than the bound, and returns the total. The statement must carry its
// own LIMIT $n, whose value is the last entry of queryArgs.
func execBatched(ctx context.Context, db querier, stmt string, queryArgs []any) (int, error) {
	total := 0
	for {
		tag, err := db.Exec(ctx, stmt, queryArgs...)
		if err != nil {
			return total, err
		}
		n := int(tag.RowsAffected())
		total += n
		if n < revokeBatchSize {
			return total, nil
		}
	}
}

// revokeMatching deletes rows selected by the filter from two token tables and
// returns the total. Empty filter fields match everything, so the same statement
// serves "all", "this client" and "this subject".
//
// It takes the shared handle rather than the pool so a caller can run it inside
// its own transaction — RevokeTokens does, because a bulk revocation that applied
// half of itself and reported a count is not something a retry can distinguish
// from success.
//
// Each table is deleted in bounded batches (R10-121): the empty-filter case is a
// whole-table DELETE, and one unbounded statement on a grown table would be
// cancelled by the pool's statement_timeout and roll the entire revocation back.
//
// Table names are compile-time constants, never request input, so Sprintf-ing one
// into the statement does not put anything user-controlled into the SQL.
func revokeMatching(ctx context.Context, db querier, tables []string, f oauth.TokenFilter) (int, error) {
	clause, args := revokePredicate(f)
	total := 0
	for _, table := range tables {
		n, err := deleteMatchingBatched(ctx, db, table, clause, args)
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// revokePredicate builds the WHERE clause and arguments for a bulk revocation.
//
// The filter's empty fields drop out, so the statement is exactly as narrow as
// the caller asked. The obvious single-statement form — `WHERE ($1 = ” OR
// client_id = $1) AND ($2 = ” OR subject = $2)` — is never sargable: a planner
// cannot turn an OR on a parameter into an index scan, so even a subject-scoped
// Kill Switch, which has a (subject, client_id) index to use, read every token row
// instead. That path runs during an incident, under the pool's statement timeout,
// where "the cut did not finish" is a real outcome.
//
// Only column names and placeholder positions are built here; the table name is a
// compile-time constant at each call site and no request value reaches the SQL.
func revokePredicate(f oauth.TokenFilter) (clause string, args []any) {
	var where []string
	if f.ClientID != "" {
		args = append(args, f.ClientID)
		where = append(where, fmt.Sprintf("client_id = $%d", len(args)))
	}
	if f.Subject != "" {
		args = append(args, f.Subject)
		where = append(where, fmt.Sprintf("subject = $%d", len(args)))
	}
	if len(where) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(where, " AND "), args
}

// Devices implements oauth.DeviceStore on Postgres. The device code is hashed;
// the user code is stored canonically and looked up case- and
// separator-insensitively through an expression index.
type Devices struct {
	pool *pgxpool.Pool
	// now judges a consume's expiry predicate. It is the store clock, not the
	// database's, for the reason postgres.go's single-clock policy states: a
	// deadline written by this process is judged by the process that wrote it.
	now func() time.Time
}

// clock reads the store clock, tolerating a Devices built without one (the
// zero-value handle) rather than dereferencing a nil function.
func (s *Devices) clock() time.Time {
	if s.now == nil {
		return time.Now()
	}
	return s.now()
}

const deviceCols = `device_code_hash, user_code, client_id, scopes, status, subject, explicit_scopes, expires_at, last_poll`

// deviceRow is one oauth_device_authorizations row, named so scanning matches by
// column rather than by position.
type deviceRow struct {
	DeviceCodeHash string     `db:"device_code_hash"`
	UserCode       string     `db:"user_code"`
	ClientID       string     `db:"client_id"`
	Scopes         []string   `db:"scopes"`
	Status         string     `db:"status"`
	Subject        string     `db:"subject"`
	ExplicitScopes []string   `db:"explicit_scopes"`
	ExpiresAt      time.Time  `db:"expires_at"`
	LastPoll       *time.Time `db:"last_poll"`
}

func (r deviceRow) device() oauth.DeviceAuthorizationRecord {
	d := oauth.DeviceAuthorizationRecord{
		DeviceCodeHash: r.DeviceCodeHash,
		UserCode:       r.UserCode,
		ClientID:       r.ClientID,
		Scopes:         scopesFrom(r.Scopes),
		Status:         oauth.DeviceStatus(r.Status),
		Subject:        r.Subject,
		Explicit:       scopesFrom(r.ExplicitScopes),
		ExpiresAt:      r.ExpiresAt,
	}
	if r.LastPoll != nil {
		d.LastPoll = *r.LastPoll
	}
	return d
}

// SaveDevice implements oauth.DeviceStore.
//
// The canonical unique index 0033 added to oauth_device_authorizations makes this
// write the authoritative uniqueness gate (S04-5): the service's GET-then-INSERT
// probe left a window two concurrent flows could both pass. A user-code collision
// is surfaced as oauth.ErrUserCodeConflict — the one condition the service retries
// on — and anything else keeps its own identity.
func (s *Devices) SaveDevice(ctx context.Context, deviceCode string, d oauth.DeviceAuthorizationRecord) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO oauth_device_authorizations (`+deviceCols+`)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		oauth.TokenHash(deviceCode), d.UserCode, d.ClientID, scopeArray(d.Scopes),
		string(d.Status), d.Subject, scopeArray(d.Explicit), d.ExpiresAt, nullTime(d.LastPoll))
	return deviceSaveError(err)
}

// deviceUserCodeConflict reports the canonical user-code unique violation 0033
// creates. The constraint name is checked when the driver supplies one, so a
// collision on the device-code primary key (cryptographically negligible, but a
// different failure) is not misfiled as "redraw the user code"; a driver that
// omits the name falls back to "any 23505 on this insert is the user-code index",
// which makes the service redraw rather than fail the flow.
func deviceUserCodeConflict(err error) bool {
	if !isUniqueViolation(err) {
		return false
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.ConstraintName != "" {
		return pgErr.ConstraintName == "oauth_device_authorizations_user_code_uniq"
	}
	return true
}

// deviceSaveError maps ONLY the canonical user-code conflict to the typed error
// the oauth layer retries on. Every other failure is returned unchanged, so an
// infrastructure fault is never retried as a collision and never loses its cause
// (S04-5).
func deviceSaveError(err error) error {
	if err == nil {
		return nil
	}
	if deviceUserCodeConflict(err) {
		return fmt.Errorf("postgres: device user code already in use: %w", oauth.ErrUserCodeConflict)
	}
	return err
}

// GetDevice implements oauth.DeviceStore.
func (s *Devices) GetDevice(ctx context.Context, deviceCode string) (oauth.DeviceAuthorizationRecord, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+deviceCols+` FROM oauth_device_authorizations WHERE device_code_hash = $1`,
		oauth.TokenHash(deviceCode))
	if err != nil {
		return oauth.DeviceAuthorizationRecord{}, err
	}
	return scanDevice(rows)
}

// GetDeviceByUserCode implements oauth.DeviceStore.
func (s *Devices) GetDeviceByUserCode(ctx context.Context, userCode string) (oauth.DeviceAuthorizationRecord, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+deviceCols+` FROM oauth_device_authorizations
		  WHERE upper(replace(user_code, '-', '')) = $1`,
		oauth.NormalizeUserCode(userCode))
	if err != nil {
		return oauth.DeviceAuthorizationRecord{}, err
	}
	return scanDevice(rows)
}

// RecordPoll implements oauth.DeviceStore. Only last_poll moves: a poll is not a
// decision, and writing the decision columns here is what let a poll erase one.
func (s *Devices) RecordPoll(ctx context.Context, deviceCodeHash string, at time.Time) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE oauth_device_authorizations
		   SET last_poll = $2
		 WHERE device_code_hash = $1`, deviceCodeHash, at)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return oauth.ErrDeviceNotFound
	}
	return nil
}

// RecordDecision implements oauth.DeviceStore. The `status = 'pending'` predicate
// is the claim: two concurrent decisions cannot both apply, so the first one is
// final and neither can overwrite the other. The refusal is reported as
// applied=false rather than an error — "somebody else already decided" is an
// answer, and the caller turns it into the same invalid_request the sequential
// case gets.
func (s *Devices) RecordDecision(ctx context.Context, deviceCodeHash string, d oauth.DeviceDecision) (bool, error) {
	tag, err := s.pool.Exec(ctx, `
		UPDATE oauth_device_authorizations
		   SET status = $2, subject = $3, scopes = $4, explicit_scopes = $5
		 WHERE device_code_hash = $1 AND status = 'pending'`,
		deviceCodeHash, string(d.Status), d.Subject, scopeArray(d.Scopes), scopeArray(d.Explicit))
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// ConsumeDevice implements oauth.DeviceStore. The DELETE ... RETURNING is the
// claim: `status = 'approved'` and `expires_at > $2` select the one row this
// caller may spend, and removing it makes a second poll lose the race and see
// zero rows — reported as ok=false, not as an error, because "already redeemed"
// is an answer the poll turns into invalid_grant.
func (s *Devices) ConsumeDevice(ctx context.Context, deviceCodeHash string) (oauth.DeviceAuthorizationRecord, bool, error) {
	rows, err := s.pool.Query(ctx, `
		DELETE FROM oauth_device_authorizations
		 WHERE device_code_hash = $1 AND status = 'approved' AND expires_at > $2
		 RETURNING `+deviceCols, deviceCodeHash, s.clock())
	if err != nil {
		return oauth.DeviceAuthorizationRecord{}, false, err
	}
	row, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[deviceRow])
	if noRows(err) {
		return oauth.DeviceAuthorizationRecord{}, false, nil
	}
	if err != nil {
		return oauth.DeviceAuthorizationRecord{}, false, err
	}
	return row.device(), true, nil
}

func scanDevice(rows pgx.Rows) (oauth.DeviceAuthorizationRecord, error) {
	row, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[deviceRow])
	if noRows(err) {
		return oauth.DeviceAuthorizationRecord{}, oauth.ErrDeviceNotFound
	}
	if err != nil {
		return oauth.DeviceAuthorizationRecord{}, err
	}
	return row.device(), nil
}

// Clients implements oauth.ClientRegistry on Postgres. Only the secret digest is
// stored; the plaintext never reaches the database.
type Clients struct{ pool *pgxpool.Pool }

// Create implements oauth.ClientRegistry.
func (s *Clients) Create(ctx context.Context, c oauth.Client) error {
	status := c.Status
	if status == "" {
		status = oauth.ClientActive
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO oauth_clients (id, name, type, status, secret_hash, redirect_uris, allowed_scopes, created_at, allow_missing_pkce)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		c.ID, c.Name, string(c.Type), string(status), nullableBytes(c.SecretHash()),
		c.RedirectURIs, scopeArray(c.AllowedScopes), c.CreatedAt, c.AllowMissingPKCE)
	return err
}

// clientRow is one oauth_clients row, named so scanning matches by column rather
// than by position.
type clientRow struct {
	ID               string    `db:"id"`
	Name             string    `db:"name"`
	Type             string    `db:"type"`
	Status           string    `db:"status"`
	SecretHash       []byte    `db:"secret_hash"`
	RedirectURIs     []string  `db:"redirect_uris"`
	AllowedScopes    []string  `db:"allowed_scopes"`
	CreatedAt        time.Time `db:"created_at"`
	AllowMissingPKCE bool      `db:"allow_missing_pkce"`
}

func (r clientRow) client() (oauth.Client, error) {
	c, err := oauth.RestoreClientWithStatus(r.ID, r.Name, oauth.ClientType(r.Type), oauth.ClientStatus(r.Status),
		r.SecretHash, r.RedirectURIs, scopesFrom(r.AllowedScopes), r.CreatedAt)
	if err != nil {
		return c, err
	}
	return c.WithAllowMissingPKCE(r.AllowMissingPKCE), nil
}

// Get implements oauth.ClientRegistry. A suspended client is reported as not
// found: the protocol plane must treat it as a client id that never existed,
// not as one that is merely forbidden.
func (s *Clients) Get(ctx context.Context, id string) (oauth.Client, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, name, type, status, secret_hash, redirect_uris, allowed_scopes, created_at, allow_missing_pkce
		  FROM oauth_clients WHERE id = $1 AND status <> 'suspended'`, id)
	if err != nil {
		return oauth.Client{}, err
	}
	return scanClient(rows)
}

// ListClients implements oauth.ClientAdmin as a keyset-paged read. The cursor
// predicate is a plain `id > $n`, so the primary key's index serves both the
// filter and the ORDER BY and the page costs a bounded index scan rather than a
// full sort of the table. It asks for one row more than the page so the caller
// can tell "this is the last page" from "there is one more" without a second
// query. Suspended clients are included, because the admin view is exactly the
// place they must remain visible.
//
// The cursor is the previous page's last id and the order is `id`, so the
// comparison is a string comparison in the database's collation. Client ids are
// ASCII (generated as `cli_…`, or seeded names), where every collation orders
// them the same way, and the in-memory registry sorts by the same key.
func (s *Clients) ListClients(ctx context.Context, limit int, cursor string) ([]oauth.Client, string, error) {
	limit, err := oauth.ResolveClientPageLimit(limit)
	if err != nil {
		return nil, "", err
	}
	after, err := oauth.DecodeClientCursor(cursor)
	if err != nil {
		return nil, "", err
	}

	const cols = `id, name, type, status, secret_hash, redirect_uris, allowed_scopes, created_at, allow_missing_pkce`
	query := `SELECT ` + cols + ` FROM oauth_clients`
	args := []any{limit + 1}
	if after != "" {
		query += ` WHERE id > $1 ORDER BY id LIMIT $2`
		args = []any{after, limit + 1}
	} else {
		query += ` ORDER BY id LIMIT $1`
	}
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, "", err
	}
	scanned, err := pgx.CollectRows(rows, pgx.RowToStructByName[clientRow])
	if err != nil {
		return nil, "", err
	}

	hasMore := len(scanned) > limit
	if hasMore {
		scanned = scanned[:limit]
	}
	out := make([]oauth.Client, 0, len(scanned))
	for _, r := range scanned {
		c, err := r.client()
		if err != nil {
			return nil, "", err
		}
		out = append(out, c)
	}
	if hasMore && len(out) > 0 {
		return out, oauth.EncodeClientCursor(out[len(out)-1].ID), nil
	}
	return out, "", nil
}

// ClientNames implements oauth.ClientNameLookup: every name for a grants page in
// one query, instead of one Get per client from inside the page's row loop.
//
// Suspended clients are included, unlike Get. The page this feeds lists tokens
// that were issued to somebody: suspension stops a client acting, it does not
// make the user's grant disappear, and an unnamed row would be the one the user
// most needs to recognise before revoking it.
// clientNameRow is the id/name projection ClientNames reads.
type clientNameRow struct {
	ID   string `db:"id"`
	Name string `db:"name"`
}

func (s *Clients) ClientNames(ctx context.Context, ids []string) (map[string]string, error) {
	out := make(map[string]string, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := s.pool.Query(ctx, `SELECT id, name FROM oauth_clients WHERE id = ANY($1)`, ids)
	if err != nil {
		return nil, fmt.Errorf("postgres: client names: %w", err)
	}
	scanned, err := pgx.CollectRows(rows, pgx.RowToStructByName[clientNameRow])
	if err != nil {
		return nil, err
	}
	for _, r := range scanned {
		out[r.ID] = r.Name
	}
	return out, nil
}

// SetStatus implements oauth.ClientAdmin.
func (s *Clients) SetStatus(ctx context.Context, id string, status oauth.ClientStatus) error {
	if status != oauth.ClientActive && status != oauth.ClientSuspended {
		return fmt.Errorf("postgres: invalid client status %q", status)
	}
	tag, err := s.pool.Exec(ctx, `UPDATE oauth_clients SET status = $2 WHERE id = $1`, id, string(status))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return oauth.ErrClientNotFound
	}
	return nil
}

// Delete implements oauth.ClientAdmin. It removes the registration and, in the
// same transaction, every credential the client holds.
//
// The revocation is part of the delete because a deleted client that keeps a
// live token has not been deleted in any sense the deployment can defend: the
// protocol plane reports the client as unknown, but the token row is still a
// capability until it expires, and an unredeemed code can mint a fresh pair. The
// rows are removed through the same predicates the bulk revocations use
// (revokeMatching / revokePredicate / revokePendingAuthorizations), so this
// method and Tokens.RevokeTokens / OIDCStore.RevokeTokens cannot drift about
// what "this client's credentials" means. Both engines' tables are covered:
// the OP's oidc_* tables, and the retired hand-rolled engine's oauth_* tables a
// migrated deployment may still hold rows in.
//
// One transaction, so a failure leaves the client and its tokens intact rather
// than half-revoked. An absent client is success: the DELETE simply matches no
// row, and the token deletes are idempotent.
func (s *Clients) Delete(ctx context.Context, id string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	f := oauth.TokenFilter{ClientID: id}
	// The OpenID Provider's tables.
	for _, tables := range [][]string{
		{"oidc_access_tokens", "oidc_refresh_tokens", "oidc_refresh_token_tombstones", "oidc_devices"},
		// The retired engine's, for a deployment migrated from it.
		{"oauth_access_tokens", "oauth_refresh_tokens", "oauth_codes", "oauth_refresh_tombstones", "oauth_device_authorizations"},
	} {
		if _, err := revokeMatching(ctx, tx, tables, f); err != nil {
			return err
		}
	}
	// Pending authorization requests and the codes minted from them are
	// capabilities too, and their only link to the client is the request row.
	if _, err := revokePendingAuthorizations(ctx, tx, f); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM oauth_clients WHERE id = $1`, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// RotateSecret implements oauth.ClientAdmin. Only a confidential client has a
// secret to rotate; a public client is refused with ErrNoSecretToRotate rather than
// given a secret it would then fail to restore, because RestoreClient rejects a
// public client that carries a secret hash.
func (s *Clients) RotateSecret(ctx context.Context, id string, secretHash []byte) error {
	if len(secretHash) == 0 {
		return errors.New("postgres: a rotation needs a secret hash")
	}
	// A non-empty but malformed digest must be refused here, not stored: the
	// reader (oauth.RestoreClientWithStatus / Authenticate) admits only the
	// salted encoding NewSecretHash produces, so persisting a legacy bare SHA-256
	// value would silently turn the client into an unknown client at the next
	// restore. oauth.ValidSecretHash is the same shape check the reader uses, so
	// the two cannot drift (S01-10).
	if !oauth.ValidSecretHash(secretHash) {
		return errors.New("postgres: a rotation needs a secret hash this service can verify")
	}
	tag, err := s.pool.Exec(ctx,
		`UPDATE oauth_clients SET secret_hash = $2 WHERE id = $1 AND type = 'confidential'`,
		id, secretHash)
	if err != nil {
		return err
	}
	if tag.RowsAffected() > 0 {
		return nil
	}
	// No confidential row matched: distinguish "unknown" from "public".
	var typ string
	if err := s.pool.QueryRow(ctx, `SELECT type FROM oauth_clients WHERE id = $1`, id).Scan(&typ); err != nil {
		if noRows(err) {
			return oauth.ErrClientNotFound
		}
		return err
	}
	return oauth.ErrNoSecretToRotate
}

// scanClient reads one client row by column name.
func scanClient(rows pgx.Rows) (oauth.Client, error) {
	row, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[clientRow])
	if noRows(err) {
		return oauth.Client{}, oauth.ErrClientNotFound
	}
	if err != nil {
		return oauth.Client{}, err
	}
	return row.client()
}

func scopeArray(scopes []oauth.Scope) []string {
	out := make([]string, len(scopes))
	for i, s := range scopes {
		out[i] = s.String()
	}
	return out
}

func scopesFrom(in []string) []oauth.Scope {
	out := make([]oauth.Scope, len(in))
	for i, s := range in {
		out[i] = oauth.Scope(s)
	}
	return out
}

func nullTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// nullableBytes maps an empty digest to SQL NULL, which is how a public client
// (no secret) is stored.
func nullableBytes(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return b
}
