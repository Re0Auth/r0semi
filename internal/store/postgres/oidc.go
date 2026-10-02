package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/internal/authorization"
	"github.com/Re0Auth/r0semi/internal/oidcstore"
	"github.com/Re0Auth/r0semi/oauth"
)

// OIDCStore is the production op.Storage + op.DeviceAuthorizationStorage for the
// OpenID Provider (ADR-0001). It is the durable half of the engine: the
// in-memory half lives in internal/store/memory, and both share oidcstore for
// the signing key, the client adapter and the consent policy.
//
// It owns the *policy* the OP cannot: which scopes exist (via the oauth.Registry
// in the client adapter), and an audit trail for every token it issues or
// revokes.
type OIDCStore struct {
	pool     *pgxpool.Pool
	clients  oauth.ClientRegistry
	registry *oauth.Registry
	login    func(ctx context.Context, authRequestID string) string
	signer   *oidcstore.Signer
	audit    audit.Logger

	// now is the clock every deadline this store writes is written with — and
	// judged with, in SQL as well as in Go. One clock per value is the point: a
	// deadline written by this process and compared against the database's now()
	// (or another replica's clock) expires at a time nobody chose, and the failure
	// is early eviction — a live session swept, a redeemable code refused. Set by
	// NewOIDCStore and overridden by DB.OIDC with the handle's clock; never nil.
	now func() time.Time

	accessTTL  time.Duration
	refreshTTL time.Duration
	requestTTL time.Duration
}

// OIDCOptions configures an OIDCStore.
type OIDCOptions struct {
	// Registry resolves scopes; it is what makes IsScopeAllowed real.
	Registry *oauth.Registry
	// Login builds the consent URL the authorize endpoint redirects to. It
	// receives the request context, which is how the composition root binds the
	// auth request to the browser session before the consent screen loads it.
	Login func(ctx context.Context, authRequestID string) string
	// Signer signs id_tokens. Required.
	Signer *oidcstore.Signer
	// Audit records token issuance and revocation. Optional.
	Audit audit.Logger
	// RequestTTL is how long a pending consent handle stays valid. It must
	// outlive the federation bind flow, which sends the user to the source and
	// back. Defaults to 30 minutes.
	RequestTTL time.Duration
}

// NewOIDCStore builds the store on an existing pool.
func NewOIDCStore(pool *pgxpool.Pool, clients oauth.ClientRegistry, opts OIDCOptions) (*OIDCStore, error) {
	switch {
	case pool == nil:
		return nil, errors.New("postgres: OIDCStore: pool is required")
	case clients == nil:
		return nil, errors.New("postgres: OIDCStore: client registry is required")
	case opts.Registry == nil:
		return nil, errors.New("postgres: OIDCStore: scope registry is required")
	case opts.Signer == nil:
		return nil, errors.New("postgres: OIDCStore: signer is required")
	}
	return &OIDCStore{
		pool:       pool,
		clients:    clients,
		registry:   opts.Registry,
		login:      opts.Login,
		signer:     opts.Signer,
		audit:      opts.Audit,
		now:        time.Now,
		accessTTL:  time.Hour,
		refreshTTL: 30 * 24 * time.Hour,
		requestTTL: requestTTL(opts.RequestTTL),
	}, nil
}

func requestTTL(configured time.Duration) time.Duration {
	if configured > 0 {
		return configured
	}
	return 30 * time.Minute
}

// OIDC returns the OpenID Provider storage on the migrated database. The store
// inherits the handle's clock, so every deadline it writes is judged by the same
// clock — see OIDCStore.now.
func (db *DB) OIDC(clients oauth.ClientRegistry, opts OIDCOptions) (*OIDCStore, error) {
	s, err := NewOIDCStore(db.pool, clients, opts)
	if err != nil {
		return nil, err
	}
	s.now = db.now
	return s, nil
}

func hashValue(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])
}

func clientIDOf(request op.TokenRequest) string { return oidcstore.ClientIDOf(request) }

// record writes one OP audit event. A failure is logged, not swallowed: the token
// or device decision has already happened, so refusing now would not undo it, but
// an audit record that vanishes without a trace is the one outcome this project
// does not accept. Same direction as the memory store and the operator plane (log
// and proceed); the subject is not logged, only the pseudonymised event carries it.
func (s *OIDCStore) record(ctx context.Context, action, subject, clientID, outcome string) {
	if s.audit == nil {
		return
	}
	if err := s.audit.Record(ctx, audit.Event{
		Action: action, Subject: subject, Provider: "oidc", Outcome: outcome,
		Detail: map[string]string{"client_id": clientID},
	}); err != nil {
		slog.Error("oidc audit record failed",
			"action", action, "client_id", clientID, "outcome", outcome, "err", err)
	}
}

// recordConsent writes the audit event for a consent decision. It is separate
// from record() because the interesting detail here is which scopes were
// granted, not only which client was involved — that is the half the operator
// log was missing, and it is the question "what did this account authorize".
//
// scopes are space-joined: the audit detail is a flat string map, and the
// approved scope set is small and already a list on the wire.
func (s *OIDCStore) recordConsent(ctx context.Context, action, subject, clientID string, scopes []string, outcome string) {
	if s.audit == nil {
		return
	}
	detail := map[string]string{"client_id": clientID}
	if len(scopes) > 0 {
		detail["scopes"] = strings.Join(scopes, " ")
	}
	if err := s.audit.Record(ctx, audit.Event{
		Action: action, Subject: subject, Provider: "oidc", Outcome: outcome,
		Detail: detail,
	}); err != nil {
		slog.Error("oidc audit record failed",
			"action", action, "client_id", clientID, "outcome", outcome, "err", err)
	}
}

// --- op.AuthStorage ---

// CreateAuthRequest implements op.Storage.
func (s *OIDCStore) CreateAuthRequest(ctx context.Context, req *oidc.AuthRequest, userID string) (op.AuthRequest, error) {
	id, err := oidcstore.RandomValue()
	if err != nil {
		return nil, err
	}
	challenge := ""
	method := ""
	if req.CodeChallenge != "" {
		challenge = req.CodeChallenge
		method = string(req.CodeChallengeMethod)
	}
	now := s.now().UTC()
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO oidc_auth_requests
			(id, client_id, redirect_uri, response_type, response_mode, scopes, state, nonce,
			 code_challenge, code_challenge_method, subject, done, created_at, expires_at,
			 prompt, max_age_seconds)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,false,$12,$13,$14,$15)`,
		id, req.ClientID, req.RedirectURI, string(req.ResponseType), string(req.ResponseMode),
		oidcstore.NonNil([]string(req.Scopes)), req.State, req.Nonce, challenge, method, userID, now, now.Add(s.requestTTL),
		// The library normalizes the freshness requirement before this call
		// (pkg/op/ValidateAuthReqPrompt: prompt=login ⇒ MaxAge=0), so the
		// normalized pair is stored verbatim rather than re-derived here.
		oidcstore.NonNil([]string(req.Prompt)), maxAgeSeconds(req.MaxAge),
	); err != nil {
		return nil, fmt.Errorf("postgres: create auth request: %w", err)
	}
	return &oidcstore.AuthRequest{
		ID: id, ClientID: req.ClientID, RedirectURI: req.RedirectURI,
		ResponseType: req.ResponseType, ResponseMode: req.ResponseMode,
		Scopes: append([]string(nil), req.Scopes...), State: req.State, Nonce: req.Nonce,
		CodeChallenge: codeChallenge(req.CodeChallenge, method),
		Subject:       userID,
		Prompt:        append([]string(nil), req.Prompt...),
		MaxAge:        cloneMaxAge(req.MaxAge),
	}, nil
}

// maxAgeSeconds renders the library's *uint max_age as the nullable integer the
// column stores: nil stays NULL ("no freshness bound was requested").
func maxAgeSeconds(in *uint) *int {
	if in == nil {
		return nil
	}
	v := int(*in)
	return &v
}

// maxAgeFromSeconds converts the stored nullable integer back to the *uint the
// library speaks. A negative value cannot be produced by this package; it is
// treated as absent rather than trusted.
func maxAgeFromSeconds(in *int) *uint {
	if in == nil || *in < 0 {
		return nil
	}
	v := uint(*in)
	return &v
}

// cloneMaxAge copies the pointed-to value so a caller's write through one
// request cannot reach the stored record or a returned copy of it.
func cloneMaxAge(in *uint) *uint {
	if in == nil {
		return nil
	}
	v := *in
	return &v
}

func codeChallenge(challenge, method string) *oidc.CodeChallenge {
	if challenge == "" {
		return nil
	}
	return &oidc.CodeChallenge{Challenge: challenge, Method: oidc.CodeChallengeMethod(method)}
}

// authRequestRow is one oidc_auth_requests row in the shape both the read and the
// consume paths select it. The db tags name the columns, so a projection change is
// a mapping error rather than a silently shifted field.
type authRequestRow struct {
	ID                  string     `db:"id"`
	ClientID            string     `db:"client_id"`
	RedirectURI         string     `db:"redirect_uri"`
	ResponseType        string     `db:"response_type"`
	ResponseMode        string     `db:"response_mode"`
	Scopes              []string   `db:"scopes"`
	State               string     `db:"state"`
	Nonce               string     `db:"nonce"`
	CodeChallenge       string     `db:"code_challenge"`
	CodeChallengeMethod string     `db:"code_challenge_method"`
	Subject             string     `db:"subject"`
	Done                bool       `db:"done"`
	AuthTime            *time.Time `db:"auth_time"`
	Prompt              []string   `db:"prompt"`
	MaxAgeSeconds       *int       `db:"max_age_seconds"`
}

// authRequestOwnerRow is the subject/client/done projection used when a refused
// request is audited: `done` tells a real pending refusal from the library's
// post-mint cleanup.
type authRequestOwnerRow struct {
	Subject  string `db:"subject"`
	ClientID string `db:"client_id"`
	Done     bool   `db:"done"`
}

// authRequestFreshnessRow is the locked projection CompleteLogin reads to decide
// whether the interactive decision must re-authenticate.
type authRequestFreshnessRow struct {
	Prompt        []string   `db:"prompt"`
	MaxAgeSeconds *int       `db:"max_age_seconds"`
	AuthTime      *time.Time `db:"auth_time"`
}

func (r authRequestRow) request() oidcstore.AuthRequest {
	return oidcstore.AuthRequest{
		ID:            r.ID,
		ClientID:      r.ClientID,
		RedirectURI:   r.RedirectURI,
		ResponseType:  oidc.ResponseType(r.ResponseType),
		ResponseMode:  oidc.ResponseMode(r.ResponseMode),
		Scopes:        r.Scopes,
		State:         r.State,
		Nonce:         r.Nonce,
		CodeChallenge: codeChallenge(r.CodeChallenge, r.CodeChallengeMethod),
		Subject:       r.Subject,
		IsDone:        r.Done,
		AuthTime:      r.AuthTime,
		Prompt:        r.Prompt,
		MaxAge:        maxAgeFromSeconds(r.MaxAgeSeconds),
	}
}

// AuthRequestByID implements op.Storage. The deadline is adjudicated here, in the
// read the consent screen performs, not only by the sweep: a pending handle is a
// capability with an expiry, and before this predicate an expired one stayed
// describable and approvable until the next tick (Z07-1, docs/issues/P2-medium.md).
func (s *OIDCStore) AuthRequestByID(ctx context.Context, id string) (op.AuthRequest, error) {
	return s.scanAuthRequest(ctx, `
		SELECT id, client_id, redirect_uri, response_type, response_mode, scopes, state, nonce,
		       code_challenge, code_challenge_method, subject, done, auth_time,
		       prompt, max_age_seconds
		  FROM oidc_auth_requests WHERE id = $1 AND expires_at > $2`, id, s.now())
}

// AuthRequestByCode implements op.Storage. It consumes the code in one
// transaction: the DELETE is the claim, so two concurrent exchanges cannot both
// find the code. It also checks expires_at here — the previous query ignored it,
// so an expired code stayed redeemable until the periodic sweep ran. The library
// deletes the request again after minting, which is a harmless no-op.
func (s *OIDCStore) AuthRequestByCode(ctx context.Context, code string) (op.AuthRequest, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var requestID string
	if err := tx.QueryRow(ctx,
		`DELETE FROM oidc_codes WHERE code_hash = $1 AND expires_at > $2 RETURNING request_id`,
		hashValue(code), s.now()).Scan(&requestID); err != nil {
		// Only "no row" is the protocol answer. A database that did not answer
		// made no statement about this code, and collapsing the two turned an
		// outage into invalid_grant — a refusal the client acts on instead of a
		// failure the operator can see (S09-7).
		if noRows(err) {
			return nil, errors.New("postgres: authorization code is unknown or expired")
		}
		return nil, fmt.Errorf("postgres: claim authorization code: %w", err)
	}

	rows, err := tx.Query(ctx, `
		DELETE FROM oidc_auth_requests
		 WHERE id = $1
		RETURNING id, client_id, redirect_uri, response_type, response_mode, scopes, state, nonce,
		          code_challenge, code_challenge_method, subject, done, auth_time,
		          prompt, max_age_seconds`, requestID)
	if err != nil {
		return nil, fmt.Errorf("postgres: delete auth request: %w", err)
	}
	row, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[authRequestRow])
	if err != nil {
		if noRows(err) {
			return nil, errors.New("postgres: auth request not found")
		}
		return nil, fmt.Errorf("postgres: auth request: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	a := row.request()
	return &a, nil
}

// scanAuthRequest runs the by-ID read AuthRequestByID issues and classifies its
// failure. The query carries the deadline predicate, so "no row" means exactly one
// thing: this store does not hold a pending request under this id — never issued,
// already decided, or expired. That is the consent screen's caller-situation, so it
// carries authorization.ErrRequestExpired and the HTTP layer answers 4xx (S04-7).
// Every other error — a pool that could not answer, a row that failed to decode —
// keeps its cause and stays a 5xx with an audit row, because reporting an outage as
// an expired link is a refusal the operator never sees.
func (s *OIDCStore) scanAuthRequest(ctx context.Context, query string, args ...any) (op.AuthRequest, error) {
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("postgres: auth request: %w", err)
	}
	row, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[authRequestRow])
	if err != nil {
		if noRows(err) {
			return nil, fmt.Errorf("postgres: auth request is unknown or expired: %w", authorization.ErrRequestExpired)
		}
		return nil, fmt.Errorf("postgres: auth request: %w", err)
	}
	a := row.request()
	return &a, nil
}

// SaveAuthCode implements op.Storage.
func (s *OIDCStore) SaveAuthCode(ctx context.Context, id, code string) error {
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO oidc_codes (code_hash, request_id, expires_at) VALUES ($1,$2,$3)
		ON CONFLICT (code_hash) DO UPDATE SET request_id = EXCLUDED.request_id`,
		hashValue(code), id, s.now().UTC().Add(s.requestTTL)); err != nil {
		return fmt.Errorf("postgres: save auth code: %w", err)
	}
	return nil
}

// DeleteAuthRequest implements op.Storage. It records a refusal only for a
// request still awaiting a decision. The library calls this after minting too
// (pkg/op/token.go CreateTokenResponse), and by then AuthRequestByCode has
// already deleted the row, so the previous unconditional record wrote a
// field-empty `oidc.consent.deny` on every successful exchange (Z20-1,
// docs/issues/P2-medium.md). A missing row records nothing.
func (s *OIDCStore) DeleteAuthRequest(ctx context.Context, id string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// Read the owner before deleting, under FOR UPDATE so a concurrent
	// CompleteLogin cannot flip done between this read and the delete. The
	// projection is the only place the two ids live; the subject is empty for a
	// request nobody signed in for, which is itself the honest record. A lookup
	// failure (including a row the code exchange already consumed) leaves denied
	// false, so nothing is recorded.
	var (
		owner  authRequestOwnerRow
		denied bool
	)
	if rows, err := tx.Query(ctx,
		`SELECT subject, client_id, done FROM oidc_auth_requests WHERE id = $1 FOR UPDATE`,
		id); err == nil {
		if o, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[authRequestOwnerRow]); err == nil {
			owner, denied = o, !o.Done
		}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM oidc_codes WHERE request_id = $1`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM oidc_auth_requests WHERE id = $1`, id); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	if denied {
		s.recordConsent(ctx, "oidc.consent.deny", owner.Subject, owner.ClientID, nil, audit.OutcomeDenied)
	}
	return nil
}

// CreateAccessToken implements op.Storage. The token ID is ours; only its hash
// is persisted, and the library encrypts the ID into the bearer token.
func (s *OIDCStore) CreateAccessToken(ctx context.Context, request op.TokenRequest) (string, time.Time, error) {
	id, err := oidcstore.RandomValue()
	if err != nil {
		return "", time.Time{}, err
	}
	issued := s.now().UTC()
	expires := issued.Add(s.accessTTL)
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO oidc_access_tokens (id_hash, client_id, subject, scopes, issued_at, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6)`,
		hashValue(id), clientIDOf(request), request.GetSubject(),
		oidcstore.NonNil(oidcstore.WithoutOfflineAccess(request.GetScopes())), issued, expires); err != nil {
		return "", time.Time{}, fmt.Errorf("postgres: create access token: %w", err)
	}
	s.record(ctx, "oidc.token", request.GetSubject(), clientIDOf(request), audit.OutcomeOK)
	return id, expires, nil
}

// ErrRefreshTokenSpent reports a refresh token presented after it had already
// been rotated. It is a refusal, not a lookup miss: the caller asked to spend a
// token this store has already consumed, which is what a replayed (or stolen)
// refresh token looks like. Returning an error rather than minting a second
// generation is the only thing that makes reuse visible.
//
// It is an *oidc.Error carrying invalid_grant: the token endpoint maps a typed
// protocol error to 400 invalid_grant, while a bare error becomes 500
// server_error — which would tell the client to retry rather than refresh.
var ErrRefreshTokenSpent = oidc.ErrInvalidGrant().WithDescription("refresh token was already rotated")

// CreateAccessAndRefreshTokens implements op.Storage. Refresh tokens rotate:
// presenting one consumes it and issues a new one.
//
// Rotation is one transaction, and the presented token is claimed by a DELETE
// whose row count is checked. Rotating as "read it now, delete it later" leaves a
// window in which two requests holding the same refresh token are both honoured —
// and the window is invisible to the race detector, because the two statements
// never contend on a lock. The consequence is worse than one extra token:
// rotation never notices the reuse, so a stolen refresh token can be replayed
// indefinitely alongside the victim's own client, and nothing signals that it
// happened.
func (s *OIDCStore) CreateAccessAndRefreshTokens(ctx context.Context, request op.TokenRequest, currentRefreshToken string) (string, string, time.Time, error) {
	accessID, err := oidcstore.RandomValue()
	if err != nil {
		return "", "", time.Time{}, err
	}
	value, err := oidcstore.RandomValue()
	if err != nil {
		return "", "", time.Time{}, err
	}

	var authTime *time.Time
	if r, ok := request.(interface{ GetAuthTime() time.Time }); ok {
		if t := r.GetAuthTime(); !t.IsZero() {
			authTime = &t
		}
	}
	var amr, audience []string
	if r, ok := request.(interface{ GetAMR() []string }); ok {
		amr = r.GetAMR()
	}
	if r, ok := request.(interface{ GetAudience() []string }); ok {
		audience = r.GetAudience()
	}
	scopes := oidcstore.NonNil(oidcstore.WithoutOfflineAccess(request.GetScopes()))
	amr = oidcstore.NonNil(amr)
	audience = oidcstore.NonNil(audience)

	now := s.now().UTC()
	expires := now.Add(s.accessTTL)

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", "", time.Time{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// familyID names the chain the new refresh token belongs to. A first issuance
	// mints one; a rotation inherits the spent row's, which is what makes the set
	// of generations descended from one authorization revocable together.
	familyID := ""
	if currentRefreshToken != "" {
		// Claim the presented token first. Under READ COMMITTED a concurrent DELETE
		// of the same row blocks, then finds nothing once the winner commits — so
		// exactly one of two racing requests sees a row to consume. The `expires_at`
		// predicate is the second half: an expired token is not "spent and
		// re-minted", and it is refused here even if a caller reached rotation
		// without the read path.
		//
		// RETURNING carries the spent row's family, its paired access-token hash and
		// its owner out of the DELETE: the row is gone after this statement, so this
		// is the last moment they are reachable, and they are exactly what the
		// tombstone and the replacement need.
		var spent refreshTokenSpentRow
		err := tx.QueryRow(ctx, `
			DELETE FROM oidc_refresh_tokens
			 WHERE token_hash = $1 AND expires_at > $2
			RETURNING family_id, id_hash, client_id, subject, expires_at`,
			hashValue(currentRefreshToken), now).
			Scan(&spent.FamilyID, &spent.IDHash, &spent.ClientID, &spent.Subject, &spent.ExpiresAt)
		switch {
		case err == nil:
			familyID = spent.FamilyID
			if familyID == "" {
				// Migration 0024 backfills, so this is unreachable on a migrated
				// database; it keeps a malformed row from turning the family
				// revocation into a no-op.
				familyID = hashValue(currentRefreshToken)
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO oidc_refresh_token_tombstones
					(token_hash, family_id, id_hash, client_id, subject, expires_at)
				VALUES ($1,$2,$3,$4,$5,$6)`,
				hashValue(currentRefreshToken), familyID, spent.IDHash,
				spent.ClientID, spent.Subject, spent.ExpiresAt); err != nil {
				return "", "", time.Time{}, fmt.Errorf("postgres: record spent refresh token: %w", err)
			}
		case noRows(err):
			// The live row is already gone, so the read path that normally turns a
			// replay into a family revocation was bypassed. If a tombstone still
			// names the family, revoke it here too rather than answering with a bare
			// refusal while the thief's generation stays live. The revocation is
			// committed before the refusal, because the deferred Rollback would
			// otherwise undo it.
			var family string
			tombErr := tx.QueryRow(ctx, `
				SELECT family_id FROM oidc_refresh_token_tombstones
				 WHERE token_hash = $1 AND expires_at > $2`,
				hashValue(currentRefreshToken), now).Scan(&family)
			switch {
			case tombErr == nil:
				if err := revokeFamilyTx(ctx, tx, family); err != nil {
					return "", "", time.Time{}, fmt.Errorf("postgres: revoke refresh token family: %w", err)
				}
				if err := tx.Commit(ctx); err != nil {
					return "", "", time.Time{}, err
				}
			case !noRows(tombErr):
				// A database that could not answer did not answer "unknown"; fail
				// closed and let the transaction roll back.
				return "", "", time.Time{}, fmt.Errorf("postgres: look up spent refresh token: %w", tombErr)
			}
			return "", "", time.Time{}, ErrRefreshTokenSpent
		default:
			return "", "", time.Time{}, fmt.Errorf("postgres: rotate refresh token: %w", err)
		}
	} else {
		id, err := oidcstore.RandomValue()
		if err != nil {
			return "", "", time.Time{}, err
		}
		familyID = id
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO oidc_access_tokens (id_hash, client_id, subject, scopes, issued_at, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6)`,
		hashValue(accessID), clientIDOf(request), request.GetSubject(), scopes, now, expires); err != nil {
		return "", "", time.Time{}, fmt.Errorf("postgres: create access token: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO oidc_refresh_tokens
			(token_hash, id_hash, client_id, subject, scopes, amr, audience, auth_time, nonce, family_id, issued_at, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		hashValue(value), hashValue(accessID), clientIDOf(request), request.GetSubject(),
		scopes, amr, audience, authTime, oidcstore.NonceOf(request), familyID, now, now.Add(s.refreshTTL),
	); err != nil {
		return "", "", time.Time{}, fmt.Errorf("postgres: create refresh token: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return "", "", time.Time{}, err
	}
	s.record(ctx, "oidc.token", request.GetSubject(), clientIDOf(request), audit.OutcomeOK)
	return accessID, value, expires, nil
}

// refreshTokenSpentRow is the projection the rotation claim's RETURNING clause
// hands back: everything the tombstone and the replacement need to inherit from
// the row the DELETE just removed.
type refreshTokenSpentRow struct {
	FamilyID  string    `db:"family_id"`
	IDHash    string    `db:"id_hash"`
	ClientID  string    `db:"client_id"`
	Subject   string    `db:"subject"`
	ExpiresAt time.Time `db:"expires_at"`
}

// revokeFamilyTx deletes a whole refresh-token family and the access tokens each
// generation was paired with. The order matters: the access delete joins through
// both the live rows and the tombstones, so it must run before either of those
// tables loses the rows that name the access hashes.
//
// The caller supplies the transaction because a family revocation is never the
// whole of what a caller is doing: the rotation path commits a tombstone with it,
// and the read path commits the revocation before it returns the refusal.
func revokeFamilyTx(ctx context.Context, tx pgx.Tx, familyID string) error {
	for _, q := range []string{`
		DELETE FROM oidc_access_tokens
		 WHERE id_hash IN (
		       SELECT id_hash FROM oidc_refresh_tokens WHERE family_id = $1
		       UNION
		       SELECT id_hash FROM oidc_refresh_token_tombstones WHERE family_id = $1)`,
		`DELETE FROM oidc_refresh_tokens WHERE family_id = $1`,
		`DELETE FROM oidc_refresh_token_tombstones WHERE family_id = $1`,
	} {
		if _, err := tx.Exec(ctx, q, familyID); err != nil {
			return err
		}
	}
	return nil
}

// refreshRequestRow is one oidc_refresh_tokens row as TokenRequestByRefreshToken
// reads it.
type refreshRequestRow struct {
	IDHash   string     `db:"id_hash"`
	ClientID string     `db:"client_id"`
	Subject  string     `db:"subject"`
	Scopes   []string   `db:"scopes"`
	AMR      []string   `db:"amr"`
	Audience []string   `db:"audience"`
	AuthTime *time.Time `db:"auth_time"`
	Nonce    string     `db:"nonce"`
}

// TokenRequestByRefreshToken implements op.Storage.
//
// The live-row SELECT is the ordinary path. When it finds nothing, the token may
// still be one this store already rotated: rotation leaves a tombstone keyed by
// the spent hash, and a replay of that hash against the tombstone is the theft
// signal RFC 9700 §4.14.2 keys on. In that case the whole family is revoked, in
// one transaction, and the caller is refused with ErrRefreshTokenSpent — which
// the library maps to invalid_grant, so the client still sees a 400 and never a
// 500.
//
// The library calls this method FIRST on a refresh grant, before it can reach
// CreateAccessAndRefreshTokens, so this is the only place the replay is visible.
func (s *OIDCStore) TokenRequestByRefreshToken(ctx context.Context, value string) (op.RefreshTokenRequest, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id_hash, client_id, subject, scopes, amr, audience, auth_time, nonce
		  FROM oidc_refresh_tokens WHERE token_hash = $1 AND expires_at > $2`, hashValue(value), s.now())
	if err != nil {
		// The database did not answer, so this is not "unknown token". The library
		// hardcodes invalid_grant on this path (pkg/op/token_refresh.go), so the
		// wire answer cannot change here — but preserving the cause is what lets
		// the composition root count and alert on a store outage (N-02).
		return nil, fmt.Errorf("postgres: load refresh token: %w", err)
	}
	row, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[refreshRequestRow])
	if err != nil {
		if !noRows(err) {
			return nil, fmt.Errorf("postgres: load refresh token: %w", err)
		}
		// The live row is gone. The tombstone rotation left for the spent hash is
		// the only surviving pointer to the family, and finding one is the theft
		// signal: revoke the whole chain. Lookup and revocation share one
		// transaction, and it is committed before the refusal is returned — the
		// deferred rollback would otherwise undo the only lasting effect.
		tx, txErr := s.pool.Begin(ctx)
		if txErr != nil {
			return nil, fmt.Errorf("postgres: revoke replayed refresh token family: %w", txErr)
		}
		defer func() { _ = tx.Rollback(ctx) }()

		var familyID string
		lookupErr := tx.QueryRow(ctx, `
			SELECT family_id FROM oidc_refresh_token_tombstones
			 WHERE token_hash = $1 AND expires_at > $2`, hashValue(value), s.now()).Scan(&familyID)
		switch {
		case lookupErr == nil:
			if err := revokeFamilyTx(ctx, tx, familyID); err != nil {
				return nil, fmt.Errorf("postgres: revoke replayed refresh token family: %w", err)
			}
			if err := tx.Commit(ctx); err != nil {
				return nil, fmt.Errorf("postgres: revoke replayed refresh token family: %w", err)
			}
			return nil, ErrRefreshTokenSpent
		case !noRows(lookupErr):
			// A database that could not answer did not answer "no family"; fail
			// closed and let the transaction roll back rather than pass the replay
			// as an ordinary unknown token.
			return nil, fmt.Errorf("postgres: revoke replayed refresh token family: %w", lookupErr)
		}
		return nil, oauth.ErrTokenNotFound
	}
	r := oidcstore.RefreshRequest{
		IDHash:   row.IDHash,
		ClientID: row.ClientID,
		Subject:  row.Subject,
		Scopes:   row.Scopes,
		AMR:      row.AMR,
		Audience: row.Audience,
		AuthTime: row.AuthTime,
		Nonce:    row.Nonce,
	}
	return &r, nil
}

// TerminateSession implements op.Storage.
//
// One transaction for both tables: the caller is told the session is over, and a
// partial delete that errored would leave the refresh half alive — which for the
// caller is not a failure it can see, because a refresh token only shows itself
// later.
func (s *OIDCStore) TerminateSession(ctx context.Context, userID, clientID string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	for _, q := range []string{
		`DELETE FROM oidc_access_tokens WHERE subject = $1 AND client_id = $2`,
		`DELETE FROM oidc_refresh_tokens WHERE subject = $1 AND client_id = $2`,
		// The spent generations of those refresh tokens go too: a tombstone is not
		// a credential, but it still names a paired access row, and the replay path
		// is what would otherwise clear it.
		`DELETE FROM oidc_refresh_token_tombstones WHERE subject = $1 AND client_id = $2`,
	} {
		if _, err := tx.Exec(ctx, q, userID, clientID); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// RevokeToken implements op.Storage. Access tokens arrive as the plaintext ID,
// refresh tokens as the plaintext value; both are hashed before lookup.
//
// Each branch deletes a pair in one transaction. Two separate statements were the
// problem: if the second failed, the caller got an error, and the retry could not
// repair it — the presented value's row was already gone, so the lookup fell
// through to RFC 7009's "unknown token is success" and answered 200 while the
// other half was still live. A refresh token in that state mints replacements
// indefinitely, and the revocation that "succeeded" is how it survives.
func (s *OIDCStore) RevokeToken(ctx context.Context, tokenOrTokenID, userID, clientID string) *oidc.Error {
	h := hashValue(tokenOrTokenID)

	// Each lookup below classifies its error. Only pgx.ErrNoRows may fall through
	// to the next shape, because that is the one answer that says the row is
	// absent. A connection error, a failover, a statement timeout or a cancelled
	// context must surface as server_error: RFC 7009's "unknown token is success"
	// is a statement about the database's answer, and a database that did not
	// answer made none. Collapsing the two turned an outage into a revocation
	// that answered 200, revoked nothing and audited nothing.
	var owner string
	err := s.pool.QueryRow(ctx, `SELECT client_id FROM oidc_access_tokens WHERE id_hash = $1`, h).Scan(&owner)
	switch {
	case err == nil:
		if owner != clientID {
			// RFC 7009 §2.1 / G-8: verify ownership, do not advertise it. A
			// foreign live token answers exactly like an unknown one — the
			// uniform RFC 7009 success — and deletes nothing
			// (docs/audit-7/findings/Z20-VERIFIED.md). The old invalid_client
			// refusal made this endpoint a liveness oracle.
			return nil
		}
		// RFC 7009 §2.1: revoke the whole grant, not just the presented token. The
		// refresh token minted with this access token carries the same id_hash.
		if err := s.revokeInOneTx(ctx, []string{
			`DELETE FROM oidc_access_tokens WHERE id_hash = $1`,
			`DELETE FROM oidc_refresh_tokens WHERE id_hash = $1`,
			`DELETE FROM oidc_refresh_token_tombstones WHERE id_hash = $1`,
		}, h); err != nil {
			return oidc.ErrServerError().WithParent(err)
		}
		s.record(ctx, "oidc.revoke", userID, clientID, audit.OutcomeOK)
		return nil
	case !noRows(err):
		return oidc.ErrServerError().WithParent(err)
	}

	// The access row is gone but its refresh half may not be: exactly the residue
	// a partial failure used to leave when the pair was deleted in two statements.
	// Without this the retry finds nothing, answers RFC 7009's "unknown token is
	// success", and the refresh token keeps minting — which is how a revocation
	// that errored once became a revocation that never happened.
	err = s.pool.QueryRow(ctx,
		`SELECT client_id FROM oidc_refresh_tokens WHERE id_hash = $1`, h).Scan(&owner)
	switch {
	case err == nil:
		if owner != clientID {
			// RFC 7009 §2.1 / G-8: the uniform success, deleting nothing.
			return nil
		}
		if err := s.revokeInOneTx(ctx, []string{
			`DELETE FROM oidc_refresh_tokens WHERE id_hash = $1`,
			`DELETE FROM oidc_access_tokens WHERE id_hash = $1`,
			`DELETE FROM oidc_refresh_token_tombstones WHERE id_hash = $1`,
		}, h); err != nil {
			return oidc.ErrServerError().WithParent(err)
		}
		s.record(ctx, "oidc.revoke", userID, clientID, audit.OutcomeOK)
		return nil
	case !noRows(err):
		return oidc.ErrServerError().WithParent(err)
	}

	err = s.pool.QueryRow(ctx, `SELECT client_id FROM oidc_refresh_tokens WHERE token_hash = $1`, h).Scan(&owner)
	switch {
	case err == nil:
		if owner != clientID {
			// RFC 7009 §2.1 / G-8: the uniform success, deleting nothing.
			return nil
		}
		// The access token goes first; the refresh row is the only place that names it.
		if err := s.revokeInOneTx(ctx, []string{`
			DELETE FROM oidc_access_tokens
			 WHERE id_hash IN (SELECT id_hash FROM oidc_refresh_tokens WHERE token_hash = $1)`,
			`DELETE FROM oidc_refresh_tokens WHERE token_hash = $1`,
			`DELETE FROM oidc_refresh_token_tombstones WHERE token_hash = $1`,
		}, h); err != nil {
			return oidc.ErrServerError().WithParent(err)
		}
		s.record(ctx, "oidc.revoke", userID, clientID, audit.OutcomeOK)
		return nil
	case !noRows(err):
		return oidc.ErrServerError().WithParent(err)
	}
	// RFC 7009: revoking an unknown token is success.
	return nil
}

// revokeInOneTx runs each statement with the same argument inside one
// transaction, in the order given. The revocation branches need exactly that
// shape: one value, two deletes that must land together.
func (s *OIDCStore) revokeInOneTx(ctx context.Context, statements []string, arg string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	for _, q := range statements {
		if _, err := tx.Exec(ctx, q, arg); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// GetRefreshTokenInfo implements op.Storage.
//
// The second return value is the identifier the library hands straight back to
// RevokeToken, which HASHES whatever it is given before looking it up (that is
// how a raw token from the wire is normally resolved). So the identifier has to
// be the raw refresh token value, not the row's id_hash — returning a hash made
// RevokeToken hash a hash, match neither column, and fall through to the RFC 7009
// "already invalid" branch, so a refresh token could not be revoked at all.
//
// It is not a disclosure: this method is given the raw token as its argument.
func (s *OIDCStore) GetRefreshTokenInfo(ctx context.Context, clientID, token string) (string, string, error) {
	var subject string
	err := s.pool.QueryRow(ctx, `
		SELECT subject FROM oidc_refresh_tokens WHERE token_hash = $1 AND client_id = $2`,
		hashValue(token), clientID).Scan(&subject)
	if err != nil {
		if noRows(err) {
			return "", "", op.ErrInvalidRefreshToken
		}
		// Not "unknown": the database could not answer. The library's revocation
		// handler treats op.ErrInvalidRefreshToken as "try the other token shapes"
		// and reserves every other error for a 500 server_error, so collapsing an
		// outage into the sentinel walks the request into a revocation that
		// answers success.
		return "", "", oidc.ErrServerError().WithParent(err)
	}
	return subject, token, nil
}

// SigningKey implements op.Storage.
func (s *OIDCStore) SigningKey(context.Context) (op.SigningKey, error) { return s.signer, nil }

// SignatureAlgorithms implements op.Storage.
func (s *OIDCStore) SignatureAlgorithms(context.Context) ([]jose.SignatureAlgorithm, error) {
	return []jose.SignatureAlgorithm{jose.RS256}, nil
}

// KeySet implements op.Storage.
func (s *OIDCStore) KeySet(context.Context) ([]op.Key, error) {
	return s.signer.KeySet(), nil
}

// --- op.OPStorage ---

// GetClientByClientID implements op.Storage. The login hook is bound to this
// request's context so it can touch the browser session while building the
// consent URL.
func (s *OIDCStore) GetClientByClientID(ctx context.Context, clientID string) (op.Client, error) {
	c, err := s.clients.Get(ctx, clientID)
	if err != nil {
		if errors.Is(err, oauth.ErrClientNotFound) {
			return nil, oidc.ErrInvalidClient()
		}
		return nil, err
	}
	return oidcstore.ProviderClient{Client: c, Registry: s.registry, Login: func(id string) string {
		if s.login == nil {
			return "/login?authRequestID=" + id
		}
		return s.login(ctx, id)
	}}, nil
}

// AuthorizeClientIDSecret implements op.Storage.
func (s *OIDCStore) AuthorizeClientIDSecret(ctx context.Context, clientID, clientSecret string) error {
	c, err := s.clients.Get(ctx, clientID)
	if err != nil {
		if errors.Is(err, oauth.ErrClientNotFound) {
			return oidc.ErrInvalidClient()
		}
		return err
	}
	if c.Type == oauth.ClientConfidential && !c.Authenticate(clientSecret) {
		return oidc.ErrInvalidClient().WithDescription("invalid client secret")
	}
	return nil
}

// SetUserinfoFromScopes implements op.Storage. Only `sub` is ever exposed
// (ADR-0001 O-3), and the subject is the whole of what it sets.
//
// It is NOT deprecated on this code path, whatever the upstream interface comment
// says. `op.CreateIDToken` fills a fresh `oidc.UserInfo` through this callback and
// then calls `claims.SetUserInfo`, which ASSIGNS `sub` from `UserInfo.Subject`
// rather than merging it (pkg/oidc/token.go). A no-op stub therefore did not mean
// "no extra claims": it meant `sub: ""` on every id_token minted by the
// authorization-code, refresh and device grants — the one claim OIDC Core §2 makes
// REQUIRED, and the identity an RP keys its session on. Both stores have to set it.
func (s *OIDCStore) SetUserinfoFromScopes(_ context.Context, userinfo *oidc.UserInfo, userID, _ string, _ []string) error {
	userinfo.Subject = userID
	return nil
}

// SetUserinfoFromRequest implements op.CanSetUserinfoFromRequest. It is the seam
// the library offers for claims that depend on the request rather than the scopes
// (op.CreateIDToken calls it right after SetUserinfoFromScopes and merges the
// claims into the id_token), and the nonce is exactly such a claim.
//
// OIDC Core §12.2: the id_token returned by a refresh MUST NOT carry a nonce
// unless it is the same nonce as in the original authorization request. The
// library reads the nonce only from an op.AuthRequest, and RefreshRequest must
// not be made to satisfy op.AuthRequest — `needsRefreshToken` switches on
// `case AuthRequest` before `case RefreshTokenRequest`, so that would break
// rotation and make CreateTokenResponse delete the auth request and emit a bogus
// consent denial. Setting the claim here is the sanctioned alternative. An empty
// nonce is left out: the claim has `omitempty`, and §12.2 forbids inventing one.
func (s *OIDCStore) SetUserinfoFromRequest(_ context.Context, userinfo *oidc.UserInfo, request op.IDTokenRequest, _ []string) error {
	nonce := oidcstore.NonceOf(request)
	if nonce == "" {
		return nil
	}
	if userinfo.Claims == nil {
		userinfo.Claims = make(map[string]any, 1)
	}
	userinfo.Claims["nonce"] = nonce
	return nil
}

// SetUserinfoFromToken implements op.Storage. The OP only ever exposes `sub`
// (ADR-0001 O-3); richer claims are a later, separate decision.
//
// The token is looked up rather than trusted. userinfo is a protected resource:
// the library reaches this method either by decrypting an opaque token into its
// ID, or — when decryption fails — by falling back to verifying the bearer as a
// signed JWT. Only the first shape can name an access token this store issued, so
// requiring `tokenID` to hit a LIVE row decides liveness (expiry, revocation and
// erasure all delete the row) and, in the same lookup, removes the fallback: a
// bearer that decrypts to nothing carries no ID that this store has ever seen.
//
// One query, and the row's own subject is what is published. The expiry is judged
// in Go from the stored value, exactly as SetIntrospectionFromToken does, so the
// two readers of one token row cannot disagree about a clock comparison.
// accessTokenReadRow is the subject/expiry projection the userinfo path reads.
type accessTokenReadRow struct {
	Subject   string    `db:"subject"`
	ExpiresAt time.Time `db:"expires_at"`
}

func (s *OIDCStore) SetUserinfoFromToken(ctx context.Context, userinfo *oidc.UserInfo, tokenID, subject, _ string) error {
	if tokenID == "" {
		return errNotAnAccessToken
	}
	rows, err := s.pool.Query(ctx, `
		SELECT subject, expires_at FROM oidc_access_tokens WHERE id_hash = $1`,
		hashValue(tokenID))
	if err != nil {
		return errNotAnAccessToken
	}
	row, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[accessTokenReadRow])
	if err != nil {
		return errNotAnAccessToken
	}
	if row.Subject != subject || !row.ExpiresAt.After(s.now()) {
		return errNotAnAccessToken
	}
	userinfo.Subject = row.Subject
	return nil
}

// errNotAnAccessToken is the userinfo refusal. It says nothing about WHICH check
// failed — an unparseable bearer, a revoked one, an expired one and an id_token
// all read the same — because the endpoint is reachable by anyone holding a
// string, and distinguishing the cases would turn it into an oracle.
var errNotAnAccessToken = errors.New("not a live access token")

// introspectionRow is the client/scope/expiry projection the introspection path
// reads.
type introspectionRow struct {
	ClientID  string    `db:"client_id"`
	Scopes    []string  `db:"scopes"`
	ExpiresAt time.Time `db:"expires_at"`
}

// SetIntrospectionFromToken implements op.Storage.
//
// The failure classes are deliberately distinct (S02-8): an unknown token and an
// expired one both answer oauth.ErrTokenNotFound, which the introspection handler
// turns into Active:false, while a query or scan failure keeps its cause and is
// answered as a 500. The earlier shape collapsed the connection/pool failure into
// the not-found class, so a broken store reported a live token as inactive.
func (s *OIDCStore) SetIntrospectionFromToken(ctx context.Context, introspection *oidc.IntrospectionResponse, tokenID, subject, _ string) error {
	rows, err := s.pool.Query(ctx, `
		SELECT client_id, scopes, expires_at FROM oidc_access_tokens WHERE id_hash = $1`,
		hashValue(tokenID))
	if err != nil {
		return fmt.Errorf("postgres: introspect token: %w", err)
	}
	row, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[introspectionRow])
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return oauth.ErrTokenNotFound
		}
		// A scan or collect failure is not "not found": it is a store fault and
		// must stay one (S02-8).
		return fmt.Errorf("postgres: introspect token: %w", err)
	}
	if !row.ExpiresAt.After(s.now()) {
		return oauth.ErrTokenNotFound
	}
	introspection.Active = true
	introspection.Subject = subject
	introspection.ClientID = row.ClientID
	introspection.Scope = row.Scopes
	introspection.Expiration = oidc.FromTime(row.ExpiresAt)
	return nil
}

// GetPrivateClaimsFromScopes implements op.Storage.
func (s *OIDCStore) GetPrivateClaimsFromScopes(context.Context, string, string, []string) (map[string]any, error) {
	return nil, nil
}

// GetKeyByIDAndClientID implements op.Storage. JWT profile grant is not supported.
func (s *OIDCStore) GetKeyByIDAndClientID(context.Context, string, string) (*jose.JSONWebKey, error) {
	return nil, errors.New("postgres: JWT profile grant is not supported")
}

// ValidateJWTProfileScopes implements op.Storage.
func (s *OIDCStore) ValidateJWTProfileScopes(_ context.Context, _ string, scopes []string) ([]string, error) {
	return scopes, nil
}

// Health implements op.Storage.
func (s *OIDCStore) Health(ctx context.Context) error { return s.pool.Ping(ctx) }

// --- op.DeviceAuthorizationStorage ---

// StoreDeviceAuthorization implements op.Storage.
func (s *OIDCStore) StoreDeviceAuthorization(ctx context.Context, clientID, deviceCode, userCode string, expires time.Time, scopes []string) error {
	if scopes == nil {
		scopes = []string{}
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO oidc_devices (device_code_hash, user_code, client_id, scopes, expires_at)
		VALUES ($1,$2,$3,$4,$5)`,
		hashValue(deviceCode), userCode, clientID, scopes, expires)
	if isUniqueViolation(err) {
		return op.ErrDuplicateUserCode
	}
	if err != nil {
		return fmt.Errorf("postgres: store device authorization: %w", err)
	}
	return nil
}

// deviceStateRow is one oidc_devices row in the shape both device-state readers
// select it.
type deviceStateRow struct {
	ClientID  string     `db:"client_id"`
	Scopes    []string   `db:"scopes"`
	ExpiresAt time.Time  `db:"expires_at"`
	Done      bool       `db:"done"`
	Denied    bool       `db:"denied"`
	Subject   string     `db:"subject"`
	AuthTime  *time.Time `db:"auth_time"`
}

func (r deviceStateRow) state() *op.DeviceAuthorizationState {
	st := op.DeviceAuthorizationState{
		ClientID: r.ClientID,
		Scopes:   r.Scopes,
		Expires:  r.ExpiresAt,
		Done:     r.Done,
		Denied:   r.Denied,
		Subject:  r.Subject,
	}
	if r.AuthTime != nil {
		st.AuthTime = *r.AuthTime
	}
	return &st
}

// GetDeviceAuthorizatonState implements op.Storage.
//
// It consumes an approved authorization on the first read: the library reads the
// state once, immediately before minting the tokens, and never marks the record
// spent. Deleting it here (rather than only reading) makes the device_code single
// use — a second exchange finds nothing — and means a revocation that fired
// between two polls cannot be replayed away. A pending or denied record is not
// touched and falls through to a plain read for the library to answer.
func (s *OIDCStore) GetDeviceAuthorizatonState(ctx context.Context, clientID, deviceCode string) (*op.DeviceAuthorizationState, error) {
	// One store-clock reading judges both the consume claim and the fall-through
	// below: the single-clock policy the poll UPDATE already follows.
	now := s.now()
	// RFC 8628 §3.5: expires_in bounds the device_code as well as the user_code,
	// so the approved-consume claim carries the same expires_at predicate
	// AuthRequestByCode's claim does (G-7, docs/issues/P2-medium.md). Without it
	// the DELETE matched an expired row and handed the library a Done state,
	// which the library consumes BEFORE it checks Expires
	// (zitadel/oidc pkg/op/device.go CheckDeviceAuthorizationState).
	rows, err := s.pool.Query(ctx, `
		DELETE FROM oidc_devices
		 WHERE device_code_hash = $1 AND client_id = $2 AND done = true AND denied = false
		   AND expires_at > $3
		RETURNING client_id, scopes, expires_at, done, denied, subject, auth_time`,
		hashValue(deviceCode), clientID, now)
	if err != nil {
		return nil, fmt.Errorf("postgres: consume device authorization: %w", err)
	}
	row, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[deviceStateRow])
	if err == nil {
		return row.state(), nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("postgres: consume device authorization: %w", err)
	}

	// RFC 8628 §3.5: a client polling faster than the advertised interval is told
	// to slow down. The library maps context.DeadlineExceeded to that error. The
	// UPDATE is the claim on this poll: a concurrent second poll blocks, then sees
	// the new last_poll and updates nothing. One store-clock value both writes
	// the deadline and judges it — the single-clock policy; the database's now()
	// would make the interval a race between two clocks.
	//
	// The interval is subtracted in Go, and the resulting instant is bound as a
	// plain timestamptz: SQL interval arithmetic here (`$4 - make_interval(secs
	// => $3)`) left the parameter untyped enough that PostgreSQL resolved the
	// subtraction as `interval - interval` and then refused the comparison
	// ("operator does not exist: timestamp with time zone <= interval"), which
	// CI's TestDevicePollingIsThrottled caught. staleBefore is the last instant a
	// previous poll may carry for this one to be admitted; `last_poll IS NULL`
	// admits the first.
	staleBefore := now.Add(-oidcstore.DefaultDevicePollInterval)
	tag, err := s.pool.Exec(ctx, `
		UPDATE oidc_devices
		   SET last_poll = $3
		 WHERE device_code_hash = $1 AND client_id = $2 AND done = false AND denied = false
		   AND (last_poll IS NULL OR last_poll <= $4)`,
		hashValue(deviceCode), clientID, now, staleBefore)
	if err != nil {
		return nil, fmt.Errorf("postgres: record device poll: %w", err)
	}
	if tag.RowsAffected() == 0 {
		st, err := s.deviceState(ctx, `device_code_hash = $1 AND client_id = $2`, hashValue(deviceCode), clientID)
		if err != nil {
			return nil, err
		}
		// The expiry predicate above is why this row reached the fall-through:
		// it is approved but past its deadline, so it missed the DELETE and the
		// throttle UPDATE. Consume it here too, and clear Done so the library's
		// Done-before-Expires order answers expired_token rather than minting
		// (G-7). deviceState itself stays unfiltered: it is shared with
		// DeviceByUserCode, where a missing row would surface as access_denied.
		if st.Done && !st.Denied && !now.Before(st.Expires) {
			if _, err := s.pool.Exec(ctx,
				`DELETE FROM oidc_devices WHERE device_code_hash = $1 AND client_id = $2`,
				hashValue(deviceCode), clientID); err != nil {
				return nil, fmt.Errorf("postgres: expire device authorization: %w", err)
			}
			st.Done = false
			return st, nil
		}
		if !st.Done && !st.Denied {
			return nil, context.DeadlineExceeded
		}
		return st, nil
	}
	return s.deviceState(ctx, `device_code_hash = $1 AND client_id = $2`, hashValue(deviceCode), clientID)
}

// deviceState reads one oidc_devices row. A missing row is oauth.ErrDeviceNotFound
// (the protocol answer); any other error is a store failure and is returned with
// its cause, never folded into "not found" — a device poll answered access_denied
// during an outage tells the client to give up on a code that is still live
// (S09-7).
func (s *OIDCStore) deviceState(ctx context.Context, where string, args ...any) (*op.DeviceAuthorizationState, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT client_id, scopes, expires_at, done, denied, subject, auth_time
		  FROM oidc_devices WHERE `+where, args...)
	if err != nil {
		return nil, fmt.Errorf("postgres: device authorization: %w", err)
	}
	row, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[deviceStateRow])
	if err != nil {
		if noRows(err) {
			return nil, oauth.ErrDeviceNotFound
		}
		return nil, fmt.Errorf("postgres: device authorization: %w", err)
	}
	return row.state(), nil
}

// --- consent / device UI helpers (app-owned, not part of op.Storage) ---

// SetAuthTime records when the human authenticated, so CompleteLogin does not
// overwrite it with the consent-decision time.
func (s *OIDCStore) SetAuthTime(ctx context.Context, id string, at time.Time) error {
	tag, err := s.pool.Exec(ctx, `UPDATE oidc_auth_requests SET auth_time = $2 WHERE id = $1`, id, at)
	if err != nil {
		return fmt.Errorf("postgres: set auth time: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return errors.New("postgres: auth request not found")
	}
	return nil
}

// CompleteLogin attaches the subject and the approved (possibly narrowed)
// scopes to a pending authorization request. It is what the consent screen
// calls before the callback.
//
// A request that asked for a fresh authentication (`prompt=login` or an
// elapsed `max_age`) must not carry the session's old auth_time into the
// id_token — and the interactive decision is not an authentication, so its clock
// must not be substituted for one either (S02-1). A real re-authentication stamps
// a satisfying auth_time first (the login hook, or the consent boundary after the
// browser returns); with none recorded the request is refused rather than answered
// with a fabricated time. The judgement runs on the store clock, not the
// database's now().
func (s *OIDCStore) CompleteLogin(ctx context.Context, id, subject string, scopes []string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: complete login: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	rows, err := tx.Query(ctx, `
		SELECT prompt, max_age_seconds, auth_time
		  FROM oidc_auth_requests
		 WHERE id = $1
		 FOR UPDATE`, id)
	if err != nil {
		return errors.New("postgres: auth request not found")
	}
	locked, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[authRequestFreshnessRow])
	if err != nil {
		return errors.New("postgres: auth request not found")
	}
	now := s.now()
	authTime := locked.AuthTime
	req := oidcstore.AuthRequest{Prompt: locked.Prompt, MaxAge: maxAgeFromSeconds(locked.MaxAgeSeconds), AuthTime: authTime}
	if req.RequiresReauthentication(now) {
		// The request asked for a fresh authentication and the recorded time does
		// not satisfy it: refuse rather than publish a decision clock as auth_time.
		return oidcstore.ErrReauthenticationRequired
	}
	if authTime == nil {
		authTime = &now
	}
	if _, err := tx.Exec(ctx, `
		UPDATE oidc_auth_requests
		   SET subject = $2, scopes = $3, done = true, auth_time = $4
		 WHERE id = $1`, id, subject, oidcstore.NonNil(scopes), authTime); err != nil {
		return fmt.Errorf("postgres: complete login: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: complete login: %w", err)
	}
	// The consent decision itself is an authorization event: who granted which
	// client which scopes, and when. The scopes recorded are the granted set,
	// which is what the caller passed — the update above already narrowed them.
	s.recordConsent(ctx, "oidc.consent.approve", subject, s.clientIDOfRequest(ctx, id), scopes, audit.OutcomeOK)
	return nil
}

// clientIDOfRequest reads the client a pending authorization request belongs
// to, for the audit record a consent decision writes. Empty when the request is
// unknown, which is the honest value for an event about nothing.
func (s *OIDCStore) clientIDOfRequest(ctx context.Context, id string) string {
	var clientID string
	_ = s.pool.QueryRow(ctx, `SELECT client_id FROM oidc_auth_requests WHERE id = $1`, id).Scan(&clientID)
	return clientID
}

// DeviceByUserCode returns the pending device authorization for a user code.
func (s *OIDCStore) DeviceByUserCode(ctx context.Context, userCode string) (*op.DeviceAuthorizationState, error) {
	return s.deviceState(ctx, `upper(replace(user_code, '-', '')) = upper(replace($1, '-', ''))`, userCode)
}

// approveDevice marks a device authorization approved. A nil scopes slice keeps
// the requested scopes; an explicit slice narrows them.
//
// It is deliberately unexported (Z20V-2): it does NOT run the ExplicitConsent
// gate, which lives in DecideDeviceAuthorization. Exporting a rewrite that skipped
// that gate left a direct caller able to approve a critical scope with no
// individual tick, so approval has exactly one exported entrance.
//
// The write carries the conditions the read does — still pending, still
// unexpired, not denied — so approving is a state transition rather than an
// assignment. Callers read the state first and refuse a spent code, but that read
// and this write are two statements: round 3 (C3-3) recorded that the write was
// unconditional, with two racing deciders both succeeding. The race was shown to
// have no payoff, and it is closed here anyway, because a decision that lands on
// a code somebody else already decided should be refused where it lands.
func (s *OIDCStore) approveDevice(ctx context.Context, userCode, subject string, scopes []string) error {
	// The store clock decides the deadline and stamps the auth time: both are
	// process-side facts this store wrote (the deadline by the caller of
	// StoreDeviceAuthorization, the auth time here), and judging either with the
	// database's now() is the two-clock mix the single-clock policy exists to
	// remove. The memory backend already uses its store clock on the same two.
	now := s.now()
	const pending = `done = false AND denied = false AND expires_at > $3`
	// RETURNING carries the client the code was issued to out of the write, so the
	// audit record can name it. The memory backend has always recorded it; the
	// Postgres event left it empty, so the production chain could not answer
	// "which client was approved into this device grant" (G-17).
	q := `UPDATE oidc_devices SET done = true, subject = $2, auth_time = $3
	       WHERE upper(replace(user_code, '-', '')) = upper(replace($1, '-', '')) AND ` + pending +
		` RETURNING client_id`
	args := []any{userCode, subject, now}
	if scopes != nil {
		q = `UPDATE oidc_devices SET done = true, subject = $2, auth_time = $3, scopes = $4
		      WHERE upper(replace(user_code, '-', '')) = upper(replace($1, '-', '')) AND ` + pending +
			` RETURNING client_id`
		args = append(args, scopes)
	}
	var clientID string
	err := s.pool.QueryRow(ctx, q, args...).Scan(&clientID)
	switch {
	case noRows(err):
		// An unknown code and one that is no longer pending are the same answer:
		// this is not a code the caller may decide.
		return fmt.Errorf("postgres: device authorization is not pending: %w", oauth.ErrDeviceNotFound)
	case err != nil:
		return fmt.Errorf("postgres: approve device: %w", err)
	}
	s.record(ctx, "oidc.device.approve", subject, clientID, audit.OutcomeOK)
	return nil
}

// DenyDevice marks a device authorization denied. subject is the account that
// refused: the interactive route already holds it, so recording it is what makes
// `oidc.device.deny` able to answer who refused, not just which client was
// involved (Z20V-1).
//
// Its condition is deliberately not the same as approveDevice's: `done = false` is
// absent, so a denial still outranks an approval whichever write lands second.
// That invariant is round 3's C3-3 conclusion and the tests pin it; what this
// adds is that a second denial is refused rather than recorded twice.
func (s *OIDCStore) DenyDevice(ctx context.Context, userCode, subject string) error {
	var clientID string
	err := s.pool.QueryRow(ctx, `
		UPDATE oidc_devices SET denied = true
		 WHERE upper(replace(user_code, '-', '')) = upper(replace($1, '-', ''))
		   AND denied = false
		RETURNING client_id`, userCode).Scan(&clientID)
	switch {
	case noRows(err):
		return fmt.Errorf("postgres: device authorization is not pending: %w", oauth.ErrDeviceNotFound)
	case err != nil:
		return fmt.Errorf("postgres: deny device: %w", err)
	}
	// client_id rides out of the write (G-17); the subject comes from the caller
	// that authenticated the denying account (Z20V-1).
	s.record(ctx, "oidc.device.deny", subject, clientID, audit.OutcomeDenied)
	return nil
}

// --- engine-neutral business-plane surface (same shapes as oauth.Service) ---

// grantTokenRow is one row of the access/refresh UNION Grants reads. The fifth
// column is a bare true/false literal, so Postgres names it "?column?" — the db
// tag says so explicitly rather than relying on position.
type grantTokenRow struct {
	ClientID  string    `db:"client_id"`
	Scopes    []string  `db:"scopes"`
	IssuedAt  time.Time `db:"issued_at"`
	ExpiresAt time.Time `db:"expires_at"`
	HasRT     bool      `db:"?column?"`
}

// Grants lists what each client can still do as this subject, derived from the
// OP token tables. It is the OP-backed counterpart of oauth.Service.Grants.
func (s *OIDCStore) Grants(ctx context.Context, subject string) ([]oauth.Grant, error) {
	if subject == "" {
		return nil, errors.New("postgres: subject is required")
	}
	rows, err := s.pool.Query(ctx, `
		SELECT client_id, scopes, issued_at, expires_at, false
		  FROM oidc_access_tokens WHERE subject = $1 AND expires_at > $2
		UNION ALL
		SELECT client_id, scopes, issued_at, expires_at, true
		  FROM oidc_refresh_tokens WHERE subject = $1 AND expires_at > $2`, subject, s.now())
	if err != nil {
		return nil, fmt.Errorf("postgres: list grants: %w", err)
	}
	scanned, err := pgx.CollectRows(rows, pgx.RowToStructByName[grantTokenRow])
	if err != nil {
		return nil, err
	}

	byClient := make(map[string]*oauth.Grant)
	for _, r := range scanned {
		g, ok := byClient[r.ClientID]
		if !ok {
			g = &oauth.Grant{ClientID: r.ClientID, IssuedAt: r.IssuedAt, ExpiresAt: r.ExpiresAt}
			byClient[r.ClientID] = g
		}
		for _, sc := range r.Scopes {
			if sc == oidc.ScopeOfflineAccess {
				continue
			}
			g.Scopes = appendScopeUnique(g.Scopes, oauth.Scope(sc))
		}
		if r.IssuedAt.Before(g.IssuedAt) {
			g.IssuedAt = r.IssuedAt
		}
		if r.ExpiresAt.After(g.ExpiresAt) {
			g.ExpiresAt = r.ExpiresAt
		}
		if r.HasRT {
			g.HasRefresh = true
		}
	}
	// Names come from one lookup for the page. They used to come from a Get
	// inside the loop above — one extra round trip per distinct client, on a query
	// that is already two unions.
	ids := make([]string, 0, len(byClient))
	for id := range byClient {
		ids = append(ids, id)
	}
	names := oauth.LookupClientNames(ctx, s.clients, ids)
	out := make([]oauth.Grant, 0, len(byClient))
	for _, g := range byClient {
		g.ClientName = names[g.ClientID]
		sort.Slice(g.Scopes, func(i, j int) bool { return g.Scopes[i] < g.Scopes[j] })
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ClientID < out[j].ClientID })
	return out, nil
}

// RevokeGrant removes every OP token a client holds for a subject. It is the
// local revocation and is idempotent.
func (s *OIDCStore) RevokeGrant(ctx context.Context, subject, clientID string) error {
	if subject == "" || clientID == "" {
		return errors.New("postgres: subject and client id are required")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `DELETE FROM oidc_access_tokens WHERE subject = $1 AND client_id = $2`, subject, clientID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM oidc_refresh_tokens WHERE subject = $1 AND client_id = $2`, subject, clientID); err != nil {
		return err
	}
	// The spent generations of those refresh tokens are part of the same grant:
	// removing them keeps the paired access rows from being reachable by the
	// replay path after the grant was revoked.
	if _, err := tx.Exec(ctx, `DELETE FROM oidc_refresh_token_tombstones WHERE subject = $1 AND client_id = $2`, subject, clientID); err != nil {
		return err
	}
	// A device authorization for this client and subject outlives its tokens:
	// leaving it would let the holder of the device_code mint a fresh pair after
	// the user revoked the grant.
	if _, err := tx.Exec(ctx, `DELETE FROM oidc_devices WHERE subject = $1 AND client_id = $2`, subject, clientID); err != nil {
		return err
	}
	// So does an authorization code minted but not yet exchanged. Codes are
	// deleted through their request because request_id is their only link to the
	// subject; the same shape as revokePendingAuthorizations below, which the
	// Kill Switch uses. Leaving them behind let a client that withheld its code
	// redeem it after the user revoked the grant — and the exchange returns a
	// refresh token, so the access did not merely survive a moment, it became
	// indefinite.
	if _, err := tx.Exec(ctx, `
		DELETE FROM oidc_codes
		 WHERE request_id IN (
		       SELECT id FROM oidc_auth_requests
		        WHERE client_id = $1 AND subject = $2)`, clientID, subject); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM oidc_auth_requests WHERE client_id = $1 AND subject = $2`, clientID, subject); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	s.record(ctx, "oidc.grant.revoke", subject, clientID, audit.OutcomeOK)
	return nil
}

// RevokeTokens implements oauth.TokenAdmin for the OP-managed token tables. It
// is what a suspended client, a compromised subject, or the Kill Switch call.
//
// Device authorizations are revoked alongside the tokens, on the same
// client/subject predicate (the table carries both columns). They are not counted
// in the result — that number is tokens — but they must go: a held device_code
// would otherwise re-mint what was just revoked, defeating the Kill Switch for
// the life of the code.
//
// All of it happens in one transaction, and the returned count is zero when it
// fails. The number is an operator's evidence that the account is contained; a
// partial application that reported "some" would be worse than none, because the
// retry is what makes it complete and a count in between is indistinguishable
// from success.
func (s *OIDCStore) RevokeTokens(ctx context.Context, f oauth.TokenFilter) (int, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	total, err := revokeMatching(ctx, tx, []string{"oidc_access_tokens", "oidc_refresh_tokens"}, f)
	if err != nil {
		return 0, err
	}
	// The tombstones of the revoked families go with them, on the same
	// client/subject filter they carry. Their count is discarded: the number this
	// method returns is tokens, and a Kill Switch report that counted residue
	// would overstate what was cut.
	if _, err := revokeMatching(ctx, tx, []string{"oidc_refresh_token_tombstones"}, f); err != nil {
		return 0, err
	}
	// A pending authorization request whose code has not been redeemed is a
	// redeemable capability, not a token. Leaving it alive let a code issued
	// before the Kill Switch mint a fresh access/refresh pair after the switch
	// reported success.
	if _, err := revokePendingAuthorizations(ctx, tx, f); err != nil {
		return 0, err
	}
	if _, err := revokeMatching(ctx, tx, []string{"oidc_devices"}, f); err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return total, nil
}

// revokePendingAuthorizations deletes auth requests selected by the filter and
// the codes minted from them. Codes are deleted first because their only link to
// the subject is request_id.
//
// It runs on the caller's handle rather than opening its own transaction: the
// caller is the one that can say what "revoked" means, and it has to be able to
// commit that answer together with the token deletes.
func revokePendingAuthorizations(ctx context.Context, db querier, f oauth.TokenFilter) (int, error) {
	removed := 0
	clause, args := revokePredicate(f)
	tag, err := db.Exec(ctx, `
		DELETE FROM oidc_codes
		 WHERE request_id IN (
		       SELECT id FROM oidc_auth_requests`+clause+`)`, args...)
	if err != nil {
		return removed, err
	}
	removed += int(tag.RowsAffected())

	tag, err = db.Exec(ctx, `DELETE FROM oidc_auth_requests`+clause, args...)
	if err != nil {
		return removed, err
	}
	removed += int(tag.RowsAffected())
	return removed, nil
}

// PurgeSubject removes a subject's non-token OP state: the pending consent
// requests, any authorization codes minted from them, and the device
// authorizations it approved or started.
//
// It is the token-free half of account erasure. Issued tokens are rows in the
// token tables and are removed by RevokeTokens, not here — so a caller doing a
// full erasure calls both. Splitting them keeps each statement's intent legible:
// this one deletes work in flight, that one deletes access already granted.
//
// One transaction, because the codes are deleted by joining through the requests
// that are about to disappear.
func (s *OIDCStore) PurgeSubject(ctx context.Context, subject string) (int, error) {
	if subject == "" {
		return 0, errors.New("postgres: subject is required")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	total := 0
	// Codes first: their only link to the subject is request_id.
	tag, err := tx.Exec(ctx, `
		DELETE FROM oidc_codes
		 WHERE request_id IN (SELECT id FROM oidc_auth_requests WHERE subject = $1)`, subject)
	if err != nil {
		return total, err
	}
	total += int(tag.RowsAffected())

	for _, q := range []string{
		`DELETE FROM oidc_auth_requests WHERE subject = $1`,
		`DELETE FROM oidc_devices WHERE subject = $1`,
	} {
		tag, err := tx.Exec(ctx, q, subject)
		if err != nil {
			return total, err
		}
		total += int(tag.RowsAffected())
	}
	if err := tx.Commit(ctx); err != nil {
		return total, err
	}
	return total, nil
}

// DescribeDeviceAuthorization is the device verification page's view of a
// pending device grant (OP-backed counterpart of the same oauth.Service method).
func (s *OIDCStore) DescribeDeviceAuthorization(ctx context.Context, userCode string) (oauth.DeviceAuthorization, error) {
	st, err := s.DeviceByUserCode(ctx, userCode)
	if err != nil {
		// An unknown code and a store outage are not the same answer: the first is
		// ErrDeviceNotFound (404), the second must stay a failure (S09-7).
		return oauth.DeviceAuthorization{}, err
	}
	if st.Done || st.Denied || s.now().After(st.Expires) {
		return oauth.DeviceAuthorization{}, oauth.ErrDeviceNotFound
	}
	client, err := s.clients.Get(ctx, st.ClientID)
	if err != nil {
		return oauth.DeviceAuthorization{}, oauth.ErrDeviceNotFound
	}
	// The page displays every scope an approval can grant, not only the catalogue
	// ones: `openid`/`profile`/... are protocol flags the catalogue deliberately
	// does not describe, and DecideDeviceAuthorization re-attaches them to the
	// grant. Dropping them here made the screen show less than the token carried
	// (A-FE-3 / A-FE-V1); they render as an explicit system-required placeholder.
	descriptors, err := deviceDisplayDescriptors(s.registry, st.Scopes, st.ClientID)
	if err != nil {
		return oauth.DeviceAuthorization{}, err
	}
	// Return the normalised spelling, never the caller's bytes: the page binds
	// and echoes this value, and op.DeviceAuthorizationState carries no user code
	// of its own. Normalising here makes the handle identical for every accepted
	// spelling of one code, so its length is bounded by the code rather than by
	// the request line (Z07-3).
	return oauth.DeviceAuthorization{
		UserCode:  oauth.NormalizeUserCode(userCode),
		Client:    client,
		Scopes:    descriptors,
		ExpiresAt: st.Expires,
	}, nil
}

// deviceDisplayDescriptors returns one descriptor per requested scope, in request
// order, so the verification page's displayed set covers everything an approval
// can grant (A-FE-3 / A-FE-V1).
//
// Catalogue scopes resolve through the registry, which still rejects an unknown
// or client-restricted data scope. A scope the catalogue does not describe — the
// standard OIDC claim scopes, which DecideDeviceAuthorization re-attaches to the
// grant — is rendered as an explicit system-required placeholder instead of being
// silently dropped. The placeholder text matches the httpapi consent view's, so
// the two screens describe one scope the same way.
func deviceDisplayDescriptors(registry *oauth.Registry, scopes []string, clientID string) ([]oauth.Descriptor, error) {
	described, _ := oidcstore.SplitProtocolScopes(scopes)
	resolved, err := registry.Resolve(oidcstore.Scopes(described), clientID)
	if err != nil {
		return nil, err
	}
	byScope := make(map[oauth.Scope]oauth.Descriptor, len(resolved))
	for _, d := range resolved {
		byScope[d.Scope] = d
	}
	out := make([]oauth.Descriptor, 0, len(scopes))
	seen := make(map[oauth.Scope]struct{}, len(scopes))
	for _, sc := range scopes {
		s := oauth.Scope(sc)
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		if d, ok := byScope[s]; ok {
			out = append(out, d)
			continue
		}
		out = append(out, oauth.Descriptor{
			Scope:       s,
			Title:       "系统必需",
			Description: "此项由授权服务器要求，权限目录中未单独描述。",
			Risk:        oauth.RiskLow,
		})
	}
	return out, nil
}

// DecideDeviceAuthorization records the user's approval or denial, narrowing
// scopes and enforcing explicit consent exactly like the interactive flow.
func (s *OIDCStore) DecideDeviceAuthorization(ctx context.Context, userCode, subject string, approve bool, scopes, explicit []oauth.Scope) error {
	if subject == "" {
		return &oauth.Error{Code: "access_denied", Description: "user is not authenticated"}
	}
	st, err := s.DeviceByUserCode(ctx, userCode)
	if err != nil {
		// Same distinction as DescribeDeviceAuthorization: an outage is not "this
		// code is not pending" (S09-7).
		return err
	}
	if st.Done || st.Denied || s.now().After(st.Expires) {
		return oauth.ErrDeviceNotFound
	}
	if !approve {
		return s.DenyDevice(ctx, userCode, subject)
	}

	granted, err := oidcstore.NarrowScopes(st.Scopes, scopes)
	if err != nil {
		return err
	}
	// Re-attach requested protocol scopes; the consent UI renders only catalogue
	// scopes, so this keeps an OpenID device authorization from being silently
	// downgraded to plain OAuth.
	_, protocol := oidcstore.SplitProtocolScopes(st.Scopes)
	for _, s := range protocol {
		if !oidcstore.HasScope(granted, s) {
			granted = append(granted, s)
		}
	}
	described, _ := oidcstore.SplitProtocolScopes(granted)
	descriptors, err := s.registry.Resolve(oidcstore.Scopes(described), st.ClientID)
	if err != nil {
		return err
	}
	if err := oidcstore.RequireExplicitConsent(descriptors, explicit); err != nil {
		return err
	}
	// ADR-0001 O-6 (revised): a device authorization always yields a refresh
	// token, so offline_access is granted implicitly.
	granted = oidcstore.WithOfflineAccess(granted)
	return s.approveDevice(ctx, userCode, subject, granted)
}

func appendScopeUnique(dst []oauth.Scope, s oauth.Scope) []oauth.Scope {
	for _, have := range dst {
		if have == s {
			return dst
		}
	}
	return append(dst, s)
}
