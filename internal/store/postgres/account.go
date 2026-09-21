package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Re0Auth/r0semi/idp"
	"github.com/Re0Auth/r0semi/internal/account"
)

// Accounts implements account.Store on Postgres.
//
// The three account invariants are enforced by the schema and by transactions,
// not by read-then-write logic:
//
//	I-3 isolation   -- UNIQUE (provider, subject)
//	I-2 last identity -- UnlinkIdentity locks the user row, then counts
//	I-1 equality    -- primary_identity is a display pointer, reassigned on unlink
type Accounts struct{ pool *pgxpool.Pool }

const accountIdentityCols = `id, user_id, provider, subject, display_name, email, avatar_url, linked_at, last_login_at`

// querier is the shared surface of *pgxpool.Pool, *pgxpool.Conn and pgx.Tx.
type querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// FindByIdentity implements account.Store.
func (s *Accounts) FindByIdentity(ctx context.Context, provider idp.Provider, subject string) (account.UserID, error) {
	var userID string
	err := s.pool.QueryRow(ctx,
		`SELECT user_id FROM accounts_identities WHERE provider = $1 AND subject = $2`,
		string(provider), subject).Scan(&userID)
	if noRows(err) {
		return "", account.ErrNotFound
	}
	if err != nil {
		return "", err
	}
	return account.UserID(userID), nil
}

// CreateWithIdentity implements account.Store.
func (s *Accounts) CreateWithIdentity(ctx context.Context, in idp.Identity) (account.User, account.Identity, error) {
	if err := in.Validate(); err != nil {
		return account.User{}, account.Identity{}, err
	}
	now := time.Now().UTC()
	user := account.User{ID: account.NewUserID(), CreatedAt: now}
	ident := account.Identity{
		ID: account.NewIdentityID(), User: user.ID,
		Provider: in.Provider, Subject: in.Subject,
		DisplayName: in.DisplayName, Email: in.Email, AvatarURL: in.AvatarURL,
		LinkedAt: now, LastLoginAt: now,
	}
	user.PrimaryIdentity = ident.ID

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return account.User{}, account.Identity{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx,
		`INSERT INTO accounts_users (id, primary_identity, created_at) VALUES ($1, $2, $3)`,
		string(user.ID), string(user.PrimaryIdentity), user.CreatedAt); err != nil {
		return account.User{}, account.Identity{}, err
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO accounts_identities (`+accountIdentityCols+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		string(ident.ID), string(ident.User), string(ident.Provider), ident.Subject,
		ident.DisplayName, ident.Email, ident.AvatarURL, ident.LinkedAt, ident.LastLoginAt); err != nil {
		if isUniqueViolation(err) {
			return account.User{}, account.Identity{}, account.ErrIdentityTaken
		}
		return account.User{}, account.Identity{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return account.User{}, account.Identity{}, err
	}
	return user, ident, nil
}

// LinkIdentity implements account.Store.
func (s *Accounts) LinkIdentity(ctx context.Context, user account.UserID, in idp.Identity) (account.Identity, error) {
	if err := in.Validate(); err != nil {
		return account.Identity{}, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return account.Identity{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM accounts_users WHERE id = $1)`, string(user)).Scan(&exists); err != nil {
		return account.Identity{}, err
	}
	if !exists {
		return account.Identity{}, account.ErrNotFound
	}

	existing, err := identityByKey(ctx, tx, in.Provider, in.Subject)
	switch {
	case err == nil:
		if existing.User == user {
			return existing, nil // re-linking the same identity is idempotent
		}
		return account.Identity{}, account.ErrIdentityTaken // I-3
	case !noRows(err):
		return account.Identity{}, err
	}

	ident := account.Identity{
		ID: account.NewIdentityID(), User: user,
		Provider: in.Provider, Subject: in.Subject,
		DisplayName: in.DisplayName, Email: in.Email, AvatarURL: in.AvatarURL,
		LinkedAt: time.Now().UTC(),
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO accounts_identities (`+accountIdentityCols+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		string(ident.ID), string(ident.User), string(ident.Provider), ident.Subject,
		ident.DisplayName, ident.Email, ident.AvatarURL, ident.LinkedAt, nil); err != nil {
		if isUniqueViolation(err) {
			// Lost a race against a concurrent link of the same identity.
			return account.Identity{}, account.ErrIdentityTaken
		}
		return account.Identity{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return account.Identity{}, err
	}
	return ident, nil
}

// UnlinkIdentity implements account.Store.
func (s *Accounts) UnlinkIdentity(ctx context.Context, user account.UserID, identity account.IdentityID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Lock the user row so two concurrent unlinks cannot both see "two left"
	// and together delete everything (I-2).
	var locked string
	err = tx.QueryRow(ctx, `SELECT id FROM accounts_users WHERE id = $1 FOR UPDATE`, string(user)).Scan(&locked)
	if noRows(err) {
		return account.ErrNotFound
	}
	if err != nil {
		return err
	}

	var owner string
	err = tx.QueryRow(ctx, `SELECT user_id FROM accounts_identities WHERE id = $1`, string(identity)).Scan(&owner)
	if noRows(err) || account.UserID(owner) != user {
		return account.ErrNotFound
	}
	if err != nil {
		return err
	}

	var count int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM accounts_identities WHERE user_id = $1`, string(user)).Scan(&count); err != nil {
		return err
	}
	if count <= 1 {
		return account.ErrLastIdentity
	}

	if _, err := tx.Exec(ctx, `DELETE FROM accounts_identities WHERE id = $1`, string(identity)); err != nil {
		return err
	}
	// If the primary was the one removed, nominate the earliest survivor. Any
	// surviving identity is equally valid for login (I-1); this is cosmetic.
	if _, err := tx.Exec(ctx, `
		UPDATE accounts_users
		   SET primary_identity = COALESCE((
		           SELECT id FROM accounts_identities
		            WHERE user_id = $1
		            ORDER BY linked_at, id
		            LIMIT 1), '')
		 WHERE id = $1 AND primary_identity = $2`, string(user), string(identity)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Identities implements account.Store.
func (s *Accounts) Identities(ctx context.Context, user account.UserID) ([]account.Identity, error) {
	var exists bool
	if err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM accounts_users WHERE id = $1)`, string(user)).Scan(&exists); err != nil {
		return nil, err
	}
	if !exists {
		return nil, account.ErrNotFound
	}

	rows, err := s.pool.Query(ctx,
		`SELECT `+accountIdentityCols+` FROM accounts_identities WHERE user_id = $1 ORDER BY linked_at, id`, string(user))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []account.Identity
	for rows.Next() {
		ident, err := scanIdentity(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ident)
	}
	return out, rows.Err()
}

// GetUser implements account.Store.
func (s *Accounts) GetUser(ctx context.Context, user account.UserID) (account.User, error) {
	var id, primary string
	var createdAt time.Time
	err := s.pool.QueryRow(ctx,
		`SELECT id, primary_identity, created_at FROM accounts_users WHERE id = $1`, string(user)).
		Scan(&id, &primary, &createdAt)
	if noRows(err) {
		return account.User{}, account.ErrNotFound
	}
	if err != nil {
		return account.User{}, err
	}
	return account.User{
		ID:              account.UserID(id),
		PrimaryIdentity: account.IdentityID(primary),
		CreatedAt:       createdAt,
	}, nil
}

// TouchLogin implements account.Store.
func (s *Accounts) TouchLogin(ctx context.Context, provider idp.Provider, subject string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE accounts_identities SET last_login_at = now() WHERE provider = $1 AND subject = $2`,
		string(provider), subject)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return account.ErrNotFound
	}
	return nil
}

func identityByKey(ctx context.Context, q querier, provider idp.Provider, subject string) (account.Identity, error) {
	row := q.QueryRow(ctx,
		`SELECT `+accountIdentityCols+` FROM accounts_identities WHERE provider = $1 AND subject = $2`,
		string(provider), subject)
	return scanIdentity(row)
}

func scanIdentity(row pgx.Row) (account.Identity, error) {
	var (
		ident     account.Identity
		id        string
		userID    string
		provider  string
		lastLogin *time.Time
	)
	if err := row.Scan(&id, &userID, &provider, &ident.Subject, &ident.DisplayName,
		&ident.Email, &ident.AvatarURL, &ident.LinkedAt, &lastLogin); err != nil {
		return account.Identity{}, err
	}
	ident.ID = account.IdentityID(id)
	ident.User = account.UserID(userID)
	ident.Provider = idp.Provider(provider)
	if lastLogin != nil {
		ident.LastLoginAt = *lastLogin
	}
	return ident, nil
}
