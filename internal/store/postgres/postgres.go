// Package postgres holds the Postgres-backed implementations of the storage
// ports (account.Store, oauth.Store, oauth.DeviceStore, oauth.ClientRegistry).
//
// They live here rather than next to their interfaces on purpose: the public
// libraries (oauth, vault) must not depend on a database driver.
package postgres

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// migrationLockKey serializes migrations across instances. Any constant works;
// this one is arbitrary but stable.
const migrationLockKey int64 = 0x7230636d6967

// DB owns the connection pool and hands out the port implementations.
type DB struct {
	pool *pgxpool.Pool
}

// Open connects, verifies the connection, and applies pending migrations. It is
// the only constructor: there is no supported way to use the stores against an
// unmigrated database.
func Open(ctx context.Context, dsn string) (*DB, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("postgres: connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres: ping: %w", err)
	}
	db := &DB{pool: pool}
	if err := db.Migrate(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return db, nil
}

// Close releases the pool.
func (db *DB) Close() { db.pool.Close() }

// Accounts returns the account store.
func (db *DB) Accounts() *Accounts { return &Accounts{pool: db.pool} }

// Tokens returns the authorization-code and token store.
func (db *DB) Tokens() *Tokens { return &Tokens{pool: db.pool} }

// Devices returns the device-authorization store.
func (db *DB) Devices() *Devices { return &Devices{pool: db.pool} }

// Vault returns the credential-record repository. Decryption lives in the vault
// package; this only stores opaque crypto material.
func (db *DB) Vault() *Vault { return &Vault{pool: db.pool} }

// Bindings returns the source-binding store. It holds metadata only.
func (db *DB) Bindings() *Bindings { return &Bindings{pool: db.pool} }

// BindFlows returns the pending bind-flow store.
func (db *DB) BindFlows() *BindFlows { return &BindFlows{pool: db.pool} }

// Sessions returns the HTTP session store.
func (db *DB) Sessions() *Sessions { return &Sessions{pool: db.pool} }

// Authz returns the pending-authorization-request store.
func (db *DB) Authz() *Authz { return &Authz{pool: db.pool} }

// Clients returns the downstream-client registry.
func (db *DB) Clients() *Clients { return &Clients{pool: db.pool} }

// Audit returns the durable audit-log sink.
func (db *DB) Audit() *AuditLogger { return &AuditLogger{pool: db.pool} }

// Migrate applies every unapplied migration in filename order, each in its own
// transaction, under an advisory lock so two instances starting at once cannot
// race.
func (db *DB) Migrate(ctx context.Context) error {
	conn, err := db.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("postgres: migrate: acquire: %w", err)
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, migrationLockKey); err != nil {
		return fmt.Errorf("postgres: migrate: lock: %w", err)
	}
	defer func() {
		// Detached: unlocking must happen even if ctx was cancelled.
		_, _ = conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, migrationLockKey)
	}()

	if _, err := conn.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    text PRIMARY KEY,
			applied_at timestamptz NOT NULL DEFAULT now()
		)`); err != nil {
		return fmt.Errorf("postgres: migrate: bookkeeping table: %w", err)
	}

	applied, err := appliedMigrations(ctx, conn)
	if err != nil {
		return err
	}
	versions, err := migrationVersions()
	if err != nil {
		return err
	}

	for _, version := range versions {
		if applied[version] {
			continue
		}
		body, err := migrationsFS.ReadFile("migrations/" + version)
		if err != nil {
			return fmt.Errorf("postgres: migrate: read %s: %w", version, err)
		}
		if err := applyMigration(ctx, conn, version, string(body)); err != nil {
			return err
		}
	}
	return nil
}

func appliedMigrations(ctx context.Context, conn *pgxpool.Conn) (map[string]bool, error) {
	rows, err := conn.Query(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("postgres: migrate: read applied: %w", err)
	}
	defer rows.Close()

	applied := make(map[string]bool)
	for rows.Next() {
		var version string
		if err := rows.Scan(&version); err != nil {
			return nil, err
		}
		applied[version] = true
	}
	return applied, rows.Err()
}

func migrationVersions() ([]string, error) {
	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		return nil, fmt.Errorf("postgres: migrate: list: %w", err)
	}
	versions := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			versions = append(versions, e.Name())
		}
	}
	sort.Strings(versions)
	return versions, nil
}

func applyMigration(ctx context.Context, conn *pgxpool.Conn, version, body string) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: migrate: begin %s: %w", version, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, body); err != nil {
		return fmt.Errorf("postgres: migrate: apply %s: %w", version, err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, version); err != nil {
		return fmt.Errorf("postgres: migrate: record %s: %w", version, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: migrate: commit %s: %w", version, err)
	}
	return nil
}

// isUniqueViolation reports a Postgres unique-constraint error (SQLSTATE 23505),
// which is how the stores enforce the account invariants without a read-then-write
// race.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// noRows reports pgx's "no rows" sentinel.
func noRows(err error) bool { return errors.Is(err, pgx.ErrNoRows) }
