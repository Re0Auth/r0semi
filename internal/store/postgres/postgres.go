// Package postgres holds the Postgres-backed implementations of the storage
// ports (account.Store, oauth.Store, oauth.DeviceStore, oauth.ClientRegistry).
//
// They live here rather than next to their interfaces on purpose: the public
// libraries (oauth, vault) must not depend on a database driver.
package postgres

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib" // database/sql driver goose runs on
	"github.com/pressly/goose/v3"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// migrationLockKey serializes migrations across instances. Any constant works;
// this one is arbitrary but stable.
const migrationLockKey int64 = 0x7230636d6967

// DB owns the connection pool and hands out the port implementations.
type DB struct {
	pool *pgxpool.Pool
	// dsn is kept so goose can open its own database/sql handle for migrations.
	dsn string
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
	db := &DB{pool: pool, dsn: dsn}
	if err := db.Migrate(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return db, nil
}

// Close releases the pool.
func (db *DB) Close() { db.pool.Close() }

// Ping reports whether the database is reachable. It is the readiness probe: a
// pool that cannot acquire a connection means this instance cannot serve, and an
// orchestrator should stop routing to it until it can.
func (db *DB) Ping(ctx context.Context) error { return db.pool.Ping(ctx) }

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

// Clients returns the downstream-client registry.
func (db *DB) Clients() *Clients { return &Clients{pool: db.pool} }

// Audit returns the durable audit-log sink. The key authenticates the record
// chain; it is required, and must be 32 bytes, because a chain signed with no key
// would look like tamper-evidence and not be.
func (db *DB) Audit(key []byte) (*AuditLogger, error) {
	return newAuditLogger(db.pool, key)
}

// Migrate applies every pending goose migration under an advisory lock, so two
// instances starting at once cannot race. The lock is held on a dedicated pool
// connection for the whole run; goose itself runs on a database/sql handle
// (the pgx stdlib driver), because that is the seam it exposes.
//
// It also adopts a pre-goose `schema_migrations` table when it finds one: its
// rows are copied into goose's version table (preserving the applied_at
// timestamps), then it is dropped. A database that has never run a migration
// simply gets a fresh goose_db_version.
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

	sqlDB, err := sql.Open("pgx", db.dsn)
	if err != nil {
		return fmt.Errorf("postgres: migrate: open database/sql handle: %w", err)
	}
	defer func() { _ = sqlDB.Close() }()

	dir, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("postgres: migrate: migrations dir: %w", err)
	}
	provider, err := goose.NewProvider(goose.DialectPostgres, sqlDB, dir)
	if err != nil {
		return fmt.Errorf("postgres: migrate: provider: %w", err)
	}
	if err := adoptLegacyMigrations(ctx, sqlDB, provider); err != nil {
		return err
	}
	if _, err := provider.Up(ctx); err != nil {
		return fmt.Errorf("postgres: migrate: up: %w", err)
	}
	return nil
}

// adoptLegacyMigrations copies a pre-goose `schema_migrations` table into
// goose's version table, then removes it. It is idempotent: re-running it after
// a partial adoption inserts nothing that is already present and still drops
// the legacy table.
func adoptLegacyMigrations(ctx context.Context, sqlDB *sql.DB, provider *goose.Provider) error {
	var legacy bool
	if err := sqlDB.QueryRowContext(ctx,
		`SELECT to_regclass('schema_migrations') IS NOT NULL`).Scan(&legacy); err != nil {
		return fmt.Errorf("postgres: migrate: detect legacy table: %w", err)
	}
	if !legacy {
		return nil
	}

	// Let goose create its version table (and its zero row) before inserting.
	if _, err := provider.GetDBVersion(ctx); err != nil {
		return fmt.Errorf("postgres: migrate: init version table: %w", err)
	}

	rows, err := sqlDB.QueryContext(ctx, `SELECT version, applied_at FROM schema_migrations`)
	if err != nil {
		return fmt.Errorf("postgres: migrate: read legacy rows: %w", err)
	}
	defer func() { _ = rows.Close() }()

	type legacyRow struct {
		filename  string
		appliedAt time.Time
	}
	var legacyRows []legacyRow
	for rows.Next() {
		var r legacyRow
		if err := rows.Scan(&r.filename, &r.appliedAt); err != nil {
			return fmt.Errorf("postgres: migrate: scan legacy row: %w", err)
		}
		legacyRows = append(legacyRows, r)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("postgres: migrate: iterate legacy rows: %w", err)
	}

	for _, r := range legacyRows {
		version, err := goose.NumericComponent(r.filename)
		if err != nil {
			return fmt.Errorf("postgres: migrate: legacy version %q: %w", r.filename, err)
		}
		if _, err := sqlDB.ExecContext(ctx, `
			INSERT INTO goose_db_version (version_id, is_applied, tstamp)
			SELECT $1, true, $2
			WHERE NOT EXISTS (SELECT 1 FROM goose_db_version WHERE version_id = $1)`,
			version, r.appliedAt); err != nil {
			return fmt.Errorf("postgres: migrate: adopt %q: %w", r.filename, err)
		}
	}

	if _, err := sqlDB.ExecContext(ctx, `DROP TABLE schema_migrations`); err != nil {
		return fmt.Errorf("postgres: migrate: drop legacy table: %w", err)
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
