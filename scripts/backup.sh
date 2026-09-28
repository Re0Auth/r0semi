#!/usr/bin/env bash
# Back up the Postgres database Re0Auth depends on, with a checksum so a restore
# can tell a truncated dump from a good one. Run it from cron/CI, not from the
# service: a backup taken inside the process shares the process's failure modes.
#
#   DATABASE_URL=postgres://... ./scripts/backup.sh /backups
#
# Optional: BACKUP_AGE_RECIPIENT=age1... encrypts the dump with age, so the
# backup bucket never holds plaintext credentials or audit history.
set -euo pipefail

dir="${1:-./backups}"
: "${DATABASE_URL:?DATABASE_URL is required}"

# 0600 from the first byte. The dump is plain SQL holding credentials and audit
# history, and the default umask (022) makes it world-readable — the same reason
# backup-keys.sh sets 077 for the key file. Setting it before mkdir also makes a
# freshly created backup directory 0700.
umask 077
mkdir -p "$dir"

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
out="$dir/re0auth-$stamp.dump"

# Check the encryption tool BEFORE dumping. Otherwise a missing `age` leaves a
# plaintext dump on disk that the operator believes was encrypted, and only then
# fails.
if [ -n "${BACKUP_AGE_RECIPIENT:-}" ] && ! command -v age >/dev/null; then
  echo "BACKUP_AGE_RECIPIENT is set but age is not installed" >&2
  exit 1
fi

# -Fc is the custom format: compressed, and restorable table-by-table.
#
# The DSN travels as an argument, so it is visible in `ps` to other users of this
# host. That is accepted: the alternative — putting it in PGDATABASE and hoping
# the client expands an env-provided dbname as a connection string — is not the
# documented behaviour of pg_dump/psql, and a check that is silently wrong on a
# restore is worse than an argv exposure on a host that should be single-tenant.
# Keep the DSN out of the shell history and out of logs; docs/operations.md says
# the same.
pg_dump --format=custom --no-owner --no-privileges --dbname "$DATABASE_URL" --file "$out"

if [ -n "${BACKUP_AGE_RECIPIENT:-}" ]; then
  age --recipient "$BACKUP_AGE_RECIPIENT" --output "$out.age" "$out"
  shred -u "$out" 2>/dev/null || rm -f "$out"
  out="$out.age"
fi

sha256sum "$out" > "$out.sha256"
echo "backup written: $out"
