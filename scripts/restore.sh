#!/usr/bin/env bash
# Restore a backup produced by scripts/backup.sh into an EMPTY database, and say
# so loudly if the target is not empty. A restore that lands on top of a live
# database is a data-loss incident, not a recovery.
#
#   DATABASE_URL=postgres://... ./scripts/restore.sh /backups/re0auth-....dump
#
# This is also the restore drill: run it against a scratch database, start
# re0auth against that database, and check /readyz plus a login before calling a
# backup good. A backup nobody has restored is a hypothesis.
set -euo pipefail

dump="${1:?usage: restore.sh <dump-file>}"
: "${DATABASE_URL:?DATABASE_URL is required}"

if [[ "$dump" == *.age ]]; then
  : "${BACKUP_AGE_IDENTITY:?BACKUP_AGE_IDENTITY is required for an encrypted backup}"
  plain="${dump%.age}"
  age --decrypt --identity "$BACKUP_AGE_IDENTITY" --output "$plain" "$dump"
  dump="$plain"
fi

if [ -f "$dump.sha256" ]; then
  sha256sum --check "$dump.sha256"
fi

# Refuse to overwrite existing objects: recovery must be deliberate.
existing="$(psql --dbname "$DATABASE_URL" -tAc \
  "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public'")"
if [ "$existing" != "0" ]; then
  echo "refusing to restore: the target already has $existing tables" >&2
  exit 1
fi

pg_restore --dbname "$DATABASE_URL" --no-owner --no-privileges --exit-on-error "$dump"
echo "restore complete: $dump"
