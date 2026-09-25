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
mkdir -p "$dir"

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
out="$dir/re0auth-$stamp.dump"

# -Fc is the custom format: compressed, and restorable table-by-table.
pg_dump --format=custom --no-owner --no-privileges --dbname "$DATABASE_URL" --file "$out"

if [ -n "${BACKUP_AGE_RECIPIENT:-}" ]; then
  if ! command -v age >/dev/null; then
    echo "BACKUP_AGE_RECIPIENT is set but age is not installed" >&2
    exit 1
  fi
  age --recipient "$BACKUP_AGE_RECIPIENT" --output "$out.age" "$out"
  shred -u "$out" 2>/dev/null || rm -f "$out"
  out="$out.age"
fi

sha256sum "$out" > "$out.sha256"
echo "backup written: $out"
