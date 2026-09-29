#!/usr/bin/env bash
# Restore a backup produced by scripts/backup.sh into an EMPTY database, and say
# so loudly if the target is not empty. A restore that lands on top of a live
# database is a data-loss incident, not a recovery.
#
#   DATABASE_URL=postgres://... ./scripts/restore.sh /backups/re0auth-....dump
#   DATABASE_URL=postgres://... BACKUP_AGE_IDENTITY=~/.age/keys.txt \
#     ./scripts/restore.sh /backups/re0auth-....dump.age
#
# This is also the restore drill: run it against a scratch database, start
# re0auth against that database, and check /readyz plus a login before calling a
# backup good. A backup nobody has restored is a hypothesis.
set -euo pipefail

dump="${1:?usage: restore.sh <dump-file>}"
: "${DATABASE_URL:?DATABASE_URL is required}"

# The checksum sidecar is REQUIRED, and it is checked against the file named on
# the command line — not against whatever path the sidecar happens to record.
#
# `sha256sum --check "$dump.sha256"` reads the filename out of the sidecar, so the
# file being restored never entered the check: a dump moved between hosts aborts
# on a path that no longer exists, while a truncated dump whose sidecar still
# names some other intact file "verifies" and goes straight into pg_restore. Both
# directions are fixed by comparing the recorded digest to the digest of $dump.
# The sidecar covers the CIPHERTEXT on the encrypted path (backup.sh writes it
# after encryption), so this runs BEFORE decryption and covers both paths.
verify() {
  # Split deliberately: under `set -u` bash expands every right-hand side before
  # `local` runs, so `local file="$1" sidecar="$file.sha256"` dies with
  # `file: unbound variable` before the sidecar check below is ever reached.
  local file="$1"
  local sidecar="$file.sha256" want got
  if [ ! -f "$sidecar" ]; then
    echo "refusing to restore: $sidecar is missing, so nothing verifies $file" >&2
    exit 1
  fi
  want="$(awk '{print $1; exit}' "$sidecar")"
  got="$(sha256sum "$file" | awk '{print $1}')"
  if [ "$want" != "$got" ]; then
    echo "checksum mismatch for $file: sidecar says $want, file hashes to $got" >&2
    exit 1
  fi
  echo "checksum verified: $file"
}
verify "$dump"

# Decryption writes a plaintext copy; it goes into a private temporary directory
# that the EXIT trap removes, never next to the ciphertext in the backup
# directory where it would outlive the restore. mktemp -d is 0700, so the
# plaintext is not readable by anyone else even while it exists.
workdir=""
cleanup() { if [ -n "$workdir" ]; then rm -rf "$workdir"; fi; }
trap cleanup EXIT

if [[ "$dump" == *.age ]]; then
  : "${BACKUP_AGE_IDENTITY:?BACKUP_AGE_IDENTITY is required for an encrypted backup}"
  workdir="$(mktemp -d)"
  plain="$workdir/$(basename "${dump%.age}")"
  age --decrypt --identity "$BACKUP_AGE_IDENTITY" --output "$plain" "$dump"
  dump="$plain"
fi

# Refuse to overwrite existing objects: recovery must be deliberate.
existing="$(psql --dbname "$DATABASE_URL" -tAc \
  "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public'")"
if [ "$existing" != "0" ]; then
  echo "refusing to restore: the target already has $existing tables" >&2
  exit 1
fi

# --single-transaction makes the restore all-or-nothing. Without it, a failure
# partway through a truncated dump leaves the target half-populated, and the
# empty-target guard above then refuses the retry — the only way forward is to
# drop the database by hand. The option implies --exit-on-error.
#
# The DSN is passed as an argument and is therefore visible in `ps` to other
# users of the host. Accepted here (see scripts/backup.sh): the alternative
# depends on the client expanding an env-provided dbname as a conninfo, which is
# not the documented behaviour, and a backup/restore host is a single-tenant one.
pg_restore --dbname "$DATABASE_URL" --no-owner --no-privileges \
  --exit-on-error --single-transaction "$dump"
echo "restore complete: $dump"
