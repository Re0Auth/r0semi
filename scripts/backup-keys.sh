#!/usr/bin/env bash
# Back up the keys Re0Auth cannot rebuild: the KEK, the OIDC signing key, the OIDC
# token key and the audit-chain key. A database dump is useless without the KEK —
# every credential's DEK was wrapped by it — and the audit chain cannot be verified
# without its key, so a backup that omits these is not a recovery.
#
#   RE0AUTH_KEK=... RE0AUTH_OIDC_TOKEN_KEY=... \
#   RE0AUTH_OIDC_SIGNING_KEY=... RE0AUTH_AUDIT_KEY=... ./scripts/backup-keys.sh /backups
#
# Reads the keys from the environment (the same names the service reads). Encrypts
# with age when BACKUP_AGE_RECIPIENT is set — the KEK must not sit in plaintext in
# the backup bucket. A checksum is written alongside, as backup.sh does. Store the
# result somewhere the database backup is not.
#
# What this does NOT cover: `vault.retired` KEKs live in the config file, not the
# environment. If a rotation is in flight, archive the config's retired-key section
# with this file — those keys are what still opens the records the current key does
# not, and losing them mid-rotation is unrecoverable.
set -euo pipefail

dir="${1:-./backups}"
mkdir -p "$dir"

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
out="$dir/re0auth-keys-$stamp.env"

# getenv prints a variable's value, or nothing if it is unset. printenv is used
# rather than an indirect expansion so the script does not depend on how a given
# bash resolves "${!name:-}".
getenv() { printenv "$1" 2>/dev/null || true; }

# write_key refuses to produce a file with a hole in it: a key backup that silently
# omits one key is worse than none, because it looks complete.
write_key() {
  local name="$1"
  local value
  value="$(getenv "$name")"
  if [ -z "$value" ]; then
    echo "$name is not set; refusing to write a key backup with a hole in it" >&2
    rm -f "$out"
    exit 1
  fi
  printf '%s=%s\n' "$name" "$value" >> "$out"
}

# 0600 from the start, so the plaintext never exists with wider permissions even
# briefly before encryption.
umask 077
: > "$out"
write_key RE0AUTH_KEK
write_key RE0AUTH_OIDC_TOKEN_KEY
write_key RE0AUTH_OIDC_SIGNING_KEY
write_key RE0AUTH_AUDIT_KEY

# Retired keys are optional, but during a rotation they are what still opens the
# records the current key does not. Copied through verbatim when present.
for name in RE0AUTH_OIDC_RETIRED_SIGNING_KEYS RE0AUTH_OIDC_RETIRED_TOKEN_KEYS; do
  value="$(getenv "$name")"
  if [ -n "$value" ]; then
    printf '%s=%s\n' "$name" "$value" >> "$out"
  fi
done

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
echo "key backup written: $out"
