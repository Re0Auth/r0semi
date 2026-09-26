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
# The config file declares secrets too, and those declarations are the part nothing
# else can know: a renamed `vault.kek_env`, the idp and source client secrets, the
# retired KEKs of a rotation in flight. The binary is asked for them
# (`-print-secret-env`; RE0AUTH_BIN overrides the path, RE0AUTH_CONFIG the file).
# When a config declares them and they cannot be enumerated, this refuses to write
# a file that would look complete.
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

# Config-declared secrets. The KEK's variable name is itself a config choice
# (vault.kek_env, default RE0AUTH_KEK), so it comes from the same enumeration
# instead of being assumed.
bin="${RE0AUTH_BIN:-./re0auth}"
cfg="${RE0AUTH_CONFIG:-config/re0auth.toml}"
kek_name="RE0AUTH_KEK"
declared=""
if [ -e "$cfg" ]; then
  if [ -x "$bin" ]; then
    declared="$("$bin" -print-secret-env -config "$cfg")"
    renamed="$(printf '%s\n' "$declared" | sed -n 's/^vault\.kek_env=//p')"
    if [ -n "$renamed" ]; then
      kek_name="$renamed"
    fi
  elif grep -Eq '(client_secret_env|kek_env)[[:space:]]*=' "$cfg"; then
    echo "$cfg declares secret variables, but $bin is not executable;" >&2
    echo "run this where the binary is, or point RE0AUTH_BIN at it" >&2
    rm -f "$out"
    exit 1
  fi
fi

# 0600 from the start, so the plaintext never exists with wider permissions even
# briefly before encryption.
umask 077
: > "$out"

# Every required key, each written once. The list is deduplicated because a config
# that declares no KEK name of its own still needs the default, and the default may
# be the declared one.
while IFS= read -r name; do
  write_key "$name"
done < <(
  {
    printf '%s\n' "$kek_name"
    printf '%s\n' RE0AUTH_OIDC_TOKEN_KEY RE0AUTH_OIDC_SIGNING_KEY RE0AUTH_AUDIT_KEY
    if [ -n "$declared" ]; then
      printf '%s\n' "$declared" | sed -n 's/^[^=]*=//p'
    fi
  } | awk 'NF && !seen[$0]++'
)

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
