#!/usr/bin/env bash
# Round-6 audit probe 2: the failure paths of scripts/backup-keys.sh, and what
# they leave on disk. Nothing here writes outside _audit/scriptprobe.
set -uo pipefail

root=/c/git/r0semi
here="$root/_audit/scriptprobe"
cd "$here" || exit 2

A=$(printf 'A%.0s' {1..32} | base64 -w0)
export RE0AUTH_KEK="$A"
export MY_KEK="$A"
export RE0AUTH_OIDC_TOKEN_KEY="$A"
export RE0AUTH_OIDC_SIGNING_KEY="$A"

echo "########## (a) a required key is unset: fail closed, no partial file? ##########"
rm -rf outa; mkdir -p outa
unset RE0AUTH_AUDIT_KEY
RE0AUTH_BIN=./bin/re0auth RE0AUTH_CONFIG=./config.toml bash "$root/scripts/backup-keys.sh" "$here/outa"
echo "exit=$?"
echo "left behind in outa:"; ls -la outa

echo
echo "########## (b) BACKUP_AGE_RECIPIENT set but age is not installed ##########"
export RE0AUTH_AUDIT_KEY="$A"
rm -rf outb; mkdir -p outb
RE0AUTH_BIN=./bin/re0auth RE0AUTH_CONFIG=./config.toml \
  BACKUP_AGE_RECIPIENT=age1probe0000000000000000000000000000000000000000000000000000 \
  bash "$root/scripts/backup-keys.sh" "$here/outb"
echo "exit=$?"
echo "left behind in outb:"; ls -la outb
for f in outb/*.env; do
  [ -e "$f" ] || continue
  echo "--- plaintext residue: $f ---"
  sed 's/=.*/=<redacted>/' "$f"
done

echo
echo "########## (c) no BACKUP_AGE_RECIPIENT at all: plaintext by default ##########"
rm -rf outc; mkdir -p outc
RE0AUTH_BIN=./bin/re0auth RE0AUTH_CONFIG=./config.toml \
  bash "$root/scripts/backup-keys.sh" "$here/outc"
echo "exit=$?"
echo "left behind in outc:"; ls -la outc
echo "--- the run's only output above; is the KEK plaintext in the file? ---"
grep -q '^MY_KEK=' outc/*.env && echo "YES: MY_KEK=<plaintext base64> is in $(ls outc/*.env)"
