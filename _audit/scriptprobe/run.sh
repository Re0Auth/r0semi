#!/usr/bin/env bash
# Round-6 audit probe: run scripts/backup-keys.sh against the fixture and show
# which variable it archives. Nothing here writes outside _audit/scriptprobe.
set -uo pipefail

root=/c/git/r0semi
here="$root/_audit/scriptprobe"
cd "$here" || exit 2

rm -rf out
mkdir -p out

# Which variable names the environment carries. RE0AUTH_KEK is what the service
# prefers (config.go:721); MY_KEK is what the config declares and what the
# backup script follows.
A=$(printf 'A%.0s' {1..32} | base64 -w0)   # 32 x 'A'
B=$(printf 'B%.0s' {1..32} | base64 -w0)   # 32 x 'B'
export RE0AUTH_KEK="$A"
export MY_KEK="$B"
export RE0AUTH_OIDC_TOKEN_KEY="$A"
export RE0AUTH_OIDC_SIGNING_KEY="$A"
export RE0AUTH_AUDIT_KEY="$A"

echo "== is the stub executable to bash? =="
test -x ./bin/re0auth && echo "bin/re0auth is [ -x ]" || echo "bin/re0auth is NOT [ -x ]"

echo "== run scripts/backup-keys.sh =="
RE0AUTH_BIN=./bin/re0auth RE0AUTH_CONFIG=./config.toml bash "$root/scripts/backup-keys.sh" "$here/out"
echo "exit=$?"

echo "== the file it wrote =="
ls -la out
f=$(ls out/*.env 2>/dev/null | head -1)
echo "--- $f ---"
cat "$f"
echo "--- which KEK did it archive? ---"
grep -c '^MY_KEK=' "$f" | sed 's/^/MY_KEK lines: /'
grep -c '^RE0AUTH_KEK=' "$f" | sed 's/^/RE0AUTH_KEK lines: /'
echo "--- the KEK the service would use (RE0AUTH_KEK) decodes to: ---"
printf '%s' "$A" | base64 -d | od -An -tx1 | head -1
echo "--- what the backup file holds for MY_KEK decodes to: ---"
grep '^MY_KEK=' "$f" | cut -d= -f2- | tr -d '\r' | base64 -d | od -An -tx1 | head -1

echo "== the backup DIRECTORY mode (mkdir happens before umask 077) =="
stat -c '%a %n' out || true
echo "== umask in this shell =="
umask
echo "== what a fresh dir made under umask 077 looks like =="
mkdir -p out2 && (umask 077; mkdir -p out3)
stat -c '%a %n' out2 out3 || true
