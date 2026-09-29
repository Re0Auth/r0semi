#!/usr/bin/env bash
# Round-6 audit probe 4: scripts/restore.sh against a PERFECT dump + sidecar.
# The script must print "checksum verified", check the target, and reach
# pg_restore. It does none of that.
set -uo pipefail

root=/c/git/r0semi
here="$root/_audit/scriptprobe"
cd "$here" || exit 2

rm -rf outd; mkdir -p outd
printf 'a database dump\n' > outd/good.dump
sha256sum outd/good.dump > outd/good.dump.sha256
echo "== fixture =="; cat outd/good.dump.sha256

echo
echo "== run restore.sh (stdout+stderr) =="
export DATABASE_URL="postgres://probe/probe"
bash "$root/scripts/restore.sh" "$here/outd/good.dump" 2>&1
echo "exit=$?"

echo
echo "== does 'file' exist in the environment? =="
( set -u; : "${file+set}" && echo "file is set" || echo "file is NOT set" )

echo
echo "== the offending line =="
sed -n '28,30p' "$root/scripts/restore.sh"
