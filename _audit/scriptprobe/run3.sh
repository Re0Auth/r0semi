#!/usr/bin/env bash
# Round-6 audit probe 3: scripts/restore.sh's integrity gate, executed.
# Nothing here writes outside _audit/scriptprobe.
set -uo pipefail

root=/c/git/r0semi
here="$root/_audit/scriptprobe"
cd "$here" || exit 2

rm -rf outr; mkdir -p outr
export DATABASE_URL="postgres://probe/probe"

printf 'a database dump\n' > outr/probe.dump
sha256sum outr/probe.dump > outr/probe.dump.sha256

echo "########## (i) sidecar missing ##########"
rm -f outr/gone.dump.sha256; cp outr/probe.dump outr/gone.dump
bash "$root/scripts/restore.sh" "$here/outr/gone.dump"; echo "exit=$?"

echo
echo "########## (ii) sidecar present but for a DIFFERENT file (the moved-dump case) ##########"
cp outr/probe.dump outr/moved.dump
sha256sum outr/probe.dump > outr/moved.dump.sha256
printf 'tampered\n' >> outr/moved.dump
bash "$root/scripts/restore.sh" "$here/outr/moved.dump"; echo "exit=$?"

echo
echo "########## (iii) truncated dump, sidecar kept ##########"
printf 'a database dump\n' > outr/trunc.dump
sha256sum outr/trunc.dump > outr/trunc.dump.sha256
printf 'a database' > outr/trunc.dump   # truncated after the sidecar was written
bash "$root/scripts/restore.sh" "$here/outr/trunc.dump"; echo "exit=$?"

echo
echo "########## (iv) sidecar matching the CURRENT bytes: does the gate pass? ##########"
bash "$root/scripts/restore.sh" "$here/outr/probe.dump"; echo "exit=$?"

echo
echo "########## (v) an attacker who can write the backup dir rewrites BOTH files ##########"
printf 'evil dump\n' > outr/evil.dump
sha256sum outr/evil.dump > outr/evil.dump.sha256
echo "sidecar says: $(cat outr/evil.dump.sha256)"
echo "(the sidecar is a bare digest: nothing binds it to a key or a signature)"
