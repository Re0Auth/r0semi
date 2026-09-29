#!/usr/bin/env bash
# Minimal repro of scripts/restore.sh:28-29's construct under `set -u`.
set -uo pipefail
echo "bash: $BASH_VERSION"

f() {
  local file="$1" sidecar="$file.sha256" want got
  echo "sidecar=[$sidecar] file=[$file]"
}
f /tmp/x
echo "rc=$?"
