#!/bin/bash
# scripts/fuzz-target.sh — Launch JOTL fuzz-v1 target server
#
# Required environment variables:
#   JAM_FUZZ=1                          — enable fuzz mode
#   JAM_FUZZ_SPEC=tiny|full             — chainspec
#   JAM_FUZZ_DATA_PATH=/tmp/jam/data/   — data persistence dir
#   JAM_FUZZ_SOCK_PATH=/tmp/jam/fuzz.sock — socket path
#   JAM_FUZZ_LOG_LEVEL=info             — log level (optional)

cd "$(dirname "${BASH_SOURCE[0]}")/.."

if [ -z "$JAM_FUZZ" ]; then
  echo "[jotl] FATAL: JAM_FUZZ not set. Use JAM_FUZZ=1 to enable fuzz mode." >&2
  exit 1
fi

missing=""
[ -z "$JAM_FUZZ_SPEC" ]      && missing="$missing JAM_FUZZ_SPEC"
[ -z "$JAM_FUZZ_DATA_PATH" ] && missing="$missing JAM_FUZZ_DATA_PATH"
[ -z "$JAM_FUZZ_SOCK_PATH" ] && missing="$missing JAM_FUZZ_SOCK_PATH"

if [ -n "$missing" ]; then
  echo "[jotl] FATAL: missing required vars:$missing" >&2
  exit 1
fi

mkdir -p "$JAM_FUZZ_DATA_PATH"

exec sbcl --dynamic-space-size 4096 --noinform --disable-debugger \
     --load scripts/load-jotl.lisp \
     --eval "(jotl:run-fuzz-target :socket \"$JAM_FUZZ_SOCK_PATH\" :spec :$JAM_FUZZ_SPEC :log-level :${JAM_FUZZ_LOG_LEVEL:-info})"
