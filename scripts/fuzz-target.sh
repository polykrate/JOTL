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

# Auto-detect available memory from cgroup (Docker) or default to 1536 MB.
# SBCL's --dynamic-space-size must fit within the container memory limit;
# we use 75% of available memory leaving room for SBCL runtime overhead.
if [ -f /sys/fs/cgroup/memory.max ]; then
  mem_bytes=$(cat /sys/fs/cgroup/memory.max 2>/dev/null)
  if [ "$mem_bytes" != "max" ] && [ -n "$mem_bytes" ]; then
    heap_mb=$(( mem_bytes * 75 / 100 / 1024 / 1024 ))
  fi
elif [ -f /sys/fs/cgroup/memory/memory.limit_in_bytes ]; then
  mem_bytes=$(cat /sys/fs/cgroup/memory/memory.limit_in_bytes 2>/dev/null)
  if [ "$mem_bytes" -lt 100000000000 ]; then
    heap_mb=$(( mem_bytes * 75 / 100 / 1024 / 1024 ))
  fi
fi
HEAP_SIZE=${heap_mb:-1536}

exec sbcl --dynamic-space-size "$HEAP_SIZE" --noinform --disable-debugger \
     --load scripts/load-jotl.lisp \
     --eval "(jotl:run-fuzz-target :socket \"$JAM_FUZZ_SOCK_PATH\" :spec :$JAM_FUZZ_SPEC :log-level :${JAM_FUZZ_LOG_LEVEL:-info})"
