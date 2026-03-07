#!/bin/bash
# Run JOTL conformance tests against jamtestvectors.
#
# Usage:
#   ./scripts/test.sh                                   # all traces, summary only
#   ./scripts/test.sh storage safrole                   # specific traces
#   ./scripts/test.sh -v storage                        # verbose (per-block + diff)
#   ./scripts/test.sh -v                                # all traces, verbose
#   ./scripts/test.sh --vectors /path/to/traces          # explicit vectors path
#   JAM_TEST_VECTORS=/path/to/traces ./scripts/test.sh   # via env var
#
# Vector discovery (first match wins):
#   1. --vectors PATH                    (CLI argument)
#   2. $JAM_TEST_VECTORS                 (environment variable)
#   3. ../jamtestvectors/traces/         (sibling repo — default dev layout)
#
# This is a test CLIENT.  It calls import-block directly (in-process,
# no socket overhead).  The chain server is NOT required.

set -euo pipefail
cd "$(dirname "$0")/.."

# Parse args
VERBOSE="nil"
TRACES=()
VECTORS_PATH=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    -v|--verbose) VERBOSE="t"; shift ;;
    --vectors)
      if [[ $# -lt 2 ]]; then
        echo "Error: --vectors requires a path argument" >&2; exit 1
      fi
      VECTORS_PATH="$2"; shift 2 ;;
    --vectors=*)
      VECTORS_PATH="${1#--vectors=}"; shift ;;
    -h|--help)
      sed -n '2,/^$/s/^# \?//p' "$0"; exit 0 ;;
    *)
      TRACES+=("\"$1\""); shift ;;
  esac
done

# ── Vector discovery ──────────────────────────────────────────────
if [[ -n "$VECTORS_PATH" ]]; then
  # CLI argument — use as-is
  export JAM_TEST_VECTORS="$VECTORS_PATH"
elif [[ -z "${JAM_TEST_VECTORS:-}" ]]; then
  # Auto-detect: sibling jamtestvectors repo
  SIBLING="$(pwd)/../jamtestvectors/traces"
  if [[ -d "$SIBLING" ]]; then
    export JAM_TEST_VECTORS="$SIBLING"
  else
    echo "Error: Cannot find test vectors." >&2
    echo "" >&2
    echo "  Tried: $SIBLING" >&2
    echo "" >&2
    echo "  Solutions:" >&2
    echo "    1. Clone the repo as a sibling:" >&2
    echo "       git clone https://github.com/w3f/jamtestvectors.git ../jamtestvectors" >&2
    echo "    2. Set the env var:" >&2
    echo "       export JAM_TEST_VECTORS=/path/to/jamtestvectors/traces" >&2
    echo "    3. Pass via CLI:" >&2
    echo "       ./scripts/test.sh --vectors /path/to/traces" >&2
    exit 1
  fi
fi

echo "Vectors: $JAM_TEST_VECTORS"

# Build Lisp traces list
if [ ${#TRACES[@]} -eq 0 ]; then
  LISP_TRACES="nil"
else
  LISP_TRACES="'($(IFS=' '; echo "${TRACES[*]}"))"
fi

# Chain logs off — the test runner controls all output
exec sbcl --noinform --dynamic-space-size 4096 --load scripts/load-jotl.lisp \
     --load tests/conformance.lisp \
     --eval "(setf jotl::*chain-log-level* nil)" \
     --eval "(jotl/test:run-all :verbose $VERBOSE :traces $LISP_TRACES)" \
     --quit
