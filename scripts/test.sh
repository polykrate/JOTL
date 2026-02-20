#!/bin/bash
# Run JOTL conformance tests against jamtestvectors.
#
# Usage:
#   ./scripts/test.sh                              # all traces, summary only
#   ./scripts/test.sh storage safrole              # specific traces
#   ./scripts/test.sh -v storage                   # verbose (per-block + diff)
#   ./scripts/test.sh -v                           # all traces, verbose
#
# This is a test CLIENT.  It calls import-block directly (in-process,
# no socket overhead).  The chain server is NOT required.

set -euo pipefail
cd "$(dirname "$0")/.."

# Parse args
VERBOSE="nil"
TRACES=()

for arg in "$@"; do
  case "$arg" in
    -v|--verbose) VERBOSE="t" ;;
    *)            TRACES+=("\"$arg\"") ;;
  esac
done

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
