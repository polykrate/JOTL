#!/bin/bash
# Run JOTL against polkajam fuzz-reports traces (0.7.2).
#
# Each trace step is self-contained: pre_state + block + post_state.
# We apply the block and compare with the expected post_state,
# reporting per-component diffs on failure.
#
# Usage:
#   ./scripts/test-reports.sh                    # all traces (run all)
#   ./scripts/test-reports.sh 1766241867         # single trace by ID
#   STOP=1 ./scripts/test-reports.sh             # stop on first failure
#   MAX_TRACES=10 ./scripts/test-reports.sh      # first 10 traces only
#
# Environment:
#   TRACES_DIR  override traces directory (default: ../jam-conformance/fuzz-reports/0.7.2/traces/)
#   TRACE_ID    filter by trace ID substring
#   MAX_TRACES  limit number of traces
#   STOP        set to 1 to stop on first failure

set -euo pipefail
cd "$(dirname "$0")/.."

# If a positional arg is given, use it as TRACE_ID
if [ $# -ge 1 ]; then
  export TRACE_ID="$1"
fi

exec sbcl --noinform --dynamic-space-size 4096 \
     --load scripts/load-jotl.lisp \
     --load tests/polkajam-traces.lisp
