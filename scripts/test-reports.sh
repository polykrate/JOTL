#!/bin/bash
# Run JOTL against polkajam fuzz-reports traces (0.7.2).
#
# Each trace step is self-contained: pre_state + block + post_state.
# We apply the block and compare with the expected post_state,
# reporting per-component diffs on failure.
#
# Usage:
#   ./scripts/test-reports.sh                                       # all traces
#   ./scripts/test-reports.sh 1766241867                            # single trace by ID
#   ./scripts/test-reports.sh --conformance /path/to/jam-conformance # add explicit path
#   STOP=1 ./scripts/test-reports.sh                                # stop on first failure
#   MAX_TRACES=10 ./scripts/test-reports.sh                         # first 10 traces only
#
# Trace discovery (all matching sources are combined, deduplicated by name):
#   1. TRACES_DIR env var (colon-separated paths)
#   2. --conformance PATH  (appended to TRACES_DIR)
#   3. ../traces-local/  (canonical local trace store, outside git)
#   4. traces/  (legacy local traces, auto-detected)
#   5. ../jam-conformance/fuzz-reports/0.7.2/traces/  (sibling repo, auto-detected)
#
# Environment:
#   TRACES_DIR  colon-separated list of trace directories
#   TRACE_ID    filter by trace ID substring
#   MAX_TRACES  limit number of traces
#   STOP        set to 1 to stop on first failure

set -euo pipefail
cd "$(dirname "$0")/.."

# Parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    --conformance)
      if [[ $# -lt 2 ]]; then
        echo "Error: --conformance requires a path argument" >&2; exit 1
      fi
      CONF_PATH="$2"
      if [[ -d "$CONF_PATH/fuzz-reports/0.7.2/traces" ]]; then
        ADD_PATH="$CONF_PATH/fuzz-reports/0.7.2/traces/"
      else
        ADD_PATH="$CONF_PATH/"
      fi
      TRACES_DIR="${TRACES_DIR:-}${TRACES_DIR:+:}$ADD_PATH"
      export TRACES_DIR
      shift 2 ;;
    --conformance=*)
      CONF_PATH="${1#--conformance=}"
      if [[ -d "$CONF_PATH/fuzz-reports/0.7.2/traces" ]]; then
        ADD_PATH="$CONF_PATH/fuzz-reports/0.7.2/traces/"
      else
        ADD_PATH="$CONF_PATH/"
      fi
      TRACES_DIR="${TRACES_DIR:-}${TRACES_DIR:+:}$ADD_PATH"
      export TRACES_DIR
      shift ;;
    -h|--help)
      sed -n '2,/^$/s/^# \?//p' "$0"; exit 0 ;;
    *)
      export TRACE_ID="$1"; shift ;;
  esac
done

exec sbcl --noinform --dynamic-space-size 4096 \
     --load scripts/load-jotl.lisp \
     --load tests/polkajam-traces.lisp
