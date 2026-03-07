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
#   ./scripts/test-reports.sh --conformance /path/to/jam-conformance # explicit path
#   STOP=1 ./scripts/test-reports.sh                                # stop on first failure
#   MAX_TRACES=10 ./scripts/test-reports.sh                         # first 10 traces only
#
# Trace discovery (first match wins):
#   1. --conformance PATH             (CLI argument → $TRACES_DIR)
#   2. $TRACES_DIR                    (environment variable)
#   3. ../jam-conformance/fuzz-reports/0.7.2/traces/  (sibling repo)
#
# Environment:
#   TRACES_DIR  override traces directory
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
      # Point TRACES_DIR to the fuzz-reports traces inside the conformance repo
      CONF_PATH="$2"
      if [[ -d "$CONF_PATH/fuzz-reports/0.7.2/traces" ]]; then
        export TRACES_DIR="$CONF_PATH/fuzz-reports/0.7.2/traces/"
      else
        export TRACES_DIR="$CONF_PATH/"
      fi
      shift 2 ;;
    --conformance=*)
      CONF_PATH="${1#--conformance=}"
      if [[ -d "$CONF_PATH/fuzz-reports/0.7.2/traces" ]]; then
        export TRACES_DIR="$CONF_PATH/fuzz-reports/0.7.2/traces/"
      else
        export TRACES_DIR="$CONF_PATH/"
      fi
      shift ;;
    -h|--help)
      sed -n '2,/^$/s/^# \?//p' "$0"; exit 0 ;;
    *)
      # Positional arg → trace ID filter
      export TRACE_ID="$1"; shift ;;
  esac
done

# Auto-detect if TRACES_DIR not set
if [[ -z "${TRACES_DIR:-}" ]]; then
  SIBLING="$(pwd)/../jam-conformance/fuzz-reports/0.7.2/traces"
  if [[ -d "$SIBLING" ]]; then
    export TRACES_DIR="$SIBLING/"
  else
    echo "Error: Cannot find fuzz-reports traces." >&2
    echo "" >&2
    echo "  Tried: $SIBLING" >&2
    echo "" >&2
    echo "  Solutions:" >&2
    echo "    1. Clone the repo as a sibling:" >&2
    echo "       git clone https://github.com/w3f/jam-conformance.git ../jam-conformance" >&2
    echo "    2. Set the env var:" >&2
    echo "       export TRACES_DIR=/path/to/traces/" >&2
    echo "    3. Pass via CLI:" >&2
    echo "       ./scripts/test-reports.sh --conformance /path/to/jam-conformance" >&2
    exit 1
  fi
fi

echo "Traces: $TRACES_DIR"

exec sbcl --noinform --dynamic-space-size 4096 \
     --load scripts/load-jotl.lisp \
     --load tests/polkajam-traces.lisp
