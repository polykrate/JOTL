#!/bin/bash
# Build a standalone JOTL binary (SBCL core image).
#
# Usage:
#   ./scripts/build.sh                    # → ./jotl  (default output)
#   ./scripts/build.sh -o /usr/local/bin/jotl
#
# The resulting binary is a self-contained SBCL image that includes
# all compiled JOTL code, Quicklisp deps, and FFI bindings.
# It does NOT include the Rust .so — that must be on LD_LIBRARY_PATH
# or in the same directory at runtime.
#
# Binary capabilities:
#   ./jotl fuzz /tmp/jam_target.sock      # fuzz-v1 target server
#   ./jotl test                           # run conformance tests
#   ./jotl test -v storage                # verbose, specific trace
#   ./jotl test --vectors /path/to/traces # explicit vectors path
#   ./jotl version                        # show version
#
# Size: ~80-150 MB (includes SBCL runtime + all compiled code)
# Startup: <100ms (no compilation, everything pre-loaded)

set -euo pipefail
cd "$(dirname "$0")/.."

OUTPUT="./jotl"

while [[ $# -gt 0 ]]; do
  case "$1" in
    -o|--output) OUTPUT="$2"; shift 2 ;;
    -h|--help)   sed -n '2,/^$/s/^# \?//p' "$0"; exit 0 ;;
    *)           echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

echo "Building JOTL binary → $OUTPUT"
echo ""

# Ensure crypto .so is built
if [[ ! -f crypto/jam-crypto/target/release/libjam_crypto.so ]]; then
  echo "Building Rust crypto FFI..."
  cargo build --manifest-path crypto/jam-crypto/Cargo.toml --release
  echo ""
fi

# Build the binary
export JOTL_BUILD_OUTPUT="$OUTPUT"

sbcl --noinform --dynamic-space-size 4096 \
     --load scripts/load-jotl.lisp \
     --load scripts/build-image.lisp

echo ""
echo "Done: $OUTPUT ($(du -h "$OUTPUT" | cut -f1))"
echo ""
echo "Usage:"
echo "  $OUTPUT fuzz /tmp/jam_target.sock"
echo "  $OUTPUT test"
echo "  $OUTPUT test -v storage --vectors /path/to/traces"
echo "  $OUTPUT version"
