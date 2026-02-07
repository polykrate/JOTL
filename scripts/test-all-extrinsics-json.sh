#!/bin/bash
# Test ALL extrinsic components - JSON validation

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT"

echo "╔════════════════════════════════════════════════════════╗"
echo "║  JOTL - Complete Extrinsic JSON Validation            ║"
echo "║  Testing: ET, EP, EA, ED                               ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""

sbcl --noinform \
  --eval "(push #P\"$PROJECT_ROOT/\" asdf:*central-registry*)" \
  --eval "(push #P\"$PROJECT_ROOT/crypto/\" asdf:*central-registry*)" \
  --eval "(ql:quickload :jam-crypto :silent t)" \
  --eval "(asdf:load-system :jotl)" \
  --load "$PROJECT_ROOT/tests/test-all-extrinsics-json.lisp" \
  --eval "(sb-ext:exit)" \
  --disable-debugger
