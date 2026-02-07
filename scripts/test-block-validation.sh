#!/bin/bash
# Test complete block validation (Header + Extrinsic)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT"

echo "╔════════════════════════════════════════════════════════╗"
echo "║  JOTL - Complete Block Validation Test                ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""

sbcl --noinform \
  --eval "(push #P\"$PROJECT_ROOT/\" asdf:*central-registry*)" \
  --eval "(push #P\"$PROJECT_ROOT/crypto/\" asdf:*central-registry*)" \
  --eval "(ql:quickload :jam-crypto :silent t)" \
  --eval "(asdf:load-system :jotl)" \
  --load "$PROJECT_ROOT/tests/test-block-validation.lisp" \
  --eval "(sb-ext:exit)" \
  --disable-debugger
