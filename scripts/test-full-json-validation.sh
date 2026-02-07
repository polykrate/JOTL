#!/bin/bash
# Test ALL extrinsic components - Full JSON validation against block.json

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT"

echo "╔════════════════════════════════════════════════════════╗"
echo "║  JOTL - Full JSON Validation (ET, EP, EG, EA, ED)     ║"
echo "║  Compare decoded binary ↔ block.json                   ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""

sbcl --noinform \
  --eval "(push #P\"$PROJECT_ROOT/\" asdf:*central-registry*)" \
  --eval "(push #P\"$PROJECT_ROOT/crypto/\" asdf:*central-registry*)" \
  --eval "(ql:quickload :jam-crypto :silent t)" \
  --eval "(asdf:load-system :jotl :force t)" \
  --eval "(ql:quickload :cl-json :silent t)" \
  --load "$PROJECT_ROOT/tests/test-full-json-validation.lisp" \
  --disable-debugger
