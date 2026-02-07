#!/bin/bash
# Test ED (Disputes) JSON validation

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT"

echo "Testing ED (Disputes) - JSON Validation"
echo "========================================"
echo ""

sbcl --noinform \
  --eval "(push #P\"$PROJECT_ROOT/\" asdf:*central-registry*)" \
  --eval "(push #P\"$PROJECT_ROOT/crypto/\" asdf:*central-registry*)" \
  --eval "(ql:quickload :jam-crypto :silent t)" \
  --eval "(asdf:load-system :jotl)" \
  --load "$PROJECT_ROOT/tests/test-disputes-json-validation.lisp" \
  --eval "(sb-ext:exit)" \
  --disable-debugger
