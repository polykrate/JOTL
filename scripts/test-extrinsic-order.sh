#!/bin/bash
# Test Extrinsic Component Order

cd "$(dirname "$0")/.." || exit 1

echo "Loading JOTL and testing extrinsic component order..."

sbcl --noinform --non-interactive \
  --eval '(require :asdf)' \
  --eval "(push (truename \".\") asdf:*central-registry*)" \
  --eval '(asdf:load-system :jotl)' \
  --eval '(asdf:load-system :jam-crypto)' \
  --load tests/test-extrinsic-order.lisp
