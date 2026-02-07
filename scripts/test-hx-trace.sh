#!/bin/bash
# Full test suite: codec roundtrips + HX traces + block roundtrip
set -e
cd "$(dirname "$0")/.."

sbcl --noinform --non-interactive \
     --eval '(push (truename ".") asdf:*central-registry*)' \
     --eval '(asdf:load-system :jotl)' \
     --eval '(ql:quickload :cl-json :silent t)' \
     --eval '(load "tests/test-block-roundtrip.lisp")'
