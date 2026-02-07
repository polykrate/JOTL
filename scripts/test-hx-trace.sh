#!/bin/bash
# Test HX computation against strawberry trace test vectors
set -e

cd /home/polycrate/Projets/JOTL

echo "=== HX Trace Test ==="
echo ""

sbcl --noinform --disable-debugger \
     --eval '(require :asdf)' \
     --eval '(push #P"/home/polycrate/Projets/JOTL/" asdf:*central-registry*)' \
     --eval '(ql:quickload :cl-json :silent t)' \
     --eval '(asdf:compile-system :jotl :force t)' \
     --eval '(asdf:load-system :jotl)' \
     --eval '(asdf:load-system :jam-crypto)' \
     --eval '(load "tests/test-hx-trace.lisp")' \
     --eval '(jotl::run-hx-trace-tests)' \
     --eval '(sb-ext:exit :code 0)'
