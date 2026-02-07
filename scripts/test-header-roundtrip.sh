#!/bin/bash
set -e

sbcl --non-interactive \
     --eval '(require :asdf)' \
     --eval '(push #P"/home/polycrate/Projets/JOTL/" asdf:*central-registry*)' \
     --eval '(asdf:compile-system :jotl :force t)' \
     --eval '(asdf:load-system :jotl)' \
     --eval '(asdf:load-system :jam-crypto)' \
     --eval '(load "tests/test-header-roundtrip.lisp")' \
     --eval '(jotl::run-header-roundtrip-tests)' \
     --eval '(sb-ext:exit :code 0)'
