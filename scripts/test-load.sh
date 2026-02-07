#!/bin/bash
# Test que JOTL charge correctement
set -e
cd /home/polycrate/Projets/JOTL

sbcl --non-interactive \
     --eval '(require :asdf)' \
     --eval '(push #P"/home/polycrate/Projets/JOTL/" asdf:*central-registry*)' \
     --eval '(asdf:load-system :jotl)' \
     --eval '(asdf:load-system :jam-crypto)' \
     --eval '(format t "~%JOTL loaded.~%  core/ codec/ utils/ block/ stf/ OK~%")' \
     --eval '(sb-ext:exit :code 0)'
