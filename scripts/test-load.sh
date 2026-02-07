#!/bin/bash
# Test que JOTL charge correctement avec la nouvelle structure

cd /home/polycrate/Projets/JOTL

cat <<'EOF' | sbcl --noinform
;; Load crypto FFI first
(load "crypto/load-crypto.lisp")

;; Now load JOTL
(handler-case
    (progn
      (asdf:load-system :jotl :force t)
      (format t "~%✅ JOTL loaded successfully!~%~%")
      (format t "Structure:~%")
      (format t "  Core: constants ✓~%")
      (format t "  Codec: primitives, structures ✓~%")
      (format t "  Block: header, extrinsic, block ✓~%")
      (format t "  State: timeslot ✓~%")
      (format t "  Crypto: FFI ✓~%~%"))
  (error (e)
    (format t "~%❌ Error loading JOTL: ~A~%" e)))
(quit)
EOF
