;;;; load-jotl.lisp - Load JOTL system with crypto FFI

(in-package :cl-user)

(format t "~%Loading JOTL v4...~%")

;; 1. Load ASDF systems (crypto FFI is loaded via jam-crypto ASDF system)
(format t "  Loading ASDF systems...~%")
(let* ((jotl-root (make-pathname :directory 
                                 (butlast (pathname-directory 
                                           (or *load-truename* *default-pathname-defaults*)))))
       (jam-crypto-asd (merge-pathnames "jam-crypto.asd" jotl-root))
       (jotl-asd (merge-pathnames "jotl.asd" jotl-root)))
  ;; Load system definitions
  (load jam-crypto-asd)
  (load jotl-asd)
  
  ;; Load systems
  (asdf:load-system :jam-crypto :force t)
  (asdf:load-system :jotl :force t))

(format t "~%✅ JOTL loaded successfully!~%~%")
(format t "Available packages:~%")
(format t "  - JOTL (main)~%")
(format t "  - JAM.FFI (crypto)~%~%")
(format t "Try: (in-package :jotl)~%~%")
