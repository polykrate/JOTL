;;;; crypto.asd - JAM Cryptography System (FFI to Rust)
;;;; Gray Paper Appendices A, E, F, G, H
;;;; Pure crypto only — PVM is now in Lisp (src/jamvm/ + src/jam-host/)

(asdf:defsystem #:jam-crypto
  :description "JAM Cryptography FFI to Rust (Blake2b, Ed25519, Bandersnatch, Erasure)"
  :author "Polycrate"
  :license "GPL-3.0"
  :version "1.0.0"
  :serial t
  :depends-on (#:cffi)
  :components ((:module "crypto"
                :serial t
                :components
                ((:file "package")
                 (:file "utils")              ; Utility functions
                 (:file "crypto")             ; Crypto FFI (Blake2b, Ed25519, Bandersnatch, Erasure)
                 (:file "primitives"))))      ; Types, Y function, constants
  
  :perform (asdf:load-op :after (o c)
             (declare (ignore o c))
             (when (find-symbol "*FFI-LOADED*" :jam.ffi)
               (let ((loaded (symbol-value (find-symbol "*FFI-LOADED*" :jam.ffi))))
                 (if loaded
                     (format t "~&✓ JAM Crypto FFI loaded successfully~%")
                     (warn "JAM Crypto FFI failed to load - crypto functions unavailable"))))))
