;;;; crypto.asd - JAM Cryptography System (FFI to Rust)
;;;; Gray Paper Appendices A, E, F, G, H

(asdf:defsystem #:jam-crypto
  :description "JAM Cryptography FFI bindings to Rust (Blake2b, Ed25519, Bandersnatch, PVM)"
  :author "Polycrate"
  :license "MIT"
  :version "1.0.0"
  :serial t
  :depends-on (#:cffi #:ironclad)
  :components ((:module "crypto"
                :serial t
                :components
                ((:file "package")
                 (:file "utils")              ; Utility functions
                 (:file "bindings")           ; FFI bindings to Rust
                 (:file "primitives")         ; Types, Y function, constants
                 (:file "pvm"))))             ; Clean JAM-codec PVM bindings
  
  :perform (asdf:load-op :after (o c)
             (declare (ignore o c))
             (when (find-symbol "*FFI-LOADED*" :jam.ffi)
               (let ((loaded (symbol-value (find-symbol "*FFI-LOADED*" :jam.ffi))))
                 (if loaded
                     (format t "~&✓ JAM Crypto FFI loaded successfully~%")
                     (warn "JAM Crypto FFI failed to load - crypto functions unavailable"))))))
