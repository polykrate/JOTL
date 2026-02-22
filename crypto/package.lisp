;;;; JAM Crypto Package Definition
;;;; FFI bindings to Rust crypto library (jam-crypto)
;;;; Pure crypto only — PVM is now in Lisp (src/jamvm/ + src/jam-host/)

(in-package :cl-user)

;;; Package is defined with only :cl dependency
;;; CFFI symbols are accessed via cffi: prefix in bindings.lisp
(defpackage :jam.ffi
  (:use :cl)
  (:export
   ;; Utilities
   #:hex-string-to-bytes
   #:bytes-to-hex-string
   #:ensure-octets
   
   ;; Blake2b-256 (GP Appendix A.1)
   #:blake2b-256
   
   ;; Keccak-256 (GP Appendix E - MMR)
   #:keccak-256
   
   ;; Ed25519 (GP Appendix A.3)
   #:ed25519-verify
   
   ;; Bandersnatch VRF (GP Appendix G)
   #:bandersnatch-vrf-output-hash
   #:bandersnatch-verify-vrf
   #:bandersnatch-verify-ring-vrf
   #:bandersnatch-verify-ring-vrf-with-output
   #:bandersnatch-compute-ring-commitment
   #:ticket-vrf-input
   #:load-bandersnatch-srs
   #:*bandersnatch-srs*
   #:*bandersnatch-srs-path*
   ;; GP notation helpers
   #:Y                     ;; Y(s) ≡ VRF output hash
   ;; Signing contexts (GP §6.18-6.20)
   #:+jam-entropy+         ;; XE = $jam_entropy
   #:+jam-ticket-seal+     ;; XT = $jam_ticket_seal
   #:+jam-fallback-seal+   ;; XF = $jam_fallback_seal
   
   ;; Deterministic Shuffle (GP Appendix F)
   #:deterministic-shuffle
   #:compute-core-assignments
   
   ;; Erasure Coding (GP Appendix H)
   #:erasure-encode
   #:erasure-encode-tiny
   #:erasure-encode-full
   
   ;; Library status
   #:*ffi-loaded*))

(in-package :jam.ffi)

(defvar *ffi-loaded* nil "T if FFI library loaded successfully")
