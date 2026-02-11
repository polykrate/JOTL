;;;; JAM Crypto Package Definition
;;;; FFI bindings to Rust crypto library (jam-crypto)
;;;; GP Appendices A, E, F, G, H

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
   
   ;; PVM - PolkaVM (GP Section 14)
   #:*pvm-engine*
   #:pvm-engine
   #:pvm-engine-reset
   #:pvm-prepare
   #:pvm-context-free
   #:with-pvm-context
   ;; PVM configuration (legacy — migrating to pvm-configure)
   ;; Keep: pvm-encode-work-item-record (encoding helper, still used)
   ;; PVM execution
   #:pvm-encode-work-item-record
   #:pvm-run
   #:pvm-accumulate-collapse
   ;; PVM result getters (legacy — migrating to pvm-collect)
   ;; Keep: pvm-has-yield-output, pvm-get-yield-output (needed for collapse)
   #:pvm-has-yield-output
   #:pvm-get-yield-output
   
   ;; New JAM-codec PVM API (wire.rs)
   #:pvm-new
   #:pvm-free
   #:pvm-configure
   #:pvm-collect
   #:with-pvm
   #:encode-pvm-config
   #:decode-pvm-side-effects
   
   ;; Library status
   #:*ffi-loaded*))

(in-package :jam.ffi)

(defvar *ffi-loaded* nil "T if FFI library loaded successfully")
