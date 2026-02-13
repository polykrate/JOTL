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
   
   ;; PVM — JAM-codec API (pvm.lisp + wire.rs)
   #:pvm-new                       ;; create instance from code blob
   #:pvm-free                      ;; free instance
   #:pvm-configure                 ;; load context as one JAM blob
   #:pvm-run                       ;; execute entry point → (status result gas)
   #:pvm-collapse                  ;; resolve Accumulate dual context (GP B.13)
   #:pvm-collect                   ;; read side-effects as one JAM blob
   #:pvm-encode-work-item-record   ;; encode AccumulateItem::WorkItem (jam-types)
   #:pvm-encode-transfer-record    ;; encode AccumulateItem::Transfer (GP 12.24 Δ₁)
   #:with-pvm                      ;; (with-pvm (var blob sid bal slot) ...)
   #:encode-pvm-config             ;; low-level: Lisp → JAM config blob
   #:decode-pvm-side-effects       ;; low-level: JAM blob → Lisp plist
   ;; Debug: host-call tracing (temporary)
   #:pvm-debug-trace-enable
   #:pvm-debug-trace-read
   
   ;; Library status
   #:*ffi-loaded*))

(in-package :jam.ffi)

(defvar *ffi-loaded* nil "T if FFI library loaded successfully")
