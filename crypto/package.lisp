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
   #:string-to-blob
   #:blob-to-string
   #:hex-string-to-bytes
   #:bytes-to-hex-string
   
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
   #:H #:HK                ;; H = blake2b, HK = keccak
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
   #:pvm-load-jam-module
   #:pvm-module-free
   #:pvm-prepare
   #:pvm-context
   #:pvm-context-free
   #:pvm-add-storage
   #:pvm-add-preimage
   #:pvm-set-entropy
   #:pvm-add-accumulate-item
   #:pvm-set-gas
   #:pvm-set-protocol-params
   #:pvm-encode-work-item-record
   #:pvm-encode-work-item-v21
   #:pvm-run
   #:pvm-get-balance
   #:pvm-get-transfer-count
   #:pvm-get-log-count
   #:pvm-get-storage-count
   #:pvm-get-storage-entry
   #:pvm-get-all-storage
   #:pvm-get-log-entry
   #:pvm-get-all-logs
   #:pvm-get-transfer-entry
   #:pvm-get-all-transfers
   #:pvm-get-ejected-count
   #:pvm-get-ejected-service
   #:pvm-get-all-ejected
   #:pvm-get-created-service-count
   #:pvm-get-created-service
   #:pvm-get-all-created
   #:pvm-set-next-service-id
   #:pvm-has-yield-output
   #:pvm-get-yield-output
   #:with-pvm-context
   
   ;; Library status
   #:*ffi-loaded*
   #:status))

(in-package :jam.ffi)

(defvar *ffi-loaded* nil "T if FFI library loaded successfully")

