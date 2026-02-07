;;;; package.lisp - Package definitions for JOTL

(defpackage #:jotl
  (:use #:cl #:alexandria)
  (:import-from #:jam.ffi
                #:blake2b-256
                #:keccak-256
                #:hex-string-to-bytes
                #:bytes-to-hex-string)
  (:documentation "JAM On The Lisp - Pure Functional Programming")
  (:export
   ;; Constants
   #:*chain*
   #:chain
   #:switch-chain
   #:with-chain
   
   ;; Constant accessors
   #:num-validators
   #:num-cores
   #:slot-duration
   #:epoch-duration
   #:max-block-gas
   #:max-refine-gas
   #:preimage-expunge-period
   #:contest-duration
   #:tickets-per-validator
   #:max-tickets-per-extrinsic
   #:rotation-period
   #:num-ec-pieces-per-segment
   
   ;; Timeslot
   #:timeslot-to-epoch-and-phase
   #:timeslot-epoch
   #:timeslot-phase
   #:epoch-phase-to-timeslot
   #:new-epoch-p
   #:timeslot-state-key
   #:get-timeslot-from-state
   #:set-timeslot-in-state
   
   ;; Block (Gray Paper §4)
   #:make-block
   #:block-header
   #:block-extrinsic
   #:block-tickets
   #:block-disputes
   #:block-preimages
   #:block-assurances
   #:block-guarantees
   #:block-slot
   
   ;; Header (Gray Paper §5)
   #:make-header
   #:header-parent-hash
   #:header-state-root
   #:header-extrinsic-hash
   #:header-slot
   #:header-epoch-mark
   #:header-tickets-mark
   #:header-author-index
   #:header-entropy-source
   #:header-offenders-mark
   #:header-seal
   #:header-hash
   #:header-is-genesis-p
   #:+ancestor-retention-hours+
   #:compute-ancestor-set
   #:is-ancestor-p
  #:compute-extrinsic-hash
  #:parent-function
  #:compute-parent-hash
  #:validate-parent-hash
  #:validate-timeslot
  #:timeslot-in-past-p
  #:timeslot-greater-than-parent-p
  
  ;; Block Validation (Gray Paper §5)
  #:validate-extrinsic-hash
  #:validate-header
  #:validate-block
  #:validate-block-from-binary
   
  ;; Extrinsic (Gray Paper §4.3)
  #:make-extrinsic
  #:extrinsic-tickets
  #:extrinsic-disputes
  #:extrinsic-preimages
  #:extrinsic-assurances
  #:extrinsic-guarantees
  
  ;; Header & Extrinsic Encoding/Decoding
  #:encode-header
  #:decode-header
  #:encode-extrinsic
  #:decode-extrinsic
  
  ;; Merkle Trie (Gray Paper Appendix D)
   #:trie-bit
   #:trie-branch
   #:trie-leaf
   #:merkle-root
   #:compute-state-root
   #:pad-key-to-32
   
   ;; Crypto (re-exported from jam.ffi)
   #:blake2b-256
   #:keccak-256
   #:hex-string-to-bytes
   #:bytes-to-hex-string
   
   ;; Version
   #:*jotl-version*))
