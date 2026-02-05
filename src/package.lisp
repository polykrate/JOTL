;;;; package.lisp
;;;; Package definition for JOTL configuration
;;;;
;;;; This is the top-level configuration module, loaded before codec modules.
;;;; It contains chainspec parameters used across bloc, state, and STF modules.

(defpackage #:jotl-config
  (:use #:cl)
  (:documentation "JAM protocol configuration and chainspec parameters")
  (:export
   
   ;; ══════════════════════════════════════════════════════════════
   ;; CHAINSPEC CONFIGURATION (Network Parameters)
   ;; ══════════════════════════════════════════════════════════════
   
   #:chainspec
   #:make-chainspec
   #:chainspec-p
   #:chainspec-name
   #:chainspec-num-validators
   #:chainspec-num-cores
   #:chainspec-preimage-expunge-period
   #:chainspec-slot-duration
   #:chainspec-epoch-duration
   #:chainspec-contest-duration
   #:chainspec-tickets-per-validator
   #:chainspec-max-tickets-per-extrinsic
   #:chainspec-rotation-period
   #:chainspec-num-ec-pieces-per-segment
   #:chainspec-max-block-gas
   #:chainspec-max-refine-gas
   #:chainspec-avail-bitfield-bytes
   
   ;; Predefined chainspecs
   #:*tiny-chainspec*           ; Tiny test network (6 validators)
   #:*full-chainspec*           ; Full network (1023 validators)
   #:*default-chainspec*        ; Default chainspec
   #:*chainspec*                ; Currently active chainspec
   #:set-chainspec              ; Switch active chainspec
   
   ;; Dynamic configuration (locally rebound in decode/encode)
   #:*validators-super-majority*  ; Dynamic var: current super-majority threshold
   #:validators-super-majority    ; Function: ceil(num-validators * 2/3 + 1)
   
  ;; Helper functions
  #:num-validators
  #:epoch-duration
  #:slot-duration
  #:max-tickets-per-extrinsic
  
  ;; ══════════════════════════════════════════════════════════════
  ;; COMMON JAM TYPES (Graypaper Section 3)
  ;; ══════════════════════════════════════════════════════════════
  
  ;; Basic types
  #:hash
  #:hash32
  #:hash256
  #:blob
  #:natural
  #:natural-limited
  #:length-type
  
  ;; Crypto types
  #:ed25519-public-key
  #:ed25519-signature
  #:bandersnatch-public-key
  #:bandersnatch-signature
  #:bls-public-key
  #:bls-signature
  
  ;; JAM identifiers
  #:service-id
  #:core-id
  #:timeslot
  #:gas-amount
  
  ;; Helper functions
  #:list-to-blob
  #:blob-to-list
  #:hash-zero
  #:hash32-p))
