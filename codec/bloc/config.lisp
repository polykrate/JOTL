;;;; config.lisp
;;;; JAM Chainspec Configuration Parameters

(in-package :jotl-bloc)

;;; Chainspec parameters for tiny and full chains
;;; Based on w3f/jamtestvectors README.md

(defstruct chainspec
  "JAM Chain Specification Parameters"
  (name nil :type symbol)                     ; :tiny or :full
  (num-validators 6 :type integer)            ; Number of validators
  (num-cores 2 :type integer)                 ; Number of cores
  (preimage-expunge-period 32 :type integer)  ; Preimage expunge period
  (slot-duration 6 :type integer)             ; Slot duration in seconds
  (epoch-duration 12 :type integer)           ; Epoch duration in slots
  (contest-duration 10 :type integer)         ; Contest duration
  (tickets-per-validator 3 :type integer)     ; Tickets per validator
  (max-tickets-per-extrinsic 3 :type integer) ; Max tickets per extrinsic
  (rotation-period 4 :type integer)           ; Rotation period
  (num-ec-pieces-per-segment 1026 :type integer) ; EC pieces per segment
  (max-block-gas 20000000 :type integer)      ; Max block gas
  (max-refine-gas 1000000000 :type integer)   ; Max refine gas
  (avail-bitfield-bytes 1 :type integer))     ; Availability bitfield size (bytes)

;;; Tiny chainspec (for testing)
(defparameter *tiny-chainspec*
  (make-chainspec
   :name :tiny
   :num-validators 6
   :num-cores 2
   :preimage-expunge-period 32
   :slot-duration 6
   :epoch-duration 12
   :contest-duration 10
   :tickets-per-validator 3
   :max-tickets-per-extrinsic 3
   :rotation-period 4
   :num-ec-pieces-per-segment 1026
   :max-block-gas 20000000
   :max-refine-gas 1000000000
   :avail-bitfield-bytes 1)
  "Tiny chainspec for testing (6 validators)")

;;; Full chainspec (matches Gray Paper)
(defparameter *full-chainspec*
  (make-chainspec
   :name :full
   :num-validators 1023
   :num-cores 341
   :preimage-expunge-period 19200
   :slot-duration 6
   :epoch-duration 600
   :contest-duration 500
   :tickets-per-validator 2
   :max-tickets-per-extrinsic 16
   :rotation-period 10
   :num-ec-pieces-per-segment 6
   :max-block-gas 3500000000
   :max-refine-gas 5000000000
   :avail-bitfield-bytes 43)
  "Full chainspec matching Gray Paper (1023 validators)")

;;; Default chainspec (tiny for testing)
(defparameter *default-chainspec* *tiny-chainspec*
  "Default chainspec (tiny)")

;;; Current active chainspec
(defparameter *chainspec* *default-chainspec*
  "Currently active chainspec")

;;; Convenience function to switch chainspec
(defun set-chainspec (spec)
  "Set the active chainspec.
   
   Args:
     spec: :tiny, :full, or a chainspec structure
   
   Examples:
     (set-chainspec :tiny)
     (set-chainspec :full)
     (set-chainspec (make-chainspec ...))"
  (setf *chainspec*
        (cond
          ((eq spec :tiny) *tiny-chainspec*)
          ((eq spec :full) *full-chainspec*)
          ((chainspec-p spec) spec)
          (t (error "Invalid chainspec: ~A. Use :tiny, :full, or a chainspec structure." spec))))
  ;; Update dynamic *validators-super-majority* based on new chainspec
  (setf *validators-super-majority* (validators-super-majority (chainspec-num-validators *chainspec*)))
  (format t "Chainspec set to: ~A (~A validators, VSM ~A)~%"
          (chainspec-name *chainspec*)
          (chainspec-num-validators *chainspec*)
          *validators-super-majority*)
  *chainspec*)

;;; Dynamic variable for validators super-majority (can be rebound locally)
(defvar *validators-super-majority* 5
  "Dynamic variable holding the current validators super-majority threshold.
   Defaults to 5 (for tiny chainspec with 6 validators).
   Can be dynamically rebound in decode/encode-chain-block based on header's epoch-marker.")

;;; Helper to get current num-validators
(defun num-validators ()
  "Get the current number of validators from active chainspec."
  (chainspec-num-validators *chainspec*))

(defun epoch-duration ()
  "Get the current epoch duration from active chainspec."
  (chainspec-epoch-duration *chainspec*))

(defun validators-super-majority (&optional (num-vals (num-validators)))
  "Calculate validators super-majority: ceil(num-validators * 2/3 + 1).
   
   This is the minimum number of validator signatures required for a super-majority
   consensus, used in judgements within disputes.
   
   Args:
     num-vals: Number of validators (defaults to current chainspec)
   
   Returns:
     Integer representing the super-majority threshold
   
   Examples:
     For tiny (6 validators): ceil(6 * 2/3 + 1) = ceil(5) = 5
     For full (1023 validators): ceil(1023 * 2/3 + 1) = ceil(683) = 683"
  (ceiling (+ (* num-vals 2/3) 1)))
