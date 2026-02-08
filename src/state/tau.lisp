;;;; stf/tau.lisp — Timeslot STF (Gray Paper §6.1-6.2)
;;;;
;;;; τ' ≡ HT                          (6.1)
;;;; let e' ℛ m' = τ'/E               (6.2)
;;;;
;;;; The STF takes τ (a number) and H (closure), returns τ' (a number).

(in-package #:jotl)

;;; ═════════════════════════════════════════════════════════════════
;;; VALUE OBJECT — τ closure
;;; ═════════════════════════════════════════════════════════════════
;;; τ is a single integer (timeslot). The closure wraps it for uniform
;;; state storage and Merkle generation. Arithmetic uses the raw number
;;; extracted via (funcall tau :value).

(define-value-object tau-state
  ((value 0))
  (:state-key +C11+)
  (:encoded :memo (E4 value)))

;;; ═════════════════════════════════════════════════════════════════
;;; EUCLIDEAN DIVISION (GP §6.2)
;;; ═════════════════════════════════════════════════════════════════

(defun timeslot-to-epoch-and-phase (timeslot)
  "τ/E → (values e m)"
  (floor timeslot (epoch-duration)))

(defun timeslot-epoch (timeslot)
  "e = ⌊τ/E⌋"
  (floor timeslot (epoch-duration)))

(defun timeslot-phase (timeslot)
  "m = τ mod E"
  (mod timeslot (epoch-duration)))

(defun epoch-phase-to-timeslot (epoch phase)
  "Inverse: (e, m) → τ = e·E + m"
  (+ (* epoch (epoch-duration)) phase))

;;; ═════════════════════════════════════════════════════════════════
;;; EPOCH BOUNDARY
;;; ═════════════════════════════════════════════════════════════════

(defun new-epoch-p (tau tau-prime)
  "T if τ→τ' crosses an epoch boundary."
  (> (timeslot-epoch tau-prime) (timeslot-epoch tau)))

;;; ═════════════════════════════════════════════════════════════════
;;; STATE CODEC — C(11) ↦ E4(τ)
;;; ═════════════════════════════════════════════════════════════════

(defun encode-state-tau (tau)
  "C(11) ↦ E4(τ) — uses tau closure's memoized encoding."
  (funcall tau :encoded))

(defun decode-state-tau (bytes &optional (offset 0))
  "Decode τ from 4 bytes LE. Returns: (values tau-closure 4)"
  (multiple-value-bind (val consumed)
      (decode-u32 bytes offset)
    (values (make-tau-state :value val) consumed)))

;;; ═════════════════════════════════════════════════════════════════
;;; τ STF (GP §5.7 + §6.1-6.2)
;;; ═════════════════════════════════════════════════════════════════

(defun timeslot-from-header (header)
  "Extract τ' ≡ HT from header closure."
  (funcall header :slot))

(defun transition-tau (tau header)
  "τ STF: τ (number) → τ' (number)
   
   GP §5.7: τ' > τ
   GP §6.1: τ' ≡ HT
   
   e', m', new-epoch-p are derivable on demand via
   (timeslot-to-epoch-and-phase τ') and (new-epoch-p τ τ')."
  (let ((tau-prime (timeslot-from-header header)))
    (assert (> tau-prime tau) ()
            "GP §5.7: τ'=~D must be > τ=~D" tau-prime tau)
    tau-prime))
