;;;; stf/tau.lisp — Timeslot STF (Gray Paper §6.1-6.2)
;;;;
;;;; τ' ≡ HT                          (6.1)
;;;; let e' ℛ m' = τ'/E               (6.2)
;;;;
;;;; The STF takes τ (a number) and H (closure), returns τ' (a number).

(in-package #:jotl)

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
;;; τ STF (GP §5.7 + §6.1-6.2)
;;; ═════════════════════════════════════════════════════════════════

(defun timeslot-from-header (header)
  "Extract τ' ≡ HT from header closure."
  (funcall header :slot))

(defun apply-timeslot-transition (tau header)
  "τ STF: τ → (values τ' e' m' new-epoch-p)
   
   GP §5.7: τ' > τ
   GP §6.1: τ' ≡ HT
   GP §6.2: e' ℛ m' = τ'/E"
  (let ((tau-prime (timeslot-from-header header)))
    (assert (> tau-prime tau) ()
            "GP §5.7: τ'=~D must be > τ=~D" tau-prime tau)
    (multiple-value-bind (e-prime m-prime)
        (timeslot-to-epoch-and-phase tau-prime)
      (values tau-prime e-prime m-prime (new-epoch-p tau tau-prime)))))
