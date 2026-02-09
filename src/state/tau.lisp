;;;; state/tau.lisp — Timeslot τ (Gray Paper §6.1-6.2)
;;;;
;;;; τ' ≡ HT                          (6.1)
;;;; let e' ℛ m' = τ'/E               (6.2)
;;;;
;;;; The closure pre-computes epoch, phase, and rotation so that any
;;;; STF can access them via (funcall tau :epoch), (funcall tau :phase), etc.
;;;;
;;;; After transition-tau, the enriched closure also embeds τ' (prime):
;;;;   (funcall tau :prime)               → τ' closure
;;;;   (funcall (funcall tau :prime) :epoch)  → ⌊τ'/E⌋

(in-package #:jotl)

;;; ═════════════════════════════════════════════════════════════════
;;; VALUE OBJECT — τ closure
;;; ═════════════════════════════════════════════════════════════════
;;;
;;; Fields:
;;;   :value    — raw timeslot integer (persisted in σ)
;;;   :prime    — nil | tau-state closure for τ' (ephemeral, set by transition-tau)
;;;
;;; Memoized:
;;;   :epoch    — ⌊value/E⌋
;;;   :phase    — value mod E
;;;   :rotation — ⌊value/R⌋

(define-value-object tau-state
  ((value 0) (prime nil))
  (:state-key +C11+)
  ;; Only :value is persisted in σ (4 bytes LE).  :prime is ephemeral.
  (:encoded :memo (E4 value))
  ;; GP §6.2 — e ℛ m = τ/E
  (:epoch    :memo (floor value (epoch-duration)))
  (:phase    :memo (mod value (epoch-duration)))
  ;; GP §11.3 — rotation index
  (:rotation :memo (floor value (rotation-period))))

;;; ═════════════════════════════════════════════════════════════════
;;; EPOCH BOUNDARY
;;; ═════════════════════════════════════════════════════════════════

(defun new-epoch-p (tau)
  "T if τ→τ' crosses an epoch boundary.
   tau is an enriched tau-state closure with :prime."
  (let ((tp (funcall tau :prime)))
    (and tp (/= (funcall tau :epoch) (funcall tp :epoch)))))

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

(defun transition-tau (tau header)
  "τ STF: τ (closure) → enriched τ (closure with :prime)
   
   GP §5.7: τ' > τ
   GP §6.1: τ' ≡ HT
   
   Returns an enriched tau-state closure:
     (funcall result :value)  → τ  (prior)
     (funcall result :prime)  → τ' closure (posterior)
     (funcall (funcall result :prime) :epoch) → ⌊τ'/E⌋
   This single enriched object is passed to every sub-STF."
  (let ((tau-prime-val (funcall header :slot)))
    (assert (> tau-prime-val (funcall tau :value)) ()
            "GP §5.7: τ'=~D must be > τ=~D" tau-prime-val (funcall tau :value))
    (make-tau-state :value (funcall tau :value)
                    :prime (make-tau-state :value tau-prime-val))))
