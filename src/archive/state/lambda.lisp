;;;; stf/lambda.lisp — λ (Archived Validator Keys)
;;;; Gray Paper §6.16
;;;;
;;;; λ ∈ K^V — Array of V full validator keys (prior epoch).
;;;; K = (ke, kb, kbl, km) = ed25519(32) + bandersnatch(32) + bls(144) + metadata(128)
;;;;
;;;; State key: C(9)
;;;; Transition: λ' = κ if epoch change, else λ  (§6.16)

(in-package #:jotl)

;;; ═══════════════════════════════════════════════════════════════
;;; VALUE OBJECT — λ closure
;;; ═══════════════════════════════════════════════════════════════
;;; CL reserves `lambda`, so value object is named `lambda-state`.
;;; Constructor: make-lambda-state. Access: (funcall λ :validators).

(define-value-object lambda-state
  ((validators nil))
  (:state-key +C9+)
  (:encoded :memo (encode-full-validator-sequence validators)))

;;; ═══════════════════════════════════════════════════════════════
;;; STATE CODEC — C(9) ↦ E(λ)
;;; ═══════════════════════════════════════════════════════════════

(defun encode-state-lambda (lambda-keys)
  "C(9) ↦ E(λ) — uses lambda closure's memoized encoding."
  (funcall lambda-keys :encoded))

(defun decode-state-lambda (bytes &optional (offset 0))
  "Decode λ from state binary.
   Returns: (values lambda-closure bytes-consumed)"
  (multiple-value-bind (validators consumed)
      (decode-full-validator-sequence bytes offset)
    (values (make-lambda-state :validators validators) consumed)))

;;; ═══════════════════════════════════════════════════════════════
;;; λ TRANSITION — GP §6.16
;;; ═══════════════════════════════════════════════════════════════
;;;
;;; λ' ≡ κ     if e' > e     (epoch change: archive current keys)
;;;      λ     otherwise     (no change)

(defun transition-lambda (tau lambda-prev kappa)
  "GP §6.16 — Archive current validator keys at epoch boundary.

   At epoch change: λ' = κ (current keys become archived).
   Otherwise: λ' = λ (unchanged).

   Args: tau (enriched τ closure with :prime),
         lambda-prev (λ closure), kappa (κ closure)
   Returns: λ' closure"
  (if (new-epoch-p tau)
      ;; Epoch change: archive current validators
      (make-lambda-state :validators (funcall kappa :validators))
      ;; No change
      lambda-prev))
