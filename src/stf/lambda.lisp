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
;;; STATE CODEC — C(9) ↦ E(λ)
;;; ═══════════════════════════════════════════════════════════════

(defun encode-state-lambda (lambda-keys)
  "C(9) ↦ E(λ) — V × 336 bytes (fixed size, no length prefix)."
  (encode-full-validator-sequence lambda-keys))

(defun decode-state-lambda (bytes &optional (offset 0))
  "Decode λ from state binary.
   Returns: (values list-of-validators bytes-consumed)"
  (decode-full-validator-sequence bytes offset))

;;; ═══════════════════════════════════════════════════════════════
;;; λ TRANSITION — GP §6.16
;;; ═══════════════════════════════════════════════════════════════
;;;
;;; λ' ≡ κ     if e' > e     (epoch change: archive current keys)
;;;      λ     otherwise     (no change)

(defun transition-lambda (header tau lambda-prev kappa)
  "GP §6.16 — Archive current validator keys at epoch boundary.

   At epoch change: λ' = κ (current keys become archived).
   Otherwise: λ' = λ (unchanged).

   Args: header (closure), tau (prior timeslot),
         lambda-prev (list of V validators), kappa (list of V validators)
   Returns: λ'"
  (let ((tau-prime (funcall header :slot)))
    (if (new-epoch-p tau tau-prime)
        kappa        ;; Epoch change: archive current
        lambda-prev))) ;; No change
