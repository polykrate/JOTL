;;;; stf/kappa.lisp — κ (Current Validator Keys)
;;;; Gray Paper §6.15
;;;;
;;;; κ ∈ K^V — Array of V full validator keys.
;;;; K = (ke, kb, kbl, km) = ed25519(32) + bandersnatch(32) + bls(144) + metadata(128)
;;;;
;;;; State key: C(8)
;;;; Transition: κ' = γk if epoch change, else κ  (§6.15)

(in-package #:jotl)

;;; ═══════════════════════════════════════════════════════════════
;;; STATE CODEC — C(8) ↦ E(κ)
;;; ═══════════════════════════════════════════════════════════════

(defun encode-state-kappa (kappa)
  "C(8) ↦ E(κ) — V × 336 bytes (fixed size, no length prefix)."
  (encode-full-validator-sequence kappa))

(defun decode-state-kappa (bytes &optional (offset 0))
  "Decode κ from state binary.
   Returns: (values list-of-validators bytes-consumed)"
  (decode-full-validator-sequence bytes offset))

;;; ═══════════════════════════════════════════════════════════════
;;; κ TRANSITION — GP §6.15
;;; ═══════════════════════════════════════════════════════════════
;;;
;;; κ' ≡ γk    if e' > e     (epoch change: adopt pending keys)
;;;      κ     otherwise     (no change)

(defun transition-kappa (header tau kappa gamma)
  "GP §6.15 — Validator key rotation at epoch boundary.

   At epoch change: κ' = γk (pending keys become current).
   Otherwise: κ' = κ (unchanged).

   Args: header (closure), tau (prior timeslot),
         kappa (list of V validators), gamma (γ closure or plist)
   Returns: κ'"
  (let ((tau-prime (funcall header :slot)))
    (if (new-epoch-p tau tau-prime)
        ;; Epoch change: adopt pending keys from γ
        (let ((gamma-k (if (functionp gamma)
                           (funcall gamma :kappa)
                           (getf gamma :kappa))))
          (or gamma-k kappa))
        ;; No change
        kappa)))
