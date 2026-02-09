;;;; state/kappa.lisp — κ Current Validator Keys (GP §6.15)
;;;;
;;;; κ ∈ K^V — Array of V full validator keys
;;;; K = (ke, kb, kbl, km)
;;;;
;;;; GP (4.9): κ' < (H, τ, κ, γ)
;;;;
;;;; Messages:
;;;;   :validators            → list of validator key plists
;;;;   :encoded               → encoded validator sequence
;;;;   :transition :tau τ :tau-prime τ' :gamma γ → κ' closure

(in-package #:jotl)

(define-state-closure kappa-state
  ((validators nil))
  (:state-key +C8+)

  (:encoded :memo (encode-full-validator-sequence validators))

  (:decode (bytes offset)
    (multiple-value-bind (vals consumed)
        (decode-full-validator-sequence bytes offset)
      (values (make-kappa-state :validators vals) consumed)))

  ;; GP §6.15: κ' = γk if epoch change, else κ
  (:transition (&key tau tau-prime gamma)
    (if (funcall tau :epoch-changed? tau-prime)
        (let ((gamma-k (funcall gamma :kappa)))
          (make-kappa-state :validators (or gamma-k validators)))
        (self :type)  ;; return self (no change) — FIXME: need :self message
        )))
