;;;; state/lambda.lisp — λ Archived Validator Keys (GP §6.16)
;;;;
;;;; λ ∈ K^V — Array of V full validator keys (prior epoch)
;;;;
;;;; GP (4.10): λ' < (H, τ, λ, κ)
;;;;
;;;; Messages:
;;;;   :validators            → list of validator key plists
;;;;   :encoded               → encoded validator sequence
;;;;   :transition :tau τ :tau-prime τ' :kappa κ → λ' closure

(in-package #:jotl)

(define-state-closure lambda-state
  ((validators nil))
  (:state-key +C9+)

  (:encoded :memo (encode-full-validator-sequence validators))

  (:decode (bytes offset)
    (multiple-value-bind (vals consumed)
        (decode-full-validator-sequence bytes offset)
      (values (make-lambda-state :validators vals) consumed)))

  ;; GP §6.16: λ' = κ if epoch change, else λ
  (:transition (&key tau tau-prime kappa)
    (if (funcall tau :epoch-changed? tau-prime)
        (make-lambda-state :validators (funcall kappa :validators))
        (self :type)  ;; return self (no change) — FIXME: need :self message
        )))
