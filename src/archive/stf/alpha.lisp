;;;; state/alpha.lisp — Core Authorizations α (GP §8.1, §13)
;;;;
;;;; α ∈ ⟦⟦H⟧A⟧C — C lists of A authorizer hashes.

(in-package #:jotl)

;;; ═══════════════════════════════════════════════════════════════
;;; α — Core Authorizations Closure
;;; ═══════════════════════════════════════════════════════════════

(define-value-object alpha
  ((pools nil))
  (:state-key +C1+)
  (:encoded :memo (encode-auth-pools pools)))

(defun encode-state-alpha (alpha)
  "C(1) ↦ E(α) — uses alpha closure's memoized encoding."
  (funcall alpha :encoded))

;;; ═══════════════════════════════════════════════════════════════
;;; TRANSITION — α' (GP §4.19)
;;; ═══════════════════════════════════════════════════════════════

(defun transition-alpha (header guarantees phi-prime alpha)
  "GP §4.19 — Core authorizations. STUB: §13"
  (declare (ignore header guarantees phi-prime)) alpha)
