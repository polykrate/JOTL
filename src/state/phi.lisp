;;;; state/phi.lisp — Authorization Queue ϕ (GP §13.3)
;;;;
;;;; ϕ ∈ ⟦⟦H⟧A⟧C — C lists of A authorizer hashes.
;;;; Same structure as α. ϕ feeds α.

(in-package #:jotl)

;;; ═══════════════════════════════════════════════════════════════
;;; ϕ — Authorization Queue Closure
;;; ═══════════════════════════════════════════════════════════════

(define-value-object phi
  ((pools nil))
  (:state-key +C2+)
  (:encoded :memo (encode-auth-pools pools)))

(defun encode-state-phi (phi)
  "C(2) ↦ E(ϕ) — uses phi closure's memoized encoding."
  (funcall phi :encoded))
