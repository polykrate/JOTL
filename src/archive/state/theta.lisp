;;;; state/theta.lisp — Accumulation Outputs θ (GP §7.4, §12.25)
;;;;
;;;; θ ∈ ⟦...⟧ — most recent accumulation outputs.

(in-package #:jotl)

;;; ═══════════════════════════════════════════════════════════════
;;; θ — Accumulation Outputs Closure
;;; ═══════════════════════════════════════════════════════════════

(define-value-object theta
  ((queue nil))
  (:state-key +C16+)
  (:encoded :memo
    (if (null queue)
        (encode-compact 0)
        (encode-sequence queue #'identity))))

(defun encode-state-theta (theta)
  "C(16) ↦ E(θ) — uses theta closure's memoized encoding."
  (funcall theta :encoded))
