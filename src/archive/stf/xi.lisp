;;;; state/xi.lisp — Accumulation History ξ (GP §12.1)
;;;;
;;;; ξ ∈ ⟦⟦H⟧⟧ — list of lists of work-package hashes.

(in-package #:jotl)

;;; ═══════════════════════════════════════════════════════════════
;;; ξ — Accumulation History Closure
;;; ═══════════════════════════════════════════════════════════════

(define-value-object xi
  ((accumulations nil))
  (:state-key +C15+)
  (:encoded :memo
    (if (null accumulations)
        (encode-compact 0)
        (encode-sequence accumulations
                         (lambda (epoch-accs)
                           (encode-sequence epoch-accs #'encode-hash-32))))))

(defun encode-state-xi (xi)
  "C(15) ↦ E(ξ) — uses xi closure's memoized encoding."
  (funcall xi :encoded))
