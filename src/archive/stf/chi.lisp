;;;; state/chi.lisp — Privileged Service IDs χ (GP §9.9)
;;;;
;;;; χ = (χM, χA, χV, χR, χZ) — privileged service indices.

(in-package #:jotl)

;;; ═══════════════════════════════════════════════════════════════
;;; χ — Privileged Service IDs Closure
;;; ═══════════════════════════════════════════════════════════════

(define-value-object chi
  ((manager 0) (assign 0) (designate 0) (empower 0))
  (:state-key +C12+)
  (:encoded :memo
    (concatenate '(vector (unsigned-byte 8))
                 (E4 manager) (E4 assign) (E4 designate) (E4 empower))))

(defun encode-state-chi (chi)
  "C(12) ↦ E(χ) — uses chi closure's memoized encoding."
  (funcall chi :encoded))
