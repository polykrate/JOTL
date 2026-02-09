;;;; state/omega.lisp — Accumulation Queue ω (GP §12.3)
;;;;
;;;; ω ∈ ⟦(s:NS, p:H, x:Y)⟧ — ready work-reports.

(in-package #:jotl)

;;; ═══════════════════════════════════════════════════════════════
;;; ω — Accumulation Queue Closure
;;; ═══════════════════════════════════════════════════════════════

(define-value-object omega
  ((reports nil))
  (:state-key +C14+)
  (:encoded :memo
    (if (null reports)
        (encode-compact 0)
        (encode-sequence reports
                         (lambda (report)
                           (concatenate '(vector (unsigned-byte 8))
                                        (E4 (or (getf report :service) 0))
                                        (encode-hash-32
                                         (or (getf report :hash) +zero-hash+))
                                        (let ((payload (getf report :payload)))
                                          (if payload
                                              (concatenate '(vector (unsigned-byte 8))
                                                           (encode-compact (length payload))
                                                           payload)
                                              (encode-compact 0)))))))))

(defun encode-state-omega (omega)
  "C(14) ↦ E(ω) — uses omega closure's memoized encoding."
  (funcall omega :encoded))
