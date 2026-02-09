;;;; stf/pi.lisp — Validator Activity Statistics π (GP §15)
;;;;
;;;; π ∈ ⟦(blocks:N2, tickets:N2, preimages:N2, guarantees:N2)⟧V
;;;; One stats entry per validator.

(in-package #:jotl)

;;; ═══════════════════════════════════════════════════════════════
;;; π — Validator Statistics Closure
;;; ═══════════════════════════════════════════════════════════════

(define-value-object pi-segment
  ((stats nil))
  (:state-key +C13+)
  (:encoded :memo
    (if (null stats)
        (encode-compact 0)
        (encode-sequence stats
                         (lambda (s)
                           (concatenate '(vector (unsigned-byte 8))
                                        (E4 (or (getf s :blocks) 0))
                                        (E4 (or (getf s :tickets) 0))
                                        (E4 (or (getf s :preimages) 0))
                                        (E4 (or (getf s :guarantees) 0))))))))

(defun encode-state-pi (pi-seg)
  "C(13) ↦ E(π) — uses pi-segment closure's memoized encoding."
  (funcall pi-seg :encoded))

;;; ═══════════════════════════════════════════════════════════════
;;; TRANSITION — π' (GP §4.20)
;;; ═══════════════════════════════════════════════════════════════

(defun transition-pi (guarantees preimages assurances tickets
                      tau kappa-prime pi-prev header s-reports)
  "GP §4.20 — Validator statistics. STUB: §15"
  (declare (ignore guarantees preimages assurances tickets
                   tau kappa-prime header s-reports))
  pi-prev)
