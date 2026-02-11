;;;; state/phi.lisp — ϕ Authorization Queue (GP §8.1-8.2)
;;;;
;;;; ϕ ∈ [⟦H⟧_Q]_C  — per-core queue of Q authorized code hashes.
;;;; Q = +auth-queue-size+ = 80.
;;;;
;;;; No :transition — modified by transition-accumulate (accumulate.lisp).
;;;; GP (4.16): ϕ' comes from accumulate.
;;;; Merkle key: C(2).
;;;;
;;;; Messages:
;;;;   :raw              → raw segment bytes (skeleton mode)
;;;;   :encoded          → binary encoding
;;;;   :decode           → reconstruct from bytes

(in-package #:jotl)

;;; Raw-bytes wrapper — will be replaced with real codec when §12.2 is implemented.
(define-state-closure phi-state
  ((raw nil))

  (:encoded raw)

  (:decode (bytes offset)
    (values (make-phi-state :raw (subseq bytes offset))
            (- (length bytes) offset))))
