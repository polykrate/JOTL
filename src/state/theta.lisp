;;;; state/theta.lisp — θ Accumulation Outputs (GP §7.4, §12.25)
;;;;
;;;; θ = most recent accumulation outputs.
;;;; Used by β' (wave 4) to compute the accumulate root for the Beefy MMR.
;;;; θ is a list of (service-id, hash) pairs produced by accumulation.
;;;;
;;;; No :transition — modified by transition-accumulate (accumulate.lisp).
;;;; Merkle key: C(16).
;;;;
;;;; Messages:
;;;;   :raw              → raw segment bytes (skeleton mode)
;;;;   :encoded          → binary encoding
;;;;   :decode           → reconstruct from bytes

(in-package #:jotl)

;;; Raw-bytes wrapper — will be replaced with real codec when §12.2 is implemented.
(define-state-closure theta-state
  ((raw nil))

  (:encoded raw)

  (:decode (bytes offset)
    (values (make-theta-state :raw (subseq bytes offset))
            (- (length bytes) offset))))
