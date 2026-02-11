;;;; state/chi.lisp — χ Privileged Service Indices (GP §9.4)
;;;;
;;;; χ = (χ_m, χ_a, χ_v, χ_r, χ_z)
;;;; χ_m : manager (blessed) service index
;;;; χ_a : authorizer-assignment service index
;;;; χ_v : designate service index
;;;; χ_r : (reserved)
;;;; χ_z : always-accumulate services + gas map
;;;;
;;;; No :transition — modified by transition-accumulate (accumulate.lisp).
;;;; Merkle key: C(12).
;;;;
;;;; Messages:
;;;;   :raw              → raw segment bytes (skeleton mode)
;;;;   :encoded          → binary encoding
;;;;   :decode           → reconstruct from bytes

(in-package #:jotl)

;;; Raw-bytes wrapper — will be replaced with real codec when §12.2 is implemented.
(define-state-closure chi-state
  ((raw nil))

  (:encoded raw)

  (:decode (bytes offset)
    (values (make-chi-state :raw (subseq bytes offset))
            (- (length bytes) offset))))
