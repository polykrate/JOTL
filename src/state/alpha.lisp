;;;; state/alpha.lisp — α Core Authorizations Pool (GP §8.1)
;;;;
;;;; α ∈ [⟦H⟧_O]_C  — per-core pool of at most O authorized code hashes.
;;;; O = +max-auth-pool+ = 8.
;;;;
;;;; GP (4.19): α' < (H, EC, ϕ', α)
;;;; Modified by wave 4 alpha transition, NOT by accumulate directly.
;;;; But ϕ' (from accumulate) feeds into α'.
;;;; Merkle key: C(1).
;;;;
;;;; Messages:
;;;;   :raw              → raw segment bytes (skeleton mode)
;;;;   :encoded          → binary encoding
;;;;   :decode           → reconstruct from bytes

(in-package #:jotl)

;;; Raw-bytes wrapper — will be replaced with real codec when §8 is implemented.
(define-state-closure alpha-state
  ((raw nil))

  (:encoded raw)

  (:decode (bytes offset)
    (values (make-alpha-state :raw (subseq bytes offset))
            (- (length bytes) offset))))
