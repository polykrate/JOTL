;;;; stf/alpha.lisp — Core Authorizations α & Authorization Queue ϕ (GP §13)
;;;;
;;;; α ∈ ⟦⟦H⟧A⟧C — C lists of A authorizer hashes.
;;;; ϕ has same structure as α: ⟦⟦H⟧A⟧C.
;;;;
;;;; α and ϕ are tightly coupled: ϕ feeds α.

(in-package #:jotl)

;;; ═══════════════════════════════════════════════════════════════
;;; SHARED ENCODER — same structure for α and ϕ
;;; ═══════════════════════════════════════════════════════════════

(defun encode-auth-pools (pools)
  "Encode core authorization pools.
   pools = list of C lists of 32-byte authorizer hashes."
  (if (null pools)
      (encode-compact 0)
      (encode-sequence pools
                       (lambda (core-auths)
                         (encode-sequence core-auths #'encode-hash-32)))))

;;; ═══════════════════════════════════════════════════════════════
;;; α — Core Authorizations (GP §13)
;;; ═══════════════════════════════════════════════════════════════

(define-value-object alpha
  ((pools nil))
  (:state-key +C1+)
  (:encoded :memo (encode-auth-pools pools)))

(defun encode-state-alpha (alpha)
  "C(1) ↦ E(α) — uses alpha closure's memoized encoding."
  (funcall alpha :encoded))

;;; ═══════════════════════════════════════════════════════════════
;;; ϕ — Authorization Queue (GP §13.3)
;;; ═══════════════════════════════════════════════════════════════

(define-value-object phi
  ((pools nil))
  (:state-key +C2+)
  (:encoded :memo (encode-auth-pools pools)))

(defun encode-state-phi (phi)
  "C(2) ↦ E(ϕ) — uses phi closure's memoized encoding."
  (funcall phi :encoded))

;;; ═══════════════════════════════════════════════════════════════
;;; TRANSITION — α' (GP §4.19)
;;; ═══════════════════════════════════════════════════════════════

(defun transition-alpha (header guarantees phi-prime alpha)
  "GP §4.19 — Core authorizations. STUB: §13"
  (declare (ignore header guarantees phi-prime)) alpha)
