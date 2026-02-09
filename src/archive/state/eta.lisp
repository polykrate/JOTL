;;;; stf/eta.lisp — Entropy η (Gray Paper §6.21-6.23)
;;;;
;;;; η ∈ ⟦H⟧₄                                                   (6.21)
;;;;
;;;; η₀ : randomness accumulator (updated every block)
;;;; η₁ : accumulator at end of most recently ended epoch
;;;; η₂ : accumulator at end of second-most recent epoch
;;;; η₃ : accumulator at end of third-most recent epoch
;;;;
;;;; η'₀ ≡ H(η₀ ⌢ Y(HV))                                       (6.22)
;;;;
;;;; η'₁, η'₂, η'₃ ≡                                            (6.23)
;;;;   (η₀, η₁, η₂)  if e' > e   (epoch change: rotate)
;;;;   (η₁, η₂, η₃)  otherwise   (no change)

(in-package #:jotl)

;;; ═══════════════════════════════════════════════════════════════
;;; VALUE OBJECT — η closure
;;; ═══════════════════════════════════════════════════════════════

(define-value-object eta
  ((eta-0 nil) (eta-1 nil) (eta-2 nil) (eta-3 nil))
  (:state-key +C6+)
  (:as-list (list eta-0 eta-1 eta-2 eta-3))
  (:encoded :memo
    (concatenate '(vector (unsigned-byte 8))
                 (or eta-0 +zero-hash+)
                 (or eta-1 +zero-hash+)
                 (or eta-2 +zero-hash+)
                 (or eta-3 +zero-hash+))))

;;; ═══════════════════════════════════════════════════════════════
;;; STATE CODEC — C(6) ↦ E(η)
;;; ═══════════════════════════════════════════════════════════════

(defun encode-state-eta (eta)
  "C(6) ↦ E(η) — uses eta closure's memoized encoding (128 bytes)."
  (funcall eta :encoded))

(defun decode-state-eta (bytes &optional (offset 0))
  "Decode η from 128 bytes: 4 × 32-byte hashes.
   Returns: (values eta-closure 128)"
  (values (make-eta :eta-0 (subseq bytes offset (+ offset 32))
                    :eta-1 (subseq bytes (+ offset 32) (+ offset 64))
                    :eta-2 (subseq bytes (+ offset 64) (+ offset 96))
                    :eta-3 (subseq bytes (+ offset 96) (+ offset 128)))
          128))

;;; ═══════════════════════════════════════════════════════════════
;;; η STF (GP §6.21-6.23)
;;; ═══════════════════════════════════════════════════════════════

(defun transition-eta (header tau eta)
  "GP §6.21-6.23 — Entropy accumulator transition.
   
   η  = eta closure
   τ  = enriched tau closure (:value τ, :prime τ' closure)
   header = closure with :entropy-source (Y(HV))
   
   Returns: η' = eta closure"
  (let* ((entropy-source  (funcall header :entropy-source))  ;; Y(HV)
         ;; Destructure η
         (eta-0 (funcall eta :eta-0))
         (eta-1 (funcall eta :eta-1))
         (eta-2 (funcall eta :eta-2))
         (eta-3 (funcall eta :eta-3))
         ;; GP §6.22: η'₀ ≡ H(η₀ ⌢ Y(HV))
         (eta-0-prime (blake2b-256
                       (concatenate '(vector (unsigned-byte 8))
                                    eta-0 entropy-source)))
         ;; GP §6.2: epoch indices
         (epoch-change-p (new-epoch-p tau)))
    ;; GP §6.23: rotation on epoch boundary
    (if epoch-change-p
        ;; Rotate: η'₁=η₀(old), η'₂=η₁, η'₃=η₂
        (make-eta :eta-0 eta-0-prime :eta-1 eta-0 :eta-2 eta-1 :eta-3 eta-2)
        ;; No change: η'₁=η₁, η'₂=η₂, η'₃=η₃
        (make-eta :eta-0 eta-0-prime :eta-1 eta-1 :eta-2 eta-2 :eta-3 eta-3))))
