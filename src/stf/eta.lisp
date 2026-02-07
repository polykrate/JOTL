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
;;; STATE CODEC — C(6) ↦ E(η)
;;; ═══════════════════════════════════════════════════════════════

(defun encode-state-eta (eta)
  "C(6) ↦ E(η) = η₀ ⌢ η₁ ⌢ η₂ ⌢ η₃ (128 bytes)"
  (apply #'concatenate '(vector (unsigned-byte 8)) eta))

(defun decode-state-eta (bytes &optional (offset 0))
  "Decode η from 128 bytes: 4 × 32-byte hashes.
   Returns: (values eta-list 128)"
  (values (list (subseq bytes offset (+ offset 32))
                (subseq bytes (+ offset 32) (+ offset 64))
                (subseq bytes (+ offset 64) (+ offset 96))
                (subseq bytes (+ offset 96) (+ offset 128)))
          128))

;;; ═══════════════════════════════════════════════════════════════
;;; η STF (GP §6.21-6.23)
;;; ═══════════════════════════════════════════════════════════════

(defun transition-eta (header tau eta)
  "GP §6.21-6.23 — Entropy accumulator transition.
   
   η  = list of 4 hashes: (η₀ η₁ η₂ η₃)
   τ  = prior timeslot (number)
   header = closure with :slot (τ') and :entropy-source (Y(HV))
   
   Returns: η' = list of 4 hashes"
  (let* ((tau-prime       (funcall header :slot))
         (entropy-source  (funcall header :entropy-source))  ;; Y(HV)
         ;; Destructure η
         (eta-0 (nth 0 eta))
         (eta-1 (nth 1 eta))
         (eta-2 (nth 2 eta))
         (eta-3 (nth 3 eta))
         ;; GP §6.22: η'₀ ≡ H(η₀ ⌢ Y(HV))
         (eta-0-prime (blake2b-256
                       (concatenate '(vector (unsigned-byte 8))
                                    eta-0 entropy-source)))
         ;; GP §6.2: epoch indices
         (epoch-change-p (new-epoch-p tau tau-prime)))
    ;; GP §6.23: rotation on epoch boundary
    (if epoch-change-p
        ;; Rotate: η'₁=η₀(old), η'₂=η₁, η'₃=η₂
        (list eta-0-prime eta-0 eta-1 eta-2)
        ;; No change: η'₁=η₁, η'₂=η₂, η'₃=η₃
        (list eta-0-prime eta-1 eta-2 eta-3))))
