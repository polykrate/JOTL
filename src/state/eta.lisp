;;;; state/eta.lisp — η Entropy (GP §6.21-6.23)
;;;;
;;;; η ∈ ⟦H⟧₄   — 4 hashes
;;;; η₀ : randomness accumulator (updated every block)
;;;; η₁ : end of most recently ended epoch
;;;; η₂ : end of second-most recent epoch
;;;; η₃ : end of third-most recent epoch
;;;;
;;;; GP (4.8): η' < (H, τ, η)
;;;;
;;;; Messages:
;;;;   :eta-0 .. :eta-3        → 32-byte hashes (codec/positional)
;;;;   :accumulator             → η₀ (alias)
;;;;   :last-epoch-entropy      → η₁ (alias)
;;;;   :vrf-entropy             → η₂ — ticket VRF & assignment entropy
;;;;   :seal-entropy            → η₃ — seal validation entropy
;;;;   :encoded                 → 128 bytes (4×32)
;;;;   :transition :header h :tau τ :tau-prime τ' → η'

(in-package #:jotl)

(define-state-closure eta-state
  ((eta-0 nil) (eta-1 nil) (eta-2 nil) (eta-3 nil))

  ;; ── Semantic aliases ─────────────────────────────────────
  (:accumulator         eta-0)   ;; η₀: randomness accumulator
  (:last-epoch-entropy  eta-1)   ;; η₁: end of last completed epoch
  (:vrf-entropy         eta-2)   ;; η₂: ticket VRF & assignment entropy
  (:seal-entropy        eta-3)   ;; η₃: seal validation entropy

  ;; ── Codec ────────────────────────────────────────────────
  (:encoded :memo
    (concatenate '(vector (unsigned-byte 8))
                 (or eta-0 +zero-hash+)
                 (or eta-1 +zero-hash+)
                 (or eta-2 +zero-hash+)
                 (or eta-3 +zero-hash+)))

  (:decode (bytes offset)
    (values (make-eta-state
             :eta-0 (subseq bytes offset (+ offset 32))
             :eta-1 (subseq bytes (+ offset 32) (+ offset 64))
             :eta-2 (subseq bytes (+ offset 64) (+ offset 96))
             :eta-3 (subseq bytes (+ offset 96) (+ offset 128)))
            128))

  ;; GP §6.21-6.23
  ;; (6.21) η'₀ = H(η₀ ⌢ HV)
  ;; (6.22) epoch change → shift: η'₁=η₀, η'₂=η₁, η'₃=η₂
  ;; (6.23) no change    → keep:  η'₁=η₁, η'₂=η₂, η'₃=η₃
  (:transition (&key header tau tau-prime)
    (let* ((entropy-source (funcall header :entropy-source))
           (epoch-change-p (funcall tau :epoch-changed? tau-prime))
           (eta-0-prime (blake2b-256
                         (concatenate '(vector (unsigned-byte 8))
                                      (or eta-0 +zero-hash+) entropy-source))))
      (if epoch-change-p
          (make-eta-state :eta-0 eta-0-prime :eta-1 eta-0 :eta-2 eta-1 :eta-3 eta-2)
          (make-eta-state :eta-0 eta-0-prime :eta-1 eta-1 :eta-2 eta-2 :eta-3 eta-3)))))
