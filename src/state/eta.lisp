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
;;;;   :save                 → 128 bytes (4×32)
;;;;   :transition :header h :tau τ :tau-prime τ' → η'

(in-package #:jotl)

(define-state-closure eta-state
  ((eta-0 nil) (eta-1 nil) (eta-2 nil) (eta-3 nil) (raw nil))

  ;; ── Semantic aliases ─────────────────────────────────────
  (:accumulator         eta-0)   ;; η₀: randomness accumulator
  (:last-epoch-entropy  eta-1)   ;; η₁: end of last completed epoch
  (:vrf-entropy         eta-2)   ;; η₂: ticket VRF & assignment entropy
  (:seal-entropy        eta-3)   ;; η₃: seal validation entropy

  ;; ── Codec ────────────────────────────────────────────────
  (:encode
    (or raw
        (let ((buf (make-array 128 :element-type '(unsigned-byte 8))))
          (replace buf (or eta-0 +zero-hash+))
          (replace buf (or eta-1 +zero-hash+) :start1 32)
          (replace buf (or eta-2 +zero-hash+) :start1 64)
          (replace buf (or eta-3 +zero-hash+) :start1 96)
          buf)))

  (:decode (bytes offset)
    (values (make-eta-state
             :eta-0 (subseq bytes offset (+ offset 32))
             :eta-1 (subseq bytes (+ offset 32) (+ offset 64))
             :eta-2 (subseq bytes (+ offset 64) (+ offset 96))
             :eta-3 (subseq bytes (+ offset 96) (+ offset 128)))
            128))

  ;; GP §6.21-6.23
  ;; (6.22) η'₀ = H(η₀ ⌢ Y(HV))  — Y extracts 32-byte VRF output from 96-byte HV
  ;; (6.22) epoch change → shift: η'₁=η₀, η'₂=η₁, η'₃=η₂
  ;; (6.23) no change    → keep:  η'₁=η₁, η'₂=η₂, η'₃=η₃
  (:transition (&key header tau tau-prime)
    (let* ((y-hv (funcall header :vrf-entropy))
           (_dbg (when (null y-hv)
                   (format t "[ETA-WARN] Y(HV) returned NIL! HV=~A~%"
                           (jam.ffi:bytes-to-hex-string
                            (or (funcall header :entropy-source) #())))
                   (force-output)))
           (epoch-change-p (funcall tau :epoch-changed? tau-prime))
           (hash-input (let ((buf (make-array 64 :element-type '(unsigned-byte 8))))
                         (replace buf (or eta-0 +zero-hash+))
                         (replace buf (or y-hv +zero-hash+) :start1 32)
                         buf))
           (eta-0-prime (blake2b-256 hash-input))
           (new-1 (if epoch-change-p eta-0 eta-1))
           (new-2 (if epoch-change-p eta-1 eta-2))
           (new-3 (if epoch-change-p eta-2 eta-3))
           (enc (let ((buf (make-array 128 :element-type '(unsigned-byte 8))))
                  (replace buf (or eta-0-prime +zero-hash+))
                  (replace buf (or new-1 +zero-hash+) :start1 32)
                  (replace buf (or new-2 +zero-hash+) :start1 64)
                  (replace buf (or new-3 +zero-hash+) :start1 96)
                  buf)))
      (make-eta-state :eta-0 eta-0-prime :eta-1 new-1 :eta-2 new-2 :eta-3 new-3
                      :raw enc))))
