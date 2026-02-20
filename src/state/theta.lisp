;;;; state/theta.lisp — θ Accumulation Outputs (GP §7.4, §12.25)
;;;;
;;;; θ = most recent accumulation outputs.
;;;; Used by β' (wave 4) to compute the accumulate root for the Beefy MMR.
;;;; θ is a list of (service-id, hash) pairs produced by accumulation.
;;;;
;;;; Merkle key: C(16).
;;;;
;;;; Messages:
;;;;   :raw              → raw segment bytes
;;;;   :save             → binary encoding
;;;;   :decode           → reconstruct from bytes
;;;;   :transition (&key commitments) → θ' from sorted (sid . yield-hash) pairs

(in-package #:jotl)

(define-state-closure theta-state
  ((raw nil))

  ;; ── Transition: encode commitments into θ' ─────────────────
  ;; GP 12.26: θ' = E(B) where B = sorted set of (service-id, yield-hash)
  ;; Encoding: compact(count) + count × (u32_le(sid) + H32(yield_hash))
  ;; COMMITMENTS: sorted alist of (sid . yield-hash-bytes), may be nil.
  ;; Returns: θ' closure — empty commitments → compact(0) = 0x00.
  (:transition (&key commitments)
    (make-theta-state
     :raw (if commitments
              (apply #'concatenate '(vector (unsigned-byte 8))
                     (encode-compact (length commitments))
                     (mapcar (lambda (c)
                               (let ((sid (car c))
                                     (yh  (cdr c)))
                                 (concatenate '(vector (unsigned-byte 8))
                                              (vector (ldb (byte 8  0) sid)
                                                      (ldb (byte 8  8) sid)
                                                      (ldb (byte 8 16) sid)
                                                      (ldb (byte 8 24) sid))
                                              (coerce yh '(vector (unsigned-byte 8))))))
                             commitments))
              ;; Empty commitments → compact(0) = single byte 0x00
              (make-array 1 :element-type '(unsigned-byte 8)
                            :initial-element 0))))

  (:save raw)

  (:decode (bytes offset)
    (values (make-theta-state :raw (subseq bytes offset))
            (- (length bytes) offset))))
