;;;; state/alpha.lisp — α Core Authorizations Pool (GP §8.1)
;;;;
;;;; α ∈ [⟦H⟧_O]_C  — per-core pool of at most O authorization code hashes.
;;;; C = (num-cores), O = +max-auth-pool+ = 8.
;;;; Each core's pool is a variable-length list of 0..O 32-byte hashes.
;;;;
;;;; GP (4.19): α'c = lastO(α*c ⌢ [ϕ'c(τ' mod Q)])
;;;; Every block: append ϕ'[c][τ' mod Q] to pool, truncate to O, remove offenders.
;;;; α*c = αc minus used authorizers from guarantees.
;;;;
;;;; Merkle key: C(1).
;;;;
;;;; Codec layout: C × (compact-len, hash32*)
;;;;   Each core: compact integer (count of hashes), then count × 32 bytes.
;;;;
;;;; Messages:
;;;;   :pools            → list of C lists of 32-byte hash vectors
;;;;   :pool-for-core c  → list of hashes for core c
;;;;   :save          → binary encoding (memoized)
;;;;   :decode           → reconstruct from bytes
;;;;   :transition       → GP (4.19): α' < (H, EC, ϕ', α)

(in-package #:jotl)

(define-state-closure alpha-state
  ((pools nil))  ;; list of C elements, each a list of 0..O 32-byte hash vectors

  ;; ── Semantic queries ─────────────────────────────────────
  (:pool-for-core (c)
    (when (< c (length pools))
      (nth c pools)))

  ;; ── Codec ────────────────────────────────────────────────
  ;; C × (compact-len, hash32*)
  (:encode :memo
    (let ((c (num-cores)))
      (let ((bufs (loop for core-idx below c
                        for pool = (when (< core-idx (length pools))
                                     (nth core-idx pools))
                        collect (encode-sequence (or pool '())
                                                (lambda (h) h)))))
        (apply #'concatenate '(vector (unsigned-byte 8)) bufs))))

  (:decode (bytes offset)
    (let ((c (num-cores))
          (pos offset)
          (pools-result '()))
      (dotimes (core-idx c)
        (multiple-value-bind (hashes consumed)
            (decode-sequence bytes
                            (lambda (b o) (values (subseq b o (+ o 32)) 32))
                            pos)
          (push hashes pools-result)
          (incf pos consumed)))
      (values (make-alpha-state :pools (nreverse pools-result))
              (- pos offset))))

  ;; ── Transition: α'c = lastO(α*c ⌢ [ϕ'c(τ' mod Q)]) ─────
  ;; GP (4.19) — every block, not just epoch boundaries.
  (:transition (&key tau-prime phi-prime offender-auth-hashes)
    (let* ((slot-prime (funcall tau-prime :slot))
           (c (num-cores))
           (banned (or offender-auth-hashes '()))
           (new-pools
            (loop for core-idx below c
                  for pool = (when (< core-idx (length pools))
                               (nth core-idx pools))
                  collect
                  (let* (;; Remove used authorizers (from guarantees)
                         (after-used
                          (if banned
                              (remove-if (lambda (h)
                                           (member h banned :test #'equalp))
                                         (or pool '()))
                              (or pool '())))
                         ;; Append ϕ'[c][τ' mod Q]
                         (queue-entry
                          (when phi-prime
                            (funcall phi-prime :element-at core-idx slot-prime)))
                         (extended
                          (if queue-entry
                              (append after-used (list queue-entry))
                              after-used))
                         ;; Truncate to last O elements
                         (truncated
                          (let ((len (length extended)))
                            (if (> len +max-auth-pool+)
                                (last extended +max-auth-pool+)
                                extended))))
                    truncated))))
      (make-alpha-state :pools new-pools))))
