;;;; state/alpha.lisp — α Core Authorizations Pool (GP §8.1)
;;;;
;;;; α ∈ [⟦H⟧_O]_C  — per-core pool of at most O authorization code hashes.
;;;; C = (num-cores), O = +max-auth-pool+ = 8.
;;;; Each core's pool is a variable-length list of 0..O 32-byte hashes.
;;;;
;;;; GP (4.19): α' < (H, EC, ϕ', α)
;;;; At epoch boundary:
;;;;   α'[c] = last_O(α[c] ⌢ [head(ϕ'[c])]) minus offender authorizations
;;;; At non-epoch:
;;;;   α'[c] = α[c] minus offender authorizations
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

  ;; ── Transition: α' < (H, EC, ϕ', α) ─────────────────────
  ;; GP (4.19)
  (:transition (&key tau tau-prime phi-prime offender-auth-hashes)
    (let* ((epoch-changed (funcall tau :epoch-changed? tau-prime))
           (c (num-cores))
           (banned (or offender-auth-hashes '()))  ;; list of 32-byte hashes to exclude
           (new-pools
            (loop for core-idx below c
                  for pool = (when (< core-idx (length pools))
                               (nth core-idx pools))
                  collect
                  (let* (;; At epoch boundary: append head of ϕ'[c]
                         (extended
                          (if (and epoch-changed phi-prime)
                              (let ((head (funcall phi-prime :head-for-core core-idx)))
                                (if head
                                    (append (or pool '()) (list head))
                                    (or pool '())))
                              (or pool '())))
                         ;; Truncate to last O elements
                         (truncated
                          (let ((len (length extended)))
                            (if (> len +max-auth-pool+)
                                (last extended +max-auth-pool+)
                                extended)))
                         ;; Remove offender authorization hashes
                         (filtered
                          (if banned
                              (remove-if (lambda (h)
                                           (member h banned :test #'equalp))
                                         truncated)
                              truncated)))
                    filtered))))
      (make-alpha-state :pools new-pools))))
