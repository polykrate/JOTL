;;;; state/xi.lisp — ξ Accumulation History (GP §12.1)
;;;;
;;;; ξ ∈ [⟦{H}⟧]_E  — epoch-long history of accumulated work-package hashes.
;;;; E slots (E = epoch-duration), each a set of 32-byte hashes.
;;;; Sets are encoded as sorted sequences for determinism.
;;;;
;;;; ξ̃ = ⋃_{x∈ξ} (x)  — flattened union of all sets (12.2).
;;;;
;;;; Merkle key: C(15).
;;;;
;;;; Codec layout: E × (compact-len, hash32*)
;;;;   Each slot: compact integer (count of hashes), then count × 32 bytes.
;;;;   For empty ξ: E bytes of 0x00 (compact(0) for each slot).
;;;;
;;;; Messages:
;;;;   :entries          → list of E lists of 32-byte hash vectors
;;;;   :entry-at (idx)   → list of hashes at slot idx
;;;;   :flattened        → ξ̃ = union of all hash sets (memoized)
;;;;   :contains? (h)    → T if hash h is in ξ̃
;;;;   :transition (&key accumulated-hashes) → ξ' with shift-left + new hashes at E-1 (GP 12.32-12.33)
;;;;   :save          → binary encoding (memoized)
;;;;   :decode           → reconstruct from bytes

(in-package #:jotl)

(define-state-closure xi-state
  ((entries nil))   ;; list of E elements, each a list of 32-byte hash vectors

  ;; ── Semantic queries ─────────────────────────────────────
  (:entry-at (idx)
    (when (< idx (length entries))
      (nth idx entries)))

  ;; (12.2) ξ̃ = ⋃_{x∈ξ} (x)
  (:flattened :memo
    (let ((result '()))
      (dolist (slot entries)
        (dolist (h slot)
          (unless (member h result :test #'equalp)
            (push h result))))
      (nreverse result)))

  ;; Quick membership test against ξ̃
  (:contains? (hash)
    (member hash (self :flattened) :test #'equalp))

  ;; ── Transition: GP 12.32-12.33 ──────────────────────────
  ;; ξ'_{E-1} = accumulated-hashes (P(R*_{...n}))
  ;; ∀i ∈ N_{E-1}: ξ'_i = ξ_{i+1}  (shift left)
  (:transition (&key accumulated-hashes)
    (let* ((e (epoch-duration))
           (old (if (and entries (listp entries) (= (length entries) e))
                    entries
                    (make-list e :initial-element nil)))
           (nxi (make-list e :initial-element nil)))
      ;; Shift left: ξ'[i] = ξ[i+1]
      (loop for i from 0 below (1- e)
            do (setf (nth i nxi) (nth (1+ i) old)))
      ;; ξ'[E-1] = accumulated-hashes
      (setf (nth (1- e) nxi) accumulated-hashes)
      (make-xi-state :entries nxi)))

  ;; ── Codec ────────────────────────────────────────────────
  ;; E × (compact-len, hash32*)
  (:save :memo
    (let ((bufs (mapcar (lambda (slot)
                          (encode-sequence (or slot '())
                                          (lambda (h) h)))  ;; hash is already 32 bytes
                        (or entries
                            (make-list (epoch-duration) :initial-element nil)))))
      (apply #'concatenate '(vector (unsigned-byte 8)) bufs)))

  (:decode (bytes offset)
    (let ((e (epoch-duration))
          (pos offset)
          (slots '()))
      (dotimes (i e)
        (multiple-value-bind (hashes consumed)
            (decode-sequence bytes
                            (lambda (b o) (values (subseq b o (+ o 32)) 32))
                            pos)
          (push hashes slots)
          (incf pos consumed)))
      (values (make-xi-state :entries (nreverse slots))
              (- pos offset)))))
