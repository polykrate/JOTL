;;;; state/chi.lisp — χ Privileged Service Indices (GP §9.4)
;;;;
;;;; GP (9.9):  χ = (χ_M, χ_V, χ_R, χ_A, χ_Z)
;;;;   χ_M ∈ N_S   : manager (blessed) service index
;;;;   χ_V ∈ N_S   : designate service index (can set ι)
;;;;   χ_R ∈ N_S   : new-service-creation service (protected range)
;;;;   χ_A ∈ [N_S]_C : per-core authorizer service indices
;;;;   χ_Z ∈ (N_S → N_G) : always-accumulate services + gas map
;;;;
;;;; No :transition — modified by transition-accumulate (accumulate.lisp).
;;;; Merkle key: C(12).
;;;;
;;;; Encoding (JAM tuple order = definition order):
;;;;   E4(χ_M) ⌢ E4(χ_V) ⌢ E4(χ_R)                   (12 bytes)
;;;;   C × E4(χ_A[c])                                   (C × 4 bytes)
;;;;   compact(|χ_Z|) ⌢ |χ_Z| × (E4(sid) ⌢ E8(gas))   (variable)
;;;;
;;;; Messages:
;;;;   :raw           → raw segment bytes
;;;;   :encoded       → binary encoding
;;;;   :decode        → reconstruct from bytes
;;;;   :fields        → decoded plist (memoized)
;;;;   :manager       → χ_M
;;;;   :designate     → χ_V
;;;;   :creation      → χ_R
;;;;   :authorizers   → χ_A (list of C service indices)
;;;;   :always-accum  → χ_Z (alist of (service-id . gas))

(in-package #:jotl)

;;; ═══════════════════════════════════════════════════════════════
;;; CODEC — decode / encode χ
;;; ═══════════════════════════════════════════════════════════════

(defun decode-chi-fields (bytes &optional (offset 0))
  "Decode χ from raw bytes starting at OFFSET.
   Returns: (values plist bytes-consumed)
   Plist keys: :manager :designate :creation :authorizers :always-accum"
  (let ((pos offset)
        (c (num-cores)))
    ;; χ_M, χ_V, χ_R — 3 × u32
    (multiple-value-bind (chi-m n) (decode-u32 bytes pos) (incf pos n)
      (multiple-value-bind (chi-v n) (decode-u32 bytes pos) (incf pos n)
        (multiple-value-bind (chi-r n) (decode-u32 bytes pos) (incf pos n)
          ;; χ_A — C × u32
          (let ((chi-a (make-list c)))
            (loop for i from 0 below c do
              (multiple-value-bind (val n) (decode-u32 bytes pos)
                (setf (nth i chi-a) val)
                (incf pos n)))
            ;; χ_Z — compact-prefixed dict of (u32 → u64)
            (multiple-value-bind (count n) (decode-compact bytes pos)
              (incf pos n)
              (let ((chi-z nil))
                (dotimes (i count)
                  (multiple-value-bind (sid n) (decode-u32 bytes pos) (incf pos n)
                    (multiple-value-bind (gas n) (decode-u64 bytes pos) (incf pos n)
                      (push (cons sid gas) chi-z))))
                (values (list :manager    chi-m
                              :designate  chi-v
                              :creation   chi-r
                              :authorizers chi-a
                              :always-accum (nreverse chi-z))
                        (- pos offset))))))))))

(defun encode-chi-fields (chi-plist)
  "Encode χ fields to bytes.
   CHI-PLIST: (:manager u32 :designate u32 :creation u32 :authorizers list :always-accum alist)"
  (let ((parts nil))
    ;; χ_M, χ_V, χ_R
    (push (E4 (getf chi-plist :manager))    parts)
    (push (E4 (getf chi-plist :designate))  parts)
    (push (E4 (getf chi-plist :creation))   parts)
    ;; χ_A — C × u32
    (dolist (sid (getf chi-plist :authorizers))
      (push (E4 sid) parts))
    ;; χ_Z — compact(count) + entries
    (let ((az (getf chi-plist :always-accum)))
      (push (encode-compact (length az)) parts)
      (dolist (entry az)
        (push (E4 (car entry))  parts)   ;; service-id
        (push (E8 (cdr entry))  parts))) ;; gas
    (apply #'concatenate '(vector (unsigned-byte 8)) (nreverse parts))))

;;; ═══════════════════════════════════════════════════════════════
;;; STATE CLOSURE — χ
;;; ═══════════════════════════════════════════════════════════════

(define-state-closure chi-state
  ((raw nil))

  ;; ── Codec ──────────────────────────────────────────────────
  (:encoded raw)

  (:decode (bytes offset)
    (let ((segment-bytes (subseq bytes offset)))
      (values (make-chi-state :raw segment-bytes)
              (- (length bytes) offset))))

  ;; ── Memoized decode (all fields at once) ───────────────────
  (:fields :memo
    (when raw (decode-chi-fields raw)))

  ;; ── Accessors ─────────────────────────────────────────────
  (:manager     (getf (self :fields) :manager))
  (:designate   (getf (self :fields) :designate))
  (:creation    (getf (self :fields) :creation))
  (:authorizers (getf (self :fields) :authorizers))
  (:always-accum (getf (self :fields) :always-accum)))
