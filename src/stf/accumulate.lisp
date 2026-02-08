;;;; stf/accumulate.lisp — Accumulation (GP §8) + related segments
;;;;
;;;; Segments managed by accumulation:
;;;;   χ  chi   — Privileged service IDs (C12)
;;;;   ω  omega — Ready work-reports (C14)
;;;;   ξ  xi    — Recent accumulations (C15)
;;;;   θ  theta — Accumulation queue (C16)
;;;;
;;;; transition-accumulate is the §4.16 orchestrator for these.

(in-package #:jotl)

;;; ═══════════════════════════════════════════════════════════════
;;; χ — Privileged Service IDs (GP §8)
;;; ═══════════════════════════════════════════════════════════════
;;; χ = (χM, χA, χV, χI) — 4 service indices.

(define-value-object chi
  ((manager 0) (assign 0) (designate 0) (empower 0))
  (:state-key +C12+)
  (:encoded :memo
    (concatenate '(vector (unsigned-byte 8))
                 (E4 manager) (E4 assign) (E4 designate) (E4 empower))))

(defun encode-state-chi (chi)
  "C(12) ↦ E(χ) — uses chi closure's memoized encoding."
  (funcall chi :encoded))

;;; ═══════════════════════════════════════════════════════════════
;;; ω — Ready Work-Reports (GP §8)
;;; ═══════════════════════════════════════════════════════════════
;;; ω ∈ ⟦(s:NS, p:H, x:Y)⟧

(define-value-object omega
  ((reports nil))
  (:state-key +C14+)
  (:encoded :memo
    (if (null reports)
        (encode-compact 0)
        (encode-sequence reports
                         (lambda (report)
                           (concatenate '(vector (unsigned-byte 8))
                                        (E4 (or (getf report :service) 0))
                                        (encode-hash-32
                                         (or (getf report :hash) +zero-hash+))
                                        (let ((payload (getf report :payload)))
                                          (if payload
                                              (concatenate '(vector (unsigned-byte 8))
                                                           (encode-compact (length payload))
                                                           payload)
                                              (encode-compact 0)))))))))

(defun encode-state-omega (omega)
  "C(14) ↦ E(ω) — uses omega closure's memoized encoding."
  (funcall omega :encoded))

;;; ═══════════════════════════════════════════════════════════════
;;; ξ — Recent Accumulations (GP §8)
;;; ═══════════════════════════════════════════════════════════════
;;; ξ ∈ ⟦⟦H⟧⟧ — list of lists of work-package hashes.

(define-value-object xi
  ((accumulations nil))
  (:state-key +C15+)
  (:encoded :memo
    (if (null accumulations)
        (encode-compact 0)
        (encode-sequence accumulations
                         (lambda (epoch-accs)
                           (encode-sequence epoch-accs #'encode-hash-32))))))

(defun encode-state-xi (xi)
  "C(15) ↦ E(ξ) — uses xi closure's memoized encoding."
  (funcall xi :encoded))

;;; ═══════════════════════════════════════════════════════════════
;;; θ — Accumulation Queue (GP §8)
;;; ═══════════════════════════════════════════════════════════════
;;; θ ∈ ⟦...⟧ — pending accumulation work items.

(define-value-object theta
  ((queue nil))
  (:state-key +C16+)
  (:encoded :memo
    (if (null queue)
        (encode-compact 0)
        (encode-sequence queue #'identity))))

(defun encode-state-theta (theta)
  "C(16) ↦ E(θ) — uses theta closure's memoized encoding."
  (funcall theta :encoded))

;;; ═══════════════════════════════════════════════════════════════
;;; TRANSITION — accumulate (GP §4.16)
;;; ═══════════════════════════════════════════════════════════════

(defun transition-accumulate (r-star omega xi delta chi iota phi tau tau-prime)
  "GP §4.16 — Accumulation. STUB: §8 + PVM
   Returns: (values ω' ξ' δ‡ χ' ι' ϕ' θ' S)"
  (declare (ignore r-star tau tau-prime))
  (values omega xi delta chi iota phi nil nil))
