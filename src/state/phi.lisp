;;;; state/phi.lisp — ϕ Authorization Queue (GP §8.1-8.2)
;;;;
;;;; ϕ ∈ [⟦H⟧_Q]_C  — per-core queue of Q authorization code hashes.
;;;; C = (num-cores), Q = +auth-queue-size+ = 80.
;;;; Each core's queue is a fixed-size list of Q 32-byte hashes.
;;;;
;;;; GP (4.16): ϕ' comes from accumulate.
;;;; Merkle key: C(2).
;;;;
;;;; Codec layout: C × Q × hash32 — fixed-size, NO compact prefix.
;;;;   Total bytes: C × Q × 32.
;;;;
;;;; Messages:
;;;;   :queues           → list of C queues, each a list of Q 32-byte hash vectors
;;;;   :queue-for-core c → queue of Q hashes for core c
;;;;   :head-for-core c  → head (first) hash from core c's queue
;;;;   :transition (&key new-queues) → ϕ' with new queues, or self if nil
;;;;   :save          → binary encoding (memoized)
;;;;   :decode           → reconstruct from bytes

(in-package #:jotl)

(define-state-closure phi-state
  ((queues nil))  ;; list of C elements, each a list of Q 32-byte hash vectors

  ;; ── Semantic queries ─────────────────────────────────────
  (:queue-for-core (c)
    (when (< c (length queues))
      (nth c queues)))

  ;; Head of core c's queue — used by α transition (4.19)
  (:head-for-core (c)
    (when (and (< c (length queues))
               (nth c queues))
      (first (nth c queues))))

  ;; ── Transition: accept new per-core queues from accumulate ──
  ;; If per-core-queues is non-nil, replace; otherwise return self unchanged.
  (:transition (&key new-queues)
    (if new-queues
        (make-phi-state :queues new-queues)
        #'self))

  ;; ── Codec ────────────────────────────────────────────────
  ;; C × Q × hash32  (fixed-size, no compact prefix)
  (:save :memo
    (let ((c (num-cores))
          (q +auth-queue-size+))
      (let ((buf (make-array (* c q 32) :element-type '(unsigned-byte 8)
                                         :initial-element 0)))
        (loop for core-idx below c
              for core-queue = (when (< core-idx (length queues))
                                 (nth core-idx queues))
              do (loop for hash-idx below q
                       for hash = (when (and core-queue (< hash-idx (length core-queue)))
                                    (nth hash-idx core-queue))
                       when hash
                       do (replace buf hash :start1 (+ (* core-idx q 32)
                                                       (* hash-idx 32)))))
        buf)))

  (:decode (bytes offset)
    (let* ((c (num-cores))
           (q +auth-queue-size+)
           (pos offset)
           (queues-result '()))
      (dotimes (core-idx c)
        (let ((core-queue '()))
          (dotimes (hash-idx q)
            (push (subseq bytes pos (+ pos 32)) core-queue)
            (incf pos 32))
          (push (nreverse core-queue) queues-result)))
      (values (make-phi-state :queues (nreverse queues-result))
              (- pos offset)))))
