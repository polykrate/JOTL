;;;; state/omega.lisp — ω Accumulation Queue (GP §12.3)
;;;;
;;;; ω ∈ [[(R, {H ∪ {}})]]_E  — E-length sequence of queues.
;;;; Each queue entry: (work-report, set-of-unfulfilled-dependency-hashes).
;;;;
;;;; No :transition — modified by transition-accumulate (accumulate.lisp).
;;;; Merkle key: C(14).
;;;;
;;;; Codec layout: E × (compact-len, (work-report-bytes, compact-len, hash32*)*)
;;;;   For each of E slots:
;;;;     compact-length (number of queued items in this slot)
;;;;     For each queued item:
;;;;       work-report (variable-length, using work-report codec)
;;;;       compact-length (number of dependency hashes)
;;;;       hash32* (dependency hashes, each 32 bytes)
;;;;
;;;; Messages:
;;;;   :queues           → list of E lists of (:report r :deps (h1 h2 ...))
;;;;   :queue-at (idx)   → list of queue entries at slot idx
;;;;   :total-queued     → total number of queued items across all slots
;;;;   :save          → binary encoding (memoized)
;;;;   :decode           → reconstruct from bytes

(in-package #:jotl)

;;; ═══════════════════════════════════════════════════════════════
;;; QUEUE ENTRY CODEC — (work-report, set-of-deps)
;;; ═══════════════════════════════════════════════════════════════

(defun load-omega-queue-entry (bytes offset)
  "Decode a single ω queue entry: (work-report, deps).
   Returns: (values entry-plist bytes-consumed)"
  (let ((pos offset))
    ;; 1. Decode work-report
    (multiple-value-bind (report report-consumed)
        (decode-work-report bytes pos)
      (incf pos report-consumed)
      ;; 2. Decode dependency hash set
      (multiple-value-bind (deps deps-consumed)
          (decode-sequence bytes
                          (lambda (b o) (values (subseq b o (+ o 32)) 32))
                          pos)
        (incf pos deps-consumed)
        (values (list :report report :deps deps)
                (- pos offset))))))

(defun encode-omega-queue-entry (entry)
  "Encode a single ω queue entry: (work-report, deps)."
  (concatenate '(vector (unsigned-byte 8))
               (encode-work-report (getf entry :report))
               (encode-sequence (or (getf entry :deps) '())
                                (lambda (h) h))))   ;; hash is already 32 bytes

;;; ═══════════════════════════════════════════════════════════════
;;; STATE CLOSURE — ω
;;; ═══════════════════════════════════════════════════════════════

(define-state-closure omega-state
  ((queues nil))   ;; list of E elements, each a list of (:report r :deps (h1 h2 ...))

  ;; ── Semantic queries ─────────────────────────────────────
  (:queue-at (idx)
    (when (< idx (length queues))
      (nth idx queues)))

  (:total-queued
    (loop for q in queues sum (length q)))

  ;; ── Codec ────────────────────────────────────────────────
  ;; E × (compact-len, queue-entry*)
  (:save :memo
    (let ((bufs (mapcar (lambda (queue)
                          (encode-sequence (or queue '())
                                          #'encode-omega-queue-entry))
                        (or queues
                            (make-list (epoch-duration) :initial-element nil)))))
      (apply #'concatenate '(vector (unsigned-byte 8)) bufs)))

  (:decode (bytes offset)
    (let ((e (epoch-duration))
          (pos offset)
          (slots '()))
      (dotimes (i e)
        (multiple-value-bind (queue consumed)
            (decode-sequence bytes #'load-omega-queue-entry pos)
          (push queue slots)
          (incf pos consumed)))
      (values (make-omega-state :queues (nreverse slots))
              (- pos offset)))))
