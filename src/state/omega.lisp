;;;; state/omega.lisp — ω Accumulation Queue (GP §12.3)
;;;;
;;;; ω ∈ [[(R, {H ∪ {}})]]_E  — E-length sequence of queues.
;;;; Each queue entry: (work-report, set-of-unfulfilled-dependency-hashes).
;;;;
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
;;;;   :r-star            → transient: resolved R* (or nil)
;;;;   :accumulated-hashes → transient: accumulated package hashes (or nil)
;;;;   :package-hashes-for (n) → P(R*_{...n}): package hashes of first n reports
;;;;   :transition (&key reports xi-flattened timeslot prev-timeslot)
;;;;                      → ω' (r-star and hashes queryable) GP 12.4-12.12
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
;;; QUEUE-EDITING FUNCTIONS — D, P, E, Q  (GP §12.1)
;;; ═══════════════════════════════════════════════════════════════

;;; ── D(r) — Dependency set (GP 12.6) ────────────────────────
;;; D(r) = {K(s) : s ∈ r.segment-root-lookup} ∪ r.context.prerequisites

(defun accum-deps (report)
  "GP §12.6: D(r) — Compute the dependency set of a work-report.
   Returns: list of 32-byte hash vectors (the union of segment-root-lookup
   work-package hashes and context prerequisites)."
  (let ((deps '()))
    ;; Add K(s) from segment-root-lookup items — these are work-package hashes
    (dolist (item (getf report :segment-root-lookup))
      (let ((h (getf item :work-package-hash)))
        (unless (member h deps :test #'equalp)
          (push h deps))))
    ;; Add prerequisites from the refine context
    (let ((ctx (getf report :context)))
      (when ctx
        (dolist (h (getf ctx :prerequisites))
          (unless (member h deps :test #'equalp)
            (push h deps)))))
    (nreverse deps)))

;;; ── P(R) — Package hashes (GP 12.9) ────────────────────────
;;; P(R) = {r.s.h : r ∈ R}

(defun vector< (a b)
  "Lexicographic comparison of byte vectors (for sorting hashes).
   Returns T if A < B in lexicographic order."
  (loop for i from 0 below (min (length a) (length b))
        for ai = (aref a i)
        for bi = (aref b i)
        when (< ai bi) return t
        when (> ai bi) return nil
        finally (return (< (length a) (length b)))))

(defun accum-package-hashes (reports)
  "GP §12.9: P(R) — Extract the set of package hashes from work-reports.
   Returns: list of 32-byte hash vectors, sorted lexicographically."
  (sort (mapcar (lambda (r) (getf (getf r :package-spec) :hash)) reports)
        #'vector<))

;;; ── E(q, s) — Edit queue (GP 12.7) ─────────────────────────

(defun accum-edit (queue hash-set)
  "GP §12.7: E(q, s) — Edit a queue by removing completed entries
   and satisfied dependencies.
   QUEUE:    list of (:report r :deps (h1 h2 ...))
   HASH-SET: list of 32-byte hash vectors (accumulated package hashes)
   Returns: edited queue."
  (loop for entry in queue
        for pkg-hash = (getf (getf (getf entry :report) :package-spec) :hash)
        unless (member pkg-hash hash-set :test #'equalp)
        collect (list :report (getf entry :report)
                      :deps (remove-if (lambda (d)
                                         (member d hash-set :test #'equalp))
                                       (getf entry :deps)))))

;;; ── Q(q) — Priority queue ordering (GP 12.8) ───────────────

(defun accum-priority-queue (queue)
  "GP §12.8: Q(q) — Priority-ordered extraction of work-reports
   from a dependency queue. Returns: ordered list of work-reports."
  (if (null queue)
      nil
      (let ((ready nil) (pending nil))
        (loop for e in queue
              if (null (getf e :deps))
                do (push e ready)
              else
                do (push e pending))
        (setf ready (nreverse ready) pending (nreverse pending))
        (if (null ready)
            nil
            (let* ((ready-reports (mapcar (lambda (e) (getf e :report)) ready))
                   (ready-hashes (accum-package-hashes ready-reports))
                   (edited       (accum-edit pending ready-hashes)))
              (append ready-reports
                      (accum-priority-queue edited)))))))

;;; ═══════════════════════════════════════════════════════════════
;;; R* COMPUTATION — partitioning, queue editing, ordering (GP 12.4-12.12)
;;; ═══════════════════════════════════════════════════════════════

(defun compute-r-star (reports omega-queues xi-flattened timeslot
                       &optional (prev-timeslot (1- timeslot)))
  "Compute R* from new reports and existing omega queues.
   GP §12.4-12.12.

   REPORTS:        list of new work-reports from ρ‡ :reported
   OMEGA-QUEUES:   list of E lists of queue entries (from ω)
   XI-FLATTENED:   ξ̃ — set of already-accumulated package hashes
   TIMESLOT:       τ' (post-transition timeslot) for computing m
   PREV-TIMESLOT:  τ  (previous timeslot, for clearing stale queue slots)

   Returns: (values r-star updated-omega-queues accumulated-hashes)"
  (let* ((e (epoch-duration))
         (m (mod timeslot e))
         (stale-gap (min e (- timeslot prev-timeslot)))
         (cleared-queues (let ((q (copy-list omega-queues)))
                           (loop for k from 1 to stale-gap do
                               (let ((idx (mod (+ prev-timeslot k) e)))
                               (setf (nth idx q) nil)))
                           q))
         (new-entries
          (mapcar (lambda (r)
                    (list :report r :deps (accum-deps r)))
                  (or reports '())))
         (r-immediate (remove-if-not (lambda (entry) (null (getf entry :deps)))
                                     new-entries))
         (r-deferred  (remove-if     (lambda (entry) (null (getf entry :deps)))
                                     new-entries))
         (r-bang (mapcar (lambda (entry) (getf entry :report)) r-immediate))
         (p-r-bang (accum-package-hashes r-bang)))

    (let ((q-slots (make-array e :initial-element nil))
          (w-slots (make-array e :initial-element nil))
          (combined-hashes (append xi-flattened p-r-bang)))
      (loop for i from 0 below e do
          (setf (aref q-slots i)
              (accum-edit (or (nth i omega-queues) nil) combined-hashes)))
      (loop for i from 0 below e do
          (setf (aref w-slots i)
              (accum-edit (or (nth i cleared-queues) nil) combined-hashes)))

      (let ((r-deferred-edited (accum-edit r-deferred combined-hashes)))
        (setf (aref q-slots m) (append (aref q-slots m) r-deferred-edited))
        (setf (aref w-slots m) (append (aref w-slots m) r-deferred-edited)))

      ;; GP §12.7: q = q_{m+1} ⌢ q_{m+2} ⌢ ... ⌢ q_{m+E}
      ;; Scan from slot (m+1) wrapping around through slot m (oldest first).
      (let* ((all-queued (loop for k from 1 to e
                               for i = (mod (+ m k) e)
                               nconc (copy-list (aref q-slots i))))
             (ordered-resolved (accum-priority-queue all-queued))
             (r-star (append r-bang ordered-resolved))
             (accumulated-hashes (accum-package-hashes r-star))
             (resolved-hashes (accum-package-hashes ordered-resolved))
             (all-done-hashes (append p-r-bang resolved-hashes)))

        (let ((new-omega-queues
               (loop for i from 0 below e
                     collect (remove-if (lambda (entry)
                                          (let ((pkg-hash (getf (getf (getf entry :report) :package-spec) :hash)))
                                            (member pkg-hash all-done-hashes :test #'equalp)))
                                        (aref w-slots i)))))
          (values r-star new-omega-queues accumulated-hashes))))))

;;; ═══════════════════════════════════════════════════════════════
;;; STATE CLOSURE — ω
;;; ═══════════════════════════════════════════════════════════════

(define-state-closure omega-state
  ((queues nil)
   (r-star nil)                ;; transient — computed by :transition, not saved
   (accumulated-hashes nil))   ;; transient — computed by :transition, not saved

  ;; ── Semantic queries ─────────────────────────────────────
  (:queue-at (idx)
    (when (< idx (length queues))
      (nth idx queues)))

  (:total-queued
    (loop for q in queues sum (length q)))

  ;; ── Query: package hashes for the first N reports in R* ──
  ;; GP 12.33: P(R*_{...n}) — used by ξ :transition
  ;; Only meaningful on ω' (after :transition populated r-star).
  (:package-hashes-for (n)
    (when r-star
      (accum-package-hashes (subseq r-star 0 (min n (length r-star))))))

  ;; ── Transition: GP 12.4-12.12 ────────────────────────────
  ;; ω owns queue editing, R* extraction, and omega' construction.
  ;; Returns: omega' (r-star and accumulated-hashes accessible via queries)
  (:transition (&key reports xi-flattened timeslot prev-timeslot)
    (multiple-value-bind (resolved-r-star new-queues resolved-hashes)
        (compute-r-star reports queues xi-flattened timeslot prev-timeslot)
      (make-omega-state :queues new-queues
                        :r-star resolved-r-star
                        :accumulated-hashes resolved-hashes)))

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
