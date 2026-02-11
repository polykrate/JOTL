;;;; accumulate.lisp — §12 Accumulate Orchestrator
;;;;
;;;; GP (4.16):
;;;;   (ω', ξ', δ†, χ', ι', ϕ', θ', S) ◁ (R*, ω, ξ, δ, χ, ι, ϕ, τ, τ')
;;;;
;;;; This is a FUNCTION ORCHESTRATOR — same level as upsilon.lisp.
;;;; It takes state closures + R* as input, returns a plist of results.
;;;; State closures (ω, ξ, χ, ϕ, etc.) are codec-only, no :transition.
;;;; All the logic lives here.
;;;;
;;;; Architecture:
;;;;   - Standalone functions: D, E, Q, P (§12.1)
;;;;   - R* computation: partitioning, queue editing, priority ordering
;;;;   - transition-accumulate: top-level entry point called by upsilon Wave 3

(in-package #:jotl)

;;; ═══════════════════════════════════════════════════════════════
;;; §12.1 STANDALONE FUNCTIONS — D, E, Q, P
;;; ═══════════════════════════════════════════════════════════════

;;; ── D(r) — Dependency set (GP 12.6) ────────────────────────
;;; D(r) = {K(s) : s ∈ r.segment-root-lookup} ∪ r.context.prerequisites
;;;
;;; The dependency set of a work-report includes:
;;; 1. Each work-package hash referenced in the segment-root-lookup
;;; 2. Each hash listed in the refine-context prerequisites

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
;;;
;;; Extract the set of work-package hashes from a list of work-reports.

(defun accum-package-hashes (reports)
  "GP §12.9: P(R) — Extract the set of package hashes from work-reports.
   Returns: list of 32-byte hash vectors."
  (mapcar (lambda (r) (getf (getf r :package-spec) :hash)) reports))

;;; ── E(q, s) — Edit queue (GP 12.7) ─────────────────────────
;;; E(q, s) removes from q:
;;;   1. Any entry whose work-report package hash ∈ s (already accumulated)
;;;   2. From remaining entries, removes any deps that are in s (now satisfied)
;;; Returns: edited queue (list of (:report r :deps (h1 h2 ...)))

(defun accum-edit (queue hash-set)
  "GP §12.7: E(q, s) — Edit a queue by removing completed entries
   and satisfied dependencies.
   QUEUE:    list of (:report r :deps (h1 h2 ...))
   HASH-SET: list of 32-byte hash vectors (accumulated package hashes)
   Returns: edited queue."
  ;; Step 1: Remove entries whose report's package hash is in hash-set
  (let ((filtered (remove-if (lambda (entry)
                               (let ((pkg-hash (getf (getf (getf entry :report)
                                                           :package-spec) :hash)))
                                 (member pkg-hash hash-set :test #'equalp)))
                             queue)))
    ;; Step 2: For remaining entries, remove satisfied deps
    (mapcar (lambda (entry)
              (list :report (getf entry :report)
                    :deps (remove-if (lambda (d)
                                       (member d hash-set :test #'equalp))
                                     (getf entry :deps))))
            filtered)))

;;; ── Q(q) — Priority queue ordering (GP 12.8) ───────────────
;;; Q(q) recursively extracts entries with empty dependency sets,
;;; then re-edits the queue to account for newly resolved deps.
;;; Returns: ordered list of work-reports (not queue entries).
;;;
;;; Algorithm:
;;;   1. Extract all entries with empty deps → ready set
;;;   2. If none ready, return nil (remaining entries stay queued for later)
;;;   3. Compute package hashes of the ready set
;;;   4. E(remaining, ready-hashes) to resolve further deps
;;;   5. Recurse on edited remaining queue
;;;   6. Return ready-reports ++ recursion result

(defun accum-priority-queue (queue)
  "GP §12.8: Q(q) — Priority-ordered extraction of work-reports
   from a dependency queue. Returns: ordered list of work-reports."
  (if (null queue)
      nil
      (let* ((ready    (remove-if-not (lambda (e)
                                        (null (getf e :deps)))
                                      queue))
             (pending  (remove-if (lambda (e)
                                    (null (getf e :deps)))
                                  queue)))
        (if (null ready)
            ;; No entries have empty deps — nothing more to extract
            nil
            (let* ((ready-reports (mapcar (lambda (e) (getf e :report)) ready))
                   (ready-hashes (accum-package-hashes ready-reports))
                   (edited       (accum-edit pending ready-hashes)))
              (append ready-reports
                      (accum-priority-queue edited)))))))

;;; ═══════════════════════════════════════════════════════════════
;;; §12.1 R* COMPUTATION — partitioning, queue editing, ordering
;;; ═══════════════════════════════════════════════════════════════

;;; GP 12.4-12.12:
;;;   m = H_T mod E   (slot within epoch)
;;;   Partition R into R! (zero deps after edit) and R^Q (deferred)
;;;   q = edit(concat(omega[m:], omega[:m], R^Q), P(R!))
;;;   R* = R! ++ Q(q)
;;;   omega' = updated omega with new queues

(defun compute-r-star (reports omega-queues xi-flattened timeslot)
  "Compute R* from new reports and existing omega queues.
   GP §12.4-12.12.

   REPORTS:      list of new work-reports from ρ‡ :reported
   OMEGA-QUEUES: list of E lists of queue entries (from ω)
   XI-FLATTENED: ξ̃ — set of already-accumulated package hashes
   TIMESLOT:     τ' (post-transition timeslot) for computing m

   Returns: (values r-star updated-omega-queues accumulated-hashes)"
  (let* ((e (epoch-duration))
         (m (mod timeslot e))
         ;; ── Compute deps for each new report ──
         (new-entries
          (mapcar (lambda (r)
                    (let ((deps (accum-deps r)))
                      ;; Remove deps already in ξ̃ (already accumulated)
                      (let ((filtered-deps
                             (remove-if (lambda (d)
                                          (member d xi-flattened :test #'equalp))
                                        deps)))
                        (list :report r :deps filtered-deps))))
                  (or reports '())))
         ;; ── Partition: R! = zero deps, R^Q = has deps ──
         (r-immediate (remove-if-not (lambda (e) (null (getf e :deps)))
                                     new-entries))
         (r-deferred  (remove-if     (lambda (e) (null (getf e :deps)))
                                     new-entries))
         ;; ── Immediate reports (list of actual work-reports) ──
         (r-bang (mapcar (lambda (e) (getf e :report)) r-immediate))
         ;; ── P(R!) — package hashes of immediate reports ──
         (p-r-bang (accum-package-hashes r-bang))
         ;; ── Concatenate omega[m:], omega[:m] (epoch rotation) ──
         ;; Then append R^Q
         (omega-rotated (append (subseq omega-queues m e)
                                (subseq omega-queues 0 m)))
         ;; ── Flatten all existing queue entries + R^Q ──
         (combined-queue (append (apply #'append omega-rotated) r-deferred))
         ;; ── E(combined, P(R!)) — edit queue with immediate hashes ──
         (edited-queue (accum-edit combined-queue p-r-bang))
         ;; ── Q(edited) — priority ordering of resolved entries ──
         (ordered-resolved (accum-priority-queue edited-queue))
         ;; ── R* = R! ++ Q(q) ──
         (r-star (append r-bang ordered-resolved))
         ;; ── Hashes of everything we accumulated ──
         (accumulated-hashes (accum-package-hashes r-star))
         ;; ── Build updated omega queues ──
         ;; The entries that remain after extracting resolved ones:
         ;; Remove from edited-queue everything that Q() extracted
         (resolved-hashes (accum-package-hashes ordered-resolved))
         (all-done-hashes (append p-r-bang resolved-hashes))
         (remaining-entries (accum-edit edited-queue all-done-hashes))
         ;; ── Re-distribute remaining entries back into E slots ──
         ;; All remaining entries go into slot m (current slot), other slots empty
         (new-omega-queues (make-list e :initial-element nil)))
    ;; Put remaining entries into the current slot
    (setf (nth m new-omega-queues) remaining-entries)
    (values r-star new-omega-queues accumulated-hashes)))

;;; ═══════════════════════════════════════════════════════════════
;;; transition-accumulate — GP (4.16) top-level entry
;;; ═══════════════════════════════════════════════════════════════

(defun transition-accumulate (r-star-input omega xi delta chi iota phi tau tau-prime)
  "GP §12: (ω', ξ', δ†, χ', ι', ϕ', θ', S) ◁ (R*, ω, ξ, δ, χ, ι, ϕ, τ, τ')

   R-STAR-INPUT: list of work-reports (from ρ‡ :reported)
   OMEGA:     ω closure (accumulation queue)
   XI:        ξ closure (accumulation history)
   DELTA:     δ closure (service accounts)
   CHI:       χ closure (privileged service IDs)
   IOTA:      ι closure (enqueued validators)
   PHI:       ϕ closure (authorization queue)
   TAU:       τ closure (pre-transition timeslot)
   TAU-PRIME: τ' closure (post-transition timeslot)

   Returns plist:
     :omega-prime     — ω' (updated accumulation queue)
     :xi-prime        — ξ' (updated accumulation history)
     :delta-dagger    — δ† (post-accumulate service accounts)
     :chi-prime       — χ' (updated privileged IDs)
     :iota-prime      — ι' (updated enqueued validators)
     :phi-prime       — ϕ' (updated authorization queue)
     :theta-prime     — θ' (accumulation outputs for β')
     :service-stats   — S  (service statistics for π')"
  (declare (ignorable tau))
  (let* ((timeslot (funcall tau-prime :slot))
         (omega-queues (funcall omega :queues))
         (xi-flattened (funcall xi :flattened))
         (e (epoch-duration))
         (m (mod timeslot e)))

    ;; ── §12.1: Compute R* via queue editing and priority ordering ──
    (multiple-value-bind (r-star new-omega-queues accumulated-hashes)
        (compute-r-star r-star-input omega-queues xi-flattened timeslot)
      (declare (ignorable r-star))

      ;; ── ω' (12.10): update omega with new queues ──
      (let ((omega-prime (make-omega-state :queues new-omega-queues)))

        ;; ── ξ' (12.11-12.12): update xi with accumulated package hashes ──
        ;; ξ'[m] = accumulated hashes from this slot
        ;; ξ'[i] = ξ[i] for i ≠ m
        (let ((xi-entries (copy-list (funcall xi :entries))))
          ;; Ensure we have E entries (in case xi is empty/nil)
          (when (null xi-entries)
            (setq xi-entries (make-list e :initial-element nil)))
          ;; Set slot m to the newly accumulated hashes
          (setf (nth m xi-entries) accumulated-hashes)
          (let ((xi-prime (make-xi-state :entries xi-entries)))

            ;; ── §12.2 Execution (STUB) ──
            ;; TODO: Execute PVM Accumulate for each service with work-digests
            ;; For now: passthrough all state

            ;; ── §12.3 Final State Integration (STUB) ──
            ;; TODO: Apply side-effects from PVM execution

            (list :omega-prime   omega-prime
                  :xi-prime      xi-prime
                  :delta-dagger  delta
                  :chi-prime     chi
                  :iota-prime    iota
                  :phi-prime     phi
                  :theta-prime   nil
                  :service-stats nil)))))))
