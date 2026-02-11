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
;;; §12.2 DATA EXTRACTION — U (operand tuples), X (deferred transfers)
;;; ═══════════════════════════════════════════════════════════════

;;; GP (12.13): U ≡ {p ∈ H, e ∈ H, a ∈ H, y ∈ H, g ∈ N_G, t ∈ B, l ∈ B ∪ E}
;;; Extracted from work-report + work-result.

(defun extract-operand-tuples (report)
  "GP §12.13: Extract operand tuples from a work-report.
   For each work-result w in r.results, build:
     p = r.package-spec.hash (package hash)
     e = r.package-spec.exports-root
     a = r.authorizer-hash
     y = w.payload-hash
     g = w.accumulate-gas (gas limit for accumulate)
     t = w.result (:ok blob | :panic | :out-of-gas | ...)
     l = r.auth-output (or empty)
   Returns: list of (service-id . U-plist) pairs."
  (let* ((pkg-spec (getf report :package-spec))
         (pkg-hash (getf pkg-spec :hash))
         (exports-root (getf pkg-spec :exports-root))
         (auth-hash (getf report :authorizer-hash))
         (auth-output (getf report :auth-output)))
    (mapcar (lambda (w)
              (cons (getf w :service-id)
                    (list :package-hash  pkg-hash
                          :exports-root  exports-root
                          :auth-hash     auth-hash
                          :payload-hash  (getf w :payload-hash)
                          :gas           (getf w :accumulate-gas)
                          :result        (getf w :result)
                          :auth-output   auth-output
                          :code-hash     (getf w :code-hash))))
            (or (getf report :results) '()))))

(defun group-by-service (tuples)
  "Group (service-id . U-plist) pairs by service-id.
   Returns: hash-table mapping service-id → list of U-plists."
  (let ((ht (make-hash-table :test 'eql)))
    (dolist (pair tuples)
      (let ((sid (car pair))
            (u   (cdr pair)))
        (push u (gethash sid ht))))
    ;; Reverse so first-in stays first
    (maphash (lambda (k v) (setf (gethash k ht) (nreverse v))) ht)
    ht))

;;; GP (12.14): X ≡ (s, d, a, m, g) — deferred transfer
;;; Deferred transfers come from prior accumulation's on-transfer outputs.

(defun deferred-transfers-for-service (transfers service-id)
  "Filter deferred transfers (X) for a specific destination service.
   TRANSFERS: list of plists (:sender s :destination d :amount a :memo m :gas-limit g)
   Returns: list of transfers where :destination = SERVICE-ID."
  (remove-if-not (lambda (x) (= (getf x :destination) service-id)) transfers))

;;; ═══════════════════════════════════════════════════════════════
;;; §12.2 PER-SERVICE PVM INVOCATION — accumulate-service
;;; ═══════════════════════════════════════════════════════════════

(defun encode-accumulate-items (items report)
  "Encode operand tuples as AccumulateItem bytes for the PVM.
   ITEMS: list of U-plists for one service.
   REPORT: the parent work-report (for package-hash, exports-root, etc.)
   Returns: list of encoded byte vectors."
  (declare (ignorable report))
  (mapcar (lambda (u)
            (let* ((result-entry (getf u :result))
                   ;; result-entry is (:ok blob) or (:panic t) etc.
                   (result-data (when (getf result-entry :ok)
                                  (getf result-entry :ok)))
                   (auth-output (getf u :auth-output)))
              (jam.ffi:pvm-encode-work-item-record
               (getf u :package-hash)
               (getf u :exports-root)
               (getf u :auth-hash)
               (getf u :payload-hash)
               (or (getf u :gas) 0)
               result-data
               auth-output)))
          items))

(defun collect-side-effects (ctx)
  "Read all PVM side-effects after accumulate execution.
   Returns a plist with :balance :gas-remaining :storage :transfers :ejected
   :created :upgrades :empower :provided-preimages :lookup :yield-output.
   Uses jam_pvm_collect (single JAM-codec blob) instead of 12 individual getters."
  (jam.ffi:pvm-collect ctx))

(defun accumulate-service (service-id items gas-limit state)
  "GP §12.2: Execute PVM Accumulate for one service.

   SERVICE-ID: the service to accumulate
   ITEMS:      list of U-plists (operand tuples for this service)
   GAS-LIMIT:  gas budget for this invocation
   STATE:      mutable accumulation state (plist with :delta :entropy :timeslot :header-hash etc.)

   Returns: (values side-effects-plist gas-used) or (values nil 0) on failure."
  (let* ((delta-kvs (getf state :delta-kvs))
         (timeslot  (getf state :timeslot))
         ;; Try to find service code blob from delta extra-kvs.
         ;; Service accounts are stored under Merkle key C(255, s).
         ;; For now, we can't decode them — gracefully skip.
         (service-code nil))
    (declare (ignorable delta-kvs))

    ;; TODO: Extract service code from delta when service account codec is available.
    ;; For now, skip PVM execution if we can't load code.
    (unless service-code
      (return-from accumulate-service (values nil 0)))

    ;; ── Create PVM instance + Configure + Run + Collect (new wire API) ──
    (handler-case
        (jam.ffi:with-pvm (ctx service-code service-id 0 timeslot)
          ;; Configure context in one blob (replaces ~8 individual setter calls)
          (jam.ffi:pvm-configure ctx
            :invocation 2  ;; Accumulate
            :service-id service-id
            :balance 0
            :timeslot timeslot
            :entropy (or (getf state :entropy)
                         (make-array 128 :element-type '(unsigned-byte 8) :initial-element 0))
            :header-hash (or (getf state :header-hash)
                             (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
            :gas gas-limit
            :accumulate-items (encode-accumulate-items items nil))

          ;; ── Run PVM accumulate_ext ──
          (multiple-value-bind (status result gas-remaining)
              (jam.ffi:pvm-run ctx "accumulate_ext")
            (declare (ignorable result))

            ;; ── Collapse (resolve dual context per GP B.13) ──
            (let ((outcome (cond
                             ((= status 0) ;; OK — check if yield hash set
                              (if (jam.ffi:pvm-has-yield-output ctx) 3 0))
                             ((= status 5) 1) ;; Trap -> Panic
                             ((= status 6) 2) ;; OOG
                             (t 1))))         ;; Other -> Panic
              (if (= outcome 3)
                  (jam.ffi:pvm-accumulate-collapse ctx 3 (jam.ffi:pvm-get-yield-output ctx))
                  (jam.ffi:pvm-accumulate-collapse ctx outcome))

              ;; ── Collect side-effects (one JAM blob instead of 12 getters) ──
              (let ((effects (collect-side-effects ctx))
                    (gas-used (- gas-limit (or gas-remaining 0))))
                (values effects gas-used)))))

      (error (e)
        (format *error-output* "~&accumulate-service: PVM error for service ~A: ~A~%" service-id e)
        (values nil 0)))))

;;; ═══════════════════════════════════════════════════════════════
;;; §12.2 DELTA LOOPS — Δ* (per-report) and Δ+ (sequential)
;;; ═══════════════════════════════════════════════════════════════

(defun apply-service-effects (effects service-id state)
  "Apply side-effects from one service's accumulation back to the mutable state S.
   Mutates STATE in-place (plist with :commitments, :gas-usage, etc.).
   Returns: updated STATE."
  (when effects
    ;; ── B: Commitments (service-id, yield-hash) ──
    (let ((yield-hash (getf effects :yield-output)))
      (when yield-hash
        (push (cons service-id yield-hash) (getf state :commitments))))

    ;; ── Deferred transfers (for subsequent services) ──
    (let ((transfers (getf effects :transfers)))
      (when (and transfers (plusp (length transfers)))
        (loop for xfer across transfers
              do (push (list :sender      service-id
                             :destination (gethash :destination xfer)
                             :amount      (gethash :amount xfer)
                             :memo        (gethash :memo xfer)
                             :gas-limit   (or (gethash :gas-limit xfer) 0))
                       (getf state :pending-transfers)))))

    ;; ── Created services ──
    (dolist (entry (getf effects :created))
      (push entry (getf state :created-services)))

    ;; ── Ejected services ──
    (dolist (entry (getf effects :ejected))
      (push entry (getf state :ejected-services)))

    ;; ── Upgrades ──
    (dolist (entry (getf effects :upgrades))
      (push entry (getf state :upgrade-list)))

    ;; ── Empower (bless) ──
    (when (getf effects :empower)
      (setf (getf state :empower) (getf effects :empower))))

  state)

(defun accumulate-report (report state)
  "GP §12.2 Δ*: Accumulate one work-report (service-aggregated, non-sequential).
   Groups operand tuples by service and invokes PVM for each.
   STATE is the mutable accumulation state.
   Returns: updated STATE."
  (let* ((tuples (extract-operand-tuples report))
         (by-service (group-by-service tuples))
         (remaining-gas (getf state :remaining-gas)))

    ;; Process each service in deterministic order (ascending service ID)
    (let ((service-ids (sort (loop for k being the hash-keys of by-service collect k) #'<)))
      (dolist (sid service-ids)
        (when (<= remaining-gas 0)
          (return))  ;; No gas left
        (let* ((items (gethash sid by-service))
               ;; Gas for this service = min(advertised accumulate-gas, remaining block gas)
               (advertised-gas (reduce #'+ items :key (lambda (u) (or (getf u :gas) 0))))
               (gas-limit (min advertised-gas remaining-gas)))
          (when (plusp gas-limit)
            (multiple-value-bind (effects gas-used)
                (accumulate-service sid items gas-limit state)
              ;; Track gas usage: U = [(service_id, gas_used)]
              (push (cons sid gas-used) (getf state :gas-usage))
              ;; Apply side-effects
              (apply-service-effects effects sid state)
              ;; Deduct gas
              (decf remaining-gas gas-used)
              (setf (getf state :remaining-gas) remaining-gas)))))))
  state)

(defun accumulate-all (r-star state)
  "GP §12.2 Δ+: Sequential accumulation of all work-reports in R*.
   For the first report, deferred transfers from prior accumulation are integrated.
   STATE is the mutable accumulation state.
   Returns: updated STATE."
  ;; Process each work-report sequentially (gas-limited)
  (dolist (report r-star)
    (when (<= (getf state :remaining-gas) 0)
      (return))
    (setf state (accumulate-report report state)))
  state)

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

      ;; ── ω' (12.10): update omega with new queues ──
      (let ((omega-prime (make-omega-state :queues new-omega-queues)))

        ;; ── ξ' (12.11-12.12): update xi with accumulated package hashes ──
        (let ((xi-entries (copy-list (funcall xi :entries))))
          (when (null xi-entries)
            (setq xi-entries (make-list e :initial-element nil)))
          (setf (nth m xi-entries) accumulated-hashes)
          (let ((xi-prime (make-xi-state :entries xi-entries)))

            ;; ── §12.2 Execution ──
            ;; Build mutable accumulation state S
            (let ((accum-state (list :delta-kvs       (funcall delta :extra-kvs)
                                     :timeslot        timeslot
                                     :entropy         nil ;; TODO: pass η from sigma
                                     :header-hash     nil ;; TODO: pass H_T from header
                                     :remaining-gas   (max-block-gas)
                                     :commitments     nil ;; B: (service-id . yield-hash) pairs
                                     :gas-usage       nil ;; U: (service-id . gas-used) pairs
                                     :pending-transfers nil ;; X: deferred transfers
                                     :created-services nil
                                     :ejected-services nil
                                     :upgrade-list    nil
                                     :empower         nil)))

              ;; Run Δ+ (sequential over R*)
              (setf accum-state (accumulate-all r-star accum-state))

              ;; ── §12.3 Final State Integration ──
              ;; Build θ' (commitments for β')
              (let ((theta-prime (when (getf accum-state :commitments)
                                   (make-theta-state
                                    :raw (apply #'concatenate '(vector (unsigned-byte 8))
                                                (mapcar (lambda (c)
                                                          (let ((sid (car c))
                                                                (yh  (cdr c)))
                                                            (concatenate '(vector (unsigned-byte 8))
                                                                         (vector (ldb (byte 8  0) sid)
                                                                                 (ldb (byte 8  8) sid)
                                                                                 (ldb (byte 8 16) sid)
                                                                                 (ldb (byte 8 24) sid))
                                                                         (coerce yh '(vector (unsigned-byte 8))))))
                                                        (nreverse (getf accum-state :commitments)))))))
                    ;; Build S (service statistics for π')
                    (service-stats (nreverse (getf accum-state :gas-usage))))

                ;; Note: χ', ι', ϕ' are only mutated by PVM host calls (Ω_B, Ω_A, Ω_D).
                ;; Until service code can be loaded, they pass through unchanged.
                ;; The empower field in accum-state would update χ', and
                ;; created/ejected would update δ†.

                (list :omega-prime   omega-prime
                      :xi-prime      xi-prime
                      :delta-dagger  delta   ;; δ† (mutated by PVM, passthrough for now)
                      :chi-prime     chi     ;; χ' (set by Ω_B via empower)
                      :iota-prime    iota    ;; ι' (set by Ω_A via auth agents)
                      :phi-prime     phi     ;; ϕ' (set by Ω_D via auth queues)
                      :theta-prime   theta-prime
                      :service-stats service-stats)))))))))
