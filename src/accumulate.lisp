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
   STATE:      mutable accumulation state (plist with :delta-kvs :entropy :timeslot :header-hash etc.)

   Returns: (values side-effects-plist gas-used) or (values nil 0) on failure."
  (let* ((delta-kvs (getf state :delta-kvs))
         (timeslot  (getf state :timeslot))
         ;; ── Parse service account from delta extra-kvs (GP D.1) ──
         (svc-data  (classify-service-sub-keys service-id delta-kvs))
         (metadata  (getf svc-data :metadata))
         (code-blob (getf svc-data :code-blob)))

    ;; No code blob found → skip PVM execution
    (unless code-blob
      (return-from accumulate-service (values nil 0)))

    ;; ── Create PVM instance + Configure + Run + Collect ──
    (handler-case
        (let* ((balance       (or (getf metadata :balance) 0))
               (code-hash     (or (getf metadata :code-hash)
                                  (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
               (min-accum-gas (or (getf metadata :min-item-gas) 0))
               (min-memo-gas  (or (getf metadata :min-memo-gas) 0))
               (items-count   (or (getf metadata :items) 0))
               (total-bytes   (or (getf metadata :bytes) 0))
               (deposit-off   (or (getf metadata :deposit-offset) 0)))
          (jam.ffi:with-pvm (ctx code-blob service-id balance timeslot)
            ;; Configure context as one JAM blob
            (jam.ffi:pvm-configure ctx
              :invocation      2  ;; Accumulate
              :service-id      service-id
              :balance         balance
              :timeslot        timeslot
              :entropy         (or (getf state :entropy)
                                   (make-array 128 :element-type '(unsigned-byte 8) :initial-element 0))
              :header-hash     (or (getf state :header-hash)
                                   (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
              :code-hash       code-hash
              :threshold       deposit-off
              :min-accum-gas   min-accum-gas
              :min-item-gas    min-accum-gas
              :min-on-transfer-gas min-memo-gas
              :items-count     items-count
              :footprint       total-bytes
              :gas             gas-limit
              ;; Service account data (storage, preimages, lookup)
              :storage         (getf svc-data :storage)
              :preimages       (getf svc-data :preimages)
              :lookup          (getf svc-data :lookup)
              ;; Accumulate items (work results for this service)
              :accumulate-items (encode-accumulate-items items nil))

            ;; ── Run PVM accumulate_ext ──
            (multiple-value-bind (status result gas-remaining)
                (jam.ffi:pvm-run ctx "accumulate_ext")
              (declare (ignorable result))

              ;; ── Collapse (resolve dual context per GP B.13) ──
              (jam.ffi:pvm-collapse ctx status)

              ;; ── Collect side-effects (one JAM blob instead of 12 getters) ──
              (let ((effects (collect-side-effects ctx))
                    (gas-used (- gas-limit (or gas-remaining 0))))
                (values effects gas-used)))))

      (error (e)
        (format *error-output* "~&accumulate-service: PVM error for service ~D: ~A~%"
                service-id e)
        (values nil 0)))))

;;; ═══════════════════════════════════════════════════════════════
;;; §12.2 DELTA LOOPS — Δ* (per-report, GP 12.19) and Δ+ (sequential)
;;; ═══════════════════════════════════════════════════════════════

;;; ── R(o, a, b) — Privilege ownership function (GP 12.20) ────
;;; "If the manager changed it (a≠o), use the manager's choice (a).
;;;  If the manager didn't change it (a=o), use the service's choice (b)."
(defun privilege-resolve (original manager-choice service-choice)
  "GP (12.20): R(o, a, b) = b if a = o, else a."
  (if (eql manager-choice original)
      service-choice
      manager-choice))

(defun compute-service-set (reports transfers free-accum)
  "Compute s = { d_s | r ∈ r, d ∈ r_d } ∪ K(f) ∪ { t_d | t ∈ t }.
   REPORTS:      list of work-reports
   TRANSFERS:    list of deferred-transfer plists (:destination ...)
   FREE-ACCUM:   alist of (service-id . gas) from χ_Z
   Returns: sorted list of unique service IDs."
  (let ((sids (make-hash-table :test 'eql)))
    ;; Service IDs from work items in reports
    (dolist (r reports)
      (dolist (w (getf r :results))
        (setf (gethash (getf w :service-id) sids) t)))
    ;; Keys of f (always-accumulate services)
    (dolist (entry free-accum)
      (setf (gethash (car entry) sids) t))
    ;; Destination service IDs from deferred transfers
    (dolist (x transfers)
      (setf (gethash (getf x :destination) sids) t))
    ;; Return sorted unique list
    (sort (loop for k being the hash-keys of sids collect k) #'<)))

(defun accumulate-star (state transfers reports free-accum)
  "GP §12.19 Δ*: Parallel service-aggregated accumulation.
   STATE:        S = (d, i, q, m, a, v, r, z, ...) — mutable accum-state plist
   TRANSFERS:    list of deferred-transfer plists (from prior round)
   REPORTS:      list of work-reports
   FREE-ACCUM:   alist of (service-id . gas) from χ_Z
   Returns: (values state' new-transfers commitments gas-usage)"
  (let* (;; ── s: set of services to accumulate ──
         (s (compute-service-set reports transfers free-accum))
         ;; ── Collect operand tuples from all reports ──
         (all-tuples (mapcan #'extract-operand-tuples reports))
         (by-service (group-by-service all-tuples))
         ;; ── Run Δ_1 for each service s ∈ s ──
         ;; results: alist of (sid . effects-plist)
         (delta-results (make-hash-table :test 'eql))
         (gas-usage nil)       ;; u = [(sid, gas-used)]
         (commitments nil)     ;; b = {(sid, yield-hash) | yield ≠ ∅}
         (new-transfers nil)   ;; t' = concat of all transfers
         (remaining-gas (getf state :remaining-gas)))

    (dolist (sid s)
      (when (<= remaining-gas 0) (return))

      (let* ((items (or (gethash sid by-service) nil))
             ;; Gas: max of (sum of advertised, free-accum gas, transfer gas)
             (work-gas (if items
                           (reduce #'+ items :key (lambda (u) (or (getf u :gas) 0)))
                           0))
             (free-gas (or (cdr (assoc sid free-accum)) 0))
             (xfer-gas (reduce #'+ (remove-if-not
                                    (lambda (x) (= (getf x :destination) sid))
                                    transfers)
                               :key (lambda (x) (or (getf x :gas-limit) 0))
                               :initial-value 0))
             (total-gas (+ work-gas free-gas xfer-gas))
             (gas-limit (min total-gas remaining-gas)))

        (when (plusp gas-limit)
          (multiple-value-bind (effects gas-used)
              (accumulate-service sid items gas-limit state)

            ;; Store Δ(s) result
            (setf (gethash sid delta-results) effects)

            ;; u: gas usage
            (push (cons sid gas-used) gas-usage)

            ;; b: commitments (yield output)
            (when (and effects (getf effects :yield-output))
              (push (cons sid (getf effects :yield-output)) commitments))

            ;; t': new deferred transfers from this service
            (when (and effects (getf effects :transfers))
              (dolist (xfer (getf effects :transfers))
                (push (list :sender      sid
                            :destination (getf xfer :to)
                            :amount      (getf xfer :amount)
                            :memo        (getf xfer :memo)
                            :gas-limit   (or (getf xfer :gas-limit) 0))
                      new-transfers)))

            ;; Track for delta† construction
            (let ((svc-effects (or (getf state :service-effects) nil)))
              (push (cons sid effects) svc-effects)
              (setf (getf state :service-effects) svc-effects))

            ;; Deduct gas
            (decf remaining-gas gas-used)
            (setf (getf state :remaining-gas) remaining-gas)))))

    ;; ── Privilege updates (GP 12.19) ──
    ;; e = (d, i, q, m, a, v, r, z) — unpack current state
    (let* ((m-mgr  (getf state :chi-manager))
           (v-des  (getf state :chi-designate))
           (r-stk  (getf state :chi-creation))
           (a-auth (getf state :chi-authorizers))
           (z-gas  (getf state :chi-always-accum))
           ;; e* = Δ(m)_e — manager service's empower output
           (mgr-effects (gethash m-mgr delta-results))
           (e-star (when mgr-effects (getf mgr-effects :empower))))

      ;; (m', z') = e*_{(m,z)}
      (when e-star
        (setf (getf state :chi-manager)      (getf e-star :manager))
        (setf (getf state :chi-always-accum) (getf e-star :gas-map)))

      ;; v' = R(v, e*_v, (Δ(v)_e)_v)
      (let* ((des-effects (gethash v-des delta-results))
             (des-empower (when des-effects (getf des-effects :empower))))
        (when (and e-star des-empower)
          (setf (getf state :chi-designate)
                (privilege-resolve v-des
                                  (getf e-star :validator)
                                  (getf des-empower :validator))))
        ;; i' = (Δ(v)_e)_i — validator keys from designate service
        (when des-empower
          (setf (getf state :iota-validators) (getf des-empower :validators))))

      ;; r' = R(r, e*_r, (Δ(r)_e)_r)
      (let* ((stk-effects (gethash r-stk delta-results))
             (stk-empower (when stk-effects (getf stk-effects :empower))))
        (when (and e-star stk-empower)
          (setf (getf state :chi-creation)
                (privilege-resolve r-stk
                                  (getf e-star :staker)
                                  (getf stk-empower :staker)))))

      ;; ∀c ∈ N_C: a'_c = R(a_c, (e*_a)_c, ((Δ(a_c)_e)_a)_c)
      ;; ∀c ∈ N_C: q'_c = ((Δ(a_c)_e)_q)_c
      (when a-auth
        (let ((new-auth (copy-list a-auth))
              (new-queues (getf state :phi-queues)))
          (loop for c from 0 below (num-cores)
                for a-c = (nth c a-auth)
                do (let* ((ac-effects (gethash a-c delta-results))
                          (ac-empower (when ac-effects (getf ac-effects :empower))))
                     ;; a'_c
                     (when (and e-star ac-empower)
                       (let ((e-star-ac (nth c (getf e-star :auth-agents)))
                             (self-ac   (nth c (getf ac-empower :auth-agents))))
                         (when (and e-star-ac self-ac)
                           (setf (nth c new-auth)
                                 (privilege-resolve a-c e-star-ac self-ac)))))
                     ;; q'_c
                     (when (and ac-empower new-queues)
                       (let ((q-c (nth c (getf ac-empower :queues))))
                         (when q-c
                           (setf (nth c new-queues) q-c))))))
          (setf (getf state :chi-authorizers) new-auth)
          (when new-queues
            (setf (getf state :phi-queues) new-queues)))))

    (values state
            (nreverse new-transfers)
            (nreverse commitments)
            (nreverse gas-usage))))

(defun accumulate-all (r-star state)
  "GP §12.2 Δ+(g, t, R*, e, f): Sequential accumulation of all work-reports.
   Recursive definition:
     Δ+(g, t, [],    e, f) = Δ*(e, t, [], f)         — base case
     Δ+(g, t, r:R*, e, f) = let (e',t',b,u) = Δ*(e, t, [r], f)
                              in (n+1, Δ+(g', t', R*, e', f))
   f (always-accumulate) is passed to EVERY Δ* call.
   After the last report, one final Δ* call processes residual
   deferred transfers + always-accumulate services.

   STATE is the mutable accumulation state (includes χ fields, f).
   Returns: updated STATE with :commitments, :gas-usage, :pending-transfers populated."
  (let ((all-commitments nil)
        (all-gas-usage nil)
        (pending-transfers (getf state :pending-transfers))
        (free-accum (getf state :chi-always-accum))
        (first-round t))

    ;; Track n = number of reports actually accumulated (GP 12.25)
    (let ((n 0))

      ;; ── Process each work-report: Δ*(e, t, [r], f) ──
      (dolist (report r-star)
        (when (<= (getf state :remaining-gas) 0)
          (return))

        (multiple-value-bind (state* new-transfers commitments gas-usage)
            (accumulate-star state
                            (if first-round pending-transfers nil)
                            (list report)
                            free-accum)  ;; f passed EVERY round
          (setf state state*)
          (setf pending-transfers new-transfers)
          (setf all-commitments (nconc all-commitments commitments))
          (setf all-gas-usage (nconc all-gas-usage gas-usage))
          (setf first-round nil)
          (incf n)))

      ;; ── Base case: Δ*(e, t, [], f) — final round ──
      ;; Process residual deferred transfers + always-accumulate
      (when (and (plusp (getf state :remaining-gas))
                 (or pending-transfers free-accum))
        (multiple-value-bind (state* new-transfers commitments gas-usage)
            (accumulate-star state
                            pending-transfers
                            nil    ;; no reports
                            free-accum)
          (setf state state*)
          (setf pending-transfers new-transfers)
          (setf all-commitments (nconc all-commitments commitments))
          (setf all-gas-usage (nconc all-gas-usage gas-usage))))

      ;; Store results back in state
      (setf (getf state :commitments) all-commitments)
      (setf (getf state :gas-usage) all-gas-usage)
      (setf (getf state :pending-transfers) pending-transfers)
      (setf (getf state :n-accumulated) n)
      state)))

;;; ═══════════════════════════════════════════════════════════════
;;; §12.3 DELTA† CONSTRUCTION — apply PVM side-effects to trie
;;; ═══════════════════════════════════════════════════════════════

(defun build-delta-dagger (accum-state delta-kvs timeslot)
  "Construct δ† from the accumulated PVM side-effects.
   Surgically updates only what changed:
   1. ServiceInfo metadata (last-accumulation-slot ← τ')
   2. Storage entries (remove old, add new from PVM)
   3. Lookup entries (replace with PVM's updated table)
   4. Preimage entries (add new from provided-preimages, keep existing)

   ACCUM-STATE: the mutable accumulation state after Δ+
   DELTA-KVS:   the original delta extra-kvs
   TIMESLOT:    τ' (post-transition timeslot)

   Returns: a new delta-state closure."
  (let ((new-kvs (copy-alist delta-kvs))
        (accumulated-sids nil)
        (svc-effects (getf accum-state :service-effects)))

    ;; Collect unique accumulated service IDs
    (dolist (se svc-effects)
      (let ((sid (car se)))
        (unless (member sid accumulated-sids)
          (push sid accumulated-sids))))

    ;; ── Update each accumulated service ──
    (dolist (sid accumulated-sids)
      ;; Find the metadata KV entry for this service
      (let ((meta-entry (find-if (lambda (kv)
                                   (and (service-metadata-key-p (car kv))
                                        (= (service-id-from-metadata-key (car kv)) sid)))
                                 new-kvs)))
        (when meta-entry
          (let ((info (decode-service-info (cdr meta-entry))))
            ;; Update last-accumulation-slot to τ'
            (setf (getf info :last-accumulation-slot) timeslot)

            ;; Find the LAST effects for this service (most recent invocation)
            ;; (effects are pushed in order, so first in list = last invocation)
            (let ((last-effects nil))
              (dolist (se svc-effects)
                (when (= (car se) sid)
                  (unless last-effects
                    (setf last-effects (cdr se)))))

              (when last-effects
                ;; Update balance from PVM
                (let ((new-balance (getf last-effects :balance)))
                  (when new-balance
                    (setf (getf info :balance) new-balance)))

                ;; ── Storage: remove old storage entries, add PVM's ──
                ;; Classify original sub-keys to identify which are storage
                (let ((orig-classified (classify-service-sub-keys sid delta-kvs)))
                  ;; Remove ONLY old storage trie entries (not preimages or lookup)
                  (let ((old-storage-h27s
                         (mapcar #'car (getf orig-classified :storage))))
                    (when old-storage-h27s
                      (setf new-kvs
                            (remove-if (lambda (kv)
                                         (and (not (service-metadata-key-p (car kv)))
                                              (not (segment-key-p (car kv)))
                                              (= (service-id-from-sub-key (car kv)) sid)
                                              (member (extract-sub-key-h (car kv))
                                                      old-storage-h27s :test #'equalp)))
                                       new-kvs)))))

                ;; Add new storage entries from PVM
                (dolist (s-entry (getf last-effects :storage))
                  (let* ((raw-key (car s-entry))
                         (val     (cdr s-entry))
                         (h-27    (storage-trie-h raw-key))
                         (trie-key (interleave-sub-key sid h-27)))
                    (push (cons trie-key (ensure-bytes val)) new-kvs)))

                ;; ── Lookup: replace lookup entries with PVM's ──
                ;; Remove old lookup trie entries
                (let ((orig-classified (classify-service-sub-keys sid delta-kvs)))
                  (let ((old-lookup-h27s
                         (mapcar (lambda (l)
                                   (lookup-trie-h (first l) (second l)))
                                 (getf orig-classified :lookup))))
                    (when old-lookup-h27s
                      (setf new-kvs
                            (remove-if (lambda (kv)
                                         (and (not (service-metadata-key-p (car kv)))
                                              (not (segment-key-p (car kv)))
                                              (= (service-id-from-sub-key (car kv)) sid)
                                              (member (extract-sub-key-h (car kv))
                                                      old-lookup-h27s :test #'equalp)))
                                       new-kvs)))))

                ;; Add PVM's lookup entries
                (dolist (l-entry (getf last-effects :lookup))
                  (let* ((hash-32  (first l-entry))
                         (length   (second l-entry))
                         (statuses (cddr l-entry))
                         (h-27     (lookup-trie-h hash-32 length))
                         (trie-key (interleave-sub-key sid h-27))
                         (val      (encode-lookup-value statuses)))
                    (push (cons trie-key val) new-kvs)))

                ;; ── Preimages: add new from provided-preimages ──
                ;; Existing preimage blobs are kept (not removed).
                (dolist (pp (getf last-effects :provided-preimages))
                  (let* ((pp-sid  (car pp))
                         (pp-data (cdr pp))
                         (pp-hash (jam.ffi:blake2b-256 pp-data))
                         (h-27    (preimage-trie-h pp-hash))
                         (trie-key (interleave-sub-key pp-sid h-27)))
                    (push (cons trie-key (ensure-bytes pp-data)) new-kvs)))))

            ;; Re-encode and replace the metadata entry
            (setf (cdr meta-entry) (encode-service-info info))))))

    (make-delta-state :raw-kvs new-kvs)))

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
      (declare (ignorable accumulated-hashes))

      ;; ── Decode χ (GP 9.9) for privilege fields ──
      (let* ((chi-mgr  (funcall chi :manager))
             (chi-des  (funcall chi :designate))
             (chi-stk  (funcall chi :creation))
             (chi-auth (funcall chi :authorizers))
             (chi-az   (funcall chi :always-accum))

             ;; ── §12.2 Execution ──
             ;; Build mutable accumulation state S = (d, i, q, m, a, v, r, z, ...)
             (original-kvs (funcall delta :extra-kvs))
             (accum-state
              (list :delta-kvs        original-kvs
                    :timeslot         timeslot
                    :entropy          nil ;; TODO: pass η from sigma
                    :header-hash      nil ;; TODO: pass H_T from header
                    :remaining-gas    (max-block-gas)
                    ;; ── GP §12.16 S fields ──
                    :chi-manager      chi-mgr    ;; m = χ_M
                    :chi-designate    chi-des    ;; v = χ_V
                    :chi-creation     chi-stk    ;; r = χ_R
                    :chi-authorizers  chi-auth   ;; a = χ_A
                    :chi-always-accum chi-az     ;; z = χ_Z
                    :iota-validators  nil        ;; i = ι (set by Δ*)
                    :phi-queues       nil        ;; q = ϕ (set by Δ*)
                    ;; ── Accumulators ──
                    :commitments      nil        ;; B: (sid . yield-hash)
                    :gas-usage        nil        ;; U: (sid . gas-used)
                    :pending-transfers nil       ;; X: deferred transfers
                    :service-effects  nil)))     ;; Per-service PVM effects

        ;; Run Δ+ (sequential over R*) — GP (12.25)
        (setf accum-state (accumulate-all r-star accum-state))

        ;; ── §12.3 Final State Integration ──

        (let* ((n (or (getf accum-state :n-accumulated) 0))

               ;; ── ξ' (12.32-12.33): shift register ──
               ;; ξ'_{E-1} = P(R*_{...n}) — package hashes of actually accumulated reports
               ;; ∀i ∈ N_{E-1}: ξ'_i = ξ_{i+1} — shift left
               (old-xi (let ((entries (funcall xi :entries)))
                         (if (and entries (listp entries) (= (length entries) e))
                             entries
                             (make-list e :initial-element nil))))
               (accumulated-n-hashes
                (accum-package-hashes (subseq r-star 0 (min n (length r-star)))))
               (new-xi (let ((nxi (make-list e :initial-element nil)))
                         ;; Shift left: ξ'[i] = ξ[i+1]
                         (loop for i from 0 below (1- e)
                               do (setf (nth i nxi) (nth (1+ i) old-xi)))
                         ;; ξ'[E-1] = P(R*_{...n})
                         (setf (nth (1- e) nxi) accumulated-n-hashes)
                         nxi))
               (xi-prime (make-xi-state :entries new-xi))

               ;; ── ω' (12.34): update omega ──
               ;; For now, use the queue-edited omega from compute-r-star
               ;; TODO: implement full 12.34 with slot clearing for τ'-τ gaps
               (omega-prime (make-omega-state :queues new-omega-queues))

               ;; ── δ† (12.30-12.31): apply PVM side-effects back to trie ──
               (delta-dagger (build-delta-dagger accum-state original-kvs timeslot))

               ;; ── χ' (12.27): updated privilege fields ──
               (chi-prime
                (make-chi-state
                 :raw (encode-chi-fields
                       (list :manager    (or (getf accum-state :chi-manager) chi-mgr)
                             :designate  (or (getf accum-state :chi-designate) chi-des)
                             :creation   (or (getf accum-state :chi-creation) chi-stk)
                             :authorizers (or (getf accum-state :chi-authorizers) chi-auth)
                             :always-accum (or (getf accum-state :chi-always-accum) chi-az)))))

               ;; ── θ' (12.26): accumulation output log ──
               (theta-prime
                (when (getf accum-state :commitments)
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
                                       (getf accum-state :commitments))))))

               ;; ── S (12.28-12.29): service statistics for π' ──
               (service-stats (getf accum-state :gas-usage)))

          (list :omega-prime   omega-prime
                :xi-prime      xi-prime
                :delta-dagger  delta-dagger
                :chi-prime     chi-prime
                :iota-prime    iota    ;; ι' (updated via Δ* if designate ran)
                :phi-prime     phi     ;; ϕ' (updated via Δ* if auth agents ran)
                :theta-prime   theta-prime
                :service-stats service-stats))))))
