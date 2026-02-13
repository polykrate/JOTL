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
   Returns: list of 32-byte hash vectors, sorted lexicographically.
   
   GP 12.9 defines P as returning a set {(r_p)_h | r ∈ r}, but for use in
   ξ' (accumulation history) we need a deterministic ordering. We sort
   lexicographically by hash bytes."
  (sort (mapcar (lambda (r) (getf (getf r :package-spec) :hash)) reports)
        #'vector<))

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
         ;; ── Step 0: Identify stale slots and prepare cleared queues for ω' ──
         ;; Stale range: (τ+1..τ'] mod E. These are cleared for ω' output
         ;; but their entries are still available for Q() to resolve chains.
         (stale-gap (min e (- timeslot prev-timeslot)))
         (cleared-queues (let ((q (copy-list omega-queues)))
                           (loop for k from 1 to stale-gap do
                             (let ((idx (mod (+ prev-timeslot k) e)))
                               (setf (nth idx q) nil)))
                           q))
         ;; ── Step 1: Compute deps for each new report ──
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
         ;; ── Step 2: Partition: R! = zero deps, R^Q = has deps ──
         (r-immediate (remove-if-not (lambda (entry) (null (getf entry :deps)))
                                     new-entries))
         (r-deferred  (remove-if     (lambda (entry) (null (getf entry :deps)))
                                     new-entries))
         ;; ── R! as work-reports ──
         (r-bang (mapcar (lambda (entry) (getf entry :report)) r-immediate))
         ;; ── P(R!) — package hashes of immediate reports ──
         (p-r-bang (accum-package-hashes r-bang)))

    ;; ── Step 3: Edit ORIGINAL omega slots with ξ̃, then P(R!) ──
    ;; Use original (uncleared) queues for Q() so chains through stale
    ;; slots can be resolved.  GP 12.11: q = E(ω[m:]⌢ω[:m]⌢R^Q, P(R!))
    (let ((q-slots (make-array e :initial-element nil))   ;; for Q() computation
          (w-slots (make-array e :initial-element nil)))  ;; for ω' output
      ;; Build q-slots from ORIGINAL omega (for R* computation)
      (loop for i from 0 below e do
          (setf (aref q-slots i)
              (accum-edit
               (accum-edit (or (nth i omega-queues) nil) xi-flattened)
               p-r-bang)))
      ;; Build w-slots from CLEARED omega (for ω' output)
      (loop for i from 0 below e do
          (setf (aref w-slots i)
              (accum-edit
               (accum-edit (or (nth i cleared-queues) nil) xi-flattened)
               p-r-bang)))

      ;; ── Step 4: Add R^Q to slot m ──
      (let ((r-deferred-edited (accum-edit r-deferred p-r-bang)))
        (setf (aref q-slots m) (append (aref q-slots m) r-deferred-edited))
        (setf (aref w-slots m) (append (aref w-slots m) r-deferred-edited)))

      ;; ── Step 5: Q() — extract ready entries across ALL q-slots ──
      (let* ((all-queued (loop for i from 0 below e
                               nconc (copy-list (aref q-slots i))))
             (ordered-resolved (accum-priority-queue all-queued))
             ;; ── R* = R! ++ Q(q) ──
             (r-star (append r-bang ordered-resolved))
             (accumulated-hashes (accum-package-hashes r-star))
             ;; Hashes of Q()-extracted entries
             (resolved-hashes (accum-package-hashes ordered-resolved))
             (all-done-hashes (append p-r-bang resolved-hashes)))

        ;; ── Step 6: Build ω' from w-slots (cleared) ──
        ;; Remove extracted entries from w-slots (which already has stale cleared).
        (let ((new-omega-queues (make-list e :initial-element nil)))
          (loop for i from 0 below e do
            (setf (nth i new-omega-queues)
                  (remove-if (lambda (entry)
                               (let ((pkg-hash (getf (getf (getf entry :report)
                                                           :package-spec)
                                                     :hash)))
                                 (member pkg-hash all-done-hashes :test #'equalp)))
                             (aref w-slots i))))
          (values r-star new-omega-queues accumulated-hashes))))))

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

(defun work-exec-result-kind (result-entry)
  "Map a WorkExecResult plist to the result-kind byte for the PVM encoder.
   GP WorkExecResult variants:
     0 = Ok (with output data)
     1 = OutOfGas
     2 = Panic
     3 = BadExports
     4 = OutputOversize
     5 = BadCode
     6 = CodeOversize"
  (cond
    ((getf result-entry :ok)              0)
    ((getf result-entry :out-of-gas)      1)
    ((getf result-entry :panic)           2)
    ((getf result-entry :bad-exports)     3)
    ((getf result-entry :output-oversize) 4)
    ((getf result-entry :bad-code)        5)
    ((getf result-entry :code-oversize)   6)
    (t 2)))  ;; Unknown → default to panic

(defun encode-work-items (items)
  "Encode work-item operand tuples as AccumulateItem::WorkItem bytes for the PVM.
   ITEMS: list of U-plists for one service.
   Returns: list of encoded byte vectors."
  (mapcar (lambda (u)
            (let* ((result-entry (getf u :result))
                   ;; result-entry is (:ok blob) or (:panic t) etc.
                   (result-kind (work-exec-result-kind result-entry))
                   (result-data (when (getf result-entry :ok)
                                  (getf result-entry :ok)))
                   (auth-output (getf u :auth-output)))
              (jam.ffi:pvm-encode-work-item-record
               (getf u :package-hash)
               (getf u :exports-root)
               (getf u :auth-hash)
               (getf u :payload-hash)
               (or (getf u :gas) 0)
               result-kind
               result-data
               auth-output)))
          items))

(defun encode-transfer-items (transfers)
  "Encode deferred transfers as AccumulateItem::Transfer bytes for the PVM.
   GP 12.24: i^T = [t | t ≤ t, t_d = s]
   TRANSFERS: list of plists (:sender :destination :amount :memo :gas-limit)
   Returns: list of encoded byte vectors."
  (mapcar (lambda (x)
            (jam.ffi:pvm-encode-transfer-record
             (or (getf x :sender) 0)
             (or (getf x :destination) 0)
             (or (getf x :amount) 0)
             (getf x :memo)
             (or (getf x :gas-limit) 0)))
          transfers))

(defun encode-accumulate-items (items transfers)
  "Encode ALL accumulate items: transfers first, then work items.
   GP 12.24: i = i^T ⌢ i^U — transfers prepended before work items.
   Returns: list of encoded byte vectors."
  (append (encode-transfer-items (or transfers nil))
          (encode-work-items (or items nil))))

(defun collect-side-effects (ctx)
  "Read all PVM side-effects after accumulate execution.
   Returns a plist with :balance :gas-remaining :storage :transfers :ejected
   :created :upgrades :empower :provided-preimages :lookup :yield-output.
   Uses jam_pvm_collect (single JAM-codec blob) instead of 12 individual getters."
  (jam.ffi:pvm-collect ctx))

(defun extract-all-service-ids (delta-kvs)
  "Extract list of all service IDs present in delta-kvs."
  (let ((ids (make-hash-table :test 'eql)))
    (dolist (kv delta-kvs)
      (when (service-metadata-key-p (car kv))
        (setf (gethash (service-id-from-metadata-key (car kv)) ids) t)))
    (loop for id being the hash-keys of ids collect id)))

(defun build-cross-service-accounts (caller-id delta-kvs raw-storage-ht)
  "Build alist of (service-id . plist) for all services EXCEPT caller-id.
   Each plist contains :code-hash :balance :threshold :min-accum-gas :min-item-gas
   :min-on-transfer-gas :items-count :footprint :storage :preimages :lookup."
  (let ((result nil))
    (dolist (sid (extract-all-service-ids delta-kvs))
      (unless (= sid caller-id)
        (let* ((svc-data (classify-service-sub-keys sid delta-kvs))
               (metadata (getf svc-data :metadata)))
          (when metadata
            (let ((raw-storage (when raw-storage-ht (gethash sid raw-storage-ht))))
              (push (cons sid
                          (list :code-hash (or (getf metadata :code-hash)
                                               (make-array 32 :element-type '(unsigned-byte 8)
                                                          :initial-element 0))
                                :balance (or (getf metadata :balance) 0)
                                :threshold (or (getf metadata :deposit-offset) 0)
                                :min-accum-gas (or (getf metadata :min-item-gas) 0)
                                :min-item-gas (or (getf metadata :min-item-gas) 0)
                                :min-on-transfer-gas (or (getf metadata :min-memo-gas) 0)
                                :items-count (or (getf metadata :items) 0)
                                :footprint (or (getf metadata :bytes) 0)
                                :storage (or raw-storage nil)
                                :preimages (getf svc-data :preimages)
                                :lookup (getf svc-data :lookup)))
                    result))))))
    result))

(defun accumulate-service (service-id items gas-limit state
                           &key (transfer-balance 0) (svc-transfers nil))
  "GP 12.24 Δ₁ + B.9 Ψ_A: Execute PVM Accumulate for one service.

   SERVICE-ID:       the service to accumulate
   ITEMS:            list of U-plists (work item operand tuples for this service)
   GAS-LIMIT:        gas budget for this invocation
   STATE:            mutable accumulation state plist
   TRANSFER-BALANCE: Σ r_a — sum of deferred transfer amounts for this service (B.9)
   SVC-TRANSFERS:    list of deferred transfer plists for this service (GP 12.24 i^T)

   GP 12.24: i = i^T ⌢ i^U — transfers prepended before work items.
   The initial balance is augmented per B.9:
     s_d[s]_b = e_d[s]_b + Σ_{r∈x} r_a

   Returns: (values side-effects-plist gas-used) or (values nil 0) on failure."
  (let* ((delta-kvs (getf state :delta-kvs))
         (timeslot  (getf state :timeslot))
         (raw-storage-ht (getf state :raw-storage))
         ;; ── Parse service account from delta extra-kvs (GP D.1) ──
         (svc-data  (classify-service-sub-keys service-id delta-kvs))
         (metadata  (getf svc-data :metadata))
         (code-blob (getf svc-data :code-blob))
         ;; ── Get raw storage for PVM (32-byte keys, not 27-byte trie hashes) ──
         (raw-storage (when raw-storage-ht
                        (gethash service-id raw-storage-ht)))
         ;; ── Build cross-service context for ΩJ (eject) host-call ──
         (cross-services (build-cross-service-accounts service-id delta-kvs raw-storage-ht))
         (existing-services (extract-all-service-ids delta-kvs)))

    ;; No code blob found → skip PVM execution
    (unless code-blob
      (return-from accumulate-service (values nil 0)))

    ;; ── Create PVM instance + Configure + Run + Collect ──
    (handler-case
        (let* ((balance       (+ (or (getf metadata :balance) 0)
                                 transfer-balance))  ;; B.9: e_d[s]_b + Σ r_a
               (code-hash     (or (getf metadata :code-hash)
                                  (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
               (min-accum-gas (or (getf metadata :min-item-gas) 0))
               (min-memo-gas  (or (getf metadata :min-memo-gas) 0))
               (items-count   (or (getf metadata :items) 0))
               (total-bytes   (or (getf metadata :bytes) 0))
               (deposit-off   (or (getf metadata :deposit-offset) 0))
               ;; Extra service fields for ΩI (info on self) — GP §D.1
               ;; These map to the last 3 u32 fields in the 89-byte trie format:
               ;; creation-slot → a_r (recent count)
               ;; last-accumulation-slot → a_a (accum gas limit)
               ;; parent-service → a_p (preimage pages)
               (recent-count   (or (getf metadata :creation-slot) 0))
               (accum-gas-lim  (or (getf metadata :last-accumulation-slot) 0))
               (preimage-pgs   (or (getf metadata :parent-service) 0)))
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
              :recent-count    recent-count
              :accum-gas-limit accum-gas-lim
              :preimage-pages  preimage-pgs
              :gas             gas-limit
              ;; Service account data:
              ;; MUST use raw 32-byte keys for storage. Never pass h27-keyed
              ;; trie entries — the PVM would return them alongside real entries,
              ;; causing double-hashing when we convert back to trie keys.
              ;; raw-storage is NIL on first invocation; PVM starts with empty
              ;; storage and the service writes what it needs from work items.
              :storage         raw-storage
              :preimages       (getf svc-data :preimages)
              :lookup          (getf svc-data :lookup)
              ;; Cross-service accounts for ΩJ (eject), ΩT (transfer), etc
              :service-accounts cross-services
              :existing-services existing-services
              ;; Accumulate items: GP 12.24 i = i^T ⌢ i^U
              ;; Transfers first, then work items
              :accumulate-items (encode-accumulate-items items svc-transfers))

            ;; ── Run PVM accumulate_ext ──
            (multiple-value-bind (status result gas-remaining)
                (jam.ffi:pvm-run ctx "accumulate_ext")
              (declare (ignorable result))

              ;; ── Collapse (resolve dual context per GP B.13) ──
              (let ((outcome (jam.ffi:pvm-collapse ctx status)))

                ;; ── Collect side-effects (one JAM blob instead of 12 getters) ──
                (let ((effects (collect-side-effects ctx))
                      ;; GP A.44: u = ϱ − max(ϱ', 0) — gas consumed, capped at budget
                      (gas-used (- gas-limit (max (or gas-remaining 0) 0))))
                  ;; Tag effects with the PVM outcome for storage/lookup decisions
                  ;; 0=Halt 1=Panic 2=OOG 3=HaltWithYield
                  (setf (getf effects :outcome) outcome)
                  (values effects gas-used))))))

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
         (gas-usage nil)       ;; u = [(sid n-items gas-used)]
         (commitments nil)     ;; b = {(sid, yield-hash) | yield ≠ ∅}
         (new-transfers nil)   ;; t' = concat of all transfers
         (remaining-gas (getf state :remaining-gas)))


    (dolist (sid s)
      (when (<= remaining-gas 0) (return))

      (let* ((items (or (gethash sid by-service) nil))
             ;; Deferred transfers for this service
             (svc-transfers (remove-if-not
                             (lambda (x) (= (getf x :destination) sid))
                             transfers))
             ;; Gas: max of (sum of advertised, free-accum gas, transfer gas)
             (work-gas (if items
                           (reduce #'+ items :key (lambda (u) (or (getf u :gas) 0)))
                           0))
             (free-gas (or (cdr (assoc sid free-accum)) 0))
             (xfer-gas (reduce #'+ svc-transfers
                               :key (lambda (x) (or (getf x :gas-limit) 0))
                               :initial-value 0))
             (total-gas (+ work-gas free-gas xfer-gas))
             (gas-limit (min total-gas remaining-gas))
             ;; B.9: Σ_{r∈x} r_a — sum of deferred transfer amounts
             (transfer-balance (reduce #'+ svc-transfers
                                       :key (lambda (x) (or (getf x :amount) 0))
                                       :initial-value 0)))

        ;; Always invoke accumulate-service, even if gas-limit=0
        ;; This ensures last_accumulation_slot is updated for all services in set s
        (multiple-value-bind (effects gas-used)
            (if (plusp gas-limit)
                (accumulate-service sid items gas-limit state
                                   :transfer-balance transfer-balance
                                   :svc-transfers svc-transfers)
                (values nil 0))


          ;; Store Δ(s) result (even if nil, to mark service as processed)
          (setf (gethash sid delta-results) effects)

          ;; u: gas usage — (sid n-items gas-used)
          ;; GP 13.12: accumulate-count = number of work-items, not invocations
          ;; Always record stats if service has work items, even if gas=0
          (when (or (plusp gas-used) (plusp (length (or items '()))))
            (push (list sid (length (or items '())) gas-used) gas-usage))

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

          ;; Deduct gas
          (when (plusp gas-used)
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

    ;; ── Update delta-kvs with this round's effects (GP: e' includes d') ──
    ;; So the next Δ* round sees the storage/balance changes from this round.
    (let ((current-kvs (getf state :delta-kvs))
          (raw-storage-ht (getf state :raw-storage))
          (timeslot    (getf state :timeslot)))
      (maphash
       (lambda (sid effects)
         ;; Always update last-accumulation-slot, even if effects=nil
         (let ((meta-entry (find-if (lambda (kv)
                                      (and (service-metadata-key-p (car kv))
                                           (= (service-id-from-metadata-key (car kv)) sid)))
                                    current-kvs)))
           (when meta-entry
             (let ((info (load-service-info (cdr meta-entry))))
               (setf (getf info :last-accumulation-slot) timeslot)
               ;; Update balance if provided by PVM
               (when (and effects (getf effects :balance))
                 (setf (getf info :balance) (getf effects :balance)))
               (setf (cdr meta-entry) (encode-service-info info)))))

         ;; Apply side-effects if present
         (when effects
           ;; ── Check PVM outcome for storage/lookup decisions ──
           ;; On Panic/OOG without checkpoint → collapse returns empty storage/lookup.
           ;; We must NOT remove old entries in this case — the GP says "revert to initial."
           ;; outcome: 0=Halt, 1=Panic, 2=OOG, 3=HaltWithYield
           (let* ((outcome (or (getf effects :outcome) 0))
                  (update-storage-p
                   (not (and (member outcome '(1 2))         ;; Panic or OOG
                             (null (getf effects :storage))  ;; empty = no checkpoint
                             (null (getf effects :lookup))))))

             (when update-storage-p
               ;; ── MERGE storage: only remove entries in PVM's scope ──
               ;; The PVM only knows about entries we explicitly passed via raw-storage.
               ;; Entries NOT in PVM scope (e.g., from pre-state trie without raw keys)
               ;; must be preserved. Scope = union(initial_h27s, final_h27s).
               (let* ((initial-raw-storage (when raw-storage-ht
                                             (gethash sid raw-storage-ht)))
                      (initial-storage-h27s
                       (mapcar (lambda (e) (storage-trie-h (car e)))
                               (or initial-raw-storage '())))
                      (final-storage-h27s
                       (mapcar (lambda (e) (storage-trie-h (car e)))
                               (or (getf effects :storage) '())))
                      (scope-h27s (remove-duplicates
                                   (append initial-storage-h27s final-storage-h27s)
                                   :test #'equalp)))
                 ;; Remove only entries in PVM's scope (initial OR final)
                 (when scope-h27s
                   (setf current-kvs
                         (remove-if (lambda (kv)
                                      (and (not (service-metadata-key-p (car kv)))
                                           (not (segment-key-p (car kv)))
                                           (= (service-id-from-sub-key (car kv)) sid)
                                           (member (extract-sub-key-h (car kv))
                                                   scope-h27s :test #'equalp)))
                                    current-kvs))))

               ;; Update raw-storage cache with PVM's final storage state
               (when raw-storage-ht
                 (setf (gethash sid raw-storage-ht) (getf effects :storage)))

               ;; ── Add new storage entries from PVM (using RAW keys) ──
               (dolist (s-entry (getf effects :storage))
                 (let* ((raw-key  (car s-entry))
                        (val      (cdr s-entry))
                        (h-27     (storage-trie-h raw-key))
                        (trie-key (interleave-sub-key sid h-27)))
                   (push (cons trie-key (ensure-bytes val)) current-kvs)))

               ;; ── MERGE lookups: only remove entries in PVM's scope ──
               (let* ((old-classified (classify-service-sub-keys sid current-kvs))
                      (initial-lookup-h27s
                       (mapcar (lambda (l) (lookup-trie-h (first l) (second l)))
                               (getf old-classified :lookup)))
                      (final-lookup-h27s
                       (mapcar (lambda (l) (lookup-trie-h (first l) (second l)))
                               (or (getf effects :lookup) '())))
                      (scope-lookup-h27s (remove-duplicates
                                         (append initial-lookup-h27s final-lookup-h27s)
                                         :test #'equalp)))
                 (when scope-lookup-h27s
                   (setf current-kvs
                         (remove-if (lambda (kv)
                                      (and (not (service-metadata-key-p (car kv)))
                                           (not (segment-key-p (car kv)))
                                           (= (service-id-from-sub-key (car kv)) sid)
                                           (member (extract-sub-key-h (car kv))
                                                   scope-lookup-h27s :test #'equalp)))
                                    current-kvs))))

               (dolist (l-entry (getf effects :lookup))
                 (let* ((hash-32  (first l-entry))
                        (length   (second l-entry))
                        (statuses (cddr l-entry))
                        (h-27     (lookup-trie-h hash-32 length))
                        (trie-key (interleave-sub-key sid h-27))
                        (val      (encode-lookup-value statuses)))
                   (push (cons trie-key val) current-kvs))))

             ;; ── Add provided preimages (always, even on panic) ──
             (dolist (pp (getf effects :provided-preimages))
               (let* ((pp-sid  (car pp))
                      (pp-data (cdr pp))
                      (pp-hash (jam.ffi:blake2b-256 pp-data))
                      (h-27    (preimage-trie-h pp-hash))
                      (trie-key (interleave-sub-key pp-sid h-27)))
                 (push (cons trie-key (ensure-bytes pp-data)) current-kvs)))

             ;; ── Handle ejected services ──
             (dolist (ejection (getf effects :ejected))
               (let ((target-id (car ejection))
                     (ejector-id (cdr ejection)))
                 (declare (ignorable ejector-id))
                 (setf current-kvs
                       (remove-if (lambda (kv)
                                    (or (and (service-metadata-key-p (car kv))
                                             (= (service-id-from-metadata-key (car kv)) target-id))
                                        (and (not (service-metadata-key-p (car kv)))
                                             (not (segment-key-p (car kv)))
                                             (= (service-id-from-sub-key (car kv)) target-id))))
                                  current-kvs))
                 (when raw-storage-ht
                   (remhash target-id raw-storage-ht))))

             ;; ── Update items/bytes from PVM-tracked values ──
             ;; The PVM tracks items_count and footprint incrementally:
             ;;   - Initialized from metadata (initial values)
             ;;   - ΩW adjusts: +1 item, +(34+|key|+|val|) per new storage entry
             ;;   - ΩS adjusts: +2 items, +(81+z) per new lookup entry
             ;;   - ΩF adjusts: -2 items, -(81+z) per removed lookup entry
             ;; After collapse, the final values reflect the correct state.
             (when (and update-storage-p
                        (getf effects :items-count)
                        (getf effects :footprint))
               (let ((meta-entry (find-if (lambda (kv)
                                            (and (service-metadata-key-p (car kv))
                                                 (= (service-id-from-metadata-key (car kv)) sid)))
                                          current-kvs)))
                 (when meta-entry
                   (let ((info (load-service-info (cdr meta-entry))))
                     (setf (getf info :items) (getf effects :items-count))
                     (setf (getf info :bytes) (getf effects :footprint))
                     (setf (cdr meta-entry) (encode-service-info info)))))))) ;; closes let/when/let/when/let*/when-effects
       ) ;; close lambda
       delta-results)
      (setf (getf state :delta-kvs) current-kvs))

    (values state
            (nreverse new-transfers)
            (nreverse commitments)
            (nreverse gas-usage))))  ;; closes values, let*, let, defun

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
        (free-accum (getf state :chi-always-accum)))

    ;; ── GP 12.18: Δ+(g, t, r, e, f) ──
    ;; Process ALL reports in ONE Δ* call (not one-by-one).
    ;; Then recurse with new deferred transfers, f = {} in recursion.
    (let ((n (length r-star)))

      ;; ── First call: Δ*(e, t, r...i, f) — all reports + free-accum ──
      (when (and (plusp (getf state :remaining-gas))
                 (or r-star pending-transfers free-accum))
        (multiple-value-bind (state* new-transfers commitments gas-usage)
            (accumulate-star state
                            pending-transfers
                            r-star        ;; ALL reports at once
                            free-accum)   ;; f = free-accum (first call only)
          (setf state state*)
          (setf pending-transfers new-transfers)
          (setf all-commitments (nconc all-commitments commitments))
          (setf all-gas-usage (nconc all-gas-usage gas-usage))))

      ;; ── Recursion: Δ+(g*, t*, [], e*, {}) — deferred transfers only ──
      ;; GP 12.18: f = {} in recursion, no more reports.
      ;; Continue until no more deferred transfers (n = |t| = 0 → stop).
      (loop while (and (plusp (getf state :remaining-gas))
                       pending-transfers)
            do (multiple-value-bind (state* new-transfers commitments gas-usage)
                   (accumulate-star state
                                   pending-transfers
                                   nil   ;; no reports
                                   nil)  ;; f = {} in recursion
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

(defun build-delta-dagger (accum-state)
  "Construct δ† from the already-updated delta-kvs in accum-state.
   All storage/lookup/preimage/metadata updates are applied in-place
   by accumulate-star during each Δ* round, so this is just a wrapper.

   ACCUM-STATE: the mutable accumulation state after Δ+

   Returns: a new delta-state closure."
  (make-delta-state :raw-kvs (getf accum-state :delta-kvs)))

;;; ═══════════════════════════════════════════════════════════════
;;; transition-accumulate — GP (4.16) top-level entry
;;; ═══════════════════════════════════════════════════════════════

(defun transition-accumulate (r-star-input omega xi delta chi iota phi tau tau-prime
                              &key eta header-hash raw-storage)
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
   ETA:       η encoded bytes (128 bytes = 4×32 entropy)
   HEADER-HASH: H_p parent header hash (32 bytes)
   RAW-STORAGE: hash-table sid → alist of (raw-key-32 . value) for PVM

   Returns plist:
     :omega-prime     — ω' (updated accumulation queue)
     :xi-prime        — ξ' (updated accumulation history)
     :delta-dagger    — δ† (post-accumulate service accounts)
     :chi-prime       — χ' (updated privileged IDs)
     :iota-prime      — ι' (updated enqueued validators)
     :phi-prime       — ϕ' (updated authorization queue)
     :theta-prime     — θ' (accumulation outputs for β')
     :service-stats   — S  (service statistics for π')"
  (let* ((timeslot (funcall tau-prime :slot))
         (prev-timeslot (if tau (funcall tau :slot) (1- timeslot)))
         (omega-queues (funcall omega :queues))
         (xi-flattened (funcall xi :flattened))
         (e (epoch-duration))
         (m (mod timeslot e)))

    ;; ── §12.1: Compute R* via queue editing and priority ordering ──
    (multiple-value-bind (r-star new-omega-queues accumulated-hashes)
        (compute-r-star r-star-input omega-queues xi-flattened timeslot
                        prev-timeslot)
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
                    :raw-storage      (or raw-storage (make-hash-table :test 'eql))
                    :timeslot         timeslot
                    :entropy          eta
                    :header-hash      header-hash
                    ;; GP (12.25): g = max(G_T, G_A·C + Σ_{x∈V(χ_Z)}(x))
                    :remaining-gas    (max (max-block-gas)
                                          (+ (* +accumulation-gas+ (num-cores))
                                             (reduce #'+ (or chi-az '())
                                                     :key #'cdr :initial-value 0)))
                    ;; ── GP §12.16 S fields ──
                    :chi-manager      chi-mgr    ;; m = χ_M
                    :chi-designate    chi-des    ;; v = χ_V
                    :chi-creation     chi-stk    ;; r = χ_R
                    :chi-authorizers  chi-auth   ;; a = χ_A
                    :chi-always-accum chi-az     ;; z = χ_Z
                    :iota-validators  nil        ;; i = ι (set by Δ* if designate runs)
                    :phi-queues       (funcall phi :queues) ;; q = ϕ (mutable copy for Δ*)
                    ;; ── Accumulators ──
                    :commitments      nil        ;; B: (sid . yield-hash)
                    :gas-usage        nil        ;; U: (sid . gas-used)
                    :pending-transfers nil)))     ;; X: deferred transfers

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
               ;; compute-r-star handles: stale gap clearing, ξ̃ editing,
               ;; R^Q insertion at slot m, and Q()-resolved entry removal.
               (omega-prime (make-omega-state :queues new-omega-queues))

               ;; ── δ† (12.30-12.31): apply PVM side-effects back to trie ──
               (delta-dagger (build-delta-dagger accum-state))

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
                ;; GP (12.27): ι' and ϕ' come from accumulate state if updated
                :iota-prime    (let ((new-vals (getf accum-state :iota-validators)))
                                 (if new-vals
                                     (make-iota-state :validators new-vals)
                                     iota))
                :phi-prime     (let ((new-qs (getf accum-state :phi-queues)))
                                 (if new-qs
                                     (make-phi-state :queues new-qs)
                                     phi))
                :theta-prime   theta-prime
                :service-stats service-stats
                :raw-storage   (getf accum-state :raw-storage)))))))
