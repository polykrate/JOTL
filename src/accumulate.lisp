;;;; accumulate.lisp — §12 Accumulate Orchestrator
;;;;
;;;; GP (4.16):
;;;;   (ω', ξ', δ†, χ', ι', ϕ', θ', S) ◁ (R*, ω, ξ, δ, χ, ι, ϕ, τ, τ')
;;;;
;;;; This is a FUNCTION ORCHESTRATOR — same level as upsilon.lisp.
;;;; It takes state closures + R* as input, returns a plist of results.
;;;; Each state closure owns its own transition logic (sovereign).
;;;; The orchestrator only sends messages and coordinates data flow.
;;;;
;;;; Architecture:
;;;;   - ω :resolve-r-star  → R* computation (§12.1)
;;;;   - ξ :advance          → shift register (§12.32-12.33)
;;;;   - δ :absorb-effects   → PVM side-effect integration (§12.3)
;;;;   - χ :resolve-privilege → privilege resolution (§12.20)
;;;;   - ι :accept-empower   → validator update
;;;;   - ϕ :accept-queues    → auth queue update
;;;;   - transition-accumulate: top-level entry point called by upsilon Wave 3

(in-package #:jotl)

;;; Debug: set to T to enable host-call tracing in accumulate-service
(defvar *debug-pvm-trace* nil
  "When T, accumulate-service attaches a host-call log to effects.")
(defvar *debug-pvm-traces* nil
  "When *debug-pvm-trace* is T, collects (sid gas-limit gas-used host-call-log) for each PVM run.")

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
              (jam-host:encode-work-item-record
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
            (jam-host:encode-transfer-record
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
  (when *debug-pvm-trace*
    (format *error-output* "~&[ENC-ITEMS] items=~D transfers=~D~%" (length items) (length transfers))
    (dolist (u items)
      (let* ((res (getf u :result))
             (rk (work-exec-result-kind res))
             (rd (when (getf res :ok) (getf res :ok)))
             (ao (getf u :auth-output)))
        (format *error-output* "~&  gas=~D rk=~D rd-len=~D ao-len=~D~%"
                (or (getf u :gas) 0) rk (if rd (length rd) 0) (if ao (length ao) 0)))))
  (append (encode-transfer-items (or transfers nil))
          (encode-work-items (or items nil))))

(defun collect-side-effects (ctx)
  "Read all PVM side-effects after accumulate execution.
   Returns a plist with :balance :gas-remaining :storage :transfers :ejected
   :created :upgrades :empower :provided-preimages :lookup :yield-output.
   CTX is now a jam-host:host-context (not a Rust pointer)."
  (jam-host:collect-effects ctx))

(defun extract-all-service-ids (delta-kvs)
  "Extract list of all service IDs present in delta-kvs."
  (let ((ids (make-hash-table :test 'eql)))
    (dolist (kv delta-kvs)
      (when (service-metadata-key-p (car kv))
        (setf (gethash (service-id-from-metadata-key (car kv)) ids) t)))
    (loop for id being the hash-keys of ids collect id)))

(defun build-cross-service-accounts (caller-id delta-kvs)
  "Build alist of (service-id . plist) for all services EXCEPT caller-id.
   Each plist contains :code-hash :balance :threshold :min-accum-gas :min-memo-gas
   :items-count :footprint :storage :preimages :lookup.
   Storage is h27-keyed (trie-classified) — PVM hashes raw keys internally."
  (let ((result nil))
    (dolist (sid (extract-all-service-ids delta-kvs))
      (unless (= sid caller-id)
        (let* ((svc-data (classify-service-sub-keys sid delta-kvs))
               (metadata (getf svc-data :metadata)))
          (when metadata
            (push (cons sid
                        (list :code-hash (or (getf metadata :code-hash)
                                             (make-array 32 :element-type '(unsigned-byte 8)
                                                        :initial-element 0))
                              :balance (or (getf metadata :balance) 0)
                              :threshold (or (getf metadata :deposit-offset) 0)
                              :min-accum-gas (or (getf metadata :min-accum-gas) 0)
                              :min-memo-gas (or (getf metadata :min-memo-gas) 0)
                              :items-count (or (getf metadata :items) 0)
                              :footprint (or (getf metadata :bytes) 0)               ;; a_o (total octets)
                              :storage (getf svc-data :storage)
                              :preimages (getf svc-data :preimages)
                              :lookup (getf svc-data :lookup)))
                  result)))))
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
         ;; ── Parse service account from delta extra-kvs (GP D.1) ──
         (svc-data  (classify-service-sub-keys service-id delta-kvs))
         (metadata  (getf svc-data :metadata))
         (code-blob (getf svc-data :code-blob))
         ;; ── h27-keyed storage from trie classification ──
         ;; PVM ΩR/ΩW hash raw guest keys to h27 internally (GP Appendix D).
         ;; We pass trie-classified entries directly — works for chain and step mode.
         (h27-storage (getf svc-data :storage))
         ;; ── Build cross-service context for ΩJ (eject) host-call ──
         (cross-services (build-cross-service-accounts service-id delta-kvs))
         (existing-services (extract-all-service-ids delta-kvs)))

    ;; No code blob found → skip PVM execution
    (unless code-blob
      (return-from accumulate-service (values nil 0)))

    ;; ── Create PVM instance + Configure + Run + Collect ──
    ;; Now uses Lisp JamVM instead of Rust FFI
    (handler-case
        (let* ((balance       (+ (or (getf metadata :balance) 0)
                                 transfer-balance))  ;; B.9: e_d[s]_b + Σ r_a
               (code-hash     (or (getf metadata :code-hash)
                                  (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
               (min-accum-gas (or (getf metadata :min-accum-gas) 0))
               (min-memo-gas  (or (getf metadata :min-memo-gas) 0))
               (items-count   (or (getf metadata :items) 0))
               (total-bytes   (or (getf metadata :bytes) 0))
               (deposit-off   (or (getf metadata :deposit-offset) 0))
               ;; Extra service fields for ΩI (info on self) — GP §9.3 + §B.7
               (creation-ts  (or (getf metadata :creation-slot) 0))            ;; a_r
               (last-accum   (or (getf metadata :last-accumulation-slot) 0))   ;; a_a
               (parent-svc   (or (getf metadata :parent-service) 0)))          ;; a_p

          ;; ── Debug: log before run ──
          (when *debug-pvm-trace*
            (let ((enc-items (encode-accumulate-items items svc-transfers)))
              (format *error-output*
                      "~&[PVM-DBG] sid=~D items=~D transfers=~D encoded-blobs=~D blob-sizes=~{~D~^ ~}~%"
                      service-id (length items) (length svc-transfers)
                      (length enc-items)
                      (mapcar #'length enc-items))))

          ;; ── Run PVM accumulate via Lisp JamVM ──
          (multiple-value-bind (effects gas-used)
              (jam-host:lisp-pvm-run-accumulate
               code-blob service-id balance timeslot
               :gas             gas-limit
               :entropy         (or (getf state :entropy)
                                    (make-array 128 :element-type '(unsigned-byte 8) :initial-element 0))
               :header-hash     (or (getf state :header-hash)
                                    (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
               :code-hash       code-hash
               :threshold       deposit-off
               :min-accum-gas   min-accum-gas
               :min-memo-gas    min-memo-gas
               :items-count     items-count
               :footprint       total-bytes
               :recent-count    creation-ts
               :accum-gas-limit last-accum
               :preimage-pages  parent-svc
               :storage         h27-storage
               :preimages       (getf svc-data :preimages)
               :lookup          (getf svc-data :lookup)
               :service-accounts cross-services
               :existing-services existing-services
               :accumulate-items (encode-accumulate-items items svc-transfers)
               :debug-trace *debug-pvm-trace*)

            ;; ── Debug: attach host-call trace ──
            (when (and *debug-pvm-trace* effects)
              (push (list :sid service-id :gas-limit gas-limit
                          :gas-used gas-used
                          :outcome (getf effects :outcome)
                          :host-call-log (getf effects :host-call-log))
                    *debug-pvm-traces*))

            (values effects gas-used)))

      (error (e)
        (format *error-output* "~&accumulate-service: PVM error for service ~D: ~A~%"
                service-id e)
        (values nil 0)))))

;;; ═══════════════════════════════════════════════════════════════
;;; §12.2 DELTA LOOPS — Δ* (per-report, GP 12.19) and Δ+ (sequential)
;;; ═══════════════════════════════════════════════════════════════

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

          ;; u: gas usage — (sid n-items gas-used)g
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

    ;; ── Privilege updates (GP 12.19) — χ owns this logic ──
    ;; Build a temp χ closure from current state fields, call :resolve-privilege,
    ;; then write results back into state plist for inter-round compatibility.
    (let ((temp-chi (make-chi-state
                     :raw (encode-chi-fields
                           (list :manager     (getf state :chi-manager)
                                 :designate   (getf state :chi-designate)
                                 :creation    (getf state :chi-creation)
                                 :authorizers (getf state :chi-authorizers)
                                 :always-accum (getf state :chi-always-accum))))))
      (multiple-value-bind (chi-new iota-vals phi-qs)
          (funcall temp-chi :resolve-privilege delta-results (getf state :phi-queues))
        ;; Write resolved chi fields back into state
        (setf (getf state :chi-manager)      (funcall chi-new :manager))
        (setf (getf state :chi-designate)    (funcall chi-new :designate))
        (setf (getf state :chi-creation)     (funcall chi-new :creation))
        (setf (getf state :chi-authorizers)  (funcall chi-new :authorizers))
        (setf (getf state :chi-always-accum) (funcall chi-new :always-accum))
        ;; Update iota/phi if changed
        (when iota-vals
          (setf (getf state :iota-validators) iota-vals))
        (when phi-qs
          (setf (getf state :phi-queues) phi-qs))))

    ;; ── Update delta-kvs with this round's effects (GP: e' includes d') ──
    ;; So the next Δ* round sees the storage/balance changes from this round.
    (let ((current-kvs (getf state :delta-kvs))
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
               ;; Update code_hash, min_accum_gas, min_memo_gas from PVM final state
               ;; These may have been changed by ΩU (upgrade host call)
               (when (and effects (getf effects :final-code-hash))
                 (setf (getf info :code-hash) (getf effects :final-code-hash)))
               (when (and effects (getf effects :final-min-accum-gas))
                 (setf (getf info :min-accum-gas) (getf effects :final-min-accum-gas)))
               (when (and effects (getf effects :final-min-memo-gas))
                 (setf (getf info :min-memo-gas) (getf effects :final-min-memo-gas)))
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
               ;; Classify initial service sub-keys ONCE for all merges.
               ;; This snapshot is taken before any storage/lookup/preimage
               ;; modifications, so all three merges use a consistent baseline.
               (let ((initial-classified (classify-service-sub-keys sid current-kvs)))

               ;; ── MERGE storage: only remove entries in PVM's scope ──
               ;; Both initial and final storage are h27-keyed (GP Appendix D).
               ;; PVM hashes raw keys internally; effects come back as h27→value.
               ;; Scope = union(initial_h27s, final_h27s).
               (let* ((initial-storage-h27s
                       (mapcar #'car (or (getf initial-classified :storage) '())))
                      (final-storage-h27s
                       (mapcar #'car (or (getf effects :storage) '())))
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

               ;; ── Add new storage entries from PVM (already h27-keyed) ──
               (dolist (s-entry (getf effects :storage))
                 (let* ((h-27     (car s-entry))
                        (val      (cdr s-entry))
                        (trie-key (interleave-sub-key sid h-27)))
                   (push (cons trie-key (ensure-bytes val)) current-kvs)))

               ;; ── MERGE lookups: only remove entries in PVM's scope ──
               ;; Re-classify AFTER storage merge to get current lookup state.
               (let* ((post-storage-classified (classify-service-sub-keys sid current-kvs))
                      (initial-lookup-h27s
                       (mapcar (lambda (l) (lookup-trie-h (first l) (second l)))
                               (getf post-storage-classified :lookup)))
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
                   (push (cons trie-key val) current-kvs)))

               ;; ── MERGE preimage blobs (a_P): scope-based ──
               ;; ΩF can remove preimage blobs. The PVM reports the final
               ;; a_P store in effects :preimages. Scope = initial ∪ final.
               (let* ((initial-preimage-h27s
                       (mapcar (lambda (p) (preimage-trie-h (car p)))
                               (or (getf initial-classified :preimages) '())))
                      (final-preimage-h27s
                       (mapcar (lambda (p) (preimage-trie-h (car p)))
                               (or (getf effects :preimages) '())))
                      (scope-preimage-h27s (remove-duplicates
                                            (append initial-preimage-h27s final-preimage-h27s)
                                            :test #'equalp)))
                 ;; Remove old preimage blob entries in scope
                 (when scope-preimage-h27s
                   (setf current-kvs
                         (remove-if (lambda (kv)
                                      (and (not (service-metadata-key-p (car kv)))
                                           (not (segment-key-p (car kv)))
                                           (= (service-id-from-sub-key (car kv)) sid)
                                           (member (extract-sub-key-h (car kv))
                                                   scope-preimage-h27s :test #'equalp)))
                                    current-kvs)))
                 ;; Add final preimage blob entries
                 (dolist (p-entry (getf effects :preimages))
                   (let* ((hash-32  (car p-entry))
                          (blob     (cdr p-entry))
                          (h-27     (preimage-trie-h hash-32))
                          (trie-key (interleave-sub-key sid h-27)))
                     (push (cons trie-key (ensure-bytes blob)) current-kvs))))

               )) ;; close (let ((initial-classified ...))) + (when update-storage-p)

             ;; ── Add provided preimages (always, even on panic) ──
           (dolist (pp (getf effects :provided-preimages))
             (let* ((pp-sid  (car pp))
                    (pp-data (cdr pp))
                    (pp-hash (jam-host:blake2b-256 pp-data))
                    (h-27    (preimage-trie-h pp-hash))
                    (trie-key (interleave-sub-key pp-sid h-27)))
               (push (cons trie-key (ensure-bytes pp-data)) current-kvs)))

           ;; ── Handle ejected services ──
           (dolist (ejection (getf effects :ejected))
             (let ((target-id (car ejection))
                   (ejector-id (second ejection))) ; (list target ejector), not cons
                 (declare (ignorable ejector-id))
               (setf current-kvs
                     (remove-if (lambda (kv)
                                  (or (and (service-metadata-key-p (car kv))
                                           (= (service-id-from-metadata-key (car kv)) target-id))
                                      (and (not (service-metadata-key-p (car kv)))
                                           (not (segment-key-p (car kv)))
                                           (= (service-id-from-sub-key (car kv)) target-id))))
                                current-kvs))))

           ;; ── Handle created services (ΩN) ──
           ;; For each created service, add a new ServiceInfo metadata entry.
           ;; The :created-full field has the full metadata (from PVM context).
           (dolist (cs (getf effects :created-full))
             (let* ((new-sid      (getf cs :id))
                    (meta-key     (make-service-metadata-key new-sid))
                    (info (list :version 0
                                :code-hash (getf cs :code-hash)
                                :balance (or (getf cs :balance) 0)
                                :min-accum-gas (or (getf cs :min-accum-gas) 0)
                                :min-memo-gas (or (getf cs :min-memo-gas) 0)
                                :bytes 0
                                :deposit-offset (or (getf cs :deposit-offset) 0)
                                :items 0
                                :creation-slot timeslot
                                :last-accumulation-slot 0
                                :parent-service (or (getf cs :parent-service) sid))))
               ;; Remove any existing metadata entry for this service
               (setf current-kvs
                     (remove-if (lambda (kv)
                                  (and (service-metadata-key-p (car kv))
                                       (= (service-id-from-metadata-key (car kv)) new-sid)))
                                current-kvs))
               ;; Add the new metadata entry
               (push (cons meta-key (encode-service-info info)) current-kvs)))

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
                              &key eta header-hash)
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
   HEADER-HASH: H_T block header hash — H(E(H)) (32 bytes)

   Storage is h27-keyed (GP Appendix D) — classified from trie on each call.
   No raw-storage cache needed; PVM hashes raw keys internally.

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
         (e (epoch-duration)))

    ;; ── §12.1: ω resolves R* (sovereign — GP 12.4-12.12) ──
    (multiple-value-bind (omega-prime r-star accumulated-hashes)
        (funcall omega :resolve-r-star r-star-input
                 (funcall xi :flattened) timeslot prev-timeslot)
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
               ;; ξ owns its shift logic via :advance message
               (accumulated-n-hashes
                (accum-package-hashes (subseq r-star 0 (min n (length r-star)))))
               (xi-prime (funcall xi :advance accumulated-n-hashes))

               ;; ── ω' already computed by :resolve-r-star above ──

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

               ;; ── GP: B is a set of (s, o) pairs → sort by service-id ascending ──
               ;; This sorted list is used for BOTH θ' encoding and β' accumulate-root.
               (sorted-commits (sort (copy-list (or (getf accum-state :commitments) nil))
                                     #'< :key #'car))

               ;; ── θ' (12.26): accumulation output log ──
               ;; Encoding: compact(count) + count*(u32_le(service_id) + H32(yield_hash))
               (theta-prime
                (when sorted-commits
                  (make-theta-state
                   :raw (apply #'concatenate '(vector (unsigned-byte 8))
                               (encode-compact (length sorted-commits))
                               (mapcar (lambda (c)
                                         (let ((sid (car c))
                                               (yh  (cdr c)))
                                           (concatenate '(vector (unsigned-byte 8))
                                                        (vector (ldb (byte 8  0) sid)
                                                                (ldb (byte 8  8) sid)
                                                                (ldb (byte 8 16) sid)
                                                                (ldb (byte 8 24) sid))
                                                        (coerce yh '(vector (unsigned-byte 8))))))
                                       sorted-commits)))))

               ;; ── S (12.28-12.29): service statistics for π' ──
               (service-stats (getf accum-state :gas-usage)))

          (list :omega-prime   omega-prime
                :xi-prime      xi-prime
                :delta-dagger  delta-dagger
                :chi-prime     chi-prime
                ;; GP (12.27): ι' and ϕ' — sovereign accept messages
                :iota-prime    (funcall iota :accept-empower
                                        (getf accum-state :iota-validators))
                :phi-prime     (funcall phi :accept-queues
                                        (getf accum-state :phi-queues))
                :theta-prime   theta-prime
                :commitments   sorted-commits   ;; sorted for β' accumulate-root
                :service-stats service-stats))))))
