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
;;;; Architecture (uniform :transition protocol):
;;;;   - ω :transition       → ω' + R* queryable (§12.1)
;;;;   - ξ :transition       → ξ' shift register (§12.32-12.33)
;;;;   - δ :transition-dagger → δ† PVM side-effect integration (§12.3)
;;;;   - χ :transition       → χ' privilege resolution + emitted data (§12.20)
;;;;   - ι :transition       → ι' validator update
;;;;   - ϕ :transition       → ϕ' auth queue update
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
        (format *error-output* "~&  gas=~D rk=~D rd-len=~D ao-len=~D payload-hash-len=~D~%"
                (or (getf u :gas) 0) rk (if rd (length rd) 0) (if ao (length ao) 0)
                (if (getf u :payload-hash) (length (getf u :payload-hash)) 0))))
    ;; Also show actual encoded blob sizes and full hex for 2+ item services
    (let ((blobs (append (encode-transfer-items (or transfers nil))
                         (encode-work-items (or items nil)))))
      (format *error-output* "~&  encoded-blob-sizes: ~{~D~^ ~}~%" (mapcar #'length blobs))
      (when (>= (length blobs) 2)
        (loop for blob in blobs for i from 0 do
          (format *error-output* "~&  BLOB[~D](~D): ~{~2,'0X~}~%" i (length blob)
                  (coerce blob 'list))))))
  (append (encode-transfer-items (or transfers nil))
          (encode-work-items (or items nil))))

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
  (let* ((delta     (getf state :delta))
         (timeslot  (getf state :timeslot))
         ;; ── δ owns its data: ask via messages ──
         (svc-data  (funcall delta :service-data service-id))
         (metadata  (getf svc-data :metadata))
         (code-blob (getf svc-data :code-blob))
         (h27-storage (getf svc-data :storage))
         (cross-services (funcall delta :cross-service-accounts service-id))
         (existing-services (funcall delta :all-service-ids)))

    ;; No code blob found → skip PVM execution.
    ;; GP B.9: Even without code, deferred transfer balance must be credited.
    ;; The balance becomes d[s]_b + Σ r_a.
    ;; last-accumulation-slot is NOT updated (service never actually ran).
    (unless code-blob
      (if (plusp transfer-balance)
          ;; Credit balance from deferred transfers without running PVM
          (return-from accumulate-service
            (values (list :balance (+ (or (getf metadata :balance) 0)
                                      transfer-balance)
                          :no-code t     ;; Flag: don't update last-accumulation-slot
                          :outcome 0)    ;; No PVM = implicit halt
                   0))
          (return-from accumulate-service (values nil 0))))

    ;; Gas=0 with code → OOG immediately, no instruction ever runs.
    ;; GP B.9: credit deferred transfer balance but do NOT update
    ;; last-accumulation-slot (no code actually executed).
    (when (zerop gas-limit)
      (return-from accumulate-service
        (values (list :balance (+ (or (getf metadata :balance) 0)
                                  transfer-balance)
                      :no-code t     ;; Flag: don't update last-accumulation-slot
                      :outcome 2)    ;; OOG
               0)))

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
                      (mapcar #'length enc-items))
              (format *error-output*
                      "~&[PVM-DBG] sid=~D last-accum-slot=~D (old=~D timeslot=~D) balance=~D~%"
                      service-id last-accum
                      (or (getf metadata :last-accumulation-slot) 0)
                      timeslot balance)))

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
               :creation-slot    creation-ts
               :last-accum-slot  last-accum
               :parent-service   parent-svc
               :storage         h27-storage
               :preimages       (getf svc-data :preimages)
               :lookup          (getf svc-data :lookup)
               :service-accounts cross-services
               :existing-services existing-services
               :accumulate-items (encode-accumulate-items items svc-transfers)
               :designate-service (let ((chi (getf state :chi)))
                                    (if chi (funcall chi :designate) 0))
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
         ;; ── Pre-group transfers by destination (O(T) once, O(1) per service) ──
         ;; push reverses order → nreverse each bucket to preserve original order
         (xfer-by-dest (let ((ht (make-hash-table :test 'eql)))
                         (dolist (x transfers)
                           (push x (gethash (getf x :destination) ht)))
                         (maphash (lambda (k v)
                                    (setf (gethash k ht) (nreverse v)))
                                  ht)
                         ht))
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
             ;; Deferred transfers for this service — O(1) hash lookup
             (svc-transfers (gethash sid xfer-by-dest))
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

        ;; Always invoke accumulate-service when there's gas OR deferred transfers.
        ;; GP B.9: balance augmentation s_d[s]_b = e_d[s]_b + Σ r_a applies
        ;; regardless of gas budget. Even gas=0 services must credit transfer balance.
        (multiple-value-bind (effects gas-used)
            (if (or (plusp gas-limit) (plusp transfer-balance))
                (accumulate-service sid items gas-limit state
                                   :transfer-balance transfer-balance
                                   :svc-transfers svc-transfers)
                (values nil 0))


          ;; Store Δ(s) result (even if nil, to mark service as processed)
          (when *debug-pvm-trace*
            (format *error-output*
                    "~&[ACCUM] sid=~D gas-used=~D outcome=~A yield?=~A~%"
                    sid gas-used
                    (when effects (getf effects :outcome))
                    (and effects (getf effects :yield-output) t))
            (when effects
              (let ((sto (getf effects :storage)))
                (format *error-output*
                        "~&[ACCUM-EFX] sid=~D storage-type=~A storage-count=~D~%"
                        sid (type-of sto)
                        (cond ((hash-table-p sto) (hash-table-count sto))
                              ((listp sto) (length sto))
                              (t 0)))
                (cond
                  ((hash-table-p sto)
                   (maphash (lambda (k v)
                              (format *error-output*
                                      "~&  [STO] key=~A vlen=~D~%"
                                      (jam.ffi:bytes-to-hex-string k)
                                      (if v (length v) 0)))
                            sto))
                  ((listp sto)
                   (dolist (s sto)
                     (format *error-output*
                             "~&  [STO] key=~A vlen=~D~%"
                             (jam.ffi:bytes-to-hex-string (car s))
                             (if (cdr s) (length (cdr s)) 0))))))))
          (setf (gethash sid delta-results) effects)

          ;; u: gas usage — (sid n-items gas-used)g
          ;; GP 13.12: accumulate-count = number of work-items, not invocations
          ;; Always record stats if service has work items, even if gas=0
          (when (or (plusp gas-used) (plusp (length (or items '()))))
            (push (list sid (length (or items '())) gas-used) gas-usage))

          ;; b: commitments (yield output)
          (when *debug-pvm-trace*
            ;; Log host call sequence for yielding services
            (when (and effects (getf effects :host-call-log))
              (format *error-output* "~&[HOST-CALLS] sid=~D calls:~%" sid)
              (dolist (entry (getf effects :host-call-log))
                (format *error-output* "~&  ~A~%" entry))))
          (when (and effects (getf effects :yield-output))
            (when *debug-pvm-trace*
              (format *error-output*
                      "~&[YIELD] sid=~D outcome=~D hash=~A~%"
                      sid (getf effects :outcome)
                      (bytes-to-hex-string (getf effects :yield-output))))
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

    ;; ── Privilege updates (GP 12.19) — χ, ι, ϕ own their logic ──
    ;; χ transitions and emits side-data for ι and ϕ (queryable on χ').
    (let ((chi-new (funcall (getf state :chi) :transition
                            :delta-results delta-results
                            :phi-queues (funcall (getf state :phi) :queues))))
      (setf (getf state :chi) chi-new)
      (let ((iota-vals (funcall chi-new :emitted-validators))
            (phi-qs    (funcall chi-new :emitted-queues)))
        (when iota-vals
          ;; ΩD stores raw 336-byte arrays; ι expects decoded validator plists.
          ;; Convert any raw byte-vector entries to (:bandersnatch :ed25519 :bls :metadata) plists.
          (let ((decoded-vals
                  (mapcar (lambda (raw)
                            (if (and (typep raw '(vector (unsigned-byte 8)))
                                     (= (length raw) 336))
                                (decode-full-validator raw 0) ;; returns (values plist 336)
                                raw))  ;; already a plist
                          iota-vals)))
            (setf (getf state :iota)
                  (funcall (getf state :iota) :transition
                           :new-validators decoded-vals))))
        (when phi-qs
          (setf (getf state :phi)
                (funcall (getf state :phi) :transition
                         :new-queues phi-qs)))))

    ;; ── δ† absorbs PVM effects (sovereign — GP 12.30-12.31) ──
    ;; δ owns all storage/lookup/preimage/metadata merge logic.
    (setf (getf state :delta)
          (funcall (getf state :delta) :transition-dagger
                   :delta-results delta-results
                   :timeslot (getf state :timeslot)))

    (values state
            (nreverse new-transfers)
            (nreverse commitments)
            (nreverse gas-usage))))  ;; closes values, let*, let, defun

(defun find-report-cutoff (gas-limit reports)
  "GP §12.18: Find max index i such that cumulative report gas ≤ gas-limit.
   Returns i — the number of reports that fit within the gas budget."
  (let ((cumulative 0))
    (loop for report in reports
          for i from 0
          do (let ((report-gas (reduce #'+ (or (getf report :results) nil)
                                        :key (lambda (r) (or (getf r :accumulate-gas) 0))
                                        :initial-value 0)))
               (when (> (+ cumulative report-gas) gas-limit)
                 (return-from find-report-cutoff i))
               (incf cumulative report-gas)))
    (length reports)))

(defun accumulate-all (r-star state)
  "GP §12.18 Δ+(g, t, R*, e, f): Sequential accumulation with report-level gas cutoff.

   Implements the recursive structure of Δ+:
   1. Find cutoff index i — how many reports fit within gas budget
   2. Call Δ*(e, t, R*[0..i), X, f) — process reports that fit + transfers
   3. Update gas: g' = g - u + Σ(transfer gas from new transfers)
   4. Recurse: Δ+(g', t, R*[i..], X', {})

   f (always-accumulate) is included in the first Δ* call only.

   STATE is the mutable accumulation state (includes χ fields, f).
   Returns: updated STATE with :commitments, :gas-usage, :pending-transfers populated."
  (let ((all-commitments nil)
        (all-gas-usage nil)
        (transfers (getf state :pending-transfers))
        (free-accum (funcall (getf state :chi) :always-accum))
        (n (length r-star))
        (reports r-star))

    (loop
      ;; GP: n = |X| + i + |f|  — terminate when nothing to process
      (let* ((gas-limit (getf state :remaining-gas))
             (i (if (plusp gas-limit)
                    (find-report-cutoff gas-limit reports)
                    0))
             (n-items (+ (length transfers) i (length free-accum))))

        ;; Termination: nothing to process
        (when (zerop n-items) (return))

        ;; Guard: if no reports fit and no transfers, avoid infinite loop
        (when (and (zerop i) (null transfers) (null free-accum))
          (return))

        ;; Batch: reports[0..i) + current transfers + free-accum
        (let ((batch-reports (subseq reports 0 i)))
          (multiple-value-bind (state* new-transfers commitments gas-usage)
              (accumulate-star state transfers batch-reports free-accum)
            (setf state state*)
            (setf all-commitments (nconc all-commitments commitments))
            (setf all-gas-usage (nconc all-gas-usage gas-usage))

            ;; GP §12.18: g' = g - u + Σ(transfer gas)
            ;; Note: accumulate-star already decremented (getf state :remaining-gas) by gas-used.
            ;; We need to ADD back the transfer gas from new deferred transfers.
            (let ((xfer-gas (reduce #'+ (or new-transfers nil)
                                      :key (lambda (x) (or (getf x :gas-limit) 0))
                                      :initial-value 0)))
              (when (plusp xfer-gas)
                (let ((new-remaining (+ (getf state :remaining-gas) xfer-gas)))
                  ;; Clamp to u64 max
                  (when (> new-remaining (1- (ash 1 64)))
                    (setf new-remaining (1- (ash 1 64))))
                  (setf (getf state :remaining-gas) new-remaining))))

            ;; Advance: remaining reports, new transfers, f = {} (no more free-accum)
            (setf reports (subseq reports i)
                  transfers new-transfers
                  free-accum nil)))))

    ;; Store results back in state
    (setf (getf state :commitments) all-commitments
          (getf state :gas-usage) all-gas-usage
          (getf state :pending-transfers) transfers
          (getf state :n-accumulated) n)
    state))

;;; ═══════════════════════════════════════════════════════════════
;;; transition-accumulate — GP (4.16) top-level entry
;;; ═══════════════════════════════════════════════════════════════

(defun transition-accumulate (r-star-input omega xi delta chi iota phi tau tau-prime
                              &key eta header)
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
   ETA:       η' closure (post-transition entropy — bytes extracted at point of use)
   HEADER:    H closure (block header — hash extracted at point of use)

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
         (prev-timeslot (if tau (funcall tau :slot) (1- timeslot))))

    ;; ── §12.1: ω transitions (sovereign — GP 12.4-12.12) ──
    (let* ((omega-prime (funcall omega :transition
                                 :reports r-star-input
                                 :xi-flattened (funcall xi :flattened)
                                 :timeslot timeslot
                                 :prev-timeslot prev-timeslot))
           (r-star (funcall omega-prime :r-star)))


      ;; ── §12.2 Execution ──
      ;; Build mutable accumulation state S.
      ;; Closures δ, χ, ι, ϕ travel inside — queried at point of use.
      (let* ((accum-state
              (list :delta            delta    ;; δ closure — sovereign
                    :chi              chi      ;; χ closure — sovereign
                    :iota             iota     ;; ι closure — sovereign
                    :phi              phi      ;; ϕ closure — sovereign
                    :timeslot         timeslot
                    :entropy          (when eta (funcall eta :encode))
                    :header-hash      (when header (funcall header :hash))
                    ;; GP (12.25): g = max(G_T, G_A·C + Σ_{x∈V(χ_Z)}(x))
                    :remaining-gas    (max (max-block-gas)
                                          (+ (* +accumulation-gas+ (num-cores))
                                             (reduce #'+ (or (funcall chi :always-accum) '())
                                                     :key #'cdr :initial-value 0)))
                    ;; ── Accumulators ──
                    :commitments      nil        ;; B: (sid . yield-hash)
                    :gas-usage        nil        ;; U: (sid . gas-used)
                    :pending-transfers nil)))     ;; X: deferred transfers

        ;; Run Δ+ (sequential over R*) — GP (12.25)
        (setf accum-state (accumulate-all r-star accum-state))

        ;; ── §12.3 Final State Integration ──

        (let* ((n (or (getf accum-state :n-accumulated) 0))

               ;; ── ξ' (12.32-12.33): shift register ──
               ;; ξ owns its shift logic; ω' owns P(R*_{...n}) computation.
               (xi-prime (funcall xi :transition
                                  :accumulated-hashes
                                  (funcall omega-prime :package-hashes-for n)))

               ;; ── ω' already computed by ω :transition above ──

               ;; ── δ† (12.30-12.31): δ already transitioned via :transition-dagger ──
               (delta-dagger (getf accum-state :delta))

               ;; ── χ' (12.27): χ already transitioned in Δ* ──
               (chi-prime (getf accum-state :chi))

               ;; ── GP: B is a set of (s, o) pairs → total order for deterministic encoding ──
               ;; Sort by (service-id ascending, yield-hash lexicographic ascending).
               ;; Same sid can appear multiple times when a service is re-accumulated
               ;; via deferred transfers within the same block.
               (sorted-commits
                (flet ((commit< (a b)
                         (let ((sa (car a)) (sb (car b)))
                           (or (< sa sb)
                               (and (= sa sb)
                                    (loop for i below (min (length (cdr a)) (length (cdr b)))
                                          when (< (aref (cdr a) i) (aref (cdr b) i))
                                            return t
                                          when (> (aref (cdr a) i) (aref (cdr b) i))
                                            return nil
                                          finally (return nil)))))))
                  (sort (copy-list (or (getf accum-state :commitments) nil))
                        #'commit<)))

               ;; ── θ' (12.26): accumulation output log ──
               ;; θ owns its encoding — :transition returns θ' from commitments.
               (theta-prime
                (funcall (make-theta-state) :transition
                         :commitments sorted-commits))

               ;; ── S (12.28-12.29): service statistics for π' ──
               (service-stats (getf accum-state :gas-usage)))

          (list :omega-prime   omega-prime
                :xi-prime      xi-prime
                :delta-dagger  delta-dagger
                :chi-prime     chi-prime
                ;; GP (12.27): ι' and ϕ' — already transitioned in Δ*
                :iota-prime    (getf accum-state :iota)
                :phi-prime     (getf accum-state :phi)
                :theta-prime   theta-prime
                :commitments   sorted-commits   ;; sorted for β' accumulate-root
                :service-stats service-stats))))))
