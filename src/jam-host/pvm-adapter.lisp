;;;; pvm-adapter.lisp — Bridge from accumulate.lisp to Lisp JamVM
;;;;
;;;; Replaces the Rust FFI PVM calls (jam.ffi:with-pvm, pvm-configure,
;;;; pvm-run, pvm-collapse, pvm-collect) with pure Lisp equivalents
;;;; using JamVM (GP Appendix A) + jam-host (GP Appendix B).
;;;;
;;;; Key entry point:
;;;;   LISP-PVM-RUN-ACCUMULATE — full accumulate invocation
;;;;
;;;; Also provides pure Lisp encoders (replacing jam.ffi FFI):
;;;;   ENCODE-WORK-ITEM-RECORD   — AccumulateItem::WorkItem
;;;;   ENCODE-TRANSFER-RECORD    — AccumulateItem::Transfer
;;;;   ENCODE-ACCUMULATE-PARAMS  — AccumulateParams (slot, sid, count)
;;;;   ENCODE-GP-CONSTANTS       — Protocol parameters for ΩY(0)

(in-package #:jam-host)

;;; ═══════════════════════════════════════════════════════════════════
;;; JAM compact encoding — delegate to helpers.lisp
;;; ═══════════════════════════════════════════════════════════════════

(defun %encode-jam-compact (value)
  "Delegate to encode-jam-compact in helpers.lisp."
  (encode-jam-compact value))

;;; ═══════════════════════════════════════════════════════════════════
;;; Buffer builder (growable octet vector)
;;; ═══════════════════════════════════════════════════════════════════

(defun %make-buf (&optional (size 256))
  (make-array size :element-type '(unsigned-byte 8) :fill-pointer 0 :adjustable t))

(defun %buf-u8 (buf val)
  (vector-push-extend (logand val #xFF) buf))

(defun %buf-u32-le (buf val)
  (loop for shift from 0 by 8 below 32
        do (vector-push-extend (logand (ash val (- shift)) #xFF) buf)))

(defun %buf-u64-le (buf val)
  (loop for shift from 0 by 8 below 64
        do (vector-push-extend (logand (ash val (- shift)) #xFF) buf)))

(defun %buf-bytes (buf data)
  (loop for b across data do (vector-push-extend b buf)))

(defun %buf-compact (buf val)
  (%buf-bytes buf (%encode-jam-compact val)))

(defun %buf-blob (buf data)
  "Compact-prefixed byte sequence."
  (%buf-compact buf (length data))
  (%buf-bytes buf data))

(defun %buf-finalize (buf)
  "Convert fill-pointer array to simple-array."
  (let ((result (make-array (fill-pointer buf) :element-type '(unsigned-byte 8))))
    (replace result buf)
    result))

;;; ═══════════════════════════════════════════════════════════════════
;;; AccumulateItem encoding — JAM codec (GP Appendix C)
;;;
;;; AccumulateItem is an enum:
;;;   0 = WorkItem(WorkItemRecord)
;;;   1 = Transfer(TransferRecord)
;;;
;;; WorkItemRecord fields (in order):
;;;   package:        [u8; 32]
;;;   exports_root:   [u8; 32]
;;;   authorizer_hash:[u8; 32]
;;;   payload:        [u8; 32]
;;;   gas_limit:      u64
;;;   result:         Result<WorkOutput, WorkError>
;;;   auth_output:    Vec<u8> (compact-prefixed)
;;;
;;; Result encoding (CompactRefineResult — NOT standard Result<T,E>):
;;;   Ok(WorkOutput(data)):      0x00 + compact(len) + data
;;;   Err(WorkError::OutOfGas):  0x01   (single byte — discriminant only)
;;;   Err(WorkError::Panic):     0x02
;;;   Err(WorkError::BadExports):0x03
;;;   Err(WorkError::OutputOversize): 0x04
;;;   Err(WorkError::BadCode):   0x05
;;;   Err(WorkError::CodeOversize):   0x06
;;;
;;; TransferRecord fields (in order):
;;;   source:      u32
;;;   destination: u32
;;;   amount:      u64
;;;   memo:        [u8; 128]
;;;   gas_limit:   u64
;;; ═══════════════════════════════════════════════════════════════════

(defun %ensure-hash32 (v)
  "Ensure V is a 32-byte octet vector."
  (if (and v (>= (length v) 32))
      (subseq v 0 32)
      (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))

(defun encode-work-item-record (package-hash exports-root auth-hash payload-hash
                                gas-limit result-kind result-data
                                &optional auth-output)
  "Encode AccumulateItem::WorkItem in JAM codec.
   RESULT-KIND: 0=Ok, 1=OutOfGas, 2=Panic, 3=BadExports,
                4=OutputOversize, 5=BadCode, 6=CodeOversize.
   Returns octet vector."
  (let ((buf (%make-buf 256)))
    ;; Enum discriminant: 0 = WorkItem
    (%buf-u8 buf 0)
    ;; package: [u8; 32]
    (%buf-bytes buf (%ensure-hash32 package-hash))
    ;; exports_root: [u8; 32]
    (%buf-bytes buf (%ensure-hash32 exports-root))
    ;; authorizer_hash: [u8; 32]
    (%buf-bytes buf (%ensure-hash32 auth-hash))
    ;; payload: [u8; 32]
    (%buf-bytes buf (%ensure-hash32 payload-hash))
    ;; gas_limit: u64 — #[codec(compact)] in WorkItemRecord
    (%buf-compact buf gas-limit)
    ;; result: Result<WorkOutput, WorkError>
    (cond
      ((zerop result-kind)
       ;; Ok(WorkOutput(data))
       (%buf-u8 buf 0)  ; Ok variant
       (let ((data (or result-data #())))
         (%buf-blob buf data)))
      (t
       ;; CompactRefineResult Err encoding: single discriminant byte.
       ;; WorkError variants: 1=OutOfGas, 2=Panic, 3=BadExports, etc.
       ;; NO separate "Err" tag — just the variant index.
       (%buf-u8 buf result-kind)))
    ;; auth_output: Vec<u8>
    (let ((ao (or auth-output #())))
      (%buf-blob buf ao))
    (%buf-finalize buf)))

(defun encode-transfer-record (source destination amount memo gas-limit)
  "Encode AccumulateItem::Transfer in JAM codec.
   MEMO: 128-byte octet vector (or nil → zeros).
   Returns octet vector."
  (let ((buf (%make-buf 256)))
    ;; Enum discriminant: 1 = Transfer
    (%buf-u8 buf 1)
    ;; source: u32
    (%buf-u32-le buf (or source 0))
    ;; destination: u32
    (%buf-u32-le buf (or destination 0))
    ;; amount: u64
    (%buf-u64-le buf (or amount 0))
    ;; memo: [u8; 128]
    (let ((m (or memo (make-array 128 :element-type '(unsigned-byte 8)
                                       :initial-element 0))))
      ;; Ensure exactly 128 bytes
      (if (>= (length m) 128)
          (%buf-bytes buf (subseq m 0 128))
          (progn
            (%buf-bytes buf m)
            (dotimes (i (- 128 (length m)))
              (%buf-u8 buf 0)))))
    ;; gas_limit: u64
    (%buf-u64-le buf (or gas-limit 0))
    (%buf-finalize buf)))

;;; ═══════════════════════════════════════════════════════════════════
;;; AccumulateParams encoding — GP B.9
;;;
;;; AccumulateParams { slot: u32, service_id: u32, item_count: u32 }
;;; JAM tuple encoding: E_4(slot) + E_4(service_id) + E_4(item_count) = 12 bytes
;;; ═══════════════════════════════════════════════════════════════════

(defun encode-accumulate-params (slot service-id item-count)
  "Encode AccumulateParams with JAM compact fields.
   All three fields have #[codec(compact)] in the Rust struct."
  (let ((buf (%make-buf 16)))
    (%buf-compact buf slot)
    (%buf-compact buf service-id)
    (%buf-compact buf item-count)
    (%buf-finalize buf)))

;;; ═══════════════════════════════════════════════════════════════════
;;; Protocol parameters encoding — for ΩY(0) fetch
;;;
;;; Format: 136 bytes LE, matching encode_gp_constants in encode.rs
;;; Uses TINY chainspec defaults.
;;; ═══════════════════════════════════════════════════════════════════

(defun encode-gp-constants (&key
                              (deposit-per-item 10)     ;; B_I
                              (deposit-per-byte 1)      ;; B_L
                              (deposit-per-account 100) ;; B_S
                              (core-count 2)            ;; C
                              (min-turnaround 32)       ;; D
                              (epoch-period 12)         ;; E
                              (max-accumulate-gas 10000000)  ;; G_A
                              (max-is-authorized-gas 50000000)  ;; G_I
                              (max-refine-gas 1000000000)       ;; G_R
                              (block-gas-limit 20000000)        ;; G_T
                              (recent-block-count 8)    ;; H
                              (max-work-items 16)       ;; I
                              (max-dependencies 8)      ;; J
                              (max-tickets-per-block 3) ;; K
                              (max-lookup-anchor-age 24) ;; L  (tiny=24)
                              (tickets-attempts 3)      ;; N
                              (auth-window 8)           ;; O   (tiny=8)
                              (slot-period-sec 6)       ;; P
                              (auth-queue-len 80)       ;; Q
                              (rotation-period 4)       ;; R
                              (max-extrinsics 128)      ;; T   (tiny=128)
                              (availability-timeout 5)  ;; U   (tiny=5)
                              (val-count 6)             ;; V
                              (max-authorizer-code 64000)      ;; W_A (tiny=64000)
                              (max-input 13794305)             ;; W_B (tiny=13794305)
                              (max-service-code 4000000)       ;; W_C (tiny=4000000)
                              (basic-piece-len 4)              ;; W_E (tiny=4)
                              (max-imports 3072)               ;; W_M (tiny=3072)
                              (segment-piece-count 1026)       ;; W_P (tiny=1026)
                              (max-report-elective 49152)      ;; W_R (tiny=48*1024)
                              (transfer-memo-size 128)         ;; W_T
                              (max-exports 3072)               ;; W_X
                              (epoch-tail-start 10))           ;; Y  (tiny=10)
  "Encode protocol parameters for ΩY fetch(kind=0).
   Returns 136-byte octet vector."
  (let ((buf (%make-buf 136)))
    ;; B_I, B_L, B_S (u64 × 3 = 24 bytes)
    (%buf-u64-le buf deposit-per-item)
    (%buf-u64-le buf deposit-per-byte)
    (%buf-u64-le buf deposit-per-account)
    ;; C (u16), D (u32), E (u32)
    (%buf-u8 buf (logand core-count #xFF))
    (%buf-u8 buf (ash core-count -8))
    (%buf-u32-le buf min-turnaround)
    (%buf-u32-le buf epoch-period)
    ;; G_A, G_I, G_R, G_T (u64 × 4 = 32 bytes)
    (%buf-u64-le buf max-accumulate-gas)
    (%buf-u64-le buf max-is-authorized-gas)
    (%buf-u64-le buf max-refine-gas)
    (%buf-u64-le buf block-gas-limit)
    ;; H, I, J, K (u16 × 4 = 8 bytes)
    (%buf-u8 buf (logand recent-block-count #xFF)) (%buf-u8 buf (ash recent-block-count -8))
    (%buf-u8 buf (logand max-work-items #xFF))     (%buf-u8 buf (ash max-work-items -8))
    (%buf-u8 buf (logand max-dependencies #xFF))   (%buf-u8 buf (ash max-dependencies -8))
    (%buf-u8 buf (logand max-tickets-per-block #xFF)) (%buf-u8 buf (ash max-tickets-per-block -8))
    ;; L (u32)
    (%buf-u32-le buf max-lookup-anchor-age)
    ;; N, O (u16 × 2 = 4 bytes)
    (%buf-u8 buf (logand tickets-attempts #xFF))   (%buf-u8 buf (ash tickets-attempts -8))
    (%buf-u8 buf (logand auth-window #xFF))        (%buf-u8 buf (ash auth-window -8))
    ;; P, Q, R, T, U, V (u16 × 6 = 12 bytes)
    (%buf-u8 buf (logand slot-period-sec #xFF))    (%buf-u8 buf (ash slot-period-sec -8))
    (%buf-u8 buf (logand auth-queue-len #xFF))     (%buf-u8 buf (ash auth-queue-len -8))
    (%buf-u8 buf (logand rotation-period #xFF))    (%buf-u8 buf (ash rotation-period -8))
    (%buf-u8 buf (logand max-extrinsics #xFF))     (%buf-u8 buf (ash max-extrinsics -8))
    (%buf-u8 buf (logand availability-timeout #xFF))(%buf-u8 buf (ash availability-timeout -8))
    (%buf-u8 buf (logand val-count #xFF))          (%buf-u8 buf (ash val-count -8))
    ;; W_A, W_B, W_C, W_E, W_M, W_P, W_R, W_T, W_X (u32 × 9 = 36 bytes)
    (%buf-u32-le buf max-authorizer-code)
    (%buf-u32-le buf max-input)
    (%buf-u32-le buf max-service-code)
    (%buf-u32-le buf basic-piece-len)
    (%buf-u32-le buf max-imports)
    (%buf-u32-le buf segment-piece-count)
    (%buf-u32-le buf max-report-elective)
    (%buf-u32-le buf transfer-memo-size)
    (%buf-u32-le buf max-exports)
    ;; Y (u32)
    (%buf-u32-le buf epoch-tail-start)
    (%buf-finalize buf)))

;;; ═══════════════════════════════════════════════════════════════════
;;; blake2b-256 — using ironclad (replaces jam.ffi:blake2b-256)
;;; ═══════════════════════════════════════════════════════════════════

(defun blake2b-256 (data)
  "Compute Blake2b-256 hash of DATA (octet vector). Returns 32-byte vector."
  (let ((d (ironclad:make-digest :blake2/256)))
    (ironclad:update-digest d (coerce data '(simple-array (unsigned-byte 8) (*))))
    (ironclad:produce-digest d)))

;;; ═══════════════════════════════════════════════════════════════════
;;; populate-host-context — fill host-context from accumulate-service args
;;; ═══════════════════════════════════════════════════════════════════

(defun populate-host-context (&key
                                (invocation +ctx-accumulate+)
                                (service-id 0)
                                (balance 0)
                                (timeslot 0)
                                (entropy #())
                                (header-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
                                (code-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
                                (threshold 0)
                                (min-accum-gas 0)
                                (min-memo-gas 0)
                                (items-count 0)
                                (footprint 0)
                                (recent-count 0)
                                (accum-gas-limit 0)
                                (preimage-pages 0)
                                (storage nil)
                                (preimages nil)
                                (lookup nil)
                                (service-accounts nil)
                                (existing-services nil)
                                (accumulate-items nil)
                                (core-count 2)
                                (auth-queue-len 80)
                                (val-count 6)
                                (debug-trace nil))
  "Build a host-context struct from keyword args.
   STORAGE:          alist of (key-bytes . value-bytes)
   PREIMAGES:        alist of (hash-32 . data-bytes)
   LOOKUP:           list of (hash-32 length . status-list)
   SERVICE-ACCOUNTS: alist of (service-id . plist {:code-hash :balance ...})
   EXISTING-SERVICES: list of u32 service IDs
   ACCUMULATE-ITEMS: list of byte-vectors (pre-encoded AccumulateItem blobs)"
  (let ((ctx (make-host-context
              :invocation invocation
              :service-id service-id
              :balance balance
              :slot timeslot
              :timeslot timeslot
              :core-count core-count
              :auth-queue-len auth-queue-len
              :val-count val-count
              :code-hash (coerce (%ensure-hash32 code-hash) '(simple-array (unsigned-byte 8) (32)))
              :threshold threshold
              :min-accum-gas min-accum-gas
              :min-memo-gas min-memo-gas
              :items-count items-count
              :footprint footprint
              :recent-count recent-count
              :accum-gas-limit accum-gas-limit
              :preimage-pages preimage-pages
              :header-hash (coerce (%ensure-hash32 header-hash) '(simple-array (unsigned-byte 8) (32)))
              :entropy-raw (coerce (or entropy #()) '(simple-array (unsigned-byte 8) (*)))
              :accumulate-items accumulate-items
              :debug-trace debug-trace
              :protocol-params (coerce (encode-gp-constants :core-count core-count
                                                            :auth-queue-len auth-queue-len
                                                            :val-count val-count)
                                       '(simple-array (unsigned-byte 8) (*))))))

    ;; ── Populate storage hash table from alist ──
    (dolist (entry (or storage nil))
      (setf (gethash (car entry) (hctx-storage ctx)) (cdr entry)))

    ;; ── Populate preimages hash table ──
    (dolist (entry (or preimages nil))
      (setf (gethash (car entry) (hctx-preimages ctx)) (cdr entry)))

    ;; ── Populate lookup hash table ──
    ;; Key: (hash . length), Value: status-list
    (dolist (entry (or lookup nil))
      (let ((hash-32 (first entry))
            (len     (second entry))
            (statuses (cddr entry)))
        (setf (gethash (cons hash-32 len) (hctx-lookup ctx)) statuses)))

    ;; ── Populate service accounts ──
    (dolist (entry (or service-accounts nil))
      (let* ((sid  (car entry))
             (acct (cdr entry))
             (sa (make-service-account
                  :code-hash (coerce (%ensure-hash32 (getf acct :code-hash))
                                     '(simple-array (unsigned-byte 8) (32)))
                  :balance        (or (getf acct :balance) 0)
                  :threshold      (or (getf acct :threshold) 0)
                  :min-accum-gas  (or (getf acct :min-accum-gas) 0)
                  :min-memo-gas   (or (getf acct :min-memo-gas) 0)
                  :items-count    (or (getf acct :items-count) 0)
                  :footprint      (or (getf acct :footprint) 0)
                  :recent-count   (or (getf acct :recent-count) 0)
                  :accum-gas-limit(or (getf acct :accum-gas-limit) 0)
                  :preimage-pages (or (getf acct :preimage-pages) 0))))
        ;; Populate sub-account storage/preimages/lookup
        (dolist (s (getf acct :storage))
          (setf (gethash (car s) (sa-storage sa)) (cdr s)))
        (dolist (p (getf acct :preimages))
          (setf (gethash (car p) (sa-preimages sa)) (cdr p)))
        (dolist (l (getf acct :lookup))
          (let ((h (first l)) (len (second l)) (st (cddr l)))
            (setf (gethash (cons h len) (sa-lookup sa)) st)))
        (setf (gethash sid (hctx-service-accounts ctx)) sa)))

    ;; ── Populate existing services set ──
    (dolist (sid (or existing-services nil))
      (setf (gethash sid (hctx-existing-services ctx)) t))

    ;; ── Initialize next-service-id (GP B.10 + B.14) ──
    ;; i = E₄⁻¹(H(compact(s) ⌢ η'₀ ⌢ compact(H_T))) mod M + S, then check.
    ;; Must be after existing-services population (check-service-id needs it).
    (let ((entropy-0 (coerce (or entropy #()) '(simple-array (unsigned-byte 8) (*)))))
      (setf (hctx-next-service-id ctx)
            (compute-next-service-id
             service-id
             entropy-0
             timeslot
             ctx)))

    ;; ── Parse entropy bytes into 4×32 array ──
    (let ((raw (coerce (or entropy #()) '(simple-array (unsigned-byte 8) (*)))))
      (when (>= (length raw) 128)
        (let ((e (hctx-entropy ctx)))
          (dotimes (slice 4)
            (dotimes (b 32)
              (setf (aref e slice b) (aref raw (+ (* slice 32) b))))))))

    ctx))

;;; ═══════════════════════════════════════════════════════════════════
;;; collect-effects — Extract side-effects from host-context
;;;
;;; Produces a plist compatible with accumulate.lisp's expectations
;;; (same keys as decode-pvm-side-effects in crypto/pvm.lisp).
;;; ═══════════════════════════════════════════════════════════════════

(defun collect-effects (ctx)
  "Extract side-effects from a host-context after execution.
   Returns a plist matching the format of jam.ffi:pvm-collect."
  ;; Convert storage hash table to alist
  (let ((storage-alist nil)
        (transfer-plists nil)
        (ejected-alist nil)
        (created-alist nil)
        (upgrade-alist nil)
        (preimages-alist nil)
        (lookup-list nil)
        (provided-list nil))

    ;; Storage: hash-table → alist of (key . value)
    (maphash (lambda (k v) (push (cons k v) storage-alist))
             (hctx-storage ctx))

    ;; Transfers: list of jam-transfer structs → list of plists
    (dolist (xfer (hctx-transfers ctx))
      (push (list :to        (xfer-to-service xfer)
                  :amount    (xfer-amount xfer)
                  :memo      (xfer-memo xfer)
                  :from      (xfer-from-service xfer)
                  :gas-limit (xfer-gas-limit xfer))
            transfer-plists))

    ;; Ejected: list of (target . ejector) cons
    (setf ejected-alist (copy-list (hctx-ejected-services ctx)))

    ;; Created: list of (service-id . code-hash) cons
    (setf created-alist (copy-list (hctx-created-services ctx)))

    ;; Upgrades: list of (service-id . code-hash) cons
    (setf upgrade-alist (copy-list (hctx-upgrades ctx)))

    ;; Preimages: hash-table → alist of (hash-32 . blob)
    (maphash (lambda (k v) (push (cons k v) preimages-alist))
             (hctx-preimages ctx))

    ;; Lookup: hash-table → list of (hash-32 length . statuses)
    (maphash (lambda (k v)
               (let ((hash-32 (car k))
                     (len     (cdr k)))
                 (push (list* hash-32 len v) lookup-list)))
             (hctx-lookup ctx))

    ;; Provided preimages: list of (service-id . data)
    (setf provided-list (copy-list (hctx-provided-preimages ctx)))

    ;; Empower: empower-state struct or nil → plist
    (let ((emp (hctx-empower ctx))
          (empower-plist nil))
      (when emp
        (let ((gas-map-alist nil))
          (maphash (lambda (k v) (push (cons k v) gas-map-alist))
                   (emp-gas-map emp))
          (setf empower-plist
                (list :manager     (emp-manager emp)
                      :auth-agents (coerce (emp-auth-agents emp) 'list)
                      :validator   (emp-validator emp)
                      :staker      (emp-staker emp)
                      :gas-map     gas-map-alist
                      :queues      (coerce (emp-queues emp) 'list)
                      :validators  (coerce (emp-validators emp) 'list)))))

      (list :balance          (hctx-balance ctx)
            :gas-remaining    0  ; filled by caller
            :storage          (nreverse storage-alist)
            :transfers        (nreverse transfer-plists)
            :ejected          ejected-alist
            :created          created-alist
            :upgrades         upgrade-alist
            :empower          empower-plist
            :provided-preimages provided-list
            :lookup           lookup-list
            :preimages        (nreverse preimages-alist)
            :yield-output     (hctx-yield-output ctx)
            :items-count      (hctx-items-count ctx)
            :footprint        (hctx-footprint ctx)
            :final-code-hash  (hctx-code-hash ctx)
            :final-min-accum-gas (hctx-min-accum-gas ctx)
            :final-min-memo-gas  (hctx-min-memo-gas ctx)
            ;; created-full: build from created-services with metadata
            :created-full     (mapcar (lambda (cs)
                                        (if (consp cs)
                                            (list :id (car cs)
                                                  :code-hash (second cs) ; (list id hash) → second, not cdr
                                                  :balance 0
                                                  :min-accum-gas 0
                                                  :min-memo-gas 0
                                                  :deposit-offset 0
                                                  :parent-service (hctx-service-id ctx))
                                            cs))
                                      created-alist)))))

;;; ═══════════════════════════════════════════════════════════════════
;;; lisp-pvm-run-accumulate — Full PVM accumulate invocation
;;;
;;; Replaces:
;;;   jam.ffi:with-pvm + pvm-configure + pvm-run + pvm-collapse + pvm-collect
;;;
;;; Returns: (values effects-plist gas-used)
;;; ═══════════════════════════════════════════════════════════════════

(defun lisp-pvm-run-accumulate (code-blob service-id balance timeslot
                                &key
                                  (gas 0)
                                  (entropy #())
                                  (header-hash nil)
                                  (code-hash nil)
                                  (threshold 0)
                                  (min-accum-gas 0)
                                  (min-memo-gas 0)
                                  (items-count 0)
                                  (footprint 0)
                                  (recent-count 0)
                                  (accum-gas-limit 0)
                                  (preimage-pages 0)
                                  (storage nil)
                                  (preimages nil)
                                  (lookup nil)
                                  (service-accounts nil)
                                  (existing-services nil)
                                  (accumulate-items nil)
                                  (core-count 2)
                                  (auth-queue-len 80)
                                  (val-count 6)
                                  (debug-trace nil))
  "Execute PVM accumulate using the Lisp JamVM.
   Returns (values effects-plist gas-used) or (values nil 0) on failure.

   EFFECTS-PLIST has the same format as jam.ffi:pvm-collect."

  ;; 1. Create VM from code blob
  (let ((vm (make-vm (coerce code-blob '(simple-array (unsigned-byte 8) (*))))))
    (unless vm
      (return-from lisp-pvm-run-accumulate (values nil 0)))

    ;; 2. Create host context
    (let ((ctx (populate-host-context
                :invocation +ctx-accumulate+
                :service-id service-id
                :balance balance
                :timeslot timeslot
                :entropy entropy
                :header-hash (or header-hash
                                 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
                :code-hash (or code-hash
                               (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
                :threshold threshold
                :min-accum-gas min-accum-gas
                :min-memo-gas min-memo-gas
                :items-count items-count
                :footprint footprint
                :recent-count recent-count
                :accum-gas-limit accum-gas-limit
                :preimage-pages preimage-pages
                :storage storage
                :preimages preimages
                :lookup lookup
                :service-accounts service-accounts
                :existing-services existing-services
                :accumulate-items accumulate-items
                :core-count core-count
                :auth-queue-len auth-queue-len
                :val-count val-count
                :debug-trace debug-trace)))

      ;; 3. Encode accumulate arguments and invoke
      (let* ((item-count (length (or accumulate-items nil)))
             (params (encode-accumulate-params timeslot service-id item-count))
             (initial-balance (hctx-balance ctx)))  ;; save for panic/OOG revert

        ;; argument-invoke: sets gas, PC, clears regs, allocates+writes args
        (multiple-value-bind (ok invoke-reason) (argument-invoke vm gas +pc-accumulate+ params)
          (unless ok
            (return-from lisp-pvm-run-accumulate (values nil 0)))

          ;; 4. Run with host-call handling
          (handler-case
              (multiple-value-bind (exit-status exit-arg _final-ctx)
                  (host-run vm ctx)
                (declare (ignore _final-ctx exit-arg))

                ;; 5. Map exit status + detect yield via return value
                (let ((outcome
                        (case exit-status
                          (:halt
                           ;; Check yield: if A0 ≠ 0, A1 = 32, read hash
                           (let ((a0 (reg vm +a0+))
                                 (a1 (reg vm +a1+)))
                             (if (and (not (hctx-yield-output ctx))
                                      (/= a0 0)
                                      (= a1 32))
                                 ;; Yield via return value
                                 (let ((hash-bytes (read-guest vm (u32 a0) 32)))
                                   (if hash-bytes
                                       (progn
                                         (setf (hctx-yield-output ctx) hash-bytes)
                                         :halt-with-yield)
                                       :halt))
                                 (if (hctx-yield-output ctx)
                                     :halt-with-yield
                                     :halt))))
                          (:panic :panic)
                          (:oog   :oog)
                          (t      :panic)))
                      (gas-remaining (pvm-gas vm)))

                  ;; 6. Apply checkpoint collapse (GP B.13) directly to ctx
                  ;; On panic/OOG: revert ctx to checkpoint snapshot (y)
                  ;; On halt: keep current ctx (x)
                  (case outcome
                    ((:panic :oog)
                     (let ((cp (hctx-checkpoint ctx)))
                       (if cp
                           ;; Revert to checkpoint
                           (progn
                             (setf (hctx-transfers ctx) (ckpt-transfers cp))
                             (setf (hctx-ejected-services ctx) (ckpt-ejected-services cp))
                             (setf (hctx-created-services ctx) (ckpt-created-services cp))
                             (setf (hctx-upgrades ctx) (ckpt-upgrades cp))
                             (setf (hctx-yield-output ctx) (ckpt-yield-output cp))
                             (setf (hctx-provided-preimages ctx) (ckpt-provided-preimages cp))
                             (setf (hctx-storage ctx) (ckpt-storage cp))
                             (setf (hctx-lookup ctx) (ckpt-lookup cp))
                             (setf (hctx-preimages ctx) (ckpt-preimages cp))
                             (setf (hctx-empower ctx) (ckpt-empower cp))
                             (setf (hctx-items-count ctx) (ckpt-items-count cp))
                             (setf (hctx-footprint ctx) (ckpt-footprint cp))
                             (setf (hctx-balance ctx) (ckpt-balance cp))
                             (setf (hctx-code-hash ctx) (ckpt-code-hash cp))
                             (setf (hctx-min-accum-gas ctx) (ckpt-min-accum-gas cp))
                             (setf (hctx-min-memo-gas ctx) (ckpt-min-memo-gas cp)))
                           ;; No checkpoint → revert to initial state
                           (progn
                             (setf (hctx-transfers ctx) nil)
                             (setf (hctx-ejected-services ctx) nil)
                             (setf (hctx-created-services ctx) nil)
                             (setf (hctx-upgrades ctx) nil)
                             (setf (hctx-yield-output ctx) nil)
                             (setf (hctx-provided-preimages ctx) nil)
                             (setf (hctx-storage ctx) (make-hash-table :test 'equalp))
                             (setf (hctx-lookup ctx) (make-hash-table :test 'equalp))
                             (setf (hctx-preimages ctx) (make-hash-table :test 'equalp))
                             (setf (hctx-empower ctx) nil)
                             (setf (hctx-items-count ctx) 0)
                             (setf (hctx-footprint ctx) 0)
                             (setf (hctx-balance ctx) initial-balance))))))

                  ;; 7. Collect effects — always via collect-effects for normalized format
                  ;; (converts hash-tables → alists, uses correct key names)
                  (let* ((outcome-code (case outcome
                                         (:halt 0)
                                         (:panic 1)
                                         (:oog 2)
                                         (:halt-with-yield 3)
                                         (t 1)))
                         (effects (collect-effects ctx))
                         (gas-used (if (= outcome-code 2)
                                       gas  ; OOG: full budget consumed
                                       (- gas (max (or gas-remaining 0) 0)))))

                    (setf (getf effects :outcome) outcome-code)
                    (setf (getf effects :gas-remaining) gas-remaining)
                    (when debug-trace
                      (setf (getf effects :host-call-log)
                            (reverse (hctx-host-call-log ctx))))

                    (values effects gas-used))))

            (error (e)
              (format *error-output*
                      "~&[LISP-PVM] ERROR for sid ~D: ~A (~A)~%"
                      service-id e (type-of e))
              (values nil 0))))))))
