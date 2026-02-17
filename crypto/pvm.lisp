;;;; pvm.lisp — Clean JAM-codec-based PVM FFI bindings
;;;;
;;;; Replaces 60+ individual getter/setter functions with 6 blob-based
;;;; functions using JAM's own codec (GP Appendix C).
;;;;
;;;; New API:
;;;;   pvm-new          — create PVM instance from service code blob
;;;;   pvm-configure    — load full context as one JAM blob
;;;;   pvm-run          — execute PVM (delegates to existing jam_run)
;;;;   pvm-collapse     — collapse Accumulate dual context
;;;;   pvm-collect      — read all side-effects as one JAM blob
;;;;   pvm-free         — free PVM instance
;;;;
;;;; Wire format: JAM tuples (GP C.4) with JAM compact (GP C.5) length
;;;; prefixes for sequences. Fixed-width LE for integers.
;;;;
;;;; NOTE: This file is part of jam-crypto (loaded BEFORE jotl), so all
;;;; JAM codec primitives are defined locally — no jotl:: references.

(in-package :jam.ffi)

;;; ═══════════════════════════════════════════════════════════════════
;;; Local JAM codec primitives (GP Appendix C)
;;;
;;; Defined here because jam-crypto loads before jotl.
;;; ═══════════════════════════════════════════════════════════════════

(defun %count-leading-ones (byte)
  "Count leading 1-bits in a byte."
  (loop for i from 7 downto 0
        while (logbitp i byte)
        count t))

(defun %encode-compact (value)
  "Encode JAM compact integer (GP C.5). Returns byte vector."
  (cond
    ((< value 128) (make-array 1 :element-type '(unsigned-byte 8) :initial-element value))
    (t (let* ((needed-bits (integer-length value))
              (l (loop for l from 1 to 8
                       for data-bits = (- (* 8 (1+ l)) l 1)
                       when (>= data-bits needed-bits)
                       return l
                       finally (return 8)))
              (total (1+ l))
              (result (make-array total :element-type '(unsigned-byte 8) :initial-element 0)))
         ;; Header byte: l leading 1-bits + (7-l) data bits
         (let* ((data-bits (max 0 (- 7 l)))
                (high-part (if (zerop data-bits) 0 (ldb (byte data-bits (* 8 l)) value)))
                (prefix-bits (1- (ash 1 l))) ;; l ones in top position
                (header (logior (ash prefix-bits (1+ data-bits)) high-part)))
           (setf (aref result 0) header))
         ;; Remaining l bytes: little-endian low part
         (loop for i from 1 below total
               do (setf (aref result i)
                        (ldb (byte 8 (* 8 (1- i))) value)))
         result))))

(defun %decode-compact (bytes &optional (offset 0))
  "Decode JAM compact integer from BYTES at OFFSET. Returns (values value consumed)."
  (let* ((first-byte (aref bytes offset))
         (l (%count-leading-ones first-byte))
         (total (1+ l)))
    (if (= l 8)
        ;; 0xFF prefix: 8 bytes LE
        (let ((val 0))
          (loop for i from 1 to 8
                do (setf val (logior val (ash (aref bytes (+ offset i)) (* 8 (1- i))))))
          (values val 9))
        (let* ((data-bits (max 0 (- 7 l)))
               (mask (1- (ash 1 data-bits)))
               (rem (logand first-byte mask))
               (low 0))
          (loop for i from 1 to l
                do (setf low (logior low (ash (aref bytes (+ offset i)) (* 8 (1- i))))))
          (values (+ low (ash rem (* 8 l))) total)))))

(defun %decode-u32 (bytes &optional (offset 0))
  "Decode u32 LE from BYTES at OFFSET. Returns (values value 4)."
  (values (logior (aref bytes offset)
                  (ash (aref bytes (+ offset 1)) 8)
                  (ash (aref bytes (+ offset 2)) 16)
                  (ash (aref bytes (+ offset 3)) 24))
          4))

(defun %decode-u64 (bytes &optional (offset 0))
  "Decode u64 LE from BYTES at OFFSET. Returns (values value 8)."
  (let ((val 0))
    (loop for i from 0 below 8
          do (setf val (logior val (ash (aref bytes (+ offset i)) (* 8 i)))))
    (values val 8)))

;;; ═══════════════════════════════════════════════════════════════════
;;; CFFI declarations for new wire-format FFI
;;; ═══════════════════════════════════════════════════════════════════

(cffi:defcfun ("jam_pvm_new" %jam-pvm-new) :pointer
  "Create JAM PVM instance from service code blob."
  (code :pointer) (code-len :size) (service-id :uint32) (balance :uint64) (slot :uint32))

(cffi:defcfun ("jam_pvm_free" %jam-pvm-free) :void
  "Free JAM PVM instance."
  (instance :pointer))

(cffi:defcfun ("jam_pvm_configure" %jam-pvm-configure) :uint32
  "Configure PVM from JAM-encoded blob."
  (instance :pointer) (blob :pointer) (blob-len :size))

(cffi:defcfun ("jam_pvm_collect" %jam-pvm-collect) :uint32
  "Collect side-effects as JAM-encoded blob."
  (instance :pointer) (out-buf :pointer) (out-cap :uint32))

;;; ═══════════════════════════════════════════════════════════════════
;;; CFFI declarations for execution / collapse (still thin C wrappers)
;;; ═══════════════════════════════════════════════════════════════════

(cffi:defcfun ("jam_run" %jam-run) :uint32
  "Run PVM from entry point. Returns status code."
  (instance :pointer) (entry-point :string) (result :pointer))

(cffi:defcfun ("jam_set_gas" %jam-set-gas) :void
  "Set gas limit." (instance :pointer) (gas :int64))

(cffi:defcfun ("jam_get_gas" %jam-get-gas) :int64
  "Get remaining gas." (instance :pointer))

(cffi:defcfun ("jam_has_yield_output" %jam-has-yield-output) :uint32
  "Check yield." (instance :pointer))

(cffi:defcfun ("jam_get_yield_output" %jam-get-yield-output) :uint32
  "Get yield hash." (instance :pointer) (out-buf :pointer))

(cffi:defcfun ("jam_accumulate_collapse" %jam-accumulate-collapse) :uint32
  "Collapse dual context (GP B.13)."
  (instance :pointer) (outcome :uint32) (yield-hash :pointer))

;;; ═══════════════════════════════════════════════════════════════════
;;; Debug: host-call tracing (temporary)
;;; ═══════════════════════════════════════════════════════════════════

(cffi:defcfun ("jam_debug_trace_enable" %jam-debug-trace-enable) :void
  "Enable host-call tracing." (instance :pointer))

(cffi:defcfun ("jam_debug_trace_count" %jam-debug-trace-count) :uint32
  "Get host-call trace count." (instance :pointer))

(cffi:defcfun ("jam_debug_trace_entry" %jam-debug-trace-entry) :uint32
  "Read one trace entry."
  (instance :pointer) (index :uint32)
  (out-id :pointer) (out-gas-before :pointer) (out-gas-after :pointer)
  (out-a0 :pointer) (out-sc :pointer))

(defun pvm-debug-trace-enable (ctx)
  "Enable host-call tracing on a PVM context."
  (%jam-debug-trace-enable ctx))

(defun pvm-debug-trace-read (ctx)
  "Read all host-call trace entries. Returns list of (id gas-before gas-after return-a0 storage-count)."
  (let ((n (%jam-debug-trace-count ctx))
        (result nil))
    (cffi:with-foreign-objects ((oid :uint32) (ogb :int64) (oga :int64) (oa0 :uint64) (osc :uint32))
      (dotimes (i n)
        (when (zerop (%jam-debug-trace-entry ctx i oid ogb oga oa0 osc))
          (push (list (cffi:mem-ref oid :uint32)
                      (cffi:mem-ref ogb :int64)
                      (cffi:mem-ref oga :int64)
                      (cffi:mem-ref oa0 :uint64)
                      (cffi:mem-ref osc :uint32))
                result))))
    (nreverse result)))

(cffi:defcfun ("jam_debug_log_count" %jam-debug-log-count) :uint32
  "Get debug log entry count." (instance :pointer))

(cffi:defcfun ("jam_debug_log_entry" %jam-debug-log-entry) :uint32
  "Read one debug log entry."
  (instance :pointer) (index :uint32) (out-buf :pointer) (buf-len :uint32))

(defun pvm-debug-log-read (ctx)
  "Read all debug log entries. Returns list of strings."
  (let ((n (%jam-debug-log-count ctx))
        (result nil))
    (cffi:with-foreign-object (buf :uint8 4096)
      (dotimes (i n)
        (let ((len (%jam-debug-log-entry ctx i buf 4096)))
          (when (> len 0)
            (push (cffi:foreign-string-to-lisp buf :count len) result)))))
    (nreverse result)))

;;; ── Guest ext_log messages (ecalli 100) ──

(cffi:defcfun ("jam_guest_log_count" %jam-guest-log-count) :uint32
  "Get guest log message count." (instance :pointer))

(cffi:defcfun ("jam_guest_log_entry" %jam-guest-log-entry) :uint32
  (instance :pointer) (index :uint32) (out-buf :pointer) (buf-len :uint32))

(defun pvm-guest-log-read (ctx)
  "Read all guest ext_log messages. Returns list of strings."
  (let ((n (%jam-guest-log-count ctx))
        (result nil))
    (cffi:with-foreign-object (buf :uint8 4096)
      (dotimes (i n)
        (let ((len (%jam-guest-log-entry ctx i buf 4096)))
          (when (> len 0)
            (push (cffi:foreign-string-to-lisp buf :count len) result)))))
    (nreverse result)))

;;; ═══════════════════════════════════════════════════════════════════
;;; CFFI declaration for work-item encoding
;;; ═══════════════════════════════════════════════════════════════════

(cffi:defcfun ("jam_encode_work_item_record" %jam-encode-work-item-record) :uint32
  "Encode AccumulateItem::WorkItem via jam-types.
   result-kind: 0=Ok, 1=OutOfGas, 2=Panic, 3=BadExports, 4=OutputOversize, 5=BadCode, 6=CodeOversize."
  (package-hash :pointer) (exports-root :pointer) (auth-hash :pointer)
  (payload-hash :pointer) (gas-limit :uint64)
  (result-kind :uint8)
  (result-data :pointer) (result-len :uint32)
  (auth-output-data :pointer) (auth-output-len :uint32)
  (out-buf :pointer) (out-capacity :uint32))

(cffi:defcfun ("jam_encode_transfer_record" %jam-encode-transfer-record) :uint32
  "Encode AccumulateItem::Transfer via jam-types (GP 12.24: Δ₁ i^T)."
  (source :uint32) (destination :uint32) (amount :uint64)
  (memo-ptr :pointer) (gas-limit :uint64)
  (out-buf :pointer) (out-capacity :uint32))

;;; ═══════════════════════════════════════════════════════════════════
;;; Lisp-side JAM encoding helpers (for configure blob)
;;; ═══════════════════════════════════════════════════════════════════

(defun write-u8 (buf val)
  "Append a u8 to buffer."
  (vector-push-extend (logand val #xff) buf))

(defun write-u16-le (buf val)
  "Append a u16 little-endian to buffer."
  (vector-push-extend (logand val #xff) buf)
  (vector-push-extend (logand (ash val -8) #xff) buf))

(defun write-u32-le (buf val)
  "Append a u32 little-endian to buffer."
  (loop for shift from 0 by 8 below 32
        do (vector-push-extend (logand (ash val (- shift)) #xff) buf)))

(defun write-u64-le (buf val)
  "Append a u64 little-endian to buffer."
  (loop for shift from 0 by 8 below 64
        do (vector-push-extend (logand (ash val (- shift)) #xff) buf)))

(defun write-i64-le (buf val)
  "Append an i64 little-endian to buffer."
  ;; Convert signed to unsigned two's complement
  (write-u64-le buf (if (minusp val) (+ val (ash 1 64)) val)))

(defun write-bytes (buf bytes)
  "Append raw bytes to buffer."
  (loop for b across (ensure-octets bytes)
        do (vector-push-extend b buf)))

(defun write-compact (buf val)
  "Append JAM compact-encoded integer to buffer."
  (let ((encoded (%encode-compact val)))
    (write-bytes buf encoded)))

(defun write-blob (buf data)
  "Append compact-prefixed byte sequence to buffer."
  (let ((d (ensure-octets data)))
    (write-compact buf (length d))
    (write-bytes buf d)))

;;; ═══════════════════════════════════════════════════════════════════
;;; encode-pvm-config — Lisp -> JAM blob for jam_pvm_configure
;;; ═══════════════════════════════════════════════════════════════════

(defun encode-pvm-config (&key
                            (invocation 2)
                            (service-id 0)
                            (balance 0)
                            (timeslot 0)
                            (entropy (make-array 128 :element-type '(unsigned-byte 8) :initial-element 0))
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
                            (gas 0)
                            (storage nil)
                            (preimages nil)
                            (lookup nil)
                            (service-accounts nil)
                            (existing-services nil)
                            (accumulate-items nil)
                            (work-items nil)
                            (core-count 2)
                            (auth-queue-len 80)
                            (val-count 6))
  "Encode PVM configuration as a JAM tuple blob.

   STORAGE:          alist of (key-bytes . value-bytes)
   PREIMAGES:        alist of (hash-32 . data-bytes)
   LOOKUP:           list of (hash-32 length . status-list)
   SERVICE-ACCOUNTS: alist of (service-id . plist {:code-hash :balance :threshold ...})
   EXISTING-SERVICES: list of u32 service IDs
   ACCUMULATE-ITEMS: list of byte-vectors
   WORK-ITEMS:       list of plists (:service-id :code-hash :gas-limit :gas-limit-accum :payload)

   Returns: (vector (unsigned-byte 8))"
  (let ((buf (make-array 512 :element-type '(unsigned-byte 8) :fill-pointer 0 :adjustable t)))

    ;; Fixed header
    (write-u8 buf invocation)
    (write-u32-le buf service-id)
    (write-u64-le buf balance)
    (write-u32-le buf timeslot)
    (write-bytes buf (ensure-octets entropy))
    (write-bytes buf (ensure-octets header-hash))
    (write-bytes buf (ensure-octets code-hash))
    (write-u64-le buf threshold)
    (write-u64-le buf min-accum-gas)
    (write-u64-le buf min-memo-gas)
    (write-u32-le buf items-count)
    (write-u64-le buf footprint)
    (write-u32-le buf recent-count)
    (write-u32-le buf accum-gas-limit)
    (write-u32-le buf preimage-pages)
    (write-i64-le buf gas)

    ;; Own storage: seq[(blob, blob)]
    (write-compact buf (length storage))
    (dolist (entry storage)
      (write-blob buf (car entry))
      (write-blob buf (cdr entry)))

    ;; Own preimages: seq[([u8;32], blob)]
    (write-compact buf (length preimages))
    (dolist (entry preimages)
      (write-bytes buf (ensure-octets (car entry)))
      (write-blob buf (cdr entry)))

    ;; Own lookup: seq[([u8;32], u32, seq[u32])]
    (write-compact buf (length lookup))
    (dolist (entry lookup)
      (let ((hash (first entry))
            (len  (second entry))
            (status (cddr entry)))
        (write-bytes buf (ensure-octets hash))
        (write-u32-le buf len)
        (write-compact buf (length status))
        (dolist (s status)
          (write-u32-le buf s))))

    ;; Cross-service accounts: seq[(u32, service_account_blob)]
    (write-compact buf (length service-accounts))
    (dolist (entry service-accounts)
      (let* ((sid (car entry))
             (acct (cdr entry)))
        (write-u32-le buf sid)
        (encode-service-account-into buf acct)))

    ;; Existing services: seq[u32]
    (write-compact buf (length existing-services))
    (dolist (sid existing-services)
      (write-u32-le buf sid))

    ;; Accumulate items: seq[blob]
    (write-compact buf (length accumulate-items))
    (dolist (item accumulate-items)
      (write-blob buf item))

    ;; Work items: seq[work_item_blob]
    (write-compact buf (length work-items))
    (dolist (wi work-items)
      (write-u32-le buf (getf wi :service-id 0))
      (write-bytes buf (ensure-octets (getf wi :code-hash
                                        (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))))
      (write-u64-le buf (getf wi :gas-limit 0))
      (write-u64-le buf (getf wi :gas-limit-accum 0))
      (write-blob buf (ensure-octets (getf wi :payload #()))))

    ;; Tail
    (write-u16-le buf core-count)
    (write-u16-le buf auth-queue-len)
    (write-u16-le buf val-count)

    ;; Convert to simple-array
    (let ((result (make-array (fill-pointer buf) :element-type '(unsigned-byte 8))))
      (replace result buf)
      result)))

(defun encode-service-account-into (buf acct)
  "Encode a service account plist into BUF.
   ACCT is a plist with keys: :code-hash :balance :threshold :min-accum-gas
   :min-memo-gas :items-count :footprint :recent-count
   :accum-gas-limit :preimage-pages :storage :preimages :lookup"
  ;; code_hash: [u8;32]
  (write-bytes buf (ensure-octets (getf acct :code-hash
                                    (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))))
  ;; u64 fields
  (write-u64-le buf (getf acct :balance 0))
  (write-u64-le buf (getf acct :threshold 0))
  (write-u64-le buf (getf acct :min-accum-gas 0))
  (write-u64-le buf (getf acct :min-memo-gas 0))
  ;; u32 fields
  (write-u32-le buf (getf acct :items-count 0))
  ;; u64
  (write-u64-le buf (getf acct :footprint 0))
  ;; u32 fields
  (write-u32-le buf (getf acct :recent-count 0))
  (write-u32-le buf (getf acct :accum-gas-limit 0))
  (write-u32-le buf (getf acct :preimage-pages 0))
  ;; storage: seq[(blob, blob)]
  (let ((storage (getf acct :storage nil)))
    (write-compact buf (length storage))
    (dolist (entry storage)
      (write-blob buf (car entry))
      (write-blob buf (cdr entry))))
  ;; preimages: seq[([u8;32], blob)]
  (let ((preimages (getf acct :preimages nil)))
    (write-compact buf (length preimages))
    (dolist (entry preimages)
      (write-bytes buf (ensure-octets (car entry)))
      (write-blob buf (cdr entry))))
  ;; lookup: seq[([u8;32], u32, seq[u32])]
  (let ((lookup (getf acct :lookup nil)))
    (write-compact buf (length lookup))
    (dolist (entry lookup)
      (write-bytes buf (ensure-octets (first entry)))
      (write-u32-le buf (second entry))
      (let ((status (cddr entry)))
        (write-compact buf (length status))
        (dolist (s status)
          (write-u32-le buf s))))))

;;; ═══════════════════════════════════════════════════════════════════
;;; Stateful binary reader
;;;
;;; A reader is a cons (bytes . (pos)) where pos is a mutable cell.
;;; This avoids deeply nested multiple-value-bind.
;;; ═══════════════════════════════════════════════════════════════════

(defun %make-reader (bytes)
  "Create a reader state: (bytes . (position))."
  (cons bytes (list 0)))

(defun %reader-pos (reader)
  (car (cdr reader)))

(defun %reader-advance! (reader n)
  (incf (car (cdr reader)) n))

(defun %read-u32 (reader)
  "Read u32 LE and advance."
  (let ((pos (%reader-pos reader)))
    (multiple-value-bind (val n) (%decode-u32 (car reader) pos)
      (%reader-advance! reader n)
      val)))

(defun %read-u64 (reader)
  "Read u64 LE and advance."
  (let ((pos (%reader-pos reader)))
    (multiple-value-bind (val n) (%decode-u64 (car reader) pos)
      (%reader-advance! reader n)
      val)))

(defun %read-compact (reader)
  "Read JAM compact integer and advance."
  (let ((pos (%reader-pos reader)))
    (multiple-value-bind (val n) (%decode-compact (car reader) pos)
      (%reader-advance! reader n)
      val)))

(defun %read-fixed (reader count)
  "Read COUNT fixed bytes and advance."
  (let* ((pos (%reader-pos reader))
         (data (subseq (car reader) pos (+ pos count))))
    (%reader-advance! reader count)
    data))

(defun %read-blob (reader)
  "Read compact-prefixed byte sequence and advance."
  (let ((len (%read-compact reader)))
    (%read-fixed reader len)))

(defun %read-byte (reader)
  "Read single byte and advance."
  (let ((b (aref (car reader) (%reader-pos reader))))
    (%reader-advance! reader 1)
    b))

;;; ═══════════════════════════════════════════════════════════════════
;;; decode-pvm-side-effects — JAM blob -> Lisp plist
;;; ═══════════════════════════════════════════════════════════════════

(defun decode-pvm-side-effects (bytes)
  "Decode a JAM-encoded side-effects blob into a plist.
   BYTES: octet vector from jam_pvm_collect.
   Returns plist with keys:
     :balance :gas-remaining :storage :transfers :ejected :created
     :upgrades :empower :provided-preimages :lookup :preimages
     :yield-output :items-count :footprint"
  (let* ((r (%make-reader bytes))
         ;; balance: u64
         (balance (%read-u64 r))
         ;; gas-remaining: i64 (read as u64, convert to signed)
         (gas-raw (%read-u64 r))
         (gas (if (>= gas-raw (ash 1 63)) (- gas-raw (ash 1 64)) gas-raw))
         ;; storage: seq[(blob, blob)]
         (storage (loop repeat (%read-compact r)
                        collect (cons (%read-blob r) (%read-blob r))))
         ;; transfers: seq[(u32, u64, [u8;128], u32, u64)]
         (transfers (loop repeat (%read-compact r)
                          collect (list :to (%read-u32 r)
                                        :amount (%read-u64 r)
                                        :memo (%read-fixed r 128)
                                        :from (%read-u32 r)
                                        :gas-limit (%read-u64 r))))
         ;; ejected: seq[(u32, u32)]
         (ejected (loop repeat (%read-compact r)
                        collect (cons (%read-u32 r) (%read-u32 r))))
         ;; created: seq[(u32, [u8;32])]
         (created (loop repeat (%read-compact r)
                        collect (cons (%read-u32 r) (%read-fixed r 32))))
         ;; upgrades: seq[(u32, [u8;32])]
         (upgrades (loop repeat (%read-compact r)
                         collect (cons (%read-u32 r) (%read-fixed r 32))))
         ;; empower: option(empower_tuple)
         (empower (when (= (%read-byte r) 1)
                    (%decode-empower r)))
         ;; provided_preimages: seq[(u32, blob)]
         (provided (loop repeat (%read-compact r)
                         collect (cons (%read-u32 r) (%read-blob r))))
         ;; lookup: seq[([u8;32], u32, seq[u32])]
         (lookup (loop repeat (%read-compact r)
                       collect (list* (%read-fixed r 32)
                                      (%read-u32 r)
                                      (loop repeat (%read-compact r)
                                            collect (%read-u32 r)))))
         ;; preimages: seq[([u8;32], blob)] — final a_P blob store
         (preimages (loop repeat (%read-compact r)
                          collect (cons (%read-fixed r 32) (%read-blob r))))
         ;; yield_output: option([u8;32])
         (yield-output (when (= (%read-byte r) 1)
                         (%read-fixed r 32)))
         ;; items_count: u32 (PVM-tracked)
         (items-count (%read-u32 r))
         ;; footprint: u64 (PVM-tracked)
         (footprint (%read-u64 r))
         ;; code_hash: [u8;32] — caller's final code hash (may be changed by ΩU)
         (final-code-hash (%read-fixed r 32))
         ;; min_accum_gas: u64 — caller's final min accumulate gas
         (final-min-accum-gas (%read-u64 r))
         ;; min_memo_gas: u64 — caller's final min memo gas
         (final-min-memo-gas (%read-u64 r))
         ;; created_full: seq[(u32, [u8;32], u64, u64, u64, u64, u32)]
         ;; Full metadata for newly created services
         (created-full (loop repeat (%read-compact r)
                             collect (list :id (%read-u32 r)
                                           :code-hash (%read-fixed r 32)
                                           :balance (%read-u64 r)
                                           :min-accum-gas (%read-u64 r)
                                           :min-memo-gas (%read-u64 r)
                                           :deposit-offset (%read-u64 r)
                                           :parent-service (%read-u32 r)))))
    (list :balance balance
          :gas-remaining gas
          :storage storage
          :transfers transfers
          :ejected ejected
          :created created
          :upgrades upgrades
          :empower empower
          :provided-preimages provided
          :lookup lookup
          :preimages preimages
          :yield-output yield-output
          :items-count items-count
          :footprint footprint
          :final-code-hash final-code-hash
          :final-min-accum-gas final-min-accum-gas
          :final-min-memo-gas final-min-memo-gas
          :created-full created-full)))


(defun %decode-empower (reader)
  "Decode EmpowerState from JAM blob using READER. Returns plist."
  (let ((manager (%read-u32 reader))
        (agents (loop repeat (%read-compact reader)
                      collect (%read-u32 reader))))
    (let ((validator (%read-u32 reader))
          (staker (%read-u32 reader)))
      (let ((gas-map (loop repeat (%read-compact reader)
                           collect (cons (%read-u32 reader) (%read-u64 reader)))))
        (let ((queues (loop repeat (%read-compact reader)
                            collect (loop repeat (%read-compact reader)
                                          collect (%read-fixed reader 32)))))
          (let ((validators (loop repeat (%read-compact reader)
                                  collect (%read-blob reader))))
            (list :manager manager
                  :auth-agents agents
                  :validator validator
                  :staker staker
                  :gas-map gas-map
                  :queues queues
                  :validators validators)))))))

;;; ═══════════════════════════════════════════════════════════════════
;;; High-level PVM API
;;; ═══════════════════════════════════════════════════════════════════

(defun pvm-new (blob service-id balance slot)
  "Create a new PVM instance from a JAM service code BLOB.
   Returns: opaque pointer (must be freed with pvm-free)."
  (let ((b (ensure-octets blob)))
    (cffi:with-pointer-to-vector-data (ptr b)
      (let ((instance (%jam-pvm-new ptr (length b) service-id balance slot)))
        (when (cffi:null-pointer-p instance)
          (error "jam_pvm_new failed"))
        instance))))

(defun pvm-free (instance)
  "Free a PVM instance."
  (unless (cffi:null-pointer-p instance)
    (%jam-pvm-free instance)))

(defun pvm-configure (instance &rest config-keys)
  "Configure a PVM instance from keyword args.
   See ENCODE-PVM-CONFIG for the full list of keyword args."
  (let ((blob (apply #'encode-pvm-config config-keys)))
    (cffi:with-pointer-to-vector-data (ptr blob)
      (let ((status (%jam-pvm-configure instance ptr (length blob))))
        (unless (zerop status)
          (error "jam_pvm_configure failed: ~A" status))
        status))))

(defun pvm-collect (instance)
  "Collect all side-effects from a PVM instance.
   Returns a plist decoded from the JAM blob."
  (let ((cap 1048576)) ;; 1 MB should be plenty
    (cffi:with-foreign-pointer (buf cap)
      (let ((len (%jam-pvm-collect instance buf cap)))
        (when (zerop len)
          (error "jam_pvm_collect: buffer too small or error"))
        ;; Copy to Lisp array
        (let ((bytes (make-array len :element-type '(unsigned-byte 8))))
          (loop for i below len
                do (setf (aref bytes i) (cffi:mem-aref buf :uint8 i)))
          (decode-pvm-side-effects bytes))))))

(defun pvm-run (instance entry-point)
  "Execute PVM from entry point.
   INSTANCE: raw pointer from pvm-new.
   ENTRY-POINT: string (\"accumulate_ext\", \"refine_ext\", etc.)
   Returns: (values status result gas-remaining)
     status: 0=OK, 5=Trap, 6=OOG, 7=HostError"
  (cffi:with-foreign-object (result-ptr :uint64)
    (setf (cffi:mem-ref result-ptr :uint64) 0)
    (let ((status (%jam-run instance entry-point result-ptr)))
      (values status
              (cffi:mem-ref result-ptr :uint64)
              (%jam-get-gas instance)))))

(defun pvm-collapse (instance status)
  "Resolve Accumulate dual context (GP B.13).
   STATUS: PVM exit code from pvm-run (0=OK, 5=Trap, 6=OOG).
   Detects yield internally and collapses accordingly.
   Returns: outcome (0=Halt, 1=Panic, 2=OOG, 3=Yield)."
  (let ((outcome (cond
                   ((= status 0)
                    (if (not (zerop (%jam-has-yield-output instance))) 3 0))
                   ((= status 5) 1)  ;; Trap → Panic
                   ((= status 6) 2)  ;; OOG
                   (t 1))))          ;; Other → Panic
    (if (= outcome 3)
        ;; Extract yield hash and collapse with it
        (cffi:with-foreign-pointer (buf 32)
          (%jam-get-yield-output instance buf)
          (%jam-accumulate-collapse instance 3 buf))
        (%jam-accumulate-collapse instance outcome (cffi:null-pointer)))
    outcome))

(defun pvm-encode-work-item-record (package-hash exports-root auth-hash payload-hash
                                    gas-limit result-kind result-data
                                    &optional auth-output)
  "Encode a WorkItemRecord as AccumulateItem using Rust's jam-types encoder.
   RESULT-KIND: 0=Ok, 1=OutOfGas, 2=Panic, 3=BadExports, 4=OutputOversize, 5=BadCode, 6=CodeOversize.
   RESULT-DATA: output bytes when RESULT-KIND=0 (Ok), ignored otherwise.
   Returns the encoded bytes, or nil on error."
  ;; Normalize: treat zero-length arrays as nil (avoids CFFI bounds errors)
  ;; For error variants (result-kind > 0), result-data is ignored
  (let* ((result-data (when (and (zerop result-kind) result-data (plusp (length result-data)))
                        result-data))
         (auth-output (when (and auth-output (plusp (length auth-output))) auth-output))
         (result-len (if result-data (length result-data) 0))
         (auth-len (if auth-output (length auth-output) 0))
         ;; Dynamic capacity: 4×32 fixed hashes + 8 gas + 1 kind + compact-len
         ;; + result-data + auth-output + overhead for compact encoding
         (out-capacity (max 1024 (+ 256 result-len auth-len)))
         (out-buf (cffi:foreign-alloc :uint8 :count out-capacity))
         (pkg (ensure-octets (or package-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))))
         (exp (ensure-octets (or exports-root (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))))
         (auth (ensure-octets (or auth-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))))
         (pay (ensure-octets (or payload-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))))
         (res (ensure-octets (or result-data (make-array 1 :element-type '(unsigned-byte 8) :initial-element 0))))
         (ao (ensure-octets (or auth-output (make-array 1 :element-type '(unsigned-byte 8) :initial-element 0)))))
    (unwind-protect
        (cffi:with-foreign-array (pkg-ptr pkg '(:array :uint8 32))
          (cffi:with-foreign-array (exp-ptr exp '(:array :uint8 32))
            (cffi:with-foreign-array (auth-ptr auth '(:array :uint8 32))
              (cffi:with-foreign-array (pay-ptr pay '(:array :uint8 32))
                (cffi:with-foreign-array (res-ptr res `(:array :uint8 ,(max 1 result-len)))
                  (cffi:with-foreign-array (ao-ptr ao `(:array :uint8 ,(max 1 auth-len)))
                    (let ((encoded-len (%jam-encode-work-item-record
                                        pkg-ptr exp-ptr auth-ptr pay-ptr
                                        gas-limit
                                        result-kind
                                        (if result-data res-ptr (cffi:null-pointer)) result-len
                                        (if auth-output ao-ptr (cffi:null-pointer)) auth-len
                                        out-buf out-capacity)))
                      (if (zerop encoded-len)
                          nil
                          (cffi:foreign-array-to-lisp out-buf `(:array :uint8 ,encoded-len))))))))))
      (cffi:foreign-free out-buf))))

(defun pvm-encode-transfer-record (source destination amount memo gas-limit)
  "Encode a TransferRecord as AccumulateItem::Transfer using Rust's jam-types encoder.
   GP 12.24: i^T items — deferred transfers for a service.
   SOURCE:      u32 service ID of sender
   DESTINATION: u32 service ID of receiver
   AMOUNT:      u64 balance transferred
   MEMO:        128-byte vector (W_T)
   GAS-LIMIT:   u64 gas for on_transfer
   Returns the encoded bytes, or nil on error."
  (let* ((memo-bytes (ensure-octets
                       (or memo (make-array 128 :element-type '(unsigned-byte 8) :initial-element 0))))
         (out-capacity 512)
         (out-buf (cffi:foreign-alloc :uint8 :count out-capacity)))
    (unwind-protect
        (cffi:with-foreign-array (memo-ptr memo-bytes '(:array :uint8 128))
          (let ((encoded-len (%jam-encode-transfer-record
                               (or source 0) (or destination 0) (or amount 0)
                               memo-ptr (or gas-limit 0)
                               out-buf out-capacity)))
            (if (zerop encoded-len)
                nil
                (cffi:foreign-array-to-lisp out-buf `(:array :uint8 ,encoded-len)))))
      (cffi:foreign-free out-buf))))

(defmacro with-pvm ((var blob service-id balance slot) &body body)
  "Execute BODY with a PVM instance, ensuring cleanup.
   VAR is bound to the raw pointer."
  `(let ((,var (pvm-new ,blob ,service-id ,balance ,slot)))
     (unwind-protect
         (progn ,@body)
       (pvm-free ,var))))
