;;;; dual-pvm.lisp — Compare Rust PVM vs Lisp PVM side by side
;;;;
;;;; Usage: sbcl --load scripts/load-jotl.lisp --load tests/dual-pvm.lisp
;;;;
;;;; Extracts a specific accumulate call from a test vector,
;;;; runs it through BOTH PVMs (Rust via FFI, Lisp native),
;;;; and compares their outputs.

(in-package #:jotl)

;;; ═══════════════════════════════════════════════════════════════════
;;; Step 1: Load Rust shared library
;;; ═══════════════════════════════════════════════════════════════════

(defvar *lib-path*
  (merge-pathnames "crypto/jam-crypto/target/release/libjam_crypto.so"
                   (asdf:system-source-directory :jotl)))

(format t "~%Loading Rust PVM from: ~A~%" *lib-path*)
(sb-alien:load-shared-object (namestring *lib-path*))
(format t "  ✓ Loaded~%")

;;; ═══════════════════════════════════════════════════════════════════
;;; Step 2: FFI declarations
;;; ═══════════════════════════════════════════════════════════════════

;; jam_pvm_new(code, code_len, service_id, balance, slot) → *JamInstance
(sb-alien:define-alien-routine ("jam_pvm_new" rust-pvm-new)
  sb-alien:system-area-pointer
  (code sb-alien:system-area-pointer)
  (code-len sb-alien:unsigned-long)
  (service-id sb-alien:unsigned-int)
  (balance sb-alien:unsigned-long)
  (slot sb-alien:unsigned-int))

;; jam_pvm_configure(instance, blob, blob_len) → u32
(sb-alien:define-alien-routine ("jam_pvm_configure" rust-pvm-configure)
  sb-alien:unsigned-int
  (instance sb-alien:system-area-pointer)
  (blob sb-alien:system-area-pointer)
  (blob-len sb-alien:unsigned-long))

;; jam_set_gas(instance, gas)
(sb-alien:define-alien-routine ("jam_set_gas" rust-set-gas)
  sb-alien:void
  (instance sb-alien:system-area-pointer)
  (gas sb-alien:long))

;; jam_get_gas(instance) → i64
(sb-alien:define-alien-routine ("jam_get_gas" rust-get-gas)
  sb-alien:long
  (instance sb-alien:system-area-pointer))

;; jam_debug_trace_enable(instance)
(sb-alien:define-alien-routine ("jam_debug_trace_enable" rust-trace-enable)
  sb-alien:void
  (instance sb-alien:system-area-pointer))

;; jam_debug_trace_count(instance) → u32
(sb-alien:define-alien-routine ("jam_debug_trace_count" rust-trace-count)
  sb-alien:unsigned-int
  (instance sb-alien:system-area-pointer))

;; jam_debug_trace_entry(instance, index, out_id, out_gas_before, out_gas_after, out_a0, out_sc) → u32
(sb-alien:define-alien-routine ("jam_debug_trace_entry" rust-trace-entry)
  sb-alien:unsigned-int
  (instance sb-alien:system-area-pointer)
  (index sb-alien:unsigned-int)
  (out-id (* sb-alien:unsigned-int))
  (out-gas-before (* sb-alien:long))
  (out-gas-after (* sb-alien:long))
  (out-a0 (* sb-alien:unsigned-long))
  (out-sc (* sb-alien:unsigned-int)))

;; jam_run(instance, entry_point, result) → u32
(sb-alien:define-alien-routine ("jam_run" rust-run)
  sb-alien:unsigned-int
  (instance sb-alien:system-area-pointer)
  (entry-point sb-alien:c-string)
  (result (* sb-alien:unsigned-long)))

;; jam_pvm_collect(instance, out_buf, out_cap) → u32
(sb-alien:define-alien-routine ("jam_pvm_collect" rust-pvm-collect)
  sb-alien:unsigned-int
  (instance sb-alien:system-area-pointer)
  (out-buf sb-alien:system-area-pointer)
  (out-cap sb-alien:unsigned-int))

;; jam_pvm_free(instance)
(sb-alien:define-alien-routine ("jam_pvm_free" rust-pvm-free)
  sb-alien:void
  (instance sb-alien:system-area-pointer))

;;; ═══════════════════════════════════════════════════════════════════
;;; Step 3: Wire-format config encoder (matches wire.rs::decode_pvm_config)
;;; ═══════════════════════════════════════════════════════════════════

(defun %wire-buf () (jam-host::%make-buf 4096))

(defun encode-wire-config (&key
                             (invocation 2)  ;; 2 = Accumulate
                             (service-id 0) (balance 0) (timeslot 0)
                             (entropy (make-array 128 :element-type '(unsigned-byte 8) :initial-element 0))
                             (header-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
                             (code-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
                             (threshold 0) (min-accum-gas 0) (min-memo-gas 0)
                             (items-count 0) (footprint 0)
                             (recent-count 0) (accum-gas-limit 0) (preimage-pages 0)
                             (gas 0)
                             (storage nil) (preimages nil) (lookup nil)
                             (service-accounts nil) (existing-services nil)
                             (accumulate-items nil) (work-items nil)
                             (core-count 2) (auth-queue-len 80) (val-count 6))
  "Encode PVM config as wire blob matching wire.rs::decode_pvm_config format."
  (let ((buf (%wire-buf)))
    ;; u8: invocation_context
    (jam-host::%buf-u8 buf invocation)
    ;; u32: service_id
    (jam-host::%buf-u32-le buf service-id)
    ;; u64: balance
    (jam-host::%buf-u64-le buf balance)
    ;; u32: timeslot
    (jam-host::%buf-u32-le buf timeslot)
    ;; [u8;128]: entropy
    (let ((ent (or entropy (make-array 128 :element-type '(unsigned-byte 8) :initial-element 0))))
      (if (>= (length ent) 128)
          (jam-host::%buf-bytes buf (subseq ent 0 128))
          (progn
            (jam-host::%buf-bytes buf ent)
            (dotimes (i (- 128 (length ent)))
              (jam-host::%buf-u8 buf 0)))))
    ;; [u8;32]: header_hash
    (jam-host::%buf-bytes buf (jam-host::%ensure-hash32 header-hash))
    ;; [u8;32]: code_hash
    (jam-host::%buf-bytes buf (jam-host::%ensure-hash32 code-hash))
    ;; u64: threshold, min_accum_gas, min_memo_gas
    (jam-host::%buf-u64-le buf threshold)
    (jam-host::%buf-u64-le buf min-accum-gas)
    (jam-host::%buf-u64-le buf min-memo-gas)
    ;; u32: items_count
    (jam-host::%buf-u32-le buf items-count)
    ;; u64: footprint
    (jam-host::%buf-u64-le buf footprint)
    ;; u32: recent_count, accum_gas_limit, preimage_pages
    (jam-host::%buf-u32-le buf recent-count)
    (jam-host::%buf-u32-le buf accum-gas-limit)
    (jam-host::%buf-u32-le buf preimage-pages)
    ;; i64: gas
    (jam-host::%buf-u64-le buf (logand gas #xFFFFFFFFFFFFFFFF))  ;; i64 as u64
    ;; seq[(blob, blob)]: own storage
    (jam-host::%buf-compact buf (length (or storage nil)))
    (dolist (entry (or storage nil))
      (jam-host::%buf-blob buf (car entry))
      (jam-host::%buf-blob buf (cdr entry)))
    ;; seq[([u8;32], blob)]: own preimages
    (jam-host::%buf-compact buf (length (or preimages nil)))
    (dolist (entry (or preimages nil))
      (jam-host::%buf-bytes buf (jam-host::%ensure-hash32 (car entry)))
      (jam-host::%buf-blob buf (cdr entry)))
    ;; seq[([u8;32], u32, seq[u32])]: own lookup
    (jam-host::%buf-compact buf (length (or lookup nil)))
    (dolist (entry (or lookup nil))
      (let ((hash-32 (first entry))
            (len     (second entry))
            (statuses (cddr entry)))
        (jam-host::%buf-bytes buf (jam-host::%ensure-hash32 hash-32))
        (jam-host::%buf-u32-le buf len)
        (jam-host::%buf-compact buf (length statuses))
        (dolist (s statuses)
          (jam-host::%buf-u32-le buf s))))
    ;; seq[(u32, service_account_blob)]: cross-service accounts
    (jam-host::%buf-compact buf (length (or service-accounts nil)))
    (dolist (entry (or service-accounts nil))
      (let* ((sid (car entry))
             (acct (cdr entry)))
        (jam-host::%buf-u32-le buf sid)
        ;; encode service account inline
        (jam-host::%buf-bytes buf (jam-host::%ensure-hash32 (getf acct :code-hash)))
        (jam-host::%buf-u64-le buf (or (getf acct :balance) 0))
        (jam-host::%buf-u64-le buf (or (getf acct :threshold) 0))
        (jam-host::%buf-u64-le buf (or (getf acct :min-accum-gas) 0))
        (jam-host::%buf-u64-le buf (or (getf acct :min-memo-gas) 0))
        (jam-host::%buf-u32-le buf (or (getf acct :items-count) 0))
        (jam-host::%buf-u64-le buf (or (getf acct :footprint) 0))
        (jam-host::%buf-u32-le buf (or (getf acct :recent-count) 0))
        (jam-host::%buf-u32-le buf (or (getf acct :accum-gas-limit) 0))
        (jam-host::%buf-u32-le buf (or (getf acct :preimage-pages) 0))
        ;; sub-storage
        (let ((sub-storage (or (getf acct :storage) nil)))
          (jam-host::%buf-compact buf (length sub-storage))
          (dolist (s sub-storage)
            (jam-host::%buf-blob buf (car s))
            (jam-host::%buf-blob buf (cdr s))))
        ;; sub-preimages
        (let ((sub-preimages (or (getf acct :preimages) nil)))
          (jam-host::%buf-compact buf (length sub-preimages))
          (dolist (p sub-preimages)
            (jam-host::%buf-bytes buf (jam-host::%ensure-hash32 (car p)))
            (jam-host::%buf-blob buf (cdr p))))
        ;; sub-lookup
        (let ((sub-lookup (or (getf acct :lookup) nil)))
          (jam-host::%buf-compact buf (length sub-lookup))
          (dolist (l sub-lookup)
            (jam-host::%buf-bytes buf (jam-host::%ensure-hash32 (first l)))
            (jam-host::%buf-u32-le buf (second l))
            (jam-host::%buf-compact buf (length (cddr l)))
            (dolist (s (cddr l))
              (jam-host::%buf-u32-le buf s))))))
    ;; seq[u32]: existing_services
    (jam-host::%buf-compact buf (length (or existing-services nil)))
    (dolist (sid (or existing-services nil))
      (jam-host::%buf-u32-le buf sid))
    ;; seq[blob]: accumulate_items
    (jam-host::%buf-compact buf (length (or accumulate-items nil)))
    (dolist (item (or accumulate-items nil))
      (jam-host::%buf-blob buf item))
    ;; seq[work_item_blob]: work_items (we pass 0 for accumulate)
    (jam-host::%buf-compact buf 0)
    ;; u16: core_count, auth_queue_len, val_count
    (jam-host::%buf-u8 buf (logand core-count #xFF))
    (jam-host::%buf-u8 buf (ash core-count -8))
    (jam-host::%buf-u8 buf (logand auth-queue-len #xFF))
    (jam-host::%buf-u8 buf (ash auth-queue-len -8))
    (jam-host::%buf-u8 buf (logand val-count #xFF))
    (jam-host::%buf-u8 buf (ash val-count -8))
    (jam-host::%buf-finalize buf)))

;;; ═══════════════════════════════════════════════════════════════════
;;; Step 4: Extract test data from trace vector
;;; ═══════════════════════════════════════════════════════════════════

(defun extract-first-accumulate-call (trace-dir block-num)
  "Extract the first service's accumulate call parameters from a trace vector.
   Returns plist with all params needed by both PVMs, or NIL."
  (let* ((step-path (trace-block-path trace-dir block-num)))
    (multiple-value-bind (pre-sigma block-cl post-sigma pre-root post-root)
        (load-trace-step step-path)
      (declare (ignore post-sigma pre-root post-root))
      
      ;; Extract from the block and state directly.
      (let* ((delta-kvs (funcall pre-sigma :merkle-kvs))
             (reports (getf block-cl :reports))
             (first-report (first reports)))
        (unless first-report
          (format t "  No reports in block ~D~%" block-num)
          (return-from extract-first-accumulate-call nil))

        ;; Use extract-operand-tuples — returns (service-id . U-plist) pairs
        (let* ((all-tuples (extract-operand-tuples first-report))
               (first-tuple (first all-tuples))
               (sid (car first-tuple)))
          (unless sid
            (format t "  No service-id in first work item~%")
            (return-from extract-first-accumulate-call nil))

          (format t "~%  Target service: ~D~%" sid)

          ;; Collect U-plists for this service
          (let ((svc-items (mapcar #'cdr
                                   (remove-if-not (lambda (tp) (= (car tp) sid))
                                                  all-tuples))))

            ;; Extract service data from delta-kvs
            (let* ((svc-data (classify-service-sub-keys sid delta-kvs))
                   (metadata (getf svc-data :metadata))
                   (code-blob (getf svc-data :code-blob))
                   (h27-storage (getf svc-data :storage))
                   (cross-services (build-cross-service-accounts sid delta-kvs))
                   (existing-services (extract-all-service-ids delta-kvs)))

              (unless code-blob
                (format t "  No code blob for service ~D~%" sid)
                (return-from extract-first-accumulate-call nil))

              (format t "  Code blob: ~D bytes~%" (length code-blob))
              (format t "  Storage entries: ~D~%" (length h27-storage))
              (format t "  Cross-service accounts: ~D~%" (length cross-services))
              (format t "  Existing services: ~D~%" (length existing-services))

              ;; Compute gas-limit: sum of :gas from U-plists
              (let* ((gas-limit (reduce #'+ svc-items
                                        :key (lambda (u) (or (getf u :gas) 0))
                                        :initial-value 0))
                     (balance (or (getf metadata :balance) 0))
                     (timeslot (or (getf block-cl :slot) 0)))

                (format t "  Gas limit: ~D~%" gas-limit)
                (format t "  Balance: ~D~%" balance)
                (format t "  Timeslot: ~D~%" timeslot)

                ;; Encode accumulate items (same path as accumulate-star)
                (let ((accum-items (encode-accumulate-items svc-items nil)))

                  (format t "  Accumulate items: ~D~%" (length accum-items))
                  (when (first accum-items)
                    (format t "  First item size: ~D bytes~%" (length (first accum-items))))

                  (list :code-blob code-blob
                        :service-id sid
                        :balance balance
                        :timeslot timeslot
                        :gas-limit gas-limit
                        :entropy (or (getf block-cl :entropy)
                                     (make-array 128 :element-type '(unsigned-byte 8) :initial-element 0))
                        :header-hash (or (getf block-cl :header-hash)
                                         (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
                        :code-hash (or (getf metadata :code-hash)
                                       (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
                        :threshold (or (getf metadata :deposit-offset) 0)
                        :min-accum-gas (or (getf metadata :min-accum-gas) 0)
                        :min-memo-gas (or (getf metadata :min-memo-gas) 0)
                        :items-count (or (getf metadata :items) 0)
                        :footprint (or (getf metadata :bytes) 0)
                        :recent-count (or (getf metadata :creation-slot) 0)
                        :accum-gas-limit (or (getf metadata :last-accumulation-slot) 0)
                        :preimage-pages (or (getf metadata :parent-service) 0)
                        :storage h27-storage
                        :preimages (getf svc-data :preimages)
                        :lookup (getf svc-data :lookup)
                        :service-accounts cross-services
                        :existing-services existing-services
                        :accumulate-items accum-items))))))))))

;;; ═══════════════════════════════════════════════════════════════════
;;; Step 5: Run Rust PVM via FFI
;;; ═══════════════════════════════════════════════════════════════════

(defun run-rust-pvm (params)
  "Run the Rust PVM with PARAMS, return (values exit-code gas-remaining host-call-log)."
  (let ((code-blob (coerce (getf params :code-blob) '(simple-array (unsigned-byte 8) (*))))
        (sid (getf params :service-id))
        (balance (getf params :balance))
        (timeslot (getf params :timeslot))
        (gas (getf params :gas-limit)))
    
    ;; Create Rust PVM instance
    (sb-sys:with-pinned-objects (code-blob)
      (let ((instance (rust-pvm-new (sb-sys:vector-sap code-blob)
                                    (length code-blob)
                                    sid balance timeslot)))
        (when (sb-sys:sap= instance (sb-sys:int-sap 0))
          (format t "  ✗ Rust jam_pvm_new returned NULL~%")
          (return-from run-rust-pvm (values 99 0 nil)))
        
        (format t "  ✓ Rust PVM instance created~%")
        
        ;; Build wire config blob
        (let ((config-blob (coerce
                            (encode-wire-config
                             :invocation 2
                             :service-id sid
                             :balance balance
                             :timeslot timeslot
                             :entropy (getf params :entropy)
                             :header-hash (getf params :header-hash)
                             :code-hash (getf params :code-hash)
                             :threshold (getf params :threshold)
                             :min-accum-gas (getf params :min-accum-gas)
                             :min-memo-gas (getf params :min-memo-gas)
                             :items-count (getf params :items-count)
                             :footprint (getf params :footprint)
                             :recent-count (getf params :recent-count)
                             :accum-gas-limit (getf params :accum-gas-limit)
                             :preimage-pages (getf params :preimage-pages)
                             :gas gas
                             :storage (getf params :storage)
                             :preimages (getf params :preimages)
                             :lookup (getf params :lookup)
                             :service-accounts (getf params :service-accounts)
                             :existing-services (getf params :existing-services)
                             :accumulate-items (getf params :accumulate-items))
                            '(simple-array (unsigned-byte 8) (*)))))
          
          (format t "  Config blob: ~D bytes~%" (length config-blob))
          
          ;; Configure
          (sb-sys:with-pinned-objects (config-blob)
            (let ((cfg-result (rust-pvm-configure instance
                                                  (sb-sys:vector-sap config-blob)
                                                  (length config-blob))))
              (unless (zerop cfg-result)
                (format t "  ✗ Rust jam_pvm_configure failed: ~D~%" cfg-result)
                (rust-pvm-free instance)
                (return-from run-rust-pvm (values 98 0 nil)))
              (format t "  ✓ Rust PVM configured~%")))
          
          ;; Enable debug tracing
          (rust-trace-enable instance)
          
          ;; Verify gas
          (let ((rust-gas-before (rust-get-gas instance)))
            (format t "  Gas before run: ~D~%" rust-gas-before))
          
          ;; Run
          (sb-alien:with-alien (result sb-alien:unsigned-long)
            (let ((exit-code (rust-run instance "accumulate_ext" (sb-alien:addr result))))
              (let ((gas-after (rust-get-gas instance)))
                (format t "  Exit code: ~D (0=ok 5=trap 6=oog)~%" exit-code)
                (format t "  Gas after: ~D~%" gas-after)
                (format t "  Result A0: ~D~%" (sb-alien:deref result))
                
                ;; Read host call trace
                (let ((trace-count (rust-trace-count instance))
                      (hc-log nil))
                  (format t "  Host calls: ~D~%" trace-count)
                  (sb-alien:with-alien (out-id sb-alien:unsigned-int)
                    (sb-alien:with-alien (out-gb sb-alien:long)
                      (sb-alien:with-alien (out-ga sb-alien:long)
                        (sb-alien:with-alien (out-a0 sb-alien:unsigned-long)
                          (sb-alien:with-alien (out-sc sb-alien:unsigned-int)
                            (dotimes (i trace-count)
                              (rust-trace-entry instance i
                                               (sb-alien:addr out-id)
                                               (sb-alien:addr out-gb)
                                               (sb-alien:addr out-ga)
                                               (sb-alien:addr out-a0)
                                               (sb-alien:addr out-sc))
                              (let ((entry (list :id (sb-alien:deref out-id)
                                                 :gas-before (sb-alien:deref out-gb)
                                                 :gas-after (sb-alien:deref out-ga)
                                                 :a0 (sb-alien:deref out-a0)
                                                 :storage-count (sb-alien:deref out-sc))))
                                (push entry hc-log)
                                (format t "    HC#~D: id=~D gb=~D ga=~D A0=~D sc=~D~%"
                                        i
                                        (getf entry :id)
                                        (getf entry :gas-before)
                                        (getf entry :gas-after)
                                        (getf entry :a0)
                                        (getf entry :storage-count)))))))))
                  
                  ;; Collect side effects
                  (let ((collect-buf (make-array 65536 :element-type '(unsigned-byte 8) :initial-element 0)))
                    (sb-sys:with-pinned-objects (collect-buf)
                      (let ((collect-len (rust-pvm-collect instance
                                                          (sb-sys:vector-sap collect-buf)
                                                          65536)))
                        (format t "  Collected: ~D bytes~%" collect-len)
                        
                        ;; Parse balance + gas from collected blob (first 16 bytes)
                        (when (> collect-len 16)
                          (let ((coll-balance (decode-fixed-le (subseq collect-buf 0 8)))
                                (coll-gas (let ((raw (decode-fixed-le (subseq collect-buf 8 16))))
                                            (if (> raw (ash 1 62)) (- raw (ash 1 64)) raw))))
                            (format t "  Collected balance: ~D~%" coll-balance)
                            (format t "  Collected gas: ~D~%" coll-gas))))))
                  
                  ;; Free
                  (rust-pvm-free instance)
                  
                  (values exit-code gas-after (nreverse hc-log)))))))))))

;;; ═══════════════════════════════════════════════════════════════════
;;; Step 6: Run Lisp PVM
;;; ═══════════════════════════════════════════════════════════════════

(defun run-lisp-pvm (params)
  "Run the Lisp PVM with PARAMS using lower-level APIs for tracing.
   Returns (values exit-code gas-remaining host-call-log)."
  (let* ((code-blob (coerce (getf params :code-blob) '(simple-array (unsigned-byte 8) (*))))
         (gas (getf params :gas-limit))
         (vm (jamvm:make-vm code-blob)))
    (unless vm
      (format t "  ✗ Lisp make-vm returned NIL~%")
      (return-from run-lisp-pvm (values 99 0 nil)))

    (format t "  ✓ Lisp PVM created~%")

    ;; Build host context with debug trace enabled
    (let* ((ctx (jam-host:populate-host-context
                 :invocation jam-host::+ctx-accumulate+
                 :service-id (getf params :service-id)
                 :balance (getf params :balance)
                 :timeslot (getf params :timeslot)
                 :entropy (getf params :entropy)
                 :header-hash (or (getf params :header-hash)
                                  (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
                 :code-hash (or (getf params :code-hash)
                                (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
                 :threshold (getf params :threshold)
                 :min-accum-gas (getf params :min-accum-gas)
                 :min-memo-gas (getf params :min-memo-gas)
                 :items-count (getf params :items-count)
                 :footprint (getf params :footprint)
                 :recent-count (getf params :recent-count)
                 :accum-gas-limit (getf params :accum-gas-limit)
                 :preimage-pages (getf params :preimage-pages)
                 :storage (getf params :storage)
                 :preimages (getf params :preimages)
                 :lookup (getf params :lookup)
                 :service-accounts (getf params :service-accounts)
                 :existing-services (getf params :existing-services)
                 :accumulate-items (getf params :accumulate-items)
                 :debug-trace t))
           ;; Encode accumulate params (slot, sid, item_count)
           (item-count (length (or (getf params :accumulate-items) nil)))
           (acc-params (jam-host:encode-accumulate-params
                        (getf params :timeslot)
                        (getf params :service-id)
                        item-count)))

      ;; argument-invoke: set gas, PC, clear regs, write args
      (multiple-value-bind (ok invoke-reason)
          (jamvm:argument-invoke vm gas jamvm:+pc-accumulate+ acc-params)
        (declare (ignore invoke-reason))
        (unless ok
          (format t "  ✗ argument-invoke failed~%")
          (return-from run-lisp-pvm (values 98 0 nil)))

        (format t "  ✓ argument-invoke OK, gas=~D~%" (jamvm:pvm-gas vm))

        ;; Run with host-call handling
        (handler-case
            (multiple-value-bind (exit-status exit-arg final-ctx)
                (jam-host:host-run vm ctx)
              (declare (ignore final-ctx exit-arg))

              (let* ((gas-remaining (jamvm:pvm-gas vm))
                     (outcome (case exit-status
                                (:halt  0)
                                (:panic 1)
                                (:oog   2)
                                (t      1)))
                     ;; Read host-call-log from ctx (built-in debug tracing)
                     (raw-log (nreverse (jam-host:hctx-host-call-log ctx)))
                     (hc-log nil))

                ;; Convert raw-log entries to plists
                ;; dispatch.lisp logs: (id gas-before gas-after a0 storage-count)
                (dolist (entry raw-log)
                  (destructuring-bind (id gb ga a0 sc) entry
                    (push (list :id id :gas-before gb :gas-after ga :a0 a0 :storage-count sc)
                          hc-log)
                    (format t "    HC#~D: id=~D gb=~D ga=~D A0=~D sc=~D~%"
                            (1- (length hc-log)) id gb ga a0 sc)))

                (setf hc-log (nreverse hc-log))

                (format t "  Exit: ~A → outcome=~D~%" exit-status outcome)
                (format t "  Gas remaining: ~D~%" gas-remaining)
                (format t "  Gas used: ~D~%" (- gas (max gas-remaining 0)))
                (format t "  Host calls: ~D~%" (length hc-log))

                ;; Collect effects
                (let ((effects (jam-host:collect-effects ctx)))
                  (when effects
                    (format t "  Balance: ~D~%" (getf effects :balance))
                    (format t "  Storage entries: ~D~%" (length (getf effects :storage)))
                    (format t "  Transfers: ~D~%" (length (getf effects :transfers)))))

                (values outcome gas-remaining hc-log)))

          (error (e)
            (format t "  ✗ Lisp PVM error: ~A~%" e)
            (values 99 0 nil)))))))

;;; ═══════════════════════════════════════════════════════════════════
;;; Step 7: Compare both PVM runs
;;; ═══════════════════════════════════════════════════════════════════

(defun compare-host-call-logs (rust-log lisp-log)
  "Compare host call logs from both PVMs."
  (format t "~%═══════════════════════════════════════════════════════~%")
  (format t "HOST CALL COMPARISON~%")
  (format t "═══════════════════════════════════════════════════════~%")
  (format t "  Rust: ~D host calls~%" (length rust-log))
  (format t "  Lisp: ~D host calls~%~%" (length lisp-log))
  
  (let ((max-len (max (length rust-log) (length lisp-log)))
        (diffs 0))
    (dotimes (i max-len)
      (let ((r (nth i rust-log))
            (l (nth i lisp-log)))
        (cond
          ((and r l)
           (let ((id-match (= (getf r :id) (getf l :id)))
                 (gb-match (= (getf r :gas-before) (getf l :gas-before)))
                 (ga-match (= (getf r :gas-after) (getf l :gas-after)))
                 (a0-match (= (getf r :a0) (getf l :a0))))
             (unless (and id-match gb-match ga-match a0-match)
               (incf diffs)
               (format t "  ✗ HC#~D DIVERGE:~%" i)
               (unless id-match
                 (format t "    ID:   Rust=~D  Lisp=~D~%" (getf r :id) (getf l :id)))
               (unless gb-match
                 (format t "    Gas-before: Rust=~D  Lisp=~D  (delta=~D)~%"
                         (getf r :gas-before) (getf l :gas-before)
                         (- (getf r :gas-before) (getf l :gas-before))))
               (unless ga-match
                 (format t "    Gas-after:  Rust=~D  Lisp=~D  (delta=~D)~%"
                         (getf r :gas-after) (getf l :gas-after)
                         (- (getf r :gas-after) (getf l :gas-after))))
               (unless a0-match
                 (format t "    A0:   Rust=~D  Lisp=~D~%" (getf r :a0) (getf l :a0)))
               (format t "    SC:   Rust=~D  Lisp=~D~%" (getf r :storage-count) (getf l :storage-count)))))
          (r
           (incf diffs)
           (format t "  ✗ HC#~D: Rust has entry, Lisp does not~%" i)
           (format t "    Rust: id=~D gb=~D ga=~D A0=~D~%"
                   (getf r :id) (getf r :gas-before) (getf r :gas-after) (getf r :a0)))
          (l
           (incf diffs)
           (format t "  ✗ HC#~D: Lisp has entry, Rust does not~%" i)
           (format t "    Lisp: id=~D gb=~D ga=~D A0=~D~%"
                   (getf l :id) (getf l :gas-before) (getf l :gas-after) (getf l :a0))))))
    
    (if (zerop diffs)
        (format t "~%  ✓ All ~D host calls MATCH~%" (length rust-log))
        (format t "~%  ✗ ~D / ~D host calls DIVERGE~%" diffs max-len))))

;;; ═══════════════════════════════════════════════════════════════════
;;; MAIN
;;; ═══════════════════════════════════════════════════════════════════

(format t "~%╔══════════════════════════════════════════════════════╗~%")
(format t "║         DUAL PVM DIAGNOSTIC — Rust vs Lisp          ║~%")
(format t "╚══════════════════════════════════════════════════════╝~%")

;; Extract test data
(format t "~%── Extracting test data from storage_light block 2 ──~%")
(let ((params (extract-first-accumulate-call
               "tests/jamtestvectors/traces/storage_light/" 2)))
  (unless params
    (format t "~%✗ Failed to extract test data~%")
    (sb-ext:exit :code 1))
  
  ;; Run Rust PVM
  (format t "~%── Running Rust PVM ──~%")
  (multiple-value-bind (rust-exit rust-gas rust-hc-log)
      (handler-case (run-rust-pvm params)
        (error (e)
          (format t "  ✗ Rust PVM error: ~A~%" e)
          (values 99 0 nil)))
    
    ;; Run Lisp PVM
    (format t "~%── Running Lisp PVM ──~%")
    (multiple-value-bind (lisp-exit lisp-gas lisp-hc-log)
        (handler-case (run-lisp-pvm params)
          (error (e)
            (format t "  ✗ Lisp PVM error: ~A~%" e)
            (values 99 0 nil)))
      
      ;; Summary comparison
      (format t "~%═══════════════════════════════════════════════════════~%")
      (format t "SUMMARY~%")
      (format t "═══════════════════════════════════════════════════════~%")
      (format t "  Exit:  Rust=~D  Lisp=~D  ~A~%"
              rust-exit lisp-exit
              (if (= rust-exit lisp-exit) "✓" "✗ DIFFER"))
      (format t "  Gas:   Rust=~D  Lisp=~D  ~A~%"
              rust-gas lisp-gas
              (if (= rust-gas lisp-gas) "✓"
                  (format nil "✗ delta=~D" (- rust-gas lisp-gas))))
      (format t "  HCs:   Rust=~D  Lisp=~D  ~A~%"
              (length rust-hc-log) (length lisp-hc-log)
              (if (= (length rust-hc-log) (length lisp-hc-log)) "✓" "✗ DIFFER"))
      
      ;; Detailed host call comparison
      (when (and rust-hc-log lisp-hc-log)
        (compare-host-call-logs rust-hc-log lisp-hc-log)))))

(format t "~%Done.~%")
(sb-ext:exit :code 0)
