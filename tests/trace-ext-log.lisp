;;;; trace-ext-log.lisp — Read ext_log messages from PVM to see error messages
;;;;
;;;; Usage: sbcl --noinform --load scripts/load-jotl.lisp --load tests/trace-ext-log.lisp

(in-package #:jotl)

(format t "~%═══ Read ext_log messages from storage_light block 2 ═══~%")

(let* ((trace-dir "tests/jamtestvectors/traces/storage_light/")
       (step-path (trace-block-path trace-dir 2)))
  (multiple-value-bind (pre-sigma block-cl post-sigma pre-root post-root)
      (load-trace-step step-path)
    (declare (ignore post-sigma pre-root post-root))

    (let* ((reports (funcall block-cl :reports))
           (r-star (loop for g in reports
                         for r = (getf g :report) when r collect r))
           (all-tuples (mapcan #'extract-operand-tuples r-star))
           (by-service (group-by-service all-tuples))
           (first-sid (car (first all-tuples)))
           (items (gethash first-sid by-service))
           (sid first-sid)
           (delta-kvs (funcall pre-sigma :merkle-kvs))
           (svc-data (classify-service-sub-keys sid delta-kvs))
           (metadata (getf svc-data :metadata))
           (code-blob (getf svc-data :code-blob))
           (h27-storage (getf svc-data :storage))
           (cross-services (build-cross-service-accounts sid delta-kvs))
           (existing-services (extract-all-service-ids delta-kvs))
           (gas-limit (reduce #'+ items :key (lambda (u) (or (getf u :gas) 0))))
           (balance (or (getf metadata :balance) 0))
           (timeslot (funcall (funcall block-cl :header) :slot))
           (code-hash (or (getf metadata :code-hash)
                          (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
           (accum-items (encode-accumulate-items items nil)))

      ;; Run with debug-trace to capture logs
      (multiple-value-bind (effects gas-used)
          (jam-host:lisp-pvm-run-accumulate
           code-blob sid balance timeslot
           :gas gas-limit
           :entropy (make-array 128 :element-type '(unsigned-byte 8) :initial-element 0)
           :header-hash (funcall block-cl :hash)
           :code-hash code-hash
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
           :accumulate-items accum-items
           :debug-trace t)

        (declare (ignore gas-used))
        (when effects
          ;; Print host call log with register details
          (let ((hclog (getf effects :host-call-log)))
            (format t "~%Host calls: ~D~%" (length hclog))
            (dolist (entry hclog)
              (let ((id (getf entry :id)))
                (format t "~%HC#~D  gas=~D→~D~%" id (getf entry :gas-before) (getf entry :gas-after))
                (format t "  IN:  A0=~D A1=~D A2=~D A3=~D A4=~D A5=~D~%"
                        (getf entry :a0-before) (getf entry :a1-before)
                        (getf entry :a2-before) (getf entry :a3-before)
                        (getf entry :a4-before) (getf entry :a5-before))
                (format t "  OUT: A0=~D A1=~D~%"
                        (getf entry :a0-after) (getf entry :a1-after))))))

        ;; Also check the hctx-logs for raw ext_log data
        ;; We need to access the context's logs  
        (format t "~%~%═══ Checking ext_log data (stored in context logs) ═══~%")
        (format t "NOTE: ext_log data is stored as byte vectors in hctx-logs.~%")
        (format t "We'll re-run with a custom omega-ext-log that prints the data.~%")))))

;; Re-run with modified ext_log that captures and prints log data
(format t "~%═══ Re-running with ext_log capture ═══~%")

(let* ((trace-dir "tests/jamtestvectors/traces/storage_light/")
       (step-path (trace-block-path trace-dir 2)))
  (multiple-value-bind (pre-sigma block-cl post-sigma pre-root post-root)
      (load-trace-step step-path)
    (declare (ignore post-sigma pre-root post-root))

    (let* ((reports (funcall block-cl :reports))
           (r-star (loop for g in reports
                         for r = (getf g :report) when r collect r))
           (all-tuples (mapcan #'extract-operand-tuples r-star))
           (by-service (group-by-service all-tuples))
           (first-sid (car (first all-tuples)))
           (items (gethash first-sid by-service))
           (sid first-sid)
           (delta-kvs (funcall pre-sigma :merkle-kvs))
           (svc-data (classify-service-sub-keys sid delta-kvs))
           (metadata (getf svc-data :metadata))
           (code-blob (getf svc-data :code-blob))
           (h27-storage (getf svc-data :storage))
           (cross-services (build-cross-service-accounts sid delta-kvs))
           (existing-services (extract-all-service-ids delta-kvs))
           (gas-limit (reduce #'+ items :key (lambda (u) (or (getf u :gas) 0))))
           (balance (or (getf metadata :balance) 0))
           (timeslot (funcall (funcall block-cl :header) :slot))
           (code-hash (or (getf metadata :code-hash)
                          (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
           (accum-items (encode-accumulate-items items nil)))

      ;; Create VM manually
      (let ((vm (jamvm:make-vm (coerce code-blob '(simple-array (unsigned-byte 8) (*))))))
        (unless vm
          (format t "ERROR: make-vm returned nil~%")
          (sb-ext:exit :code 1))

        (let ((ctx (jam-host:populate-host-context
                    :invocation jam-host:+ctx-accumulate+
                    :service-id sid :balance balance :timeslot timeslot
                    :entropy (make-array 128 :element-type '(unsigned-byte 8) :initial-element 0)
                    :header-hash (funcall block-cl :hash)
                    :code-hash code-hash
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
                    :accumulate-items accum-items
                    :debug-trace t)))

          ;; Instrument ext_log to print data
          (let ((saved-fn (gethash 100 jam-host::*omega-table*)))
            (setf (gethash 100 jam-host::*omega-table*)
                  (lambda (vm ctx)
                    (let* ((level (jamvm:reg vm jamvm:+a0+))
                           (text-ptr (jamvm:u32 (jamvm:reg vm jamvm:+a3+)))
                           (text-len (jamvm:u32 (jamvm:reg vm jamvm:+a4+)))
                           (data (jam-host::read-guest vm text-ptr text-len)))
                      (format t "~%  ext_log(level=~D, ptr=0x~X, len=~D):~%" level text-ptr text-len)
                      (when data
                        ;; Try to print as UTF-8 text
                        (handler-case
                            (format t "    TEXT: ~A~%" (sb-ext:octets-to-string data :external-format :utf-8))
                          (error ()
                            (format t "    HEX: ~{~2,'0X~^ ~}~%" (coerce data 'list)))))
                      (jamvm:set-reg vm jamvm:+a0+ 0)
                      :continue)))

            ;; Set up argument invocation
            (let* ((item-count (length accum-items))
                   (params (jam-host::encode-accumulate-params timeslot sid item-count)))
              (multiple-value-bind (ok reason) (jamvm:argument-invoke vm gas-limit jamvm:+pc-accumulate+ params)
                (declare (ignore reason))
                (when ok
                  ;; Run
                  (multiple-value-bind (exit-status exit-arg final-ctx)
                      (jam-host::host-run vm ctx)
                    (declare (ignore final-ctx exit-arg))
                    (format t "~%~%Exit: ~A, gas remaining: ~D~%" exit-status (jamvm:pvm-gas vm))))))

            ;; Restore
            (setf (gethash 100 jam-host::*omega-table*) saved-fn)))))))

(format t "~%Done.~%")
(sb-ext:exit :code 0)
