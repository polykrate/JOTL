;;;; trace-pvm-panic.lisp — Trace PVM execution around the panic point
;;;;
;;;; Usage: sbcl --noinform --load scripts/load-jotl.lisp --load tests/trace-pvm-panic.lisp

(in-package #:jotl)

(format t "~%═══ TRACE PVM PANIC: storage_light block 2 ═══~%")

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

      (format t "  sid=~D gas=~D blob=~D items=~D~%" sid gas-limit (length code-blob) (length items))

      ;; Create VM and context manually for tracing
      (let ((vm (jamvm:make-vm (coerce code-blob '(simple-array (unsigned-byte 8) (*))))))
        (unless vm
          (format t "  ERROR: make-vm returned nil~%")
          (sb-ext:exit :code 1))

        (let ((ctx (jam-host:populate-host-context
                    :invocation jam-host:+ctx-accumulate+
                    :service-id sid
                    :balance balance
                    :timeslot timeslot
                    :entropy (make-array 128 :element-type '(unsigned-byte 8) :initial-element 0)
                    :header-hash (funcall block-cl :hash)
                    :code-hash code-hash
                    :threshold (or (getf metadata :deposit-offset) 0)
                    :min-accum-gas (or (getf metadata :min-accum-gas) 0)
                    :min-memo-gas (or (getf metadata :min-memo-gas) 0)
                    :items-count (or (getf metadata :items) 0)
                    :footprint (or (getf metadata :bytes) 0)
                    :creation-slot (or (getf metadata :creation-slot) 0)
                    :last-accum-slot (or (getf metadata :last-accumulation-slot) 0)
                    :parent-service (or (getf metadata :parent-service) 0)
                    :storage h27-storage
                    :preimages (getf svc-data :preimages)
                    :lookup (getf svc-data :lookup)
                    :service-accounts cross-services
                    :existing-services existing-services
                    :accumulate-items accum-items)))

          ;; Set up argument invocation
          (let* ((item-count (length accum-items))
                 (params (jam-host::encode-accumulate-params timeslot sid item-count)))
            (multiple-value-bind (ok reason) (jamvm:argument-invoke vm gas-limit jamvm:+pc-accumulate+ params)
              (unless ok
                (format t "  ERROR: argument-invoke failed: ~A~%" reason)
                (sb-ext:exit :code 1))

              (format t "  PC=~D gas=~D~%" (jamvm:pvm-pc vm) (jamvm:pvm-gas vm))
              (format t "  Regs: A0=~D A1=~D A2=~D~%"
                      (jamvm:reg vm jamvm:+a0+)
                      (jamvm:reg vm jamvm:+a1+)
                      (jamvm:reg vm jamvm:+a2+))

              ;; Run with manual stepping + host call handling
              ;; Keep last 30 instructions before panic
              (let ((trace-ring (make-array 30 :initial-element nil))
                    (trace-idx 0)
                    (total-steps 0)
                    (host-calls 0))

                (loop
                  (let* ((pc (jamvm:pvm-pc vm))
                         (gas (jamvm:pvm-gas vm))
                         (result (jamvm:vm-step vm)))
                    (incf total-steps)

                    ;; Record in ring buffer
                    (setf (aref trace-ring trace-idx)
                          (list :step total-steps :pc pc :gas gas :result result
                                :a0 (jamvm:reg vm jamvm:+a0+)))
                    (setf trace-idx (mod (1+ trace-idx) 30))

                    (cond
                      ;; Continue
                      ((null result) nil)

                      ;; Host call
                      ((eq result :host-call)
                       (incf host-calls)
                       (let* ((hc-id (jamvm:pvm-exit-arg vm))
                              (hc-result (jam-host::host-dispatch vm ctx hc-id)))
                         ;; Record host call in trace
                         (setf (aref trace-ring (mod (1- trace-idx) 30))
                               (append (aref trace-ring (mod (1- trace-idx) 30))
                                       (list :hc-id hc-id :hc-result hc-result)))
                         (case hc-result
                           (:continue
                            (jamvm::vm-advance-past-ecalli vm)
                            (setf (jamvm:pvm-status vm) nil))
                           (:oog
                            (format t "~%  HOST CALL OOG at step ~D, HC#~D~%" total-steps hc-id)
                            (return))
                           (t
                            (format t "~%  HOST CALL result=~A at step ~D, HC#~D~%" hc-result total-steps hc-id)
                            (return)))))

                      ;; Page fault
                      ((eq result :page-fault)
                       (format t "~%  PAGE FAULT at step ~D, addr=0x~X~%" total-steps (jamvm:pvm-exit-arg vm))
                       (return))

                      ;; Panic
                      ((eq result :panic)
                       (format t "~%  *** PANIC at step ~D, PC=~D ***~%" total-steps pc)
                       ;; Decode the instruction at fault PC
                       (handler-case
                           (let ((inst (jamvm:decode-instruction vm pc)))
                             (format t "  Instruction at PC ~D: ~A~%" pc inst))
                         (error (e) (format t "  Could not decode: ~A~%" e)))
                       (format t "  Regs: A0=~D A1=~D SP=~D~%"
                               (jamvm:reg vm jamvm:+a0+)
                               (jamvm:reg vm jamvm:+a1+)
                               (jamvm:reg vm jamvm:+sp+))
                       (return))

                      ;; Halt
                      ((eq result :halt)
                       (format t "~%  HALT at step ~D, A0=~D~%" total-steps (jamvm:reg vm jamvm:+a0+))
                       (return))

                      ;; OOG
                      ((eq result :oog)
                       (format t "~%  OOG at step ~D~%" total-steps)
                       (return))

                      (t
                       (format t "~%  UNKNOWN result ~A at step ~D~%" result total-steps)
                       (return)))))

                ;; Print ring buffer
                (format t "~%  ─── Last ~D instructions before exit ───~%" 30)
                (format t "  Total steps: ~D, Host calls: ~D~%" total-steps host-calls)
                (format t "  Final PC=~D gas=~D~%" (jamvm:pvm-pc vm) (jamvm:pvm-gas vm))
                (dotimes (i 30)
                  (let ((entry (aref trace-ring (mod (+ trace-idx i) 30))))
                    (when entry
                      (format t "    ~A~%" entry))))))))))))

(format t "~%Done.~%")
(sb-ext:exit :code 0)
