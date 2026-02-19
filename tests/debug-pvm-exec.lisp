;;;; debug-pvm-exec.lisp — Trace PVM execution for a specific block
(in-package :jotl)

(defun debug-block-6 ()
  (let* ((dir "tests/jamtestvectors/traces/storage_light/")
         (step-path (trace-block-path dir 6))
         (bytes (alexandria:read-file-into-byte-vector step-path)))
    (multiple-value-bind (pre-sigma block-cl post-sigma)
        (decode-trace-step-bin bytes)
      (declare (ignore post-sigma))
      (let* ((h (funcall block-cl :header))
             (rho (funcall pre-sigma :load :rho))
             (e-a (funcall block-cl :assurances))
             (rho-dd (funcall rho :transition-ddagger
                              :assurances e-a
                              :tau-prime (make-tau-state :slot (funcall h :slot))
                              :parent-hash (funcall h :parent-hash)
                              :kappa (funcall pre-sigma :load :kappa)))
             (reported (funcall rho-dd :reported))
             (first-report (first reported))
             (first-result (first (getf first-report :results)))
             (sid (getf first-result :service-id))
             (svc-data (classify-service-sub-keys sid (funcall pre-sigma :extra-kvs)))
             (code-blob (getf svc-data :code-blob))
             (metadata (getf svc-data :metadata))
             (vm (jamvm:make-vm (coerce code-blob
                                        '(simple-array (unsigned-byte 8) (*))))))
        (unless vm
          (format t "make-vm returned NIL~%")
          (return-from debug-block-6))
        
        (format t "VM created. code=~D bitmask=~D jump-table=~D~%"
                (length (jamvm:pvm-code vm))
                (length (jamvm:pvm-bitmask vm))
                (length (jamvm:pvm-jump-table vm)))

        ;; Build host context
        (let* ((items (list (jam-host:encode-work-item-record
                             (getf (getf first-report :package-spec) :hash)
                             (getf (getf first-report :package-spec) :exports-root)
                             (getf first-report :authorizer-hash)
                             (getf first-result :payload-hash)
                             (or (getf first-result :accumulate-gas) 0)
                             0 (getf (getf first-result :result) :ok)
                             (getf first-report :auth-output))))
               (params (jam-host:encode-accumulate-params
                        (funcall h :slot) sid (length items)))
               ;; Build host context
               (ctx (jam-host:populate-host-context
                     :invocation jam-host:+ctx-accumulate+
                     :service-id sid
                     :balance (or (getf metadata :balance) 0)
                     :timeslot (funcall h :slot)
                     :code-hash (or (getf metadata :code-hash)
                                    (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
                     :min-accum-gas (or (getf metadata :min-accum-gas) 0)
                     :min-memo-gas (or (getf metadata :min-memo-gas) 0)
                     :items-count (or (getf metadata :items) 0)
                     :footprint (or (getf metadata :bytes) 0)
                     :storage (getf svc-data :storage)
                     :preimages (getf svc-data :preimages)
                     :accumulate-items items)))

          ;; Set debug trace
          (setf (jam-host:hctx-debug-trace ctx) t)
          
          ;; invoke
          (multiple-value-bind (ok reason)
              (jamvm:argument-invoke vm 20000000 jamvm:+pc-accumulate+ params)
            (format t "invoke: ok=~A reason=~A~%" ok reason)
            (format t "  pc=~D gas=~D SP=~X A0=~D A1=~D~%"
                    (jamvm:pvm-pc vm) (jamvm:pvm-gas vm)
                    (jamvm:reg vm jamvm:+sp+)
                    (jamvm:reg vm jamvm:+a0+)
                    (jamvm:reg vm jamvm:+a1+))

            (when ok
              ;; Run with host-call handling
              (format t "~%Running with host-call handling...~%")
              (handler-case
                  (multiple-value-bind (exit-status exit-arg final-ctx)
                      (jam-host:host-run vm ctx)
                    (declare (ignore final-ctx))
                    (format t "  exit: ~A arg=~A~%" exit-status exit-arg)
                    (format t "  gas-remain=~D~%" (jamvm:pvm-gas vm))
                    (format t "  A0=~D A1=~D~%"
                            (jamvm:reg vm jamvm:+a0+) (jamvm:reg vm jamvm:+a1+))
                    ;; Show host-call log
                    (let ((hclog (jam-host:hctx-host-call-log ctx)))
                      (format t "  Host calls: ~D~%" (length hclog))
                      (dolist (entry (reverse hclog))
                        (format t "    id=~D gas=~D->~D A0=~D~%"
                                (first entry) (second entry) (third entry) (fourth entry)))))
                (error (e)
                  (format t "  ERROR: ~A (~A)~%" e (type-of e))
                  ;; Still show host-call log
                  (let ((hclog (jam-host:hctx-host-call-log ctx)))
                    (format t "  Host calls before error: ~D~%" (length hclog))
                    (dolist (entry (reverse hclog))
                      (format t "    id=~D gas=~D->~D A0=~D~%"
                              (first entry) (second entry) (third entry) (fourth entry)))))))))))))

(debug-block-6)
(format t "~%Done.~%")
(uiop:quit)
