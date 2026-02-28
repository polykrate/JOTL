;;; diag-pvm-svc0-pass.lisp — Run a PASSING trace and trace service 0

(in-package #:jotl)

(defvar *target-sid* 0)

(defun svc0p-trace-dir (trace-id)
  (let ((base (asdf:system-source-directory :jotl)))
    (merge-pathnames
     (format nil "../jam-conformance/fuzz-reports/0.7.2/traces/~A/" trace-id)
     base)))

(defun svc0p-run (trace-id step)
  (format t "~%=== SVC0 PASS TRACE: ~A / ~A ===~%" trace-id step)
  (let* ((dir (svc0p-trace-dir trace-id))
         (step-path (merge-pathnames (format nil "~A.bin" step) dir))
         (bytes (alexandria:read-file-into-byte-vector step-path)))
    (multiple-value-bind (pre-sigma block-cl post-sigma)
        (decode-trace-step-bin bytes)
      (declare (ignore post-sigma))
      
      (let ((header (funcall block-cl :header)))
        (format t "Block slot: ~D~%" (funcall header :slot)))

      ;; Wrap accumulate-service 
      (let ((orig-accum-svc (fdefinition 'accumulate-service))
            (orig-dispatch (fdefinition 'jam-host::host-dispatch)))
        (unwind-protect
             (progn
               ;; HC tracer for service 0
               (setf (fdefinition 'jam-host::host-dispatch)
                     (lambda (vm ctx id)
                       (let ((sid (jam-host::hctx-service-id ctx)))
                         (if (= sid *target-sid*)
                             (let* ((a0 (jamvm:reg vm jamvm:+a0+))
                                    (a1 (jamvm:reg vm jamvm:+a1+))
                                    (a2 (jamvm:reg vm jamvm:+a2+))
                                    (a3 (jamvm:reg vm jamvm:+a3+))
                                    (result (funcall orig-dispatch vm ctx id))
                                    (a0-after (jamvm:reg vm jamvm:+a0+)))
                               (format t "  HC~D: a0=~D a1=~D a2=~D a3=~D → a0=~D~%"
                                       id a0 a1 a2 a3 a0-after)
                               result)
                             (funcall orig-dispatch vm ctx id)))))

               (setf (fdefinition 'accumulate-service)
                     (lambda (sid items gas-limit state &key (transfer-balance 0) (svc-transfers nil))
                       (when (= sid *target-sid*)
                         (format t "~%[ACCUM-SVC] sid=~D items=~D gas=~D xfer-bal=~D xfers=~D~%"
                                 sid (length items) gas-limit transfer-balance (length svc-transfers)))
                       (multiple-value-bind (effects gas-used)
                           (funcall orig-accum-svc sid items gas-limit state
                                    :transfer-balance transfer-balance
                                    :svc-transfers svc-transfers)
                         (when (= sid *target-sid*)
                           (format t "  → outcome=~A gas-used=~D last-pc=~A~%"
                                   (when effects (getf effects :outcome))
                                   gas-used jamvm:*vm-last-step-pc*))
                         (values effects gas-used))))

               ;; Run
               (let ((*chain-log-level* nil)
                     (*debug-pvm-trace* nil))
                 (import-block pre-sigma block-cl)))

          ;; Restore
          (setf (fdefinition 'accumulate-service) orig-accum-svc)
          (setf (fdefinition 'jam-host::host-dispatch) orig-dispatch))))))

;; Try a few passing traces
(dolist (trace '("1766241814" "1766241867" "1766242639" "1766243176"))
  (let* ((dir (svc0p-trace-dir trace))
         (steps (directory (merge-pathnames "*.bin" dir))))
    (dolist (s steps)
      (let ((step-name (pathname-name s)))
        (handler-case (svc0p-run trace step-name)
          (error (e) (format t "ERROR: ~A~%" e)))))))

(sb-ext:exit :code 0)
