(in-package #:jotl)

(defun di-trace-dir (trace-id)
  (merge-pathnames
   (format nil "../jam-conformance/fuzz-reports/0.7.2/traces/~A/" trace-id)
   (truename (asdf:system-source-directory :jotl))))

(defun di-run-trace (trace-id step)
  (format t "~%=== IOTA DIAG: ~A / ~A ===~%" trace-id step)
  (let* ((dir (di-trace-dir trace-id))
         (path (merge-pathnames (format nil "~A.bin" step) dir))
         (bytes (alexandria:read-file-into-byte-vector path)))
    (multiple-value-bind (pre-sigma block-cl post-sigma)
        (decode-trace-step-bin bytes)
      (declare (ignore post-sigma))

      ;; Wrap host-run to trace raw exit status
      (let ((orig-host-run (fdefinition 'jam-host::host-run))
            (orig-pvm-run (fdefinition 'jam-host:lisp-pvm-run-accumulate)))
        (unwind-protect
             (progn
               ;; Wrap host-run to see raw exit status
               (setf (fdefinition 'jam-host::host-run)
                     (lambda (vm ctx)
                       (let ((sid (jam-host::hctx-service-id ctx)))
                         (multiple-value-bind (status exit-arg final-ctx)
                             (funcall orig-host-run vm ctx)
                           (when (= sid 0)
                             (format t "[HOST-RUN] sid=0 raw-exit=~A exit-arg=~A gas=~D pc=~D last-pc=~A~%"
                                     status exit-arg (jamvm:pvm-gas vm) (jamvm:pvm-pc vm)
                                     jamvm:*vm-last-step-pc*))
                         (when (and (= sid 0) (eq status :panic))
                           ;; Show what instruction was at last-pc
                           (let ((last-pc jamvm:*vm-last-step-pc*))
                             (when last-pc
                               (let ((code (jamvm:pvm-code vm)))
                                 (when (< last-pc (length code))
                                   (format t "  opcode-at-panic-pc=~D (0x~2,'0X)~%"
                                           (aref code last-pc) (aref code last-pc)))))))

                           (values status exit-arg final-ctx)))))

               ;; Also trace the PVM outcome
               (setf (fdefinition 'jam-host:lisp-pvm-run-accumulate)
                     (lambda (code-blob service-id balance timeslot &rest keys)
                       (multiple-value-bind (effects gas-used)
                           (apply orig-pvm-run code-blob service-id balance timeslot keys)
                         (when (= service-id 0)
                           (format t "[PVM-RESULT] sid=0 outcome=~A gas-used=~D~%"
                                   (when effects (getf effects :outcome))
                                   gas-used)
                           (format t "  empower=~A desig=~A~%"
                                   (if (and effects (getf effects :empower)) "YES" "nil")
                                   (if (and effects (getf effects :designated-validators))
                                       (length (getf effects :designated-validators))
                                       "nil")))
                         (values effects gas-used))))

               (let ((*chain-log-level* nil)
                     (jamvm::*djump-debug* t))
                 (handler-case
                     (import-block pre-sigma block-cl)
                   (error (e)
                     (format t "ERROR: ~A~%" e)))))
          ;; Restore
          (setf (fdefinition 'jam-host::host-run) orig-host-run)
          (setf (fdefinition 'jam-host:lisp-pvm-run-accumulate) orig-pvm-run))))))

(defun di-run ()
  (di-run-trace "1766243861_7323" "00000024")
  (format t "~%========================================~%")
  (di-run-trace "1766479507_7943" "00000018"))

(di-run)
