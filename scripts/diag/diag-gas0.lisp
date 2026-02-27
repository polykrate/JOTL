;;;; diag/diag-gas0.lisp — Trace gas accounting for service 0 in trace 2

(in-package :jotl)

(defvar *dg-trace-id* "1767896003_7770")
(defvar *dg-step* "00000033")
(defvar *dg-target-sid* 0)

(defun dg-trace-dir ()
  (merge-pathnames (format nil "../jam-conformance/fuzz-reports/0.7.2/traces/~A/"
                           *dg-trace-id*)
                   (truename (asdf:system-source-directory :jotl))))

(defun dg-run ()
  (format t "~%=== GAS DIAGNOSTIC for sid ~D ===~%" *dg-target-sid*)
  (format t "Trace: ~A  Step: ~A~%" *dg-trace-id* *dg-step*)

  (let* ((step-path (merge-pathnames (format nil "~A.bin" *dg-step*)
                                     (dg-trace-dir)))
         (bytes (alexandria:read-file-into-byte-vector step-path)))
    (multiple-value-bind (pre-sigma block-cl post-sigma)
        (decode-trace-step-bin bytes)
      (declare (ignore post-sigma))

      ;; Intercept to trace gas for service 0
      (let ((orig-accum (fdefinition 'accumulate-service))
            (orig-pvm (fdefinition 'jam-host:lisp-pvm-run-accumulate))
            (orig-dispatch (fdefinition 'jam-host::host-dispatch)))

        (unwind-protect
            (progn
              ;; Wrap accumulate-service
              (setf (fdefinition 'accumulate-service)
                    (lambda (service-id items gas-limit state
                             &key (transfer-balance 0) (svc-transfers nil))
                      (when (= service-id *dg-target-sid*)
                        (format t "~%[ACCUM-SVC] sid=~D gas-limit=~D xfer-balance=~D~%"
                                service-id gas-limit transfer-balance)
                        (format t "  work-items=~D svc-transfers=~D~%"
                                (length items) (length svc-transfers))
                        (when svc-transfers
                          (dolist (xfer svc-transfers)
                            (format t "  xfer: sender=~D amount=~D gas-limit=~D~%"
                                    (getf xfer :sender) (getf xfer :amount)
                                    (getf xfer :gas-limit)))))
                      (multiple-value-bind (effects gas-used)
                          (funcall orig-accum service-id items gas-limit state
                                   :transfer-balance transfer-balance
                                   :svc-transfers svc-transfers)
                        (when (= service-id *dg-target-sid*)
                          (format t "  => gas-used=~D outcome=~A~%"
                                  gas-used (when effects (getf effects :outcome)))
                          (format t "  => gas-remaining=~A~%"
                                  (when effects (getf effects :gas-remaining))))
                        (values effects gas-used))))

              ;; Wrap host-dispatch to trace ACTUAL gas for target service
              (setf (fdefinition 'jam-host::host-dispatch)
                    (lambda (vm ctx id)
                      (let ((gas-before (jamvm:pvm-gas vm))
                            (is-target (= (jam-host::hctx-service-id ctx)
                                          *dg-target-sid*))
                            (a0-before (jamvm:reg vm jamvm:+a0+))
                            (a1-before (jamvm:reg vm jamvm:+a1+))
                            (a2-before (jamvm:reg vm jamvm:+a2+))
                            (a3-before (jamvm:reg vm jamvm:+a3+)))
                        (let ((result (funcall orig-dispatch vm ctx id)))
                          (when is-target
                            (let ((gas-after (jamvm:pvm-gas vm))
                                  (a0-after (jamvm:reg vm jamvm:+a0+)))
                              (format t "  [HC~D] gas ~D→~D (Δ=~D) a0=~D→~D ~@[a1=~D ~]~@[a2=~D ~]~@[a3=~D ~]~A~%"
                                      id gas-before gas-after
                                      (- gas-before gas-after)
                                      a0-before a0-after
                                      (when (member id '(20 18 1)) a1-before)
                                      (when (member id '(20)) a2-before)
                                      (when (member id '(20)) a3-before)
                                      result)))
                          result))))

              ;; Wrap lisp-pvm-run-accumulate
              (setf (fdefinition 'jam-host:lisp-pvm-run-accumulate)
                    (lambda (code-blob service-id balance timeslot &rest keys)
                      (when (= service-id *dg-target-sid*)
                        (format t "~%[PVM-RUN] sid=~D bal=~D ts=~D gas=~D~%"
                                service-id balance timeslot (getf keys :gas)))
                      (multiple-value-bind (effects gas-used)
                          (apply orig-pvm code-blob service-id balance timeslot keys)
                        (when (= service-id *dg-target-sid*)
                          (format t "  [PVM-RESULT] gas-used=~D outcome=~D gas-rem=~A~%"
                                  gas-used
                                  (when effects (getf effects :outcome))
                                  (when effects (getf effects :gas-remaining))))
                        (values effects gas-used))))

              ;; Run
              (let ((*chain-log-level* nil)
                    (*debug-pvm-trace* nil)
                    (*debug-pvm-traces* nil))
                (import-block pre-sigma block-cl)))

          ;; Restore
          (setf (fdefinition 'jam-host::host-dispatch) orig-dispatch
                (fdefinition 'accumulate-service) orig-accum
                (fdefinition 'jam-host:lisp-pvm-run-accumulate) orig-pvm))))))

(dg-run)
(format t "~%Done.~%")
(sb-ext:exit :code 0)
