;;; diag-flow-trace.lisp — Trace control flow for service 0 to find why HC17 is skipped
(in-package #:jotl)

(defvar *target-sid* 0)
(defvar *hc17-pcs* '(41816 45599 45607))

(defun dft-trace-dir (trace-id)
  (let ((base (asdf:system-source-directory :jotl)))
    (merge-pathnames
     (format nil "../jam-conformance/fuzz-reports/0.7.2/traces/~A/" trace-id)
     base)))

(defun dft-run (trace-id step)
  (format t "~%=== FLOW TRACE: ~A / ~A ===~%" trace-id step)
  (let* ((dir (dft-trace-dir trace-id))
         (step-path (merge-pathnames (format nil "~A.bin" step) dir))
         (bytes (alexandria:read-file-into-byte-vector step-path)))
    (multiple-value-bind (pre-sigma block-cl post-sigma)
        (decode-trace-step-bin bytes)
      (declare (ignore post-sigma))

      (let ((orig-vm-step (fdefinition 'jamvm:vm-step))
            (orig-dispatch (fdefinition 'jam-host::host-dispatch))
            (orig-accum-svc (fdefinition 'accumulate-service))
            (all-hc-calls nil)  ;; list of (instruction-count pc hc-id a0 a1 a2 a3 a4 a5)
            (instruction-count 0)
            (hit-hc17-pcs nil)
            (first-50-instrs nil))

        (unwind-protect
             (progn
               ;; Intercept vm-step to track instruction count and first 50 instructions
               (setf (fdefinition 'jamvm:vm-step)
                     (lambda (vm)
                       (let ((pc (jamvm:pvm-pc vm)))
                         (setf jamvm:*vm-last-step-pc* pc)
                         (incf instruction-count)
                         ;; Log first 50 instructions
                         (when (<= instruction-count 50)
                           (handler-case
                               (multiple-value-bind (info skip args)
                                   (jamvm:decode-instruction vm pc)
                                 (declare (ignore args))
                                 (push (list instruction-count pc
                                             (if info (jamvm::opi-name info) :unknown)
                                             skip (jamvm:pvm-gas vm))
                                       first-50-instrs))
                             (error () nil)))
                         ;; Check if we're passing through HC17 PCs
                         (when (member pc *hc17-pcs*)
                           (push (list instruction-count pc) hit-hc17-pcs)))
                       (funcall orig-vm-step vm)))

               ;; Intercept host-dispatch to log ALL host calls
               (setf (fdefinition 'jam-host::host-dispatch)
                     (lambda (vm ctx id)
                       (let ((sid (jam-host::hctx-service-id ctx)))
                         (when (= sid *target-sid*)
                           (push (list :n instruction-count
                                       :pc (or jamvm:*vm-last-step-pc* 0)
                                       :hc id
                                       :a0 (jamvm:reg vm 7)
                                       :a1 (jamvm:reg vm 8)
                                       :a2 (jamvm:reg vm 9)
                                       :a3 (jamvm:reg vm 10)
                                       :a4 (jamvm:reg vm 11)
                                       :a5 (jamvm:reg vm 12))
                                 all-hc-calls)))
                       (funcall orig-dispatch vm ctx id)))

               ;; Wrap accumulate-service
               (setf (fdefinition 'accumulate-service)
                     (lambda (sid items gas-limit state &key (transfer-balance 0) (svc-transfers nil))
                       (if (= sid *target-sid*)
                           (progn
                             (setf all-hc-calls nil
                                   instruction-count 0
                                   hit-hc17-pcs nil
                                   first-50-instrs nil)
                             (multiple-value-bind (effects gas-used)
                                 (funcall orig-accum-svc sid items gas-limit state
                                          :transfer-balance transfer-balance
                                          :svc-transfers svc-transfers)

                               ;; Print first 50 instructions
                               (format t "~%--- First 50 instructions from PC=5 ---~%")
                               (dolist (instr (nreverse first-50-instrs))
                                 (format t "  [~6D] pc=~6D ~15A skip=~D gas=~D~%"
                                         (first instr) (second instr) (third instr)
                                         (fourth instr) (fifth instr)))

                               ;; Print HC17 PC hits
                               (format t "~%--- HC17 PC hits ---~%")
                               (if hit-hc17-pcs
                                   (dolist (hit (nreverse hit-hc17-pcs))
                                     (format t "  Hit HC17 PC=~D at instruction ~D~%" (second hit) (first hit)))
                                   (format t "  NO HC17 PCs were visited!~%"))

                               ;; Print ALL host calls in order
                               (format t "~%--- ALL host calls for service ~D ---~%" *target-sid*)
                               (format t "Total: ~D host calls, ~D instructions~%" (length all-hc-calls) instruction-count)
                               (dolist (hc (nreverse all-hc-calls))
                                 (format t "  [~6D] pc=~6D HC~D a0=~D a1=~D a2=~D a3=~D a4=~D a5=~D~%"
                                         (getf hc :n) (getf hc :pc) (getf hc :hc)
                                         (getf hc :a0) (getf hc :a1) (getf hc :a2)
                                         (getf hc :a3) (getf hc :a4) (getf hc :a5)))

                               ;; Print outcome
                               (format t "~%--- RESULT ---~%")
                               (format t "  outcome=~A gas-used=~D total-instructions=~D~%"
                                       (when effects (getf effects :outcome)) gas-used instruction-count)

                               (values effects gas-used)))
                           (funcall orig-accum-svc sid items gas-limit state
                                    :transfer-balance transfer-balance
                                    :svc-transfers svc-transfers))))

               (let ((*chain-log-level* nil)
                     (*debug-pvm-trace* nil))
                 (import-block pre-sigma block-cl)))

          ;; Restore
          (setf (fdefinition 'jamvm:vm-step) orig-vm-step
                (fdefinition 'jam-host::host-dispatch) orig-dispatch
                (fdefinition 'accumulate-service) orig-accum-svc))))))

(dft-run "1766479507_7943" "00000018")
(sb-ext:exit :code 0)
