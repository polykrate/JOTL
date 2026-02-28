;;; diag-pvm-svc0b.lisp — Deep PVM trace with instruction decoding
;;; Focus: understand why trap at pc=97133 and where the branch diverges

(in-package #:jotl)

(defvar *ring-buf* nil)
(defvar *ring-idx* 0)
(defvar *ring-size* 500)
(defvar *target-sid* 0)

(defun svc0b-trace-dir (trace-id)
  (let ((base (asdf:system-source-directory :jotl)))
    (merge-pathnames
     (format nil "../jam-conformance/fuzz-reports/0.7.2/traces/~A/" trace-id)
     base)))

(defun svc0b-run (trace-id step)
  (format t "~%=== PVM SVC0 DEEP TRACE: ~A / ~A ===~%" trace-id step)
  (let* ((dir (svc0b-trace-dir trace-id))
         (step-path (merge-pathnames (format nil "~A.bin" step) dir))
         (bytes (alexandria:read-file-into-byte-vector step-path)))
    (multiple-value-bind (pre-sigma block-cl post-sigma)
        (decode-trace-step-bin bytes)
      (declare (ignore post-sigma))

      ;; Block info
      (let ((header (funcall block-cl :header)))
        (format t "Block slot: ~D~%" (funcall header :slot)))

      ;; Wrap vm-step to record decoded instruction in ring buffer
      (let ((orig-vm-step (fdefinition 'jamvm:vm-step))
            (orig-dispatch (fdefinition 'jam-host::host-dispatch)))

        (unwind-protect
             (progn
               ;; Intercept vm-step: record decoded instruction
               (setf (fdefinition 'jamvm:vm-step)
                     (lambda (vm)
                       (when *ring-buf*
                         (let ((pc (jamvm:pvm-pc vm)))
                           (setf jamvm:*vm-last-step-pc* pc)
                           ;; Decode instruction
                           (multiple-value-bind (info skip args)
                               (jamvm:decode-instruction vm pc)
                             (let ((entry (vector
                                           pc
                                           (jamvm:pvm-gas vm)
                                           (if info (jamvm::opi-name info) :unknown)
                                           skip
                                           ;; Capture relevant registers
                                           (jamvm:reg vm jamvm:+a0+)
                                           (jamvm:reg vm jamvm:+a1+)
                                           (jamvm:reg vm jamvm:+a2+)
                                           (jamvm:reg vm jamvm:+a3+)
                                           (jamvm:reg vm jamvm:+a4+)
                                           (jamvm:reg vm jamvm:+a5+)
                                           ;; Also capture other registers for branching
                                           (jamvm:reg vm jamvm:+s0+)
                                           (jamvm:reg vm jamvm:+s1+)
                                           (jamvm:reg vm jamvm:+t0+)
                                           (jamvm:reg vm jamvm:+t1+)
                                           (jamvm:reg vm jamvm:+t2+)
                                           ;; Immediate if any
                                           (when args (jamvm::arg-imm args)))))
                               (setf (aref *ring-buf* (mod *ring-idx* *ring-size*)) entry)
                               (incf *ring-idx*)))))
                       ;; Call original
                       (funcall orig-vm-step vm)))

               ;; Intercept host-dispatch for HC logging
               (setf (fdefinition 'jam-host::host-dispatch)
                     (lambda (vm ctx id)
                       (let ((sid (jam-host::hctx-service-id ctx)))
                         (if (= sid *target-sid*)
                             (let* ((a0 (jamvm:reg vm jamvm:+a0+))
                                    (a1 (jamvm:reg vm jamvm:+a1+))
                                    (a2 (jamvm:reg vm jamvm:+a2+))
                                    (result (funcall orig-dispatch vm ctx id))
                                    (a0-after (jamvm:reg vm jamvm:+a0+)))
                               (format t "  HC~D: a0=~D a1=~D a2=~D → a0=~D result=~A~%"
                                       id a0 a1 a2 a0-after result)
                               result)
                             (funcall orig-dispatch vm ctx id)))))

               ;; Wrap accumulate-service for target
               (let ((orig-accum-svc (fdefinition 'accumulate-service)))
                 (unwind-protect
                      (progn
                        (setf (fdefinition 'accumulate-service)
                              (lambda (sid items gas-limit state &key (transfer-balance 0) (svc-transfers nil))
                                (if (= sid *target-sid*)
                                    (progn
                                      (setf *ring-buf* (make-array *ring-size* :initial-element nil)
                                            *ring-idx* 0)
                                      (setf jamvm:*vm-trap-log* nil)
                                      (multiple-value-bind (effects gas-used)
                                          (funcall orig-accum-svc sid items gas-limit state
                                                   :transfer-balance transfer-balance
                                                   :svc-transfers svc-transfers)
                                        ;; Report
                                        (format t "~%--- RESULT: outcome=~A gas-used=~D last-pc=~A ---~%"
                                                (when effects (getf effects :outcome))
                                                gas-used jamvm:*vm-last-step-pc*)

                                        ;; Trap log
                                        (when jamvm:*vm-trap-log*
                                          (format t "~%  TRAP LOG:~%")
                                          (dolist (tl (reverse jamvm:*vm-trap-log*))
                                            (format t "    ~A~%" tl)))

                                        ;; Ring buffer: last 100 instructions
                                        (let ((total (min *ring-idx* *ring-size*))
                                              (start (max 0 (- *ring-idx* *ring-size*))))
                                          (format t "~%  Total instructions: ~D~%" *ring-idx*)
                                          ;; Show last 100
                                          (let ((show-start (max start (- *ring-idx* 100))))
                                            (format t "  Last ~D instructions:~%"
                                                    (- *ring-idx* show-start))
                                            (loop for abs-i from show-start below *ring-idx*
                                                  do (let ((e (aref *ring-buf* (mod abs-i *ring-size*))))
                                                       (when e
                                                         (format t "    [~6D] pc=~6D gas=~8D ~12A skip=~D a0=~D a1=~D s0=~D s1=~D t0=~D~%"
                                                                 abs-i
                                                                 (aref e 0) (aref e 1)
                                                                 (aref e 2) (aref e 3)
                                                                 (aref e 4) (aref e 5)
                                                                 (aref e 10) (aref e 11)
                                                                 (aref e 12)))))))

                                        (setf *ring-buf* nil)
                                        (values effects gas-used)))
                                    (funcall orig-accum-svc sid items gas-limit state
                                             :transfer-balance transfer-balance
                                             :svc-transfers svc-transfers))))

                        ;; Run
                        (let ((*chain-log-level* nil)
                              (*debug-pvm-trace* nil))
                          (import-block pre-sigma block-cl)))

                   ;; Restore accumulate-service
                   (setf (fdefinition 'accumulate-service) orig-accum-svc))))

          ;; Restore
          (setf (fdefinition 'jamvm:vm-step) orig-vm-step)
          (setf (fdefinition 'jam-host::host-dispatch) orig-dispatch))))))

(svc0b-run "1766479507_7943" "00000018")
(sb-ext:exit :code 0)
