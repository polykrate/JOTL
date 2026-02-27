;;; diag-pvm-deep.lisp — Deep PVM trace for service 3953987607
;;; Goal: understand why it panics instead of yielding
;;; Strategy: trace HC1 result + last 200 instructions before panic

(in-package #:jotl)

(defvar *ring-buf* nil)
(defvar *ring-idx* 0)
(defvar *ring-size* 200)
(defvar *target-sid* 3953987607)
(defvar *hc-log* nil)

(defun dpd-trace-dir (trace-id)
  (let ((base (asdf:system-source-directory :jotl)))
    (merge-pathnames
     (format nil "../jam-conformance/fuzz-reports/0.7.2/traces/~A/" trace-id)
     base)))

(defun dpd-run (trace-id step)
  (format t "~%=== PVM DEEP TRACE: ~A / ~A sid=~D ===~%" trace-id step *target-sid*)
  (let* ((dir (dpd-trace-dir trace-id))
         (step-path (merge-pathnames (format nil "~A.bin" step) dir))
         (bytes (alexandria:read-file-into-byte-vector step-path)))
    (multiple-value-bind (pre-sigma block-cl post-sigma)
        (decode-trace-step-bin bytes)
      (declare (ignore post-sigma))

      ;; Block info
      (let ((header (funcall block-cl :header)))
        (format t "Block slot: ~D~%" (funcall header :timeslot)))

      ;; Wrap host-dispatch to log HC calls for target
      (let ((orig-dispatch (fdefinition 'jam-host::host-dispatch))
            (orig-vm-step  (fdefinition 'jamvm:vm-step)))

        (unwind-protect
             (progn
               ;; Intercept host-dispatch
               (setf (fdefinition 'jam-host::host-dispatch)
                     (lambda (vm ctx id)
                       (let ((sid (jam-host::hctx-service-id ctx)))
                         (if (= sid *target-sid*)
                             (let* ((gas-before (jamvm:pvm-gas vm))
                                    (a0-before (jamvm:reg vm jamvm:+a0+))
                                    (a1-before (jamvm:reg vm jamvm:+a1+))
                                    (a2-before (jamvm:reg vm jamvm:+a2+))
                                    (a3-before (jamvm:reg vm jamvm:+a3+))
                                    (a4-before (jamvm:reg vm jamvm:+a4+))
                                    (a5-before (jamvm:reg vm jamvm:+a5+))
                                    (result (funcall orig-dispatch vm ctx id))
                                    (gas-after (jamvm:pvm-gas vm))
                                    (a0-after (jamvm:reg vm jamvm:+a0+)))
                               (push (list :hc id
                                           :gas-before gas-before :gas-after gas-after
                                           :regs-before (list a0-before a1-before a2-before
                                                              a3-before a4-before a5-before)
                                           :a0-after a0-after
                                           :result result)
                                     *hc-log*)
                               result)
                             (funcall orig-dispatch vm ctx id)))))

               ;; Intercept vm-step to record ring buffer for target
               (setf (fdefinition 'jamvm:vm-step)
                     (lambda (vm)
                       (when *ring-buf*
                         (let ((entry (list :pc (jamvm:pvm-pc vm)
                                            :gas (jamvm:pvm-gas vm)
                                            :regs (loop for i from 0 below 13
                                                        collect (jamvm:reg vm i)))))
                           (setf (aref *ring-buf* (mod *ring-idx* *ring-size*)) entry)
                           (incf *ring-idx*)))
                       (setf jamvm:*vm-last-step-pc* (jamvm:pvm-pc vm))
                       (funcall orig-vm-step vm)))

               ;; Wrap accumulate-service for target
               (let ((orig-accum-svc (fdefinition 'accumulate-service)))
                 (unwind-protect
                      (progn
                        (setf (fdefinition 'accumulate-service)
                              (lambda (sid items gas-limit state &key (transfer-balance 0) (svc-transfers nil))
                                (if (= sid *target-sid*)
                                    (progn
                                      (setf *ring-buf* (make-array *ring-size* :initial-element nil)
                                            *ring-idx* 0
                                            *hc-log* nil)
                                      (multiple-value-bind (effects gas-used)
                                          (funcall orig-accum-svc sid items gas-limit state
                                                   :transfer-balance transfer-balance
                                                   :svc-transfers svc-transfers)
                                        ;; Report
                                        (format t "~%--- sid=~D outcome=~D gas-used=~D last-pc=~A ---~%"
                                                sid (when effects (getf effects :outcome))
                                                gas-used jamvm:*vm-last-step-pc*)
                                        (format t "  yield: ~A~%"
                                                (if (and effects (getf effects :yield-output)) "YES" "no"))

                                        ;; HC log
                                        (format t "~%  Host calls (~D):~%" (length *hc-log*))
                                        (dolist (hc (reverse *hc-log*))
                                          (format t "    HC~D: gas ~D→~D (Δ=~D) regs=~{~D~^,~} → a0=~D result=~A~%"
                                                  (getf hc :hc)
                                                  (getf hc :gas-before) (getf hc :gas-after)
                                                  (- (getf hc :gas-before) (getf hc :gas-after))
                                                  (getf hc :regs-before)
                                                  (getf hc :a0-after)
                                                  (getf hc :result)))

                                        ;; Ring buffer: last N instructions before end
                                        (let ((total (min *ring-idx* *ring-size*))
                                              (start (max 0 (- *ring-idx* *ring-size*))))
                                          (format t "~%  Last ~D instructions (of ~D total):~%"
                                                  total *ring-idx*)
                                          ;; Show first 10 and last 30
                                          (when (> total 40)
                                            (format t "    ... (showing first 10 + last 30) ...~%"))
                                          (dotimes (i total)
                                            (let* ((idx (mod (+ start i) *ring-size*))
                                                   (entry (aref *ring-buf* idx)))
                                              (when entry
                                                (let ((abs-i (+ start i)))
                                                  (when (or (< abs-i 10) (>= abs-i (- *ring-idx* 30)))
                                                    (format t "    [~6D] pc=~6D gas=~D a0=~D~%"
                                                            abs-i
                                                            (getf entry :pc)
                                                            (getf entry :gas)
                                                            (first (getf entry :regs)))))))))

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

          ;; Restore host-dispatch + vm-step
          (setf (fdefinition 'jam-host::host-dispatch) orig-dispatch)
          (setf (fdefinition 'jamvm:vm-step) orig-vm-step))))))

(dpd-run "1768066437_3920" "00000012")
(sb-ext:exit :code 0)
