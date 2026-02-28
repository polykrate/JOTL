;;; diag-poststate-cmp.lisp — Compare expected vs actual post-state for service 0
(in-package #:jotl)

(defvar *target-sid* 0)

(defun dpc-trace-dir (trace-id)
  (let ((base (asdf:system-source-directory :jotl)))
    (merge-pathnames
     (format nil "../jam-conformance/fuzz-reports/0.7.2/traces/~A/" trace-id)
     base)))

(defun dpc-run (trace-id step)
  (format t "~%=== POST-STATE COMPARE: ~A / ~A ===~%" trace-id step)
  (let* ((dir (dpc-trace-dir trace-id))
         (step-path (merge-pathnames (format nil "~A.bin" step) dir))
         (bytes (alexandria:read-file-into-byte-vector step-path)))
    (multiple-value-bind (pre-sigma block-cl post-sigma)
        (decode-trace-step-bin bytes)

      (let ((header (funcall block-cl :header)))
        (format t "Block slot: ~D~%" (funcall header :slot)))

      ;; --- Expected post-state ---
      (format t "~%--- EXPECTED POST-STATE (svc ~D) ---~%" *target-sid*)
      (let* ((exp-delta (funcall post-sigma :load :delta))
             (exp-svc (funcall exp-delta :service-data *target-sid*))
             (exp-meta (getf exp-svc :metadata)))
        (if exp-meta
            (format t "  balance:     ~D~%  gas-limit:   ~D~%  min-gas:     ~D~%  items-count: ~D~%  items-size:  ~D~%"
                    (getf exp-meta :balance) (getf exp-meta :gas-limit-policy)
                    (getf exp-meta :min-accum-gas) (getf exp-meta :items-count) (getf exp-meta :items-size))
            (format t "  Service ~D NOT FOUND~%" *target-sid*)))

      ;; --- JOTL-computed post-state ---
      (format t "~%--- COMPUTING JOTL POST-STATE ---~%")
      (let* ((orig-accum-svc (fdefinition 'accumulate-service))
             (wrapper (lambda (sid items gas-limit state &key (transfer-balance 0) (svc-transfers nil))
                        (when (= sid *target-sid*)
                          (format t "[ACCUM-SVC ~D] items=~D gas=~D xfer-bal=~D~%"
                                  sid (length items) gas-limit transfer-balance))
                        (multiple-value-bind (effects gas-used)
                            (funcall orig-accum-svc sid items gas-limit state
                                     :transfer-balance transfer-balance
                                     :svc-transfers svc-transfers)
                          (when (= sid *target-sid*)
                            (format t "  → outcome=~A gas-used=~D~%"
                                    (when effects (getf effects :outcome)) gas-used))
                          (values effects gas-used)))))
        (setf (fdefinition 'accumulate-service) wrapper)
        (unwind-protect
             (let* ((*chain-log-level* nil)
                    (*debug-pvm-trace* nil)
                    (result (import-block pre-sigma block-cl)))
               (format t "~%--- JOTL POST-STATE (svc ~D) ---~%" *target-sid*)
               (let* ((jotl-delta (funcall result :load :delta))
                      (jotl-svc (funcall jotl-delta :service-data *target-sid*))
                      (jotl-meta (getf jotl-svc :metadata)))
                 (if jotl-meta
                     (format t "  balance:     ~D~%  gas-limit:   ~D~%  min-gas:     ~D~%  items-count: ~D~%  items-size:  ~D~%"
                             (getf jotl-meta :balance) (getf jotl-meta :gas-limit-policy)
                             (getf jotl-meta :min-accum-gas) (getf jotl-meta :items-count) (getf jotl-meta :items-size))
                     (format t "  Service ~D NOT FOUND~%" *target-sid*)))

               ;; Compare components
               (dolist (comp '(:pi :iota :delta))
                 (format t "~%--- ~A COMPARISON ---~%" comp)
                 (let* ((exp-cl (funcall post-sigma :load comp))
                        (jotl-cl (funcall result :load comp))
                        (exp-bytes (funcall exp-cl :save))
                        (jotl-bytes (funcall jotl-cl :save)))
                   (format t "  expected: ~D bytes  JOTL: ~D bytes → ~A~%"
                           (length exp-bytes) (length jotl-bytes)
                           (if (equalp exp-bytes jotl-bytes) "MATCH" "MISMATCH")))))
          (setf (fdefinition 'accumulate-service) orig-accum-svc))))))

(dpc-run "1766479507_7943" "00000018")
(sb-ext:exit :code 0)
