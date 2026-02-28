;;; diag-rstar-detail.lisp — Trace R* origin: immediate vs deferred reports
;;; Shows which work items for service 0 come from current guarantees vs omega queues
(in-package #:jotl)

(defvar *target-sid* 0)

(defun drsd-trace-dir (trace-id)
  (let ((base (asdf:system-source-directory :jotl)))
    (merge-pathnames
     (format nil "../jam-conformance/fuzz-reports/0.7.2/traces/~A/" trace-id)
     base)))

(defun drsd-run (trace-id step)
  (format t "~%=== R* DETAIL: ~A / ~A ===~%" trace-id step)
  (let* ((dir (drsd-trace-dir trace-id))
         (step-path (merge-pathnames (format nil "~A.bin" step) dir))
         (bytes (alexandria:read-file-into-byte-vector step-path)))
    (multiple-value-bind (pre-sigma block-cl post-sigma)
        (decode-trace-step-bin bytes)
      (declare (ignore post-sigma))

      (let ((header (funcall block-cl :header)))
        (format t "Block slot: ~D~%" (funcall header :slot)))

      ;; 1. Show omega queues from pre-state
      (let* ((omega (funcall pre-sigma :load :omega))
             (omega-queues (funcall omega :queues)))
        (format t "~%--- OMEGA QUEUES (pre-state) ---~%")
        (loop for q in omega-queues for i from 0 do
          (when q
            (format t "  slot[~D]: ~D entries~%" i (length q))
            (dolist (entry q)
              (let* ((report (getf entry :report))
                     (deps (getf entry :deps))
                     (pkg-hash (getf (getf report :package-spec) :hash))
                     (results (getf report :results)))
                (format t "    pkg=~{~2,'0X~} deps=~D results=~D~%"
                        (coerce (subseq pkg-hash 0 8) 'list) (length deps) (length results))
                (dolist (w results)
                  (let* ((sid (getf w :service-id))
                         (result (getf w :result))
                         (rk (work-exec-result-kind result))
                         (data (when (getf result :ok) (getf result :ok))))
                    (when (= sid *target-sid*)
                      (format t "      → SVC ~D: rk=~D(~A) data-len=~D first=~{~2,'0X~}~%"
                              sid rk
                              (case rk (0 "OK") (1 "OOG") (2 "PANIC") (t "OTHER"))
                              (if data (length data) 0)
                              (if data
                                  (coerce (subseq data 0 (min 20 (length data))) 'list)
                                  '()))))))))))

      ;; 2. Show current block guarantees
      (let ((guarantees (funcall block-cl :guarantees)))
        (format t "~%--- CURRENT BLOCK GUARANTEES ---~%")
        (format t "~D guarantees~%" (length guarantees))
        (dolist (g guarantees)
          (let* ((report (getf g :report))
                 (pkg-hash (getf (getf report :package-spec) :hash))
                 (results (getf report :results)))
            (format t "  pkg=~{~2,'0X~} results=~D~%"
                    (coerce (subseq pkg-hash 0 8) 'list) (length results))
            (dolist (w results)
              (let* ((sid (getf w :service-id))
                     (result (getf w :result))
                     (rk (work-exec-result-kind result))
                     (data (when (getf result :ok) (getf result :ok))))
                (when (= sid *target-sid*)
                  (format t "    → SVC ~D: rk=~D(~A) data-len=~D first=~{~2,'0X~}~%"
                          sid rk
                          (case rk (0 "OK") (1 "OOG") (2 "PANIC") (t "OTHER"))
                          (if data (length data) 0)
                          (if data
                              (coerce (subseq data 0 (min 20 (length data))) 'list)
                              '()))))))))

      ;; 3. Intercept accumulate-star to see final R* and its items
      (let ((orig-accum-star (fdefinition 'accumulate-star)))
        (unwind-protect
             (progn
               (setf (fdefinition 'accumulate-star)
                     (lambda (state transfers reports free-accum)
                       (format t "~%--- ACCUMULATE-STAR CALLED ---~%")
                       (format t "  reports=~D transfers=~D~%" (length reports) (length transfers))
                       ;; Show each report's items for target service
                       (loop for r in reports for ri from 0 do
                         (let* ((pkg-hash (getf (getf r :package-spec) :hash))
                                (results (getf r :results)))
                           (dolist (w results)
                             (let* ((sid (getf w :service-id))
                                    (result (getf w :result))
                                    (rk (work-exec-result-kind result))
                                    (data (when (getf result :ok) (getf result :ok))))
                               (when (= sid *target-sid*)
                                 (format t "  R[~D] pkg=~{~2,'0X~} → SVC ~D: rk=~D(~A) gas=~D data-len=~D first=~{~2,'0X~}~%"
                                         ri
                                         (coerce (subseq pkg-hash 0 8) 'list)
                                         sid rk
                                         (case rk (0 "OK") (1 "OOG") (2 "PANIC") (t "OTHER"))
                                         (getf w :accumulate-gas)
                                         (if data (length data) 0)
                                         (if data
                                             (coerce (subseq data 0 (min 30 (length data))) 'list)
                                             '())))))))
                       (funcall orig-accum-star state transfers reports free-accum)))
               (let ((*chain-log-level* nil)
                     (*debug-pvm-trace* nil))
                 (import-block pre-sigma block-cl)))
          (setf (fdefinition 'accumulate-star) orig-accum-star))))))

(drsd-run "1766479507_7943" "00000018")
(sb-ext:exit :code 0)
