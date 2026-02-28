;;; diag-rstar-deps.lisp — Check deferred report dependencies and R* computation
(in-package #:jotl)

(defun drsd2-trace-dir (trace-id)
  (let ((base (asdf:system-source-directory :jotl)))
    (merge-pathnames
     (format nil "../jam-conformance/fuzz-reports/0.7.2/traces/~A/" trace-id)
     base)))

(defun drsd2-run (trace-id step)
  (format t "~%=== R* DEPS TRACE: ~A / ~A ===~%" trace-id step)
  (let* ((dir (drsd2-trace-dir trace-id))
         (step-path (merge-pathnames (format nil "~A.bin" step) dir))
         (bytes (alexandria:read-file-into-byte-vector step-path)))
    (multiple-value-bind (pre-sigma block-cl post-sigma)
        (decode-trace-step-bin bytes)
      (declare (ignore post-sigma))

      (let ((header (funcall block-cl :header)))
        (format t "Block slot: ~D~%" (funcall header :slot)))

      ;; Get rho (core assignments) pre-state
      (format t "~%--- RHO (pre-state core assignments) ---~%")
      (let* ((rho (funcall pre-sigma :load :rho))
             (assignments (funcall rho :assignments)))
        (loop for a in assignments for i from 0 do
          (when a
            (let* ((report (getf a :report))
                   (timeout (getf a :timeout))
                   (pkg-hash (getf (getf report :package-spec) :hash))
                   (n-results (length (getf report :results))))
              (format t "  core[~D] pkg=~{~2,'0X~} timeout=~D results=~D~%"
                      i (coerce (subseq pkg-hash 0 8) 'list) timeout n-results)
              ;; Show services in results
              (dolist (w (getf report :results))
                (format t "    svc=~D rk=~A~%" (getf w :service-id)
                        (let ((r (getf w :result)))
                          (cond ((getf r :ok) "OK") ((getf r :panic) "PANIC")
                                ((getf r :out-of-gas) "OOG") (t "OTHER")))))))))

      ;; Show assurances in this block
      (format t "~%--- ASSURANCES ---~%")
      (let ((assurances (funcall block-cl :assurances)))
        (format t "  ~D assurances~%" (length assurances))
        (dolist (a assurances)
          (let ((cores (getf a :bitfield)))
            (format t "  validator=~D assuring cores: " (getf a :validator-index))
            (when cores
              (loop for byte across cores
                    for bi from 0 do
                (dotimes (bit 8)
                  (when (logbitp bit byte)
                    (format t "~D " (+ (* bi 8) bit))))))
            (format t "~%"))))

      ;; Show omega queues
      (format t "~%--- OMEGA QUEUES (pre-state) ---~%")
      (let* ((omega (funcall pre-sigma :load :omega))
             (omega-queues (funcall omega :queues)))
        (loop for q in omega-queues for i from 0 do
          (when q
            (format t "  slot[~D]: ~D entries~%" i (length q))
            (dolist (entry q)
              (let* ((report (getf entry :report))
                     (deps (getf entry :deps))
                     (pkg-hash (getf (getf report :package-spec) :hash)))
                (format t "    pkg=~{~2,'0X~}~%" (coerce (subseq pkg-hash 0 8) 'list))
                (format t "    deps=~D:~%" (length deps))
                (dolist (d deps)
                  (format t "      ~{~2,'0X~}~%" (coerce (subseq d 0 8) 'list))))))))

      ;; Show xi-flattened
      (format t "~%--- XI-FLATTENED (already accumulated) ---~%")
      (let* ((xi (funcall pre-sigma :load :xi))
             (xi-flat (funcall xi :flattened)))
        (format t "  ~D hashes~%" (length xi-flat))
        (dolist (h xi-flat)
          (format t "    ~{~2,'0X~}~%" (coerce (subseq h 0 8) 'list))))

      ;; Now compute R* manually
      (format t "~%--- COMPUTING R* ---~%")
      (let* ((rho (funcall pre-sigma :load :rho))
             (rho-dagger rho)  ;; no disputes in this test
             (assurances (funcall block-cl :assurances))
             (parent-hash (funcall (funcall block-cl :header) :parent-hash))
             (tau-prime (funcall block-cl :header))
             (kappa (funcall pre-sigma :load :kappa)))

        ;; Run transition-ddagger to get R*
        (handler-case
            (let ((rho-ddagger (funcall rho-dagger :transition-ddagger
                                        :assurances assurances
                                        :tau-prime tau-prime
                                        :parent-hash parent-hash
                                        :kappa kappa)))
              (let ((reported (funcall rho-ddagger :reported)))
                (format t "  Reported from assurances: ~D reports~%" (length reported))
                (dolist (r reported)
                  (let ((pkg-hash (getf (getf r :package-spec) :hash)))
                    (format t "    pkg=~{~2,'0X~} results=~D~%"
                            (coerce (subseq pkg-hash 0 8) 'list)
                            (length (getf r :results)))))))
          (error (e)
            (format t "  ERROR during transition-ddagger: ~A~%" e)))))))

(drsd2-run "1766479507_7943" "00000018")
(sb-ext:exit :code 0)
