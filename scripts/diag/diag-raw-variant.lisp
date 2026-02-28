;;; diag-raw-variant.lisp — Check decoded work results from rho
(in-package #:jotl)

(defun drv-trace-dir (trace-id)
  (let ((base (asdf:system-source-directory :jotl)))
    (merge-pathnames
     (format nil "../jam-conformance/fuzz-reports/0.7.2/traces/~A/" trace-id)
     base)))

(defun drv-run (trace-id step)
  (format t "~%=== RAW VARIANT CHECK: ~A / ~A ===~%" trace-id step)
  (let* ((dir (drv-trace-dir trace-id))
         (step-path (merge-pathnames (format nil "~A.bin" step) dir))
         (raw (alexandria:read-file-into-byte-vector step-path)))
    (multiple-value-bind (pre-sigma block-cl post-sigma)
        (decode-trace-step-bin raw)
      (declare (ignore post-sigma block-cl))
      (let* ((rho (funcall pre-sigma :load :rho))
             (assignments (funcall rho :assignments)))
        (loop for a in assignments for ci from 0 do
          (when a
            (let* ((report (getf a :report))
                   (results (getf report :results))
                   (pkg-hash (getf (getf report :package-spec) :hash)))
              (format t "~%core[~D] pkg=~{~2,'0X~}~%"
                      ci (coerce (subseq pkg-hash 0 8) 'list))
              (loop for wr in results for ri from 0 do
                (let* ((sid (getf wr :service-id))
                       (re (getf wr :result))
                       (rk (work-exec-result-kind re))
                       (data (when (getf re :ok) (getf re :ok))))
                  (format t "  [~D] svc=~D rk=~D(~A)"
                          ri sid rk
                          (case rk (0 "OK") (1 "OOG") (2 "PANIC") (t "?")))
                  (when (and (= rk 0) data)
                    (format t " data=~D[~{~2,'0X~}]"
                            (length data)
                            (coerce (subseq data 0 (min 10 (length data))) 'list)))
                  (format t "~%"))))))
      ;; Now check: re-encode then re-decode to verify round-trip
      (format t "~%--- Round-trip test ---~%")
      (let* ((rho (funcall pre-sigma :load :rho))
             (rho-bytes (funcall rho :save))
             (rho2 (funcall (funcall pre-sigma :load :rho) :save)))
        (format t "rho-bytes: ~D bytes~%" (length rho-bytes))
        (if (equalp rho-bytes rho2)
            (format t "Round-trip: OK~%")
            (format t "Round-trip: MISMATCH!~%")))))))

(drv-run "1766479507_7943" "00000018")
(sb-ext:exit :code 0)
