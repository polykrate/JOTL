;;; diag-wi-origin.lisp — Trace exact origin of work item results from block data
;;; Shows raw block bytes → decoded WorkResult → AccumulateItem encoding
(in-package #:jotl)

(defun dwo-trace-dir (trace-id)
  (let ((base (asdf:system-source-directory :jotl)))
    (merge-pathnames
     (format nil "../jam-conformance/fuzz-reports/0.7.2/traces/~A/" trace-id)
     base)))

(defun dwo-run (trace-id step)
  (format t "~%=== WI ORIGIN TRACE: ~A / ~A ===~%" trace-id step)
  (let* ((dir (dwo-trace-dir trace-id))
         (step-path (merge-pathnames (format nil "~A.bin" step) dir))
         (bytes (alexandria:read-file-into-byte-vector step-path)))
    (multiple-value-bind (pre-sigma block-cl post-sigma)
        (decode-trace-step-bin bytes)
      (declare (ignore pre-sigma post-sigma))

      (let* ((guarantees (funcall block-cl :guarantees)))
        (format t "~%Guarantees: ~D~%" (length guarantees))

        (loop for g in guarantees for gi from 0 do
          (let* ((report (getf g :report))
                 (results (getf report :results))
                 (pkg-spec (getf report :package-spec))
                 (auth-output (getf report :auth-output)))
            (format t "~%  G[~D] core=~D results=~D auth-output-len=~D~%"
                    gi (getf report :core-index)
                    (length results) (length auth-output))
            
            ;; For each work result
            (loop for w in results for wi from 0 do
              (let* ((sid (getf w :service-id))
                     (acc-gas (getf w :accumulate-gas))
                     (result (getf w :result))
                     (rk (jotl::work-exec-result-kind result))
                     (ok-data (getf result :ok)))
                (format t "    WR[~D] sid=~D gas=~D rk=~D(~A)~%"
                        wi sid acc-gas rk
                        (case rk (0 "OK") (1 "OOG") (2 "PANIC") (3 "BAD-EXPORTS")
                              (4 "OUTPUT-OVERSIZE") (5 "BAD-CODE") (6 "CODE-OVERSIZE")
                              (t "?")))
                (when (= rk 0)
                  (format t "           data-len=~D first-20=~{~2,'0X~}~%"
                          (length ok-data)
                          (coerce (subseq ok-data 0 (min 20 (length ok-data))) 'list)))
                (when (= rk 2)
                  (format t "           PANIC result — no data~%"))
                ;; Show what bootstrap would see as instruction
                (when (and (= sid 0) (= rk 0) ok-data (>= (length ok-data) 2))
                  (let ((ver (aref ok-data 0))
                        (opcode (aref ok-data 1)))
                    (format t "           bootstrap: version=~D opcode=0x~2,'0X (~D)~%"
                            ver opcode opcode)
                    (when (= opcode #x10)
                      (format t "           >>> THIS IS THE PANIC INSTRUCTION <<<~%"))))))))

        ;; Also re-encode and verify the raw report bytes match
        (format t "~%--- Raw report bytes check ---~%")
        (loop for g in guarantees for gi from 0 do
          (let ((raw (getf g :report-raw-bytes)))
            (when raw
              (format t "  G[~D] raw-report-bytes: ~D bytes, first-10: ~{~2,'0X~}~%"
                      gi (length raw)
                      (coerce (subseq raw 0 (min 10 (length raw))) 'list)))))))))

(dwo-run "1766479507_7943" "00000018")
(sb-ext:exit :code 0)
