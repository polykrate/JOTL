;;; diag-expected-pi.lisp — Compare expected vs JOTL PI for service 0 item count
(in-package #:jotl)

(defun dep-trace-dir (trace-id)
  (let ((base (asdf:system-source-directory :jotl)))
    (merge-pathnames
     (format nil "../jam-conformance/fuzz-reports/0.7.2/traces/~A/" trace-id)
     base)))

(defun dep-run (trace-id step)
  (format t "~%=== EXPECTED PI: ~A / ~A ===~%" trace-id step)
  (let* ((dir (dep-trace-dir trace-id))
         (step-path (merge-pathnames (format nil "~A.bin" step) dir))
         (raw (alexandria:read-file-into-byte-vector step-path)))
    (multiple-value-bind (pre-sigma block-cl post-sigma)
        (decode-trace-step-bin raw)
      (declare (ignore block-cl))
      ;; Expected post PI
      (let* ((exp-pi (funcall post-sigma :load :pi))
             (exp-pi-bytes (funcall exp-pi :save))
             ;; JOTL PI
             (jotl-result (let ((*chain-log-level* nil) (*debug-pvm-trace* nil))
                            (import-block pre-sigma (multiple-value-bind (ps bc ps2)
                                                        (decode-trace-step-bin raw)
                                                      (declare (ignore ps ps2))
                                                      bc))))
             (jotl-pi (funcall jotl-result :load :pi))
             (jotl-pi-bytes (funcall jotl-pi :save)))
        ;; Decode PI_S section to find service 0's stats
        (format t "~%Expected PI: ~D bytes~%" (length exp-pi-bytes))
        (format t "JOTL PI:     ~D bytes~%" (length jotl-pi-bytes))
        ;; Dump first diverging byte
        (when (not (equalp exp-pi-bytes jotl-pi-bytes))
          (format t "~%First diff:~%")
          (loop for i from 0 below (min (length exp-pi-bytes) (length jotl-pi-bytes))
                when (not (= (aref exp-pi-bytes i) (aref jotl-pi-bytes i)))
                do (format t "  byte ~D: exp=~2,'0X jotl=~2,'0X~%" i (aref exp-pi-bytes i) (aref jotl-pi-bytes i))
                   (loop-finish)))
        ;; Decode PI_S from expected
        (format t "~%--- Decoding expected PI_S ---~%")
        (let* ((exp-pi-s (funcall exp-pi :service-stats)))
          (dolist (entry exp-pi-s)
            (let* ((sid (getf entry :id))
                   (rec (getf entry :record)))
              (format t "  svc ~D: items=~D gas=~D refines=~D~%"
                      sid
                      (getf rec :accumulation-count)
                      (getf rec :accumulation-gas-used)
                      (getf rec :refinement-count)))))
        (format t "~%--- Decoding JOTL PI_S ---~%")
        (let* ((jotl-pi-s (funcall jotl-pi :service-stats)))
          (dolist (entry jotl-pi-s)
            (let* ((sid (getf entry :id))
                   (rec (getf entry :record)))
              (format t "  svc ~D: items=~D gas=~D refines=~D~%"
                      sid
                      (getf rec :accumulation-count)
                      (getf rec :accumulation-gas-used)
                      (getf rec :refinement-count)))))))))

(dep-run "1766479507_7943" "00000018")
(sb-ext:exit :code 0)
