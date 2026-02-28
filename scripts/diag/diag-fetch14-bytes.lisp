;;; diag-fetch14-bytes.lisp — Dump exact encoded AccumulateItem bytes
(in-package #:jotl)

(defun df14-decode-item (item i)
  "Decode and print one AccumulateItem byte vector."
  (format t "  ITEM[~D] len=~D disc=~D(~A)"
          i (length item) (aref item 0)
          (case (aref item 0) (0 "WorkItem") (1 "Transfer") (t "?")))
  (when (= (aref item 0) 0)
    (let ((gas-start 129))
      (multiple-value-bind (gas gas-bytes) (decode-compact item gas-start)
        (format t " gas=~D(~Db)" gas gas-bytes)
        (let* ((rs (+ gas-start gas-bytes))
               (rb (aref item rs)))
          (format t " result=~2,'0X(~A)" rb
                  (case rb (0 "Ok") (1 "OOG") (2 "Panic") (t "?")))
          (when (= rb 0)
            (multiple-value-bind (dlen dlb) (decode-compact item (1+ rs))
              (let ((ds (+ rs 1 dlb)))
                (format t " data=~D[~{~2,'0X~}]" dlen
                        (coerce (subseq item ds (min (+ ds (min dlen 10)) (length item))) 'list))
                (let ((ao-start (+ ds dlen)))
                  (when (< ao-start (length item))
                    (multiple-value-bind (ao-len aob) (decode-compact item ao-start)
                      (declare (ignore aob))
                      (format t " ao=~D" ao-len)))))))))))
  (format t "~%"))

(defun df14-trace-dir (trace-id)
  (let ((base (asdf:system-source-directory :jotl)))
    (merge-pathnames
     (format nil "../jam-conformance/fuzz-reports/0.7.2/traces/~A/" trace-id)
     base)))

(defun df14-run (trace-id step)
  (format t "~%=== FETCH-14 BYTES: ~A / ~A ===~%" trace-id step)
  (let* ((dir (df14-trace-dir trace-id))
         (step-path (merge-pathnames (format nil "~A.bin" step) dir))
         (raw (alexandria:read-file-into-byte-vector step-path)))
    (multiple-value-bind (pre-sigma block-cl post-sigma)
        (decode-trace-step-bin raw)
      (declare (ignore post-sigma))
      (let ((orig (fdefinition 'accumulate-service)))
        (unwind-protect
             (progn
               (setf (fdefinition 'accumulate-service)
                     (lambda (sid items gas-limit state
                              &key (transfer-balance 0) (svc-transfers nil))
                       (when (= sid 0)
                         (let* ((enc (encode-accumulate-items items svc-transfers))
                                (buf (jam-host::encode-accumulate-items-list enc)))
                           (format t "~%[SVC 0] ~D items, buf=~D bytes~%" (length enc) (length buf))
                           (loop for it in enc for i from 0 do (df14-decode-item it i))))
                       (funcall orig sid items gas-limit state
                                :transfer-balance transfer-balance
                                :svc-transfers svc-transfers)))
               (let ((*chain-log-level* nil) (*debug-pvm-trace* nil))
                 (import-block pre-sigma block-cl)))
          (setf (fdefinition 'accumulate-service) orig))))))

(df14-run "1766479507_7943" "00000018")
(sb-ext:exit :code 0)
