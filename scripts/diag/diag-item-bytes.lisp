;;; diag-item-bytes.lisp — Dump raw bytes of each encoded AccumulateItem
;;; Parse each item field-by-field to verify boundaries
(in-package #:jotl)
;;; decode-compact is in JOTL package (from lib/primitives.lisp)

(defvar *target-sid* 0)

(defun dib-trace-dir (trace-id)
  (let ((base (asdf:system-source-directory :jotl)))
    (merge-pathnames
     (format nil "../jam-conformance/fuzz-reports/0.7.2/traces/~A/" trace-id)
     base)))

(defun parse-work-item (buf &optional (start 0))
  "Parse a WorkItem from BUF starting at START. Returns next position."
  (let ((pos start))
    ;; discriminant
    (let ((disc (aref buf pos)))
      (format t "    [~D] disc=~D(~A)~%" pos disc
              (case disc (0 "WorkItem") (1 "Transfer") (t "?")))
      (incf pos))
    ;; 4 hashes
    (dolist (name '("package" "exports_root" "auth_hash" "payload_hash"))
      (format t "    [~D..~D] ~A=~{~2,'0X~}~%" pos (+ pos 31) name
              (coerce (subseq buf pos (+ pos 32)) 'list))
      (incf pos 32))
    ;; gas_limit (compact)
    (multiple-value-bind (gas gas-bytes)
        (decode-compact buf pos)
      (format t "    [~D..~D] gas=~D (~D bytes: ~{~2,'0X~})~%"
              pos (+ pos gas-bytes -1) gas gas-bytes
              (coerce (subseq buf pos (+ pos gas-bytes)) 'list))
      (incf pos gas-bytes))
    ;; result
    (let ((result-byte (aref buf pos)))
      (format t "    [~D] result_disc=~D(~A)~%" pos result-byte
              (case result-byte (0 "Ok") (1 "OOG") (2 "Panic")
                (3 "BadExports") (4 "OutputOversize") (5 "BadCode")
                (6 "CodeOversize") (t "?")))
      (incf pos)
      (when (= result-byte 0)
        ;; Ok: compact(len) + data
        (multiple-value-bind (dlen dl-bytes)
            (decode-compact buf pos)
          (format t "    [~D..~D] data_len=~D (~D bytes)~%" pos (+ pos dl-bytes -1) dlen dl-bytes)
          (incf pos dl-bytes)
          (format t "    [~D..~D] data(~D)=~{~2,'0X~}~%"
                  pos (+ pos dlen -1) dlen
                  (coerce (subseq buf pos (min (+ pos dlen) (length buf))) 'list))
          (incf pos dlen))))
    ;; auth_output (compact(len) + data)
    (multiple-value-bind (ao-len ao-bytes)
        (decode-compact buf pos)
      (format t "    [~D..~D] auth_output_len=~D (~D bytes)~%" pos (+ pos ao-bytes -1) ao-len ao-bytes)
      (incf pos ao-bytes)
      (when (plusp ao-len)
        (format t "    [~D..~D] auth_output=~{~2,'0X~}~%"
                pos (+ pos ao-len -1)
                (coerce (subseq buf pos (min (+ pos ao-len) (length buf))) 'list))
        (incf pos ao-len)))
    (format t "    --- item ends at offset ~D ---~%" pos)
    pos))

(defun dib-run (trace-id step)
  (format t "~%=== ITEM BYTES DUMP: ~A / ~A ===~%" trace-id step)
  (let* ((dir (dib-trace-dir trace-id))
         (step-path (merge-pathnames (format nil "~A.bin" step) dir))
         (bytes (alexandria:read-file-into-byte-vector step-path)))
    (multiple-value-bind (pre-sigma block-cl post-sigma)
        (decode-trace-step-bin bytes)
      (declare (ignore post-sigma))
      
      (let ((orig-accum-svc (fdefinition 'accumulate-service)))
        (unwind-protect
             (progn
               (setf (fdefinition 'accumulate-service)
                     (lambda (sid items gas-limit state &key (transfer-balance 0) (svc-transfers nil))
                       (when (= sid *target-sid*)
                         (format t "~%[ACCUM-SVC] sid=~D items=~D transfers=~D gas=~D~%"
                                 sid (length items) (length (or svc-transfers nil)) gas-limit)
                         ;; Encode items
                         (let* ((encoded-items (encode-accumulate-items items svc-transfers))
                                (buf (jam-host::encode-accumulate-items-list encoded-items)))
                           (format t "~%Total buffer: ~D bytes, ~D items~%" (length buf) (length encoded-items))
                           ;; Parse compact count
                           (multiple-value-bind (count cnt-bytes)
                               (decode-compact buf 0)
                             (format t "Compact count=~D (~D bytes)~%" count cnt-bytes)
                             ;; Parse each item
                             (let ((pos cnt-bytes))
                               (loop for i from 0 below (min count 3) do
                                 (format t "~%--- ITEM ~D at offset ~D ---~%" i pos)
                                 (handler-case
                                     (setf pos (parse-work-item buf pos))
                                   (error (e)
                                     (format t "  PARSE ERROR at item ~D: ~A~%" i e)
                                     (return))))))))
                       (funcall orig-accum-svc sid items gas-limit state
                                :transfer-balance transfer-balance
                                :svc-transfers svc-transfers)))
               (let ((*chain-log-level* nil)
                     (*debug-pvm-trace* nil))
                 (import-block pre-sigma block-cl)))
          (setf (fdefinition 'accumulate-service) orig-accum-svc))))))

(dib-run "1766479507_7943" "00000018")
(sb-ext:exit :code 0)
