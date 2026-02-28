;;; diag-items-dump.lisp — Intercept accumulate-service and dump ALL items
(in-package #:jotl)

(defvar *target-sid* 0)

(defun did-trace-dir (trace-id)
  (let ((base (asdf:system-source-directory :jotl)))
    (merge-pathnames
     (format nil "../jam-conformance/fuzz-reports/0.7.2/traces/~A/" trace-id)
     base)))

(defun did-run (trace-id step)
  (format t "~%=== ITEMS DUMP: ~A / ~A ===~%" trace-id step)
  (let* ((dir (did-trace-dir trace-id))
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
                         (format t "~%[ACCUM-SVC] sid=~D work-items=~D transfers=~D gas=~D xfer-bal=~D~%"
                                 sid (length items) (length svc-transfers) gas-limit transfer-balance)
                         
                         ;; Dump each work item's result kind + first bytes of output data
                         (loop for u in items for i from 0 do
                           (let* ((result (getf u :result))
                                  (rk (work-exec-result-kind result))
                                  (ok-data (getf result :ok)))
                             (format t "  WI[~D] rk=~D(~A) gas=~D data-len=~A first-bytes=~A~%"
                                     i rk
                                     (case rk (0 "OK") (1 "OOG") (2 "Panic") (t "?"))
                                     (or (getf u :gas) 0)
                                     (if ok-data (length ok-data) "N/A")
                                     (when ok-data
                                       (format nil "~{~2,'0X~}"
                                               (coerce (subseq ok-data 0 (min 30 (length ok-data))) 'list))))))
                         
                         ;; Dump each transfer
                         (loop for x in svc-transfers for i from 0 do
                           (format t "  XF[~D] sender=~D dest=~D amt=~D gas=~D memo-len=~D~%"
                                   i (or (getf x :sender) 0) (or (getf x :destination) 0)
                                   (or (getf x :amount) 0) (or (getf x :gas-limit) 0)
                                   (if (getf x :memo) (length (getf x :memo)) 0)))
                         
                         ;; Encode and dump
                         (let ((encoded (encode-accumulate-items items svc-transfers)))
                           (format t "  Encoded: ~D blobs~%" (length encoded))
                           (loop for blob in encoded for i from 0 do
                             (let ((disc (aref blob 0)))
                               (format t "  E[~D] disc=~D(~A) len=~D first-10=~{~2,'0X~}~%"
                                       i disc (if (= disc 0) "WI" "XF") (length blob)
                                       (coerce (subseq blob 0 (min 10 (length blob))) 'list))))
                           ;; Final blob size
                           (let ((final (jam-host::encode-accumulate-items-list encoded)))
                             (format t "  Final blob: ~D bytes (count=~D)~%"
                                     (length final) (length encoded)))))
                       
                       ;; Call original
                       (funcall orig-accum-svc sid items gas-limit state
                                :transfer-balance transfer-balance
                                :svc-transfers svc-transfers)))
               
               (let ((*chain-log-level* nil)
                     (*debug-pvm-trace* nil))
                 (import-block pre-sigma block-cl)))
          
          (setf (fdefinition 'accumulate-service) orig-accum-svc))))))

(did-run "1766479507_7943" "00000018")
(sb-ext:exit :code 0)
