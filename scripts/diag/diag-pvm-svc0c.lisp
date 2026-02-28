;;; diag-pvm-svc0c.lisp — Dump accumulate items encoding for service 0
;;; Compare what we encode vs what the service expects

(in-package #:jotl)

(defun svc0c-trace-dir (trace-id)
  (let ((base (asdf:system-source-directory :jotl)))
    (merge-pathnames
     (format nil "../jam-conformance/fuzz-reports/0.7.2/traces/~A/" trace-id)
     base)))

(defun svc0c-run (trace-id step)
  (format t "~%=== SVC0 ENCODING DIAG: ~A / ~A ===~%" trace-id step)
  (let* ((dir (svc0c-trace-dir trace-id))
         (step-path (merge-pathnames (format nil "~A.bin" step) dir))
         (bytes (alexandria:read-file-into-byte-vector step-path)))
    (multiple-value-bind (pre-sigma block-cl post-sigma)
        (decode-trace-step-bin bytes)
      (declare (ignore post-sigma))

      ;; Block info
      (let ((header (funcall block-cl :header)))
        (format t "Block slot: ~D~%" (funcall header :slot)))

      ;; Get the guarantees from the block
      (let ((guarantees (funcall block-cl :guarantees)))
        (format t "Guarantees: ~D~%" (length guarantees))

        ;; Show what reports target service 0
        (dolist (g guarantees)
          (let* ((report (getf g :report))
                 (items (getf report :results)))
            (format t "~%  Core ~D: ~D items~%" (getf report :core-index) (length items))
            (dolist (item items)
              (let* ((sid (getf item :service-id))
                     (gas (getf item :gas-limit))
                     (result (getf item :result)))
                (when (or (= sid 0) t)  ;; show all
                  (format t "    sid=~D gas=~D result-kind=~D~%"
                          sid gas
                          (work-exec-result-kind result))))))))

      ;; Run with debug tracing to dump items
      (let ((*debug-pvm-trace* t))
        (let ((orig-accum-svc (fdefinition 'accumulate-service)))
          (unwind-protect
               (progn
                 (setf (fdefinition 'accumulate-service)
                       (lambda (sid items gas-limit state &key (transfer-balance 0) (svc-transfers nil))
                         (when (= sid 0)
                           (format t "~%=== SERVICE 0 ACCUMULATE ===~%")
                           (format t "items=~D gas=~D xfer-bal=~D svc-xfers=~D~%"
                                   (length items) gas-limit transfer-balance (length svc-transfers))
                           ;; Show each work item
                           (dolist (u items)
                             (format t "~%  Work item: sid=~D gas=~D~%"
                                     (or (getf u :service-id) "?") (or (getf u :gas) 0))
                             (let ((res (getf u :result)))
                               (format t "    result-kind=~D~%" (work-exec-result-kind res))
                               (when (getf res :ok)
                                 (format t "    ok-data-len=~D~%" (length (getf res :ok)))))
                             (format t "    payload-hash=~A~%"
                                     (if (getf u :payload-hash)
                                         (subseq (bytes-to-hex-string (getf u :payload-hash)) 0 16)
                                         "NIL"))
                             (format t "    auth-output=~A~%"
                                     (if (getf u :auth-output)
                                         (length (getf u :auth-output))
                                         "NIL")))
                           ;; Encode and show size
                           (let ((encoded (encode-accumulate-items items svc-transfers)))
                             (format t "~%  Encoded items: ~D blobs, total ~D bytes~%"
                                     (length encoded)
                                     (reduce #'+ encoded :key #'length))
                             ;; Show first and last blob
                             (when encoded
                               (format t "  Blob 0 (~D bytes): ~{~2,'0X~^ ~}~%"
                                       (length (first encoded))
                                       (coerce (subseq (first encoded) 0 (min 50 (length (first encoded)))) 'list))
                               (let ((last (car (last encoded))))
                                 (format t "  Blob ~D (~D bytes): ~{~2,'0X~^ ~}~%"
                                         (1- (length encoded))
                                         (length last)
                                         (coerce (subseq last 0 (min 50 (length last))) 'list))))))
                         (funcall orig-accum-svc sid items gas-limit state
                                  :transfer-balance transfer-balance
                                  :svc-transfers svc-transfers)))
                 ;; Run
                 (let ((*chain-log-level* nil))
                   (import-block pre-sigma block-cl)))
            (setf (fdefinition 'accumulate-service) orig-accum-svc)))))))

(svc0c-run "1766479507_7943" "00000018")
(sb-ext:exit :code 0)
