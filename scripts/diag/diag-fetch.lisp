;;; diag-fetch.lisp — Compare ΩY fetch data with reference expectation
;;; Dumps protocol params and accumulate items for comparison

(in-package #:jotl)

(defun df-trace-dir (trace-id)
  (let ((base (asdf:system-source-directory :jotl)))
    (merge-pathnames
     (format nil "../jam-conformance/fuzz-reports/0.7.2/traces/~A/" trace-id)
     base)))

(defun df-run (trace-id step target-sid)
  (format t "~%=== FETCH DIAG: ~A / ~A (sid=~D) ===~%" trace-id step target-sid)
  (let* ((dir (df-trace-dir trace-id))
         (step-path (merge-pathnames (format nil "~A.bin" step) dir))
         (bytes (alexandria:read-file-into-byte-vector step-path)))
    (multiple-value-bind (pre-sigma block-cl post-sigma)
        (decode-trace-step-bin bytes)
      (declare (ignore post-sigma))

      ;; Wrap accumulate-service to intercept the host context
      (let ((orig-accum-svc (fdefinition 'accumulate-service))
            (orig-dispatch  (fdefinition 'jam-host::host-dispatch)))
        (unwind-protect
             (progn
               ;; Wrap host-dispatch to capture ALL fetch calls
               (setf (fdefinition 'jam-host::host-dispatch)
                     (lambda (vm ctx id)
                       (let ((sid (jam-host::hctx-service-id ctx)))
                         (when (and (= sid target-sid) (= id 1))
                           ;; HC1 = fetch
                           (let ((kind (jamvm:reg vm (+ jamvm:+a0+ 3)))  ;; a3 = kind
                                 (a    (jamvm:reg vm (+ jamvm:+a0+ 4)))  ;; a4
                                 (b    (jamvm:reg vm (+ jamvm:+a0+ 5)))) ;; a5
                             (format t "  HC1: kind=~D a=~D b=~D buf=~D off=~D len=~D"
                                     kind a b
                                     (jamvm:reg vm jamvm:+a0+)
                                     (jamvm:reg vm (+ jamvm:+a0+ 1))
                                     (jamvm:reg vm (+ jamvm:+a0+ 2)))
                             (let ((result (funcall orig-dispatch vm ctx id)))
                               (format t " → a0=~D~%" (jamvm:reg vm jamvm:+a0+))
                               ;; If kind=0 (protocol params), dump the data
                               (when (zerop kind)
                                 (let ((pp (jam-host::hctx-protocol-params ctx)))
                                   (format t "    protocol-params len=~D~%" (length pp))
                                   (format t "    hex: ~{~2,'0X~}~%" (coerce pp 'list))))
                               ;; If kind=14 (accumulate items), dump length
                               (when (= kind 14)
                                 (let* ((items (jam-host::hctx-accumulate-items ctx))
                                        (encoded (jam-host::encode-accumulate-items-list items)))
                                   (format t "    items=~D encoded-len=~D~%" (length items) (length encoded))
                                   (format t "    first-32: ~{~2,'0X~}~%"
                                           (coerce (subseq encoded 0 (min 32 (length encoded))) 'list))))
                               result)))
                         (when (/= sid target-sid)
                           (funcall orig-dispatch vm ctx id))
                         (when (and (= sid target-sid) (/= id 1))
                           (funcall orig-dispatch vm ctx id)))))

               ;; Wrap accumulate-service
               (setf (fdefinition 'accumulate-service)
                     (lambda (sid items gas-limit state &key (transfer-balance 0) (svc-transfers nil))
                       (when (= sid target-sid)
                         (format t "~%[TARGET] sid=~D gas=~D items=~D~%" sid gas-limit (length items))
                         ;; Show items detail
                         (dolist (u items)
                           (let ((res (getf u :result)))
                             (format t "  item: gas=~D result-kind=~D payload-hash-len=~D~%"
                                     (or (getf u :gas) 0)
                                     (work-exec-result-kind res)
                                     (if (getf u :payload-hash) (length (getf u :payload-hash)) 0)))))
                       (funcall orig-accum-svc sid items gas-limit state
                                :transfer-balance transfer-balance
                                :svc-transfers svc-transfers)))

               (let ((*chain-log-level* nil)
                     (*debug-pvm-trace* nil))
                 (import-block pre-sigma block-cl)))

          (setf (fdefinition 'accumulate-service) orig-accum-svc
                (fdefinition 'jam-host::host-dispatch) orig-dispatch))))))

;; Run for sid=3953987607 on the step-12 trace
(df-run "1768066437_3920" "00000012" 3953987607)

(sb-ext:exit :code 0)
