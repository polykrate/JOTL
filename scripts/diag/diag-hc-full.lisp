;;; diag-hc-full.lisp — Dump all HC calls with full registers + HC100 messages
(in-package #:jotl)

(defvar *target-sid* 0)

(defun dhf-trace-dir (trace-id)
  (let ((base (asdf:system-source-directory :jotl)))
    (merge-pathnames
     (format nil "../jam-conformance/fuzz-reports/0.7.2/traces/~A/" trace-id)
     base)))

(defun dhf-run (trace-id step)
  (format t "~%=== HC FULL DUMP: ~A / ~A ===~%" trace-id step)
  (let* ((dir (dhf-trace-dir trace-id))
         (step-path (merge-pathnames (format nil "~A.bin" step) dir))
         (bytes (alexandria:read-file-into-byte-vector step-path)))
    (multiple-value-bind (pre-sigma block-cl post-sigma)
        (decode-trace-step-bin bytes)
      (declare (ignore post-sigma))
      
      (let ((header (funcall block-cl :header)))
        (format t "Block slot: ~D~%" (funcall header :slot)))
      
      (let ((orig-dispatch (fdefinition 'jam-host::host-dispatch))
            (orig-accum-svc (fdefinition 'accumulate-service))
            (hc-count 0)
            (captured-vm nil))
        
        (unwind-protect
             (progn
               (setf (fdefinition 'jam-host::host-dispatch)
                     (lambda (vm ctx id)
                       (let ((sid (jam-host::hctx-service-id ctx)))
                         (if (= sid *target-sid*)
                             (let* ((a0 (jamvm:reg vm jamvm:+a0+))
                                    (a1 (jamvm:reg vm jamvm:+a1+))
                                    (a2 (jamvm:reg vm jamvm:+a2+))
                                    (a3 (jamvm:reg vm jamvm:+a3+))
                                    (a4 (jamvm:reg vm jamvm:+a4+))
                                    (a5 (jamvm:reg vm jamvm:+a5+))
                                    (pc jamvm:*vm-last-step-pc*)
                                    (result (funcall orig-dispatch vm ctx id))
                                    (a0-after (jamvm:reg vm jamvm:+a0+))
                                    (a1-after (jamvm:reg vm jamvm:+a1+)))
                               (incf hc-count)
                               (setf captured-vm vm)
                               (format t "~%[~2D] HC~D @pc=~A~%"
                                       hc-count id pc)
                               (format t "  IN:  a0=~D a1=~D a2=~D a3=~D a4=~D a5=~D~%"
                                       a0 a1 a2 a3 a4 a5)
                               (format t "  OUT: a0=~D a1=~D~%" a0-after a1-after)
                              ;; For HC100 (ext_log): dump target + text
                              ;; HC100: A0=level, A1=target_ptr, A2=target_len, A3=text_ptr, A4=text_len
                              (when (= id 100)
                                ;; Target (module name) from A1/A2
                                (let ((tgt-ptr (logand a1 #xFFFFFFFF))
                                      (tgt-len (logand a2 #xFFFFFFFF)))
                                  (when (and (plusp tgt-ptr) (plusp tgt-len) (<= tgt-len 256))
                                    (let ((tgt-bytes (jam-host:read-guest vm tgt-ptr tgt-len)))
                                      (when tgt-bytes
                                        (handler-case
                                            (format t "  TARGET: ~A~%"
                                                    (sb-ext:octets-to-string tgt-bytes :external-format :utf-8))
                                          (error () nil))))))
                                ;; Text (actual message) from A3/A4
                                (let ((txt-ptr (logand a3 #xFFFFFFFF))
                                      (txt-len (logand a4 #xFFFFFFFF)))
                                  (when (and (plusp txt-ptr) (plusp txt-len) (<= txt-len 8192))
                                    (let ((txt-bytes (jam-host:read-guest vm txt-ptr txt-len)))
                                      (when txt-bytes
                                        (format t "  HEX: ~{~2,'0X~}~%" (coerce txt-bytes 'list))
                                        (handler-case
                                            (format t "  TEXT: ~A~%"
                                                    (sb-ext:octets-to-string txt-bytes :external-format :utf-8))
                                          (error () nil)))))))
                               ;; For HC1 (fetch): show kind
                               (when (= id 1)
                                 (format t "  FETCH kind=~D a=~D b=~D → len=~D~%"
                                         a3 a4 a5 a0-after))
                               ;; For HC4 (write_storage): show val_len 
                               (when (= id 4)
                                 (format t "  WRITE key_ptr=~D key_len=~D val_ptr=~D val_len=~D → old=~D~%"
                                         a0 a1 a2 a3 a0-after))
                               ;; For HC3 (read_storage):
                               (when (= id 3)
                                 (format t "  READ key_ptr=~D key_len=~D buf_ptr=~D buf_len=~D → len=~D~%"
                                         a0 a1 a2 a3 a0-after))
                               result)
                             (funcall orig-dispatch vm ctx id)))))
               
               (setf (fdefinition 'accumulate-service)
                     (lambda (sid items gas-limit state &key (transfer-balance 0) (svc-transfers nil))
                       (when (= sid *target-sid*)
                         (format t "~%[ACCUM-SVC] sid=~D items=~D gas=~D xfer-bal=~D~%"
                                 sid (length items) gas-limit transfer-balance))
                       (multiple-value-bind (effects gas-used)
                           (funcall orig-accum-svc sid items gas-limit state
                                    :transfer-balance transfer-balance
                                    :svc-transfers svc-transfers)
                         (when (= sid *target-sid*)
                           (format t "~%--- RESULT: outcome=~A gas-used=~D last-pc=~A ---~%"
                                   (when effects (getf effects :outcome))
                                   gas-used jamvm:*vm-last-step-pc*))
                         (values effects gas-used))))
               
               (let ((*chain-log-level* nil)
                     (*debug-pvm-trace* nil))
                 (import-block pre-sigma block-cl)))
          
          (setf (fdefinition 'jam-host::host-dispatch) orig-dispatch)
          (setf (fdefinition 'accumulate-service) orig-accum-svc))))))

(dhf-run "1766479507_7943" "00000018")
(sb-ext:exit :code 0)
