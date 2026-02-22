;;;; diag-fetch-trace.lisp — Intercept ΩY/ΩR/ΩW and dump all host-call data flow
;;;;
;;;; Usage:
;;;;   sbcl --load scripts/load-jotl.lisp --load tests/diag-pi.lisp \
;;;;        --eval '(setf jotl::*chain-log-level* nil)' \
;;;;        --load tests/diag-fetch-trace.lisp --quit
(in-package :jotl)

(defun diag-fetch-data (trace-dir block-num target-sid)
  "Trace ΩY calls and dump data for TARGET-SID."
  (let* ((step-path (trace-block-path trace-dir block-num))
         (bytes (alexandria:read-file-into-byte-vector step-path))
         (*chain-log-level* nil)
         (fetch-log nil))
    (declare (special *chain-log-level*))
    (let ((orig-fetch (gethash 1 jam-host::*omega-table*)))
      ;; Hook ΩY
      (setf (gethash 1 jam-host::*omega-table*)
            (lambda (vm ctx)
              (when (= (jam-host::hctx-service-id ctx) target-sid)
                (let ((kind (jamvm:reg vm jamvm:+a3+))
                      (a    (jamvm:reg vm jamvm:+a4+))
                      (b    (jamvm:reg vm jamvm:+a5+))
                      (buf-ptr (jamvm:u32 (jamvm:reg vm jamvm:+a0+)))
                      (offset  (jamvm:reg vm jamvm:+a1+))
                      (buf-len (jamvm:reg vm jamvm:+a2+)))
                  (let ((data (jam-host::fetch-data ctx kind a b)))
                    (push (list :kind kind :a a :b b
                                :buf-ptr buf-ptr :offset offset :buf-len buf-len
                                :data-len (when data (length data))
                                :data-hex (when (and data (<= (length data) 400))
                                            (bytes-to-hex-string data)))
                          fetch-log))))
              (funcall orig-fetch vm ctx)))
      (unwind-protect
          (progn
            (multiple-value-bind (pre-sigma block-cl post-sigma)
                (decode-trace-step-bin bytes)
              (declare (ignore post-sigma))
              (import-block pre-sigma block-cl))
            ;; Print fetch log
            (format t "~%=== ΩY calls for SID ~D in block ~D ===~%" target-sid block-num)
            (dolist (entry (nreverse fetch-log))
              (format t "~%  kind=~D a=~D b=~D~%" (getf entry :kind) (getf entry :a) (getf entry :b))
              (format t "    buf-ptr=0x~X offset=~D buf-len=~D~%"
                      (getf entry :buf-ptr) (getf entry :offset) (getf entry :buf-len))
              (format t "    data-len=~A~%" (getf entry :data-len))
              (when (getf entry :data-hex)
                (format t "    data=~A~%" (getf entry :data-hex)))))
        (setf (gethash 1 jam-host::*omega-table*) orig-fetch)))))

(defun diag-full-trace (trace-dir block-num target-sid)
  "Intercept ΩY/ΩR/ΩW calls for TARGET-SID, showing all data flow."
  (let* ((step-path (trace-block-path trace-dir block-num))
         (bytes (alexandria:read-file-into-byte-vector step-path))
         (*chain-log-level* nil)
         (rw-log nil))
    (declare (special *chain-log-level*))
    (let ((orig-write (gethash 4 jam-host::*omega-table*))
          (orig-read  (gethash 3 jam-host::*omega-table*))
          (orig-fetch (gethash 1 jam-host::*omega-table*)))

      ;; Hook ΩY (fetch data)
      (setf (gethash 1 jam-host::*omega-table*)
            (lambda (vm ctx)
              (when (= (jam-host::hctx-service-id ctx) target-sid)
                (let ((kind (jamvm:reg vm jamvm:+a3+))
                      (a    (jamvm:reg vm jamvm:+a4+))
                      (b    (jamvm:reg vm jamvm:+a5+))
                      (buf-ptr (jamvm:u32 (jamvm:reg vm jamvm:+a0+)))
                      (offset  (jamvm:reg vm jamvm:+a1+))
                      (buf-len (jamvm:reg vm jamvm:+a2+)))
                  (push (list :op :FETCH :kind kind :a a :b b
                              :buf-ptr buf-ptr :offset offset :buf-len buf-len
                              :pc (jamvm:pvm-pc vm) :gas (jamvm:pvm-gas vm))
                        rw-log)))
              ;; Call original, then capture result
              (let ((result (funcall orig-fetch vm ctx)))
                (when (= (jam-host::hctx-service-id ctx) target-sid)
                  (let ((ret-a0 (jamvm:reg vm jamvm:+a0+)))
                    (push (list :op :FETCH-RESULT :a0 ret-a0
                                :pc (jamvm:pvm-pc vm))
                          rw-log)))
                result)))

      ;; Hook ΩW (write storage)
      (setf (gethash 4 jam-host::*omega-table*)
            (lambda (vm ctx)
              (let* ((key-ptr   (jamvm:u32 (jamvm:reg vm jamvm:+a0+)))
                     (key-len   (jamvm:u32 (jamvm:reg vm jamvm:+a1+)))
                     (value-ptr (jamvm:u32 (jamvm:reg vm jamvm:+a2+)))
                     (value-len (jamvm:u32 (jamvm:reg vm jamvm:+a3+)))
                     (key (jam-host:read-guest vm key-ptr key-len))
                     (value (when (plusp value-len)
                              (jam-host:read-guest vm value-ptr value-len)))
                     (h27 (when key (jam-host:storage-hash-key key))))
                (when (and key (= (jam-host::hctx-service-id ctx) target-sid))
                  (push (list :op :WRITE :h27 h27 :key key :val value
                              :pc (jamvm:pvm-pc vm) :gas (jamvm:pvm-gas vm))
                        rw-log)))
              (funcall orig-write vm ctx)))

      ;; Hook ΩR (read storage)
      (setf (gethash 3 jam-host::*omega-table*)
            (lambda (vm ctx)
              (let* ((service-raw (jamvm:reg vm jamvm:+a0+))
                     (key-ptr     (jamvm:u32 (jamvm:reg vm jamvm:+a1+)))
                     (key-len     (jamvm:u32 (jamvm:reg vm jamvm:+a2+)))
                     (is-self (or (= service-raw jam-host::+hc-none+)
                                  (= service-raw (jamvm:u64 (jam-host::hctx-service-id ctx))))))
                (when (and is-self (= (jam-host::hctx-service-id ctx) target-sid))
                  (let* ((key (jam-host:read-guest vm key-ptr key-len))
                         (h27 (when key (jam-host:storage-hash-key key)))
                         (cur-val (when h27 (gethash h27 (jam-host::hctx-storage ctx)))))
                    (push (list :op :READ :h27 h27 :key key
                                :cur-val cur-val
                                :pc (jamvm:pvm-pc vm) :gas (jamvm:pvm-gas vm))
                          rw-log))))
              (funcall orig-read vm ctx)))

      (unwind-protect
          (progn
            (multiple-value-bind (pre-sigma block-cl post-sigma)
                (decode-trace-step-bin bytes)
              (declare (ignore post-sigma))
              (import-block pre-sigma block-cl))
            (format t "~%═══ Block ~D SID=~D full host-call trace ═══~%" block-num target-sid)
            (dolist (entry (nreverse rw-log))
              (let ((op (getf entry :op)))
                (case op
                  (:FETCH
                   (format t "  [pc=~D gas=~D] FETCH kind=~D a=~D b=~D buf=~D off=~D len=~D~%"
                           (getf entry :pc) (getf entry :gas)
                           (getf entry :kind) (getf entry :a) (getf entry :b)
                           (getf entry :buf-ptr) (getf entry :offset) (getf entry :buf-len)))
                  (:FETCH-RESULT
                   (format t "    → result a0=~D~%" (getf entry :a0)))
                  (:READ
                   (let ((cv (getf entry :cur-val)))
                     (format t "  [pc=~D gas=~D] READ  key=~A val=~A~%"
                             (getf entry :pc) (getf entry :gas)
                             (bytes-to-hex-string (getf entry :key))
                             (if cv (bytes-to-hex-string cv) "NONE"))))
                  (:WRITE
                   (let ((v (getf entry :val)))
                     (format t "  [pc=~D gas=~D] WRITE key=~A val(~D)=~A~%"
                             (getf entry :pc) (getf entry :gas)
                             (bytes-to-hex-string (getf entry :key))
                             (if v (length v) 0)
                             (if v (bytes-to-hex-string v) "DELETE"))))))))
        ;; Restore
        (setf (gethash 4 jam-host::*omega-table*) orig-write)
        (setf (gethash 3 jam-host::*omega-table*) orig-read)
        (setf (gethash 1 jam-host::*omega-table*) orig-fetch)))))

;; Default: run full trace for SID 3953987607 in block 45
(let ((trace-dir (merge-pathnames "tests/jamtestvectors/traces/fuzzy/"
                                   (truename "."))))
  (diag-full-trace trace-dir 45 3953987607))
