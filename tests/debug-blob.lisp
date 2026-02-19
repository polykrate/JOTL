;;;; debug-blob.lisp — Debug program blob parsing and memory layout
(in-package :jotl)

(let* ((dir "tests/jamtestvectors/traces/storage_light/")
       (step-path (trace-block-path dir 6))
       (bytes (alexandria:read-file-into-byte-vector step-path)))
  (multiple-value-bind (pre-sigma block-cl post-sigma)
      (decode-trace-step-bin bytes)
    (declare (ignore post-sigma))
    (let* ((h (funcall block-cl :header))
           (rho (funcall pre-sigma :load :rho))
           (e-a (funcall block-cl :assurances))
           (rho-dd (funcall rho :transition-ddagger
                            :assurances e-a
                            :tau-prime (make-tau-state :slot (funcall h :slot))
                            :parent-hash (funcall h :parent-hash)
                            :kappa (funcall pre-sigma :load :kappa)))
           (reported (funcall rho-dd :reported))
           (first-result (first (getf (first reported) :results)))
           (sid (getf first-result :service-id))
           (svc-data (classify-service-sub-keys sid (funcall pre-sigma :extra-kvs)))
           (code-blob (getf svc-data :code-blob)))

      (let ((vm (jamvm:make-vm (coerce code-blob '(simple-array (unsigned-byte 8) (*))))))
        (when vm
          (let ((m (jamvm:pvm-memory vm)))
            (format t "Memory layout:~%")
            (format t "  heap-base:  0x~X~%" (jamvm::mem-heap-base m))
            (format t "  heap-top:   0x~X~%" (jamvm::mem-heap-top m))
            (format t "  stack-base: 0x~X~%" (jamvm::mem-stack-base m))
            (format t "  stack-top:  0x~X~%" (jamvm::mem-stack-top m))
            (format t "  SP:         0x~X~%" (jamvm:reg vm jamvm:+sp+))
            
            ;; Show mapped pages
            (let ((pages nil))
              (maphash (lambda (k v) (declare (ignore v)) (push k pages))
                       (jamvm:mem-pages m))
              (setf pages (sort pages #'<))
              (format t "  Mapped pages (~D): ~{0x~X ~}~%"
                      (length pages)
                      (mapcar (lambda (p) (* p 4096)) (subseq pages 0 (min 10 (length pages))))))

            ;; Test reads
            (format t "~%Read tests:~%")
            (format t "  [0x10000] = ~A~%"
                    (handler-case (jamvm:mem-read-u8 m #x10000)
                      (error (e) (format nil "ERROR: ~A" e))))
            (format t "  [0x30000] = ~A~%"
                    (handler-case (jamvm:mem-read-u8 m #x30000)
                      (error (e) (format nil "ERROR: ~A" e))))
            
            ;; Run for a bit
            (format t "~%Running PVM accumulate...~%")
            (let ((params (jam-host:encode-accumulate-params 2 0 1)))
              (multiple-value-bind (ok reason) 
                  (jamvm:argument-invoke vm 1000000 jamvm:+pc-accumulate+ params)
                (format t "invoke: ok=~A reason=~A pc=~D gas=~D~%"
                        ok reason (jamvm:pvm-pc vm) (jamvm:pvm-gas vm))
                (when ok
                  ;; Run 10 steps manually
                  (loop for step from 1 to 10
                        do (multiple-value-bind (status arg) (jamvm:vm-step vm)
                             (format t "  step ~D: status=~A arg=~A pc=~D gas=~D~%"
                                     step status arg (jamvm:pvm-pc vm) (jamvm:pvm-gas vm))
                             (when (and status (not (eq status :host-call)))
                               (return)))))))))))))

(format t "~%Done.~%")
(uiop:quit)
