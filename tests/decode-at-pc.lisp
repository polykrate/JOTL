;;;; decode-at-pc.lisp — Decode instructions at specific PC values
(in-package #:jotl)

(let* ((trace-dir "tests/jamtestvectors/traces/storage_light/")
       (step-path (trace-block-path trace-dir 2)))
  (multiple-value-bind (pre-sigma block-cl post-sigma pre-root post-root)
      (load-trace-step step-path)
    (declare (ignore post-sigma pre-root post-root block-cl))
    (let* ((delta-kvs (funcall pre-sigma :merkle-kvs))
           (sid 0)
           (svc-data (classify-service-sub-keys sid delta-kvs))
           (code-blob (getf svc-data :code-blob))
           (vm (jamvm:make-vm (coerce code-blob '(simple-array (unsigned-byte 8) (*))))))
      (when vm
        (dolist (pc '(82589 82593 82597 82601 82605))
          (handler-case
              (let ((code (jamvm::pvm-code vm)))
                (when (< pc (length code))
                  (format t "PC ~D: opcode=~D " pc (aref code pc))
                  (let ((inst (jamvm:decode-instruction vm pc)))
                    (format t "decoded=~S~%" inst))))
            (error (e) (format t "PC ~D: ERROR: ~A~%" pc e))))))))
(sb-ext:exit :code 0)
