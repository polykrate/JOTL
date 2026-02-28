;;; diag-code-check.lisp — Verify service 0 code blob hash and check PVM parsing
(in-package #:jotl)

(defun dcc-trace-dir (trace-id)
  (let ((base (asdf:system-source-directory :jotl)))
    (merge-pathnames
     (format nil "../jam-conformance/fuzz-reports/0.7.2/traces/~A/" trace-id)
     base)))

(defun dcc-run (trace-id step)
  (format t "~%=== CODE CHECK: ~A / ~A ===~%" trace-id step)
  (let* ((dir (dcc-trace-dir trace-id))
         (step-path (merge-pathnames (format nil "~A.bin" step) dir))
         (raw (alexandria:read-file-into-byte-vector step-path)))
    (multiple-value-bind (pre-sigma block-cl post-sigma)
        (decode-trace-step-bin raw)
      (declare (ignore block-cl post-sigma))
      (let* ((delta (funcall pre-sigma :load :delta))
             (svc-data (funcall delta :service-data 0))
             (code-blob (getf svc-data :code-blob))
             (meta (getf svc-data :metadata)))
        (format t "Code blob: ~D bytes~%" (length code-blob))
        (format t "Code blob first 16: ~{~2,'0X~}~%" (coerce (subseq code-blob 0 (min 16 (length code-blob))) 'list))
        ;; Compute blake2b hash
        (let* ((hash (ironclad:digest-sequence :blake2/256 code-blob)))
          (format t "blake2b-256: ~{~2,'0X~}~%" (coerce hash 'list)))
        ;; Check code hash from metadata
        (let ((stored-hash (getf meta :code-hash)))
          (when stored-hash
            (format t "stored hash: ~{~2,'0X~}~%" (coerce stored-hash 'list))))
        ;; Check bytes around the trap instruction at PC=97133
        (format t "~%Code at PC=97133 region:~%")
        (let ((start (max 0 (- 97133 20)))
              (end (min (length code-blob) (+ 97133 20))))
          (loop for i from start below end do
            (format t "  ~6D: ~2,'0X" i (aref code-blob i))
            (when (= i 97133) (format t "  ← PC=97133"))
            (format t "~%")))
        ;; Decode instruction at PC=97133
        (format t "~%Decoding instruction at PC=97133:~%")
        (let ((vm (jamvm:make-vm code-blob)))
          (multiple-value-bind (info skip args)
              (jamvm:decode-instruction vm 97133)
            (if info
                (format t "  opcode=~A skip=~D" (jamvm::opi-name info) skip)
                (format t "  *** UNKNOWN / TRAP ***"))
            (format t "~%")))))))

(dcc-run "1766479507_7943" "00000018")
(sb-ext:exit :code 0)
