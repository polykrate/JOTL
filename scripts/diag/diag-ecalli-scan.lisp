;;; diag-ecalli-scan.lisp — Scan service 0 code blob for all ecalli instructions
(in-package #:jotl)

(defvar *target-sid* 0)

(defun des-trace-dir (trace-id)
  (let ((base (asdf:system-source-directory :jotl)))
    (merge-pathnames
     (format nil "../jam-conformance/fuzz-reports/0.7.2/traces/~A/" trace-id)
     base)))

(defun des-run (trace-id step)
  (format t "~%=== ECALLI SCAN: ~A / ~A ===~%" trace-id step)
  (let* ((dir (des-trace-dir trace-id))
         (step-path (merge-pathnames (format nil "~A.bin" step) dir))
         (bytes (alexandria:read-file-into-byte-vector step-path)))
    (multiple-value-bind (pre-sigma block-cl post-sigma)
        (decode-trace-step-bin bytes)
      (declare (ignore block-cl post-sigma))

      ;; Get service 0's code blob
      (let* ((delta (funcall pre-sigma :load :delta))
             (svc-data (funcall delta :service-data *target-sid*))
             (metadata (getf svc-data :metadata))
             (code-hash (getf metadata :code-hash))
             (preimages (getf svc-data :preimages)))
        (format t "Service ~D code-hash: ~{~2,'0X~}~%" *target-sid* (coerce code-hash 'list))
        (format t "Preimage count: ~D~%" (length preimages))

        ;; Find code blob
        (let ((code-blob nil))
          (dolist (preim preimages)
            (let* ((hash (car preim))
                   (data (cdr preim)))
              (when (equalp hash code-hash)
                (setf code-blob data))))

          (unless code-blob
            (format t "CODE BLOB NOT FOUND!~%")
            (return-from des-run))

          (format t "Code blob size: ~D bytes~%" (length code-blob))

          ;; Create a VM to use the bitmask/skip-table
          (let ((vm (jamvm:make-vm (coerce code-blob '(simple-array (unsigned-byte 8) (*))))))
            (format t "VM created, code length: ~D~%" (length (jamvm:pvm-code vm)))

            ;; Scan all instruction start positions for ecalli (opcode 10)
            (let ((ecalli-count 0)
                  (ecalli-by-id (make-hash-table :test 'eql))
                  (total-instructions 0))
              (let ((pc 0)
                    (code (jamvm:pvm-code vm))
                    (len (length (jamvm:pvm-code vm))))
                (loop while (< pc len) do
                  (multiple-value-bind (info skip args)
                      (jamvm:decode-instruction vm pc)
                    (incf total-instructions)
                    (when (and info (eq (jamvm::opi-name info) :ecalli))
                      (let ((id (jamvm::arg-imm args)))
                        (incf ecalli-count)
                        (push pc (gethash id ecalli-by-id))
                        (when (= id 17)
                          (format t "  *** FOUND ecalli 17 (checkpoint) at PC=~D ***~%" pc))))
                    ;; Advance PC
                    (if (and info (> skip 0))
                        (incf pc (1+ skip))
                        (incf pc 1)))))

              (format t "~%Total instructions scanned: ~D~%" total-instructions)
              (format t "Total ecalli instructions: ~D~%" ecalli-count)
              (format t "~%Ecalli by host call ID:~%")
              (let ((sorted-ids (sort (loop for id being the hash-keys of ecalli-by-id collect id) #'<)))
                (dolist (id sorted-ids)
                  (let ((positions (reverse (gethash id ecalli-by-id))))
                    (format t "  HC~D: ~D occurrences at PCs ~{~D~^ ~}~%" id (length positions) positions)))))))))))

(des-run "1766479507_7943" "00000018")
(sb-ext:exit :code 0)
