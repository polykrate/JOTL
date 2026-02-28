;;; diag-bitmask-check.lisp — Check bitmask at PC=97133 and trace how PVM reaches it
(in-package #:jotl)

(defun dbc-trace-dir (trace-id)
  (let ((base (asdf:system-source-directory :jotl)))
    (merge-pathnames
     (format nil "../jam-conformance/fuzz-reports/0.7.2/traces/~A/" trace-id)
     base)))

(defun dbc-run (trace-id step)
  (format t "~%=== BITMASK CHECK: ~A / ~A ===~%" trace-id step)
  (let* ((dir (dbc-trace-dir trace-id))
         (step-path (merge-pathnames (format nil "~A.bin" step) dir))
         (raw (alexandria:read-file-into-byte-vector step-path)))
    (multiple-value-bind (pre-sigma block-cl post-sigma)
        (decode-trace-step-bin raw)
      (declare (ignore block-cl post-sigma))
      (let* ((delta (funcall pre-sigma :load :delta))
             (svc-data (funcall delta :service-data 0))
             (code-blob (getf svc-data :code-blob))
             (vm (jamvm:make-vm code-blob)))
        ;; Check bitmask at PC=97133
        (format t "~%Bitmask at PC=97133: ~D~%"
                (jamvm::bitmask-bit (jamvm:pvm-bitmask vm) 97133))
        (format t "Code byte at PC=97133: ~2,'0X (~D)~%"
                (aref (jamvm:pvm-code vm) 97133)
                (aref (jamvm:pvm-code vm) 97133))
        (format t "Effective opcode at 97133: ~D~%"
                (jamvm::pvm-opcode vm 97133))
        (format t "valid-opcode-p(22): ~A~%"
                (jamvm::valid-opcode-p 22))
        ;; Show surrounding bitmask context
        (format t "~%Bitmask bits 97125..97145:~%")
        (loop for i from 97125 below 97145 do
          (format t "  PC=~6D: bm=~D byte=~2,'0X eff=~D~A~%"
                  i
                  (jamvm::bitmask-bit (jamvm:pvm-bitmask vm) i)
                  (if (< i (length (jamvm:pvm-code vm)))
                      (aref (jamvm:pvm-code vm) i) 0)
                  (jamvm::pvm-opcode vm i)
                  (if (= i 97133) " ← TRAP PC" "")))
        ;; Now check: what's at the basic-block entry from before?
        ;; If the PVM reaches 97133, something jumped there.
        ;; Check basic-blocks bit
        (format t "~%basic-blocks at 97133: ~D~%"
                (if (< 97133 (length (jamvm::pvm-basic-blocks vm)))
                    (sbit (jamvm::pvm-basic-blocks vm) 97133)
                    -1))))))

(dbc-run "1766479507_7943" "00000018")
(sb-ext:exit :code 0)
