;;;; diag-gas.lisp — Count host calls per service and verify gas
(in-package :jotl)

(defun diag-hc-count (trace-path)
  (let ((bytes (alexandria:read-file-into-byte-vector trace-path)))
    (multiple-value-bind (pre-sigma block-cl post-sigma pre-root post-root)
        (decode-trace-step-bin bytes)
      (declare (ignore pre-root post-root post-sigma))
      ;; Enable PVM trace
      (let ((*debug-pvm-trace* t)
            (*debug-pvm-traces* nil)
            (*chain-log-level* nil))
        (handler-case
            (multiple-value-bind (sigma-prime computed-root)
                (import-block pre-sigma block-cl)
              (declare (ignore sigma-prime computed-root))
              ;; *debug-pvm-traces* holds per-service PVM trace data
              (dolist (entry *debug-pvm-traces*)
                (let* ((sid (getf entry :sid))
                       (gas-limit (getf entry :gas-limit))
                       (gas-used (getf entry :gas-used))
                       (hc-log (getf entry :host-call-log))
                       (hc-count (length (or hc-log nil))))
                  (format t "  sid=~D gas-limit=~D gas-used=~D hc-count=~D~%"
                          sid gas-limit gas-used hc-count)
                  ;; Count by HC ID
                  (let ((id-counts (make-hash-table)))
                    (dolist (hc (or hc-log nil))
                      (incf (gethash (getf hc :id) id-counts 0)))
                    (maphash (lambda (k v) (format t "    HC[~D]: ~D calls~%" k v))
                             id-counts)))))
          (error (err)
            (format t "  STF error: ~A~%" err)))))))

(format t "~%══════ Trace 3: 1766241968 step 24 (diff=+10 for sid 0) ══════~%")
(diag-hc-count "/home/polycrate/Projets/Jam/jam-conformance/fuzz-reports/0.7.2/traces/1766241968/00000024.bin")

(format t "~%══════ Trace 1: 1767896003_7770 step 33 (diff=-3672 for sid 0) ══════~%")
(diag-hc-count "/home/polycrate/Projets/Jam/jam-conformance/fuzz-reports/0.7.2/traces/1767896003_7770/00000033.bin")

(sb-ext:exit :code 0)
