;;;; diag/diag-gas4.lisp — Show all host calls for the divergent service

(in-package :jotl)

(defvar *dg4-trace-id* "1767895984_7922")
(defvar *dg4-step* "00000061")

(defun dg4-trace-dir ()
  (merge-pathnames (format nil "../jam-conformance/fuzz-reports/0.7.2/traces/~A/"
                           *dg4-trace-id*)
                   (truename (asdf:system-source-directory :jotl))))

(defun dg4-run ()
  (format t "~%=== GAS4 DIAGNOSTIC ===~%")

  (let* ((step-path (merge-pathnames (format nil "~A.bin" *dg4-step*)
                                     (dg4-trace-dir)))
         (bytes (alexandria:read-file-into-byte-vector step-path)))
    (multiple-value-bind (pre-sigma block-cl post-sigma pre-root post-root)
        (decode-trace-step-bin bytes)
      (declare (ignore post-sigma pre-root post-root))

      (let ((*debug-pvm-trace* t)
            (*debug-pvm-traces* nil)
            (*chain-log-level* nil))

        (handler-case
            (let ((sigma-prime (import-block pre-sigma block-cl)))
              (declare (ignore sigma-prime))
              ;; Show all traces for sid=3101749195
              (format t "~%=== Host call traces ===~%")
              (dolist (trace (reverse *debug-pvm-traces*))
                (let ((sid (getf trace :sid)))
                  (format t "~%SID=~D gas-limit=~D gas-used=~D outcome=~D~%"
                          sid (getf trace :gas-limit) (getf trace :gas-used)
                          (getf trace :outcome))
                  (when (= sid 3101749195)
                    (format t "  === DETAILED HOST CALLS for 3101749195 ===~%")
                    (dolist (hc (getf trace :host-call-log))
                      ;; hc is a plist with :id :gas-before :gas-after etc.
                      (format t "  HC ~2D  gas: ~D→~D (Δ=~D)  a0: ~D→~D  result=~A~%"
                              (getf hc :id)
                              (getf hc :gas-before) (getf hc :gas-after)
                              (- (getf hc :gas-before) (getf hc :gas-after))
                              (getf hc :a0-before) (getf hc :a0-after)
                              (getf hc :result)))
                    (format t "  Total host calls: ~D~%"
                            (length (getf trace :host-call-log)))))))
          (error (e)
            (format t "~%ERROR: ~A~%" e)))))))

(dg4-run)
(sb-ext:exit :code 0)
