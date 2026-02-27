;;;; diag/diag-hc-count.lisp — Count host calls for the divergent service
;;;;
;;;; Tests the hypothesis: ecalli costs 1 gas (instruction) + 10 (host-dispatch) = 11,
;;;; but GP says total should be 10. If 62 host calls → Δ=62.

(in-package :jotl)

(defvar *dhc-trace-id* "1767895984_7922")
(defvar *dhc-step* "00000061")

(defun dhc-trace-dir ()
  (merge-pathnames (format nil "../jam-conformance/fuzz-reports/0.7.2/traces/~A/"
                           *dhc-trace-id*)
                   (truename (asdf:system-source-directory :jotl))))

(defun dhc-run ()
  (format t "~%=== HOST CALL COUNT DIAGNOSTIC ===~%")
  (format t "Trace: ~A  Step: ~A~%" *dhc-trace-id* *dhc-step*)
  (format t "Hypothesis: ecalli costs 1+10=11, should be 10. Δ=1 per host call.~%")

  (let* ((step-path (merge-pathnames (format nil "~A.bin" *dhc-step*)
                                     (dhc-trace-dir)))
         (bytes (alexandria:read-file-into-byte-vector step-path)))
    (multiple-value-bind (pre-sigma block-cl post-sigma pre-root post-root)
        (decode-trace-step-bin bytes)
      (declare (ignore post-sigma pre-root post-root))

      ;; Enable PVM debug tracing
      (let ((*debug-pvm-trace* t)
            (*debug-pvm-traces* nil)
            (*chain-log-level* nil))

        ;; Run the block
        (import-block pre-sigma block-cl)

        ;; Check host call counts
        (format t "~%=== HOST CALL TRACES ===~%")
        (format t "Number of PVM traces: ~D~%" (length *debug-pvm-traces*))
        (dolist (trace (reverse *debug-pvm-traces*))
          (let* ((sid (getf trace :sid))
                 (gas-limit (getf trace :gas-limit))
                 (gas-used (getf trace :gas-used))
                 (log (getf trace :host-call-log))
                 (hc-count (length (or log nil))))
            (format t "~%  sid=~D gas-limit=~D gas-used=~D host-calls=~D~%"
                    sid gas-limit gas-used hc-count)
            (when (= sid 3101749195)
              (format t "  >>> TARGET SERVICE <<<~%")
              (format t "  If Δ=1 per HC: predicted Δ = ~D~%" hc-count)
              (format t "  Actual Δ = 62~%")
              (format t "  Match? ~A~%" (if (= hc-count 62) "YES!!!" "NO"))
              ;; Show host call breakdown
              (let ((hc-counts (make-hash-table)))
                (dolist (entry log)
                  (let ((id (getf entry :id)))
                    (incf (gethash id hc-counts 0))))
                (format t "  Host call breakdown:~%")
                (maphash (lambda (id count)
                           (format t "    HC~D: ~D times~%" id count))
                         hc-counts)))))))))

(dhc-run)
(format t "~%Done.~%")
(sb-ext:exit :code 0)
