;;;; diag/diag-gas.lisp — Diagnose accumulate gas divergence
;;;;
;;;; Shows per-service gas entries from accumulate to find the Δ=62 source.

(in-package :jotl)

(defvar *dg-trace-id* "1767895984_7922")
(defvar *dg-step* "00000061")

(defun dg-trace-dir ()
  (merge-pathnames (format nil "../jam-conformance/fuzz-reports/0.7.2/traces/~A/"
                           *dg-trace-id*)
                   (truename (asdf:system-source-directory :jotl))))

(defun dg-run ()
  (format t "~%=== GAS DIAGNOSTIC ===~%")
  (format t "Trace: ~A  Step: ~A~%" *dg-trace-id* *dg-step*)

  (let* ((step-path (merge-pathnames (format nil "~A.bin" *dg-step*)
                                     (dg-trace-dir)))
         (bytes (alexandria:read-file-into-byte-vector step-path)))
    (multiple-value-bind (pre-sigma block-cl post-sigma pre-root post-root)
        (decode-trace-step-bin bytes)
      (declare (ignore pre-root post-root))

      ;; Show block info
      (let* ((header (funcall block-cl :header))
             (ts (funcall header :timeslot)))
        (format t "Block timeslot: ~D~%" ts))

      ;; Bind *debug-pvm-trace* to trace gas details
      (let ((*debug-pvm-trace* t)
            (*debug-pvm-traces* nil)
            (*chain-log-level* nil))

        (handler-case
            (let ((sigma-prime (import-block pre-sigma block-cl)))
              ;; Show all collected gas traces
              (format t "~%=== PVM TRACES (reversed) ===~%")
              (dolist (trace (reverse *debug-pvm-traces*))
                (format t "  sid=~D gas-limit=~D gas-used=~D outcome=~D~%"
                        (getf trace :sid)
                        (getf trace :gas-limit)
                        (getf trace :gas-used)
                        (getf trace :outcome)))

              ;; Also look at the computed gas-usage in the state
              ;; It's stored in :gas-usage of the accum-state

              ;; Compare PI
              (let* ((computed-pi (funcall sigma-prime :segment :pi))
                     (expected-pi (funcall post-sigma :segment :pi)))
                (if (equalp computed-pi expected-pi)
                    (format t "~%PI: MATCH~%")
                    (format t "~%PI: MISMATCH (c=~D e=~D bytes)~%"
                            (length computed-pi) (length expected-pi)))))
          (error (e)
            (format t "~%ERROR: ~A~%" e)))))))

(dg-run)
(sb-ext:exit :code 0)
