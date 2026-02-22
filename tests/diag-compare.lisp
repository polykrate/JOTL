;;;; diag-compare.lisp — Compare passing vs failing block theta
(in-package #:jotl)

(defun diag-compare-blocks (passing-block failing-block)
  "Compare host call traces between a passing and failing block."
  (format t "~%===== PASSING BLOCK ~D =====~%" passing-block)
  (diag-block-full passing-block)
  (format t "~%===== FAILING BLOCK ~D =====~%" failing-block)
  (diag-block-full failing-block))

(defun diag-block-full (n)
  "Run block N with full debug tracing, print theta match + HC details."
  (let* ((dir "tests/jamtestvectors/traces/fuzzy/")
         (step-path (trace-block-path dir n))
         (bytes (alexandria:read-file-into-byte-vector step-path)))
    (multiple-value-bind (pre-sigma block-cl post-sigma pre-root post-root)
        (decode-trace-step-bin bytes)
      (declare (ignore pre-root post-root))
      (let ((*chain-log-level* nil)
            (*debug-pvm-trace* t)
            (*debug-pvm-traces* nil))
        (declare (special *chain-log-level* *debug-pvm-trace* *debug-pvm-traces*))
        (multiple-value-bind (sigma-prime computed-root)
            (import-block pre-sigma block-cl)
          (declare (ignore computed-root))
          (let ((exp-theta (funcall post-sigma :segment :theta))
                (got-theta (funcall sigma-prime :segment :theta)))
            (format t "~%--- Block ~D theta ---~%" n)
            (format t "Match: ~A~%" (equalp exp-theta got-theta))
            (format t "exp-theta(~D bytes): ~{~2,'0X~^ ~}~%"
                    (length exp-theta) (coerce (subseq exp-theta 0 (min 80 (length exp-theta))) 'list))
            (format t "got-theta(~D bytes): ~{~2,'0X~^ ~}~%"
                    (length got-theta) (coerce (subseq got-theta 0 (min 80 (length got-theta))) 'list))
            ;; Print collected PVM traces
            (dolist (entry (reverse *debug-pvm-traces*))
              (format t "~%  SID=~D outcome=~A yield?=~A~%"
                      (getf entry :service-id)
                      (getf entry :outcome)
                      (if (getf entry :yield-hash) t nil))
              (when (getf entry :yield-hash)
                (format t "  yield-hash: ~{~2,'0X~}~%"
                        (coerce (getf entry :yield-hash) 'list)))
              (format t "  host-calls(~D):~%" (length (getf entry :host-call-log)))
              (dolist (hc (reverse (getf entry :host-call-log)))
                (format t "    ~A~%" hc)))))))))
