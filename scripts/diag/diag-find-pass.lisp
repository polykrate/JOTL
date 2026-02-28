;;; diag-find-pass.lisp — Find traces where service 0 is accumulated
(in-package #:jotl)

(let ((traces-dir (merge-pathnames
                   "../jam-conformance/fuzz-reports/0.7.2/traces/"
                   (asdf:system-source-directory :jotl)))
      (found 0)
      (checked 0)
      (total 0))
  (dolist (trace-dir (directory (merge-pathnames "*/" traces-dir)))
    (when (> found 5) (return))
    (let* ((trace-id (car (last (pathname-directory trace-dir))))
           (steps (sort (directory (merge-pathnames "*.bin" trace-dir))
                        #'string< :key #'namestring)))
      (dolist (step-path steps)
        (when (> found 5) (return))
        (incf total)
        (handler-case
            (let* ((bytes (alexandria:read-file-into-byte-vector step-path))
                   (step-name (pathname-name step-path)))
              (multiple-value-bind (pre-sigma block-cl post-sigma)
                  (decode-trace-step-bin bytes)
                (declare (ignore post-sigma))
                ;; Check chi
                (let* ((chi (handler-case (funcall pre-sigma :load :chi) (error () nil)))
                       (always-accum (when chi (funcall chi :always-accum))))
                  (when (and always-accum (find 0 always-accum :key #'car))
                    (incf checked)
                    (when (< checked 20)
                      (format t "SVC0: ~A / ~A (always-accum gas=~D)~%"
                              trace-id step-name
                              (cdr (find 0 always-accum :key #'car))))
                    ;; Try import
                    (let ((*chain-log-level* nil)
                          (*debug-pvm-trace* nil))
                      (handler-case
                          (multiple-value-bind (sigma-prime root)
                              (import-block pre-sigma block-cl)
                            (declare (ignore root sigma-prime))
                            (incf found))
                        (error (e)
                          (when (< checked 20)
                            (format t "  ERR: ~A~%" e)))))))))
          (error (e) nil)))))
  (format t "~%Total steps: ~D, with svc0: ~D, passing: ~D~%" total checked found))

(sb-ext:exit :code 0)
