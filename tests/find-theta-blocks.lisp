;;;; find-theta-blocks.lisp — Find blocks with non-empty theta
(in-package #:jotl)

(defun find-theta-blocks ()
  (let ((dir "tests/jamtestvectors/traces/fuzzy/"))
    (dolist (blk (loop for i from 1 to 200 collect i))
      (handler-case
        (let* ((step-path (trace-block-path dir blk))
               (bytes (alexandria:read-file-into-byte-vector step-path)))
          (multiple-value-bind (pre-sigma block-cl post-sigma pre-root post-root)
              (decode-trace-step-bin bytes)
            (declare (ignore pre-sigma block-cl pre-root post-root))
            (let ((theta (funcall post-sigma :segment :theta)))
              (when (and theta (plusp (length theta)) (> (length theta) 1))
                (format t "Block ~3D: theta ~D bytes~%" blk (length theta))))))
        (error (e) (declare (ignore e)))))))
