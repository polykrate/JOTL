;;;; audit-codecs.lisp — Full segment comparison block 6 (pre-commit check)
(in-package :jotl)

(let* ((dir "tests/jamtestvectors/traces/storage"))
  ;; Run ALL blocks 1-10 and report segment match status
  (let ((sigma nil))
    (multiple-value-bind (g-hdr sigma0) (load-genesis (trace-genesis-path dir))
      (declare (ignore g-hdr))
      (setf sigma sigma0))

    (loop for blk-num from 1 to 10 do
      (handler-case
          (multiple-value-bind (pre blk post pre-root post-root)
              (load-trace-step (trace-block-path dir blk-num))
            (declare (ignore pre pre-root post-root))
            (let ((sigma-prime (apply-block sigma blk)))
              (format t "~&Block ~D: " blk-num)
              (let ((all-ok t))
                (dolist (seg '(:alpha :beta :gamma :delta :eta :iota :kappa
                               :lambda :pi :rho :tau :phi :psi :chi :xi))
                  (let ((exp (funcall post :segment seg))
                        (got (funcall sigma-prime :segment seg)))
                    (when (and exp got (not (equalp exp got)))
                      (setf all-ok nil)
                      (format t "~A✗ " seg))))
                (if all-ok
                    (format t "✓ all segments match")
                    (format t ""))
                (terpri))
              (setf sigma sigma-prime)))
        (error (e)
          (format t "~&Block ~D: ERROR ~A~%" blk-num e)
          ;; Try to continue by applying block anyway
          (handler-case
              (multiple-value-bind (pre blk post)
                  (load-trace-step (trace-block-path dir blk-num))
                (declare (ignore pre post))
                (setf sigma (apply-block sigma blk)))
            (error (e2)
              (format t "  (could not apply block: ~A)~%" e2)
              (return))))))))
