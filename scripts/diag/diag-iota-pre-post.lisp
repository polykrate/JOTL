;;; diag-iota-pre-post.lisp — Compare IOTA pre-state vs expected post-state
;;; If they differ, the reference impl successfully ran omega-designate (no panic)
(in-package #:jotl)

(defun dipp-trace-dir (trace-id)
  (let ((base (asdf:system-source-directory :jotl)))
    (merge-pathnames
     (format nil "../jam-conformance/fuzz-reports/0.7.2/traces/~A/" trace-id)
     base)))

(defun dipp-run (trace-id step)
  (format t "~%=== IOTA PRE vs POST: ~A / ~A ===~%" trace-id step)
  (let* ((dir (dipp-trace-dir trace-id))
         (step-path (merge-pathnames (format nil "~A.bin" step) dir))
         (bytes (alexandria:read-file-into-byte-vector step-path)))
    (multiple-value-bind (pre-sigma block-cl post-sigma)
        (decode-trace-step-bin bytes)
      (declare (ignore block-cl))

      (let* ((pre-iota (funcall pre-sigma :load :iota))
             (exp-iota (funcall post-sigma :load :iota))
             (pre-bytes (funcall pre-iota :save))
             (exp-bytes (funcall exp-iota :save)))
        (format t "  pre IOTA: ~D bytes~%" (length pre-bytes))
        (format t "  exp IOTA: ~D bytes~%" (length exp-bytes))
        (if (equalp pre-bytes exp-bytes)
            (format t "  IOTA pre==exp → reference also PANICKED (no designate changes)~%")
            (progn
              (format t "  IOTA pre!=exp → reference SUCCEEDED (designate changes applied)~%")
              ;; Show first difference
              (loop for i from 0 below (min (length pre-bytes) (length exp-bytes))
                    when (not (= (aref pre-bytes i) (aref exp-bytes i)))
                    do (format t "  First diff at byte ~D: pre=~2,'0X exp=~2,'0X~%" i (aref pre-bytes i) (aref exp-bytes i))
                       (return))))

        ;; Also check pre-delta vs exp-delta
        (let* ((pre-delta (funcall pre-sigma :load :delta))
               (exp-delta (funcall post-sigma :load :delta))
               (pre-d-bytes (funcall pre-delta :save))
               (exp-d-bytes (funcall exp-delta :save)))
          (format t "~%  pre DELTA: ~D bytes~%" (length pre-d-bytes))
          (format t "  exp DELTA: ~D bytes~%" (length exp-d-bytes))
          (if (equalp pre-d-bytes exp-d-bytes)
              (format t "  DELTA pre==exp → no storage changes in reference~%")
              (format t "  DELTA pre!=exp → reference made storage changes~%")))))))

(dipp-run "1766479507_7943" "00000018")
(sb-ext:exit :code 0)
