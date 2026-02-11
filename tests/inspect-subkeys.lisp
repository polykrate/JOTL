(in-package :jotl)
;; Check xi structure from pre-state for block 6
(with-chain :tiny
  (multiple-value-bind (pre-sigma block post-sigma pre-root post-root)
      (load-trace-step "tests/jamtestvectors/traces/storage/00000006.bin")
    (declare (ignore block post-sigma pre-root post-root))
    (let* ((xi (funcall pre-sigma :load :xi))
           (entries (funcall xi :entries)))
      (format t "E = ~D~%" (epoch-duration))
      (format t "xi entries count = ~D~%" (length entries))
      (loop for slot in entries for i from 0
            do (format t "  xi[~D]: ~D hashes~%" i (length slot))))))
