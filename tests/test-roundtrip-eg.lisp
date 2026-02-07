;;;; Round-trip test for guarantees encoding
(in-package :jotl)

(let* ((bin (alexandria:read-file-into-byte-vector
             "tests/jamtestvectors/codec/tiny/guarantees_extrinsic.bin")))
  (format t "Original: ~d bytes~%" (length bin))
  ;; decode-guarantees-extrinsic returns (values guarantee-list bytes-consumed)
  (multiple-value-bind (guarantees consumed)
      (decode-guarantees-extrinsic bin 0)
    (format t "Decoded: ~d guarantees, consumed ~d bytes~%" (length guarantees) consumed)
    (handler-case
        (let ((re-encoded (encode-guarantees-extrinsic guarantees)))
          (format t "Re-encoded: ~d bytes~%" (length re-encoded))
          (if (equalp bin re-encoded)
              (format t "~%ROUND-TRIP PERFECT!~%")
              (progn
                (format t "~%MISMATCH~%")
                (format t "  Size diff: ~d vs ~d~%" (length bin) (length re-encoded))
                (loop for i from 0 below (min (length bin) (length re-encoded))
                      when (/= (aref bin i) (aref re-encoded i))
                        do (format t "  First diff at byte ~d: expected 0x~2,'0X got 0x~2,'0X~%"
                                   i (aref bin i) (aref re-encoded i))
                           (return)))))
      (error (e) (format t "~%ENCODE ERROR: ~a~%" e)))))
