;;;; Round-trip test for ALL extrinsic components + full extrinsic
(in-package :jotl)

(defun load-tiny (name)
  (alexandria:read-file-into-byte-vector
   (merge-pathnames name "tests/jamtestvectors/codec/tiny/")))

(defun test-rt (label bin decode-fn encode-fn)
  "Test round-trip: decode then re-encode, compare bytes."
  (handler-case
      (multiple-value-bind (decoded consumed)
          (funcall decode-fn bin 0)
        (let ((re-encoded (funcall encode-fn decoded)))
          (format t "~a: ~d bytes, decoded ~d, re-encoded ~d ~a~%"
                  label (length bin) consumed (length re-encoded)
                  (if (equalp bin re-encoded) "OK" "FAIL"))))
    (error (e) (format t "~a: ERROR: ~a~%" label e))))

;; ET
(test-rt "ET (Tickets)"
         (load-tiny "tickets_extrinsic.bin")
         #'decode-tickets-extrinsic
         #'encode-tickets-extrinsic)

;; EP
(test-rt "EP (Preimages)"
         (load-tiny "preimages_extrinsic.bin")
         #'decode-preimages-extrinsic
         #'encode-preimages-extrinsic)

;; EA
(test-rt "EA (Assurances)"
         (load-tiny "assurances_extrinsic.bin")
         #'decode-assurances-extrinsic
         #'encode-assurances-extrinsic)

;; ED
(test-rt "ED (Disputes)"
         (load-tiny "disputes_extrinsic.bin")
         #'decode-disputes-extrinsic
         #'encode-disputes-extrinsic)

;; EG
(test-rt "EG (Guarantees)"
         (load-tiny "guarantees_extrinsic.bin")
         #'decode-guarantees-extrinsic
         #'encode-guarantees-extrinsic)

;; Full Extrinsic
(format t "~%--- Full Extrinsic ---~%")
(let ((bin (load-tiny "extrinsic.bin")))
  (handler-case
      (multiple-value-bind (decoded consumed)
          (decode-extrinsic bin 0)
        (format t "Full extrinsic: ~d bytes decoded, consumed ~d~%" (length bin) consumed)
        (let ((re-encoded (encode-extrinsic
                           (getf decoded :tickets)
                           (getf decoded :disputes)
                           (getf decoded :preimages)
                           (getf decoded :assurances)
                           (getf decoded :guarantees))))
          (format t "Re-encoded: ~d bytes ~a~%"
                  (length re-encoded)
                  (if (equalp bin re-encoded) "OK" "FAIL"))
          (when (not (equalp bin re-encoded))
            (loop for i from 0 below (min (length bin) (length re-encoded))
                  when (/= (aref bin i) (aref re-encoded i))
                    do (format t "  First diff at byte ~d: expected 0x~2,'0X got 0x~2,'0X~%"
                               i (aref bin i) (aref re-encoded i))
                       (return)))))
    (error (e) (format t "Full extrinsic ERROR: ~a~%" e))))
