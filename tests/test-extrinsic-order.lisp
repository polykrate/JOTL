;;;; test-extrinsic-order.lisp - Test Extrinsic Component Order

(ql:quickload :jotl :silent t)
(ql:quickload :jam-crypto :silent t)

(in-package :jotl)

(format t "~%=== Testing Extrinsic Component Order ===~%~%")

;; Load binary
(defparameter *extrinsic-bin*
  (with-open-file (stream "tests/jamtestvectors/codec/tiny/extrinsic.bin"
                          :direction :input
                          :element-type '(unsigned-byte 8))
    (let ((bytes (make-array (file-length stream) :element-type '(unsigned-byte 8))))
      (read-sequence bytes stream)
      bytes)))

(format t "Loaded extrinsic.bin: ~a bytes~%~%" (length *extrinsic-bin*))

;; Decode extrinsic
(format t "Decoding extrinsic...~%")
(handler-case
    (multiple-value-bind (decoded bytes-consumed)
        (decode-extrinsic *extrinsic-bin* 0)
      (format t "✅ Decoded successfully!~%")
      (format t "   Bytes consumed: ~a / ~a~%~%" bytes-consumed (length *extrinsic-bin*))
      
      (format t "Components:~%")
      (format t "  ET (Tickets):   ~a items~%" (length (getf decoded :tickets)))
      (format t "  ED (Disputes):  ~a verdicts, ~a culprits, ~a faults~%"
              (length (getf (getf decoded :disputes) :verdicts))
              (length (getf (getf decoded :disputes) :culprits))
              (length (getf (getf decoded :disputes) :faults)))
      (format t "  EP (Preimages): ~a items~%" (length (getf decoded :preimages)))
      (format t "  EA (Assurances): ~a items~%" (length (getf decoded :assurances)))
      (format t "  EG (Guarantees): ~a items~%~%" (length (getf decoded :guarantees)))
      
      ;; Check if we consumed all bytes
      (if (= bytes-consumed (length *extrinsic-bin*))
          (format t "✅ All bytes consumed! Order is correct!~%")
          (format t "⚠️  Bytes remaining: ~a (possible issue)~%" 
                  (- (length *extrinsic-bin*) bytes-consumed)))
      
      ;; Exit with success
      (sb-ext:exit :code 0))
  (error (e)
    (format t "❌ DECODE FAILED: ~a~%~%" e)
    (format t "Current order in extrinsic.lisp: ET → EP → EG → EA → ED~%")
    (format t "Gray Paper §4.3: E ≡ (ET, ED, EP, EA, EG)~%")
    (format t "~%This is the CORRECTED order based on test vectors.~%")
    (sb-ext:exit :code 1)))
