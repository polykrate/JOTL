;;;; test-header-hash.lisp
;;;; Test header hash computation

(ql:quickload '(:jotl :jam-crypto) :silent t)

(defun test-header-hash ()
  "Test header hash computation."
  (format t "~%╔════════════════════════════════════════════════════════╗~%")
  (format t "║  JOTL - Header Hash Computation Test                  ║~%")
  (format t "╚════════════════════════════════════════════════════════╝~%~%")
  
  (let* ((header-path "/home/polycrate/Projets/JOTL/tests/jamtestvectors/codec/tiny/header_0.bin")
         (header-bytes (with-open-file (stream header-path :element-type '(unsigned-byte 8))
                         (let ((data (make-array (file-length stream) :element-type '(unsigned-byte 8))))
                           (read-sequence data stream)
                           data))))
    
    (format t "Loaded header: ~a bytes~%~%" (length header-bytes))
    
    ;; Decode header
    (format t "Decoding header...~%")
    (multiple-value-bind (decoded-header bytes-consumed)
        (jotl:decode-header header-bytes 0)
      
      (format t "  ✅ Decoded ~a bytes~%~%" bytes-consumed)
      
      ;; Display key fields
      (format t "Header fields:~%")
      (format t "  Slot (HT):      ~a~%" (getf decoded-header :slot))
      (format t "  Author (HI):    ~a~%" (getf decoded-header :author-index))
      (format t "  Epoch mark:     ~a~%" (if (getf decoded-header :epoch-mark) "Some" "None"))
      (format t "  Tickets mark:   ~a~%" (if (getf decoded-header :tickets-mark) "Some" "None"))
      (format t "~%")
      
      ;; Compute hash
      (format t "Computing header hash...~%")
      (let ((computed-hash (jotl:compute-header-hash-from-decoded decoded-header)))
        
        (format t "  ✅ Computed hash: ~a~%~%" 
                (jam.ffi:bytes-to-hex-string computed-hash))
        
        ;; Test: Encode and decode round-trip
        (format t "Testing round-trip (decode → encode → hash)...~%")
        
        (let* ((encoded (jotl:encode-header-unsealed
                         (getf decoded-header :parent-hash)
                         (getf decoded-header :state-root)
                         (getf decoded-header :extrinsic-hash)
                         (getf decoded-header :slot)
                         (getf decoded-header :epoch-mark)
                         (getf decoded-header :tickets-mark)
                         (getf decoded-header :offenders-mark)
                         (getf decoded-header :author-index)
                         (getf decoded-header :entropy-source)))
               (encoded-hash (jam.ffi:blake2b-256 encoded)))
          
          (format t "  Encoded size:    ~a bytes~%" (length encoded))
          (format t "  Encoded hash:    ~a~%" (jam.ffi:bytes-to-hex-string encoded-hash))
          (format t "  Computed hash:   ~a~%" (jam.ffi:bytes-to-hex-string computed-hash))
          (format t "  Match: ~a~%~%" (equalp encoded-hash computed-hash))
          
          (if (equalp encoded-hash computed-hash)
              (format t "✅ PASS: Header hash computation works!~%")
              (format t "❌ FAIL: Hash mismatch!~%")))))))

;; Run the test
(test-header-hash)
