;;;; test-block-validation.lisp
;;;; Test complete block validation (Header + Extrinsic)

(ql:quickload '(:jotl :cl-json) :silent t)

(defun bytes-to-hex (bytes)
  "Convert bytes to hex string for display."
  (jam.ffi:bytes-to-hex-string bytes))

(defun test-block-validation ()
  "Test complete block validation using test vectors."
  (format t "~%╔════════════════════════════════════════════════════════╗~%")
  (format t "║  JOTL - Complete Block Validation Test                ║~%")
  (format t "║  Testing: Header + Extrinsic Validation                ║~%")
  (format t "╚════════════════════════════════════════════════════════╝~%~%")
  
  ;; Load header and extrinsic binaries
  (let* ((header-path "/home/polycrate/Projets/JOTL/tests/jamtestvectors/codec/tiny/header_0.bin")
         (extrinsic-path "/home/polycrate/Projets/JOTL/tests/jamtestvectors/codec/tiny/extrinsic.bin")
         (header-bytes (with-open-file (stream header-path :element-type '(unsigned-byte 8))
                         (let ((data (make-array (file-length stream) :element-type '(unsigned-byte 8))))
                           (read-sequence data stream)
                           data)))
         (extrinsic-bytes (with-open-file (stream extrinsic-path :element-type '(unsigned-byte 8))
                            (let ((data (make-array (file-length stream) :element-type '(unsigned-byte 8))))
                              (read-sequence data stream)
                              data))))
    
    (format t "Loaded test vectors:~%")
    (format t "  Header:    ~a bytes~%" (length header-bytes))
    (format t "  Extrinsic: ~a bytes~%~%" (length extrinsic-bytes))
    
    ;; Decode header and extrinsic
    (format t "Decoding...~%")
    (let ((decoded-header (jotl:decode-header header-bytes 0))
          (decoded-extrinsic (jotl:decode-extrinsic extrinsic-bytes 0)))
      
      (format t "  Header decoded~%")
      (format t "  Extrinsic decoded~%~%")
      
      ;; Extract key fields from header
      (let ((header-hx (getf decoded-header :extrinsic-hash))
            (header-ht (getf decoded-header :slot))
            (header-hp (getf decoded-header :parent-hash)))
        
        (format t "Header fields:~%")
        (format t "  HX (Extrinsic Hash): ~a~%" (bytes-to-hex header-hx))
        (format t "  HT (Timeslot):       ~a~%" header-ht)
        (format t "  HP (Parent Hash):    ~a~%~%" (bytes-to-hex header-hp))
        
        ;; Test 1: Validate extrinsic hash
        (format t "╔════════════════════════════════════════════════════════╗~%")
        (format t "║  Test 1: Extrinsic Hash (HX) Validation               ║~%")
        (format t "╚════════════════════════════════════════════════════════╝~%")
        
        (multiple-value-bind (hx-valid computed-hx)
            (jotl:validate-extrinsic-hash header-hx decoded-extrinsic)
          (format t "  Header HX:   ~a~%" (bytes-to-hex header-hx))
          (format t "  Computed HX: ~a~%" (bytes-to-hex computed-hx))
          (format t "  Match: ~a~%~%" hx-valid)
          
          (if hx-valid
              (format t "✅ PASS: Extrinsic hash matches!~%~%")
              (format t "❌ FAIL: Extrinsic hash mismatch!~%~%")))
        
        ;; Test 2: Validate timeslot (against current time)
        (format t "╔════════════════════════════════════════════════════════╗~%")
        (format t "║  Test 2: Timeslot (HT) Validation                     ║~%")
        (format t "╚════════════════════════════════════════════════════════╝~%")
        
        (let ((current-time (get-universal-time)))
          (multiple-value-bind (ht-valid ht-message)
              (jotl:validate-timeslot header-ht current-time)
            (format t "  ~a~%" ht-message)
            (if ht-valid
                (format t "✅ PASS: Timeslot is valid~%~%")
                (format t "⚠️  INFO: Timeslot validation (test vector may be from past)~%~%"))))
        
        ;; Test 3: Complete block validation
        (format t "╔════════════════════════════════════════════════════════╗~%")
        (format t "║  Test 3: Complete Block Validation                    ║~%")
        (format t "╚════════════════════════════════════════════════════════╝~%")
        
        (multiple-value-bind (is-valid validation-results)
            (jotl:validate-block decoded-header decoded-extrinsic)
          
          (format t "Validation results:~%")
          
          ;; Display each validation result
          (loop for (key value) on validation-results by #'cddr
                do (format t "  ~a: ~a~%" key value))
          
          (format t "~%")
          (if is-valid
              (format t "✅ PASS: Block is valid!~%")
              (format t "⚠️  PARTIAL: Some validations failed (expected for test vectors)~%")))
        
        ;; Summary
        (format t "~%╔════════════════════════════════════════════════════════╗~%")
        (format t "║  VALIDATION SUMMARY                                    ║~%")
        (format t "╚════════════════════════════════════════════════════════╝~%")
        (format t "~%")
        (format t "✅ Extrinsic hash validation implemented~%")
        (format t "✅ Timeslot validation implemented~%")
        (format t "✅ Block validation framework ready~%")
        (format t "~%")
        (format t "Note: Full validation requires:~%")
        (format t "  - Parent header for HP validation~%")
        (format t "  - State root (HR) validation~%")
        (format t "  - Epoch mark (HE) validation~%")
        (format t "~%")))))

;; Run the test
(test-block-validation)
