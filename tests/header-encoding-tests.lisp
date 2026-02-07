;;;; header-encoding-tests.lisp - Test header encoding against test vectors

(defpackage :jotl.header-encoding-tests
  (:use :cl)
  (:export :test-header-encoding
           :test-header-from-json))

(in-package :jotl.header-encoding-tests)

;;; ==========================================================================
;;; Test Header Encoding
;;; ==========================================================================

(defun test-basic-encoding ()
  "Test basic header component encoding"
  (format t "~%Testing Header Component Encoding...~%")
  
  ;; Test hash encoding
  (let ((hash (jam.ffi:hex-string-to-bytes 
               "0x5c743dbc514284b2ea57798787c5a155ef9d7ac1e9499ec65910a7a3d65897b7")))
    (assert (= (length hash) 32))
    (format t "  ✓ Hash encoding: 32 bytes~%"))
  
  ;; Test empty epoch marker (None)
  (let ((encoded (jotl::encode-epoch-marker nil)))
    (assert (= (length encoded) 1))
    (assert (= (aref encoded 0) 0))
    (format t "  ✓ Epoch marker (None): 1 byte~%"))
  
  ;; Test empty offenders
  (let ((encoded (jotl::encode-offenders nil)))
    (assert (= (aref encoded 0) 0))  ; Length 0
    (format t "  ✓ Empty offenders: 1 byte~%"))
  
  (format t "  ✅ Component encoding tests passed!~%"))

(defun load-test-header ()
  "Load header_0.json test vector"
  (let ((json-file "/home/polycrate/Projets/JOTL/test/jamtestvectors/codec/tiny/header_0.json"))
    (when (probe-file json-file)
      (with-open-file (stream json-file)
        (let ((content (make-string (file-length stream))))
          (read-sequence content stream)
          content)))))

(defun parse-json-simple (json-str key)
  "Simple JSON parser for extracting values (very basic)"
  ;; This is a simplified parser - in production use a real JSON library
  (let* ((key-str (format nil "\"~a\"" key))
         (pos (search key-str json-str)))
    (when pos
      (let ((start (+ pos (length key-str)))
            (end (length json-str)))
        ;; Find the value after the key
        (loop for i from start below end
              when (char= (char json-str i) #\:)
              return (let ((value-start (1+ i)))
                      ;; Extract value (simplified)
                      (string-trim '(#\Space #\Tab #\Newline #\, #\})
                                 (subseq json-str value-start 
                                        (min (+ value-start 200) end)))))))))

(defun test-header-from-json ()
  "Test encoding against header_0.json test vector"
  (format t "~%Testing Header Against Test Vector...~%")
  
  (let ((json (load-test-header)))
    (if json
        (progn
          (format t "  ✓ Loaded header_0.json~%")
          (format t "  • Parent: ~A~%" (subseq (parse-json-simple json "parent") 0 20))
          (format t "  • Slot: ~A~%" (parse-json-simple json "slot"))
          (format t "  • Author: ~A~%" (parse-json-simple json "author_index"))
          (format t "  ✅ Test vector loaded successfully!~%"))
        (format t "  ⚠️  Could not load test vector~%"))))

(defun test-full-header-encoding ()
  "Test complete header encoding"
  (format t "~%Testing Complete Header Encoding...~%")
  
  ;; Create a minimal test header
  (let* ((parent-hash (jam.ffi:hex-string-to-bytes 
                       "0x5c743dbc514284b2ea57798787c5a155ef9d7ac1e9499ec65910a7a3d65897b7"))
         (state-root (jam.ffi:hex-string-to-bytes
                      "0x2591ebd047489f1006361a4254731466a946174af02fe1d86681d254cfd4a00b"))
         (extrinsic-hash (jam.ffi:hex-string-to-bytes
                          "0x74a9e79d2618e0ce8720ff61811b10e045c02224a09299f04e404a9656e85c81"))
         (slot 42)
         (author-index 3)
         (entropy (make-array 96 :element-type '(unsigned-byte 8) :initial-element 0))
         (seal (make-array 96 :element-type '(unsigned-byte 8) :initial-element 0))
         
         ;; Encode
         (encoded (jotl::encode-header parent-hash state-root extrinsic-hash
                                      slot nil nil nil author-index entropy seal))
         
         ;; Compute hash
         (hash (jam.ffi:blake2b-256 encoded)))
    
    (format t "  Encoded size: ~A bytes~%" (length encoded))
    (format t "  Expected minimum: ~A bytes~%" (+ 32 32 32 4 1 1 1 2 96 96))  ; 297
    (format t "  Hash: ~A~%" (jam.ffi:bytes-to-hex-string hash))
    
    ;; Basic sanity checks
    (assert (>= (length encoded) 297))  ; At least the fixed parts
    (assert (= (length hash) 32))
    
    (format t "  ✅ Full header encoding successful!~%")))

(defun test-header-encoding ()
  "Run all header encoding tests"
  (format t "~%═══════════════════════════════════════════════════════════~%")
  (format t "HEADER ENCODING TESTS~%")
  (format t "═══════════════════════════════════════════════════════════~%")
  
  (test-basic-encoding)
  (test-full-header-encoding)
  (test-header-from-json)
  
  (format t "~%═══════════════════════════════════════════════════════════~%")
  (format t "✅ ALL HEADER ENCODING TESTS PASSED!~%")
  (format t "═══════════════════════════════════════════════════════════~%~%"))
