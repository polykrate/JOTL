;;;; codec-tests.lisp - Tests for JAM Codec

(defpackage :jotl.codec-tests
  (:use :cl)
  (:export :run-all-codec-tests))

(in-package :jotl.codec-tests)

;;; ==========================================================================
;;; Fixed-Length Integer Encoding Tests (C.12)
;;; ==========================================================================

(defun test-fixed-le-basic ()
  "Test basic fixed-length little-endian encoding"
  (format t "~%Testing Fixed-Length LE Encoding...~%")
  
  ;; u8
  (let ((encoded (jotl:E1 42)))
    (assert (= (length encoded) 1))
    (assert (= (aref encoded 0) 42))
    (assert (= (jotl:decode-fixed-le encoded) 42))
    (format t "  ✓ u8: 42 = ~A~%" encoded))
  
  ;; u16
  (let ((encoded (jotl:E2 258)))  ; 0x0102 in little-endian
    (assert (= (length encoded) 2))
    (assert (= (aref encoded 0) 2))   ; Low byte
    (assert (= (aref encoded 1) 1))   ; High byte
    (assert (= (jotl:decode-fixed-le encoded) 258))
    (format t "  ✓ u16: 258 = ~A~%" encoded))
  
  ;; u32
  (let ((encoded (jotl:E4 #x01020304)))
    (assert (= (length encoded) 4))
    (assert (= (aref encoded 0) #x04))  ; Little-endian
    (assert (= (aref encoded 1) #x03))
    (assert (= (aref encoded 2) #x02))
    (assert (= (aref encoded 3) #x01))
    (assert (= (jotl:decode-fixed-le encoded) #x01020304))
    (format t "  ✓ u32: 0x01020304~%"))
  
  (format t "  ✅ All fixed-length encoding tests passed!~%"))

;;; ==========================================================================
;;; Compact Integer Encoding Tests
;;; ==========================================================================

(defun test-compact-encoding ()
  "Test compact (variable-length) integer encoding"
  (format t "~%Testing Compact Encoding...~%")
  
  ;; Single byte mode (0-63)
  (let ((encoded (jotl:encode-compact 0)))
    (assert (= (length encoded) 1))
    (assert (= (aref encoded 0) 0))
    (assert (= (jotl:decode-compact encoded) 0))
    (format t "  ✓ Compact: 0 = 1 byte~%"))
  
  (let ((encoded (jotl:encode-compact 42)))
    (assert (= (length encoded) 1))
    (assert (= (jotl:decode-compact encoded) 42))
    (format t "  ✓ Compact: 42 = 1 byte~%"))
  
  (let ((encoded (jotl:encode-compact 63)))
    (assert (= (length encoded) 1))
    (assert (= (jotl:decode-compact encoded) 63))
    (format t "  ✓ Compact: 63 = 1 byte~%"))
  
  ;; Two byte mode (64-16383)
  (let ((encoded (jotl:encode-compact 64)))
    (assert (= (length encoded) 2))
    (assert (= (jotl:decode-compact encoded) 64))
    (format t "  ✓ Compact: 64 = 2 bytes~%"))
  
  (let ((encoded (jotl:encode-compact 16383)))
    (assert (= (length encoded) 2))
    (assert (= (jotl:decode-compact encoded) 16383))
    (format t "  ✓ Compact: 16383 = 2 bytes~%"))
  
  ;; Four byte mode (16384 - 2^30-1)
  (let ((encoded (jotl:encode-compact 16384)))
    (assert (= (length encoded) 4))
    (assert (= (jotl:decode-compact encoded) 16384))
    (format t "  ✓ Compact: 16384 = 4 bytes~%"))
  
  (let ((encoded (jotl:encode-compact 1000000)))
    (assert (= (length encoded) 4))
    (assert (= (jotl:decode-compact encoded) 1000000))
    (format t "  ✓ Compact: 1000000 = 4 bytes~%"))
  
  (format t "  ✅ All compact encoding tests passed!~%"))

;;; ==========================================================================
;;; Sequence Encoding Tests
;;; ==========================================================================

(defun test-sequence-encoding ()
  "Test sequence encoding with compact length prefix"
  (format t "~%Testing Sequence Encoding...~%")
  
  ;; Empty sequence
  (let ((encoded (jotl:encode-sequence '() #'jotl:E1)))
    (assert (= (aref encoded 0) 0))  ; Length 0
    (format t "  ✓ Empty sequence~%"))
  
  ;; Sequence of u8
  (let* ((items '(1 2 3 4 5))
         (encoded (jotl:encode-sequence items #'jotl:E1)))
    (assert (= (aref encoded 0) 5))  ; Length 5 (compact)
    (multiple-value-bind (decoded size) 
        (jotl:decode-sequence encoded #'(lambda (bytes offset) 
                                           (values (aref bytes offset) 1)))
      (assert (equal decoded items))
      (format t "  ✓ Sequence [1,2,3,4,5] encoded/decoded~%")))
  
  (format t "  ✅ All sequence encoding tests passed!~%"))

;;; ==========================================================================
;;; Run All Tests
;;; ==========================================================================

(defun run-all-codec-tests ()
  "Run all codec tests"
  (format t "~%═══════════════════════════════════════════════════════════~%")
  (format t "JAM CODEC TESTS~%")
  (format t "═══════════════════════════════════════════════════════════~%")
  
  (test-fixed-le-basic)
  (test-compact-encoding)
  (test-sequence-encoding)
  
  (format t "~%═══════════════════════════════════════════════════════════~%")
  (format t "✅ ALL CODEC TESTS PASSED!~%")
  (format t "═══════════════════════════════════════════════════════════~%~%"))
