;;;; Crypto Utilities
;;;; Helper functions for crypto operations

(in-package :jam.ffi)

;;; ============================================================
;;; Byte Array Utilities
;;; ============================================================

(defun string-to-blob (string)
  "Convert a string to a byte array (UTF-8)."
  (map '(vector (unsigned-byte 8)) #'char-code string))

(defun blob-to-string (blob)
  "Convert a byte array to a string (assuming ASCII/UTF-8)."
  (map 'string #'code-char blob))

(defun hex-string-to-bytes (hex-string)
  "Convert a hex string (with or without 0x prefix) to byte array."
  (let ((hex (if (and (>= (length hex-string) 2)
                      (string-equal (subseq hex-string 0 2) "0x"))
                 (subseq hex-string 2)
                 hex-string)))
    (let ((bytes (make-array (/ (length hex) 2) :element-type '(unsigned-byte 8))))
      (loop for i from 0 below (length bytes)
            for j from 0 by 2
            do (setf (aref bytes i)
                     (parse-integer hex :start j :end (+ j 2) :radix 16)))
      bytes)))

(defun bytes-to-hex-string (bytes &key (prefix t))
  "Convert a byte array to a hex string."
  (with-output-to-string (s)
    (when prefix (write-string "0x" s))
    (loop for byte across bytes
          do (format s "~2,'0x" byte))))
