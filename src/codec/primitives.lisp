;;;; primitives.lisp - JAM Codec (Gray Paper Appendix C)
;;;; NOT SCALE! JAM has its own encoding, especially for compact integers.

(in-package :jotl)

;;; ==========================================================================
;;; C.1.7 - Fixed-Length Integer Encoding (Gray Paper C.12)
;;; ==========================================================================
;;;
;;; El : N_2^(8l) → B_l
;;; Encodes natural numbers in little-endian fashion
;;; Used for almost all integer encoding across the protocol
;;;
;;; E_l(x) = {
;;;   []                           if l = 0
;;;   [x mod 256] ⌢ E_(l-1)(⌊x/256⌋)  otherwise
;;; }

(defun encode-fixed-le (value num-bytes)
  "Encode VALUE as NUM-BYTES in little-endian (Gray Paper C.12).
   
   Args:
     value: Natural number to encode
     num-bytes: Number of bytes to use (1, 2, 4, 8, etc.)
   
   Returns:
     Byte array of length num-bytes"
  (check-type value (integer 0 *))
  (check-type num-bytes (integer 1 *))
  
  (when (>= value (expt 2 (* 8 num-bytes)))
    (error "Value ~A too large for ~A bytes" value num-bytes))
  
  (let ((result (make-array num-bytes :element-type '(unsigned-byte 8))))
    (loop for i from 0 below num-bytes
          do (setf (aref result i) (ldb (byte 8 (* 8 i)) value)))
    result))

(defun decode-fixed-le (bytes)
  "Decode little-endian bytes to natural number (Gray Paper C.12).
   
   Args:
     bytes: Byte array
   
   Returns:
     Natural number"
  (let ((result 0))
    (loop for i from 0 below (length bytes)
          do (setf result (logior result (ash (aref bytes i) (* 8 i)))))
    result))

;; Convenience aliases for common sizes (Gray Paper notation)
(defun E1 (value) "Encode u8"  (encode-fixed-le value 1))
(defun E2 (value) "Encode u16" (encode-fixed-le value 2))
(defun E4 (value) "Encode u32" (encode-fixed-le value 4))
(defun E8 (value) "Encode u64" (encode-fixed-le value 8))

;; User-friendly named aliases
(defun encode-u8 (value) "Encode u8" (encode-fixed-le value 1))
(defun encode-u16 (value) "Encode u16" (encode-fixed-le value 2))
(defun encode-u32 (value) "Encode u32" (encode-fixed-le value 4))
(defun encode-u64 (value) "Encode u64" (encode-fixed-le value 8))

(defun decode-u8 (bytes &optional (offset 0))
  "Decode u8 from bytes at offset.
   Returns: (values decoded-value bytes-consumed)"
  (values (decode-fixed-le (subseq bytes offset (+ offset 1))) 1))

(defun decode-u16 (bytes &optional (offset 0))
  "Decode u16 from bytes at offset.
   Returns: (values decoded-value bytes-consumed)"
  (values (decode-fixed-le (subseq bytes offset (+ offset 2))) 2))

(defun decode-u32 (bytes &optional (offset 0))
  "Decode u32 from bytes at offset.
   Returns: (values decoded-value bytes-consumed)"
  (values (decode-fixed-le (subseq bytes offset (+ offset 4))) 4))

(defun decode-u64 (bytes &optional (offset 0))
  "Decode u64 from bytes at offset.
   Returns: (values decoded-value bytes-consumed)"
  (values (decode-fixed-le (subseq bytes offset (+ offset 8))) 8))

;;; ==========================================================================
;;; JAM Compact Integer Encoding (GP Appendix C.1.5)
;;; ==========================================================================
;;;
;;; ⚠️  THIS IS NOT SCALE COMPACT! JAM uses a different scheme!
;;;
;;; The number of leading 1-bits in the first byte determines how many
;;; additional bytes follow. Value stored big-endian in remaining bits.
;;;
;;; Leading 1s | Total bytes | Data bits | Max value
;;; -----------+-------------+-----------+-----------
;;;     0      |      1      |     7     |       127
;;;     1      |      2      |    14     |    16,383
;;;     2      |      3      |    21     | 2,097,151
;;;     3      |      4      |    28     | ~268M
;;;     4      |      5      |    35     | ~34B
;;;     5      |      6      |    42     | ~4T
;;;     6      |      7      |    49     | ~562T
;;;     7      |      8      |    56     | ~72P
;;;     8      |      9      |    64     | 2^64-1

(defun count-leading-ones (byte)
  "Count the number of leading 1-bits in a byte (MSB first)."
  (loop for i from 7 downto 0
        while (logbitp i byte)
        count 1))

(defun encode-compact (value)
  "Encode natural number in JAM compact format.
   
   JAM compact encoding (NOT SCALE!):
   Number of leading 1-bits in first byte = number of additional bytes.
   Value stored big-endian in remaining bits.
   
   Args:
     value: Natural number (usually a length or small integer)
   
   Returns:
     Byte array (1-9 bytes)"
  (check-type value (integer 0 *))
  
  (cond
    ;; 1 byte: 0xxxxxxx (0-127)
    ((< value #x80)
     (make-array 1 :element-type '(unsigned-byte 8)
                 :initial-contents (list value)))
    
    ;; 2 bytes: 10xxxxxx xxxxxxxx (128-16383)
    ((< value #x4000)
     (make-array 2 :element-type '(unsigned-byte 8)
                 :initial-contents
                 (list (logior #x80 (ash value -8))
                       (logand value #xFF))))
    
    ;; 3 bytes: 110xxxxx xxxxxxxx xxxxxxxx (16384-2097151)
    ((< value #x200000)
     (make-array 3 :element-type '(unsigned-byte 8)
                 :initial-contents
                 (list (logior #xC0 (ash value -16))
                       (logand (ash value -8) #xFF)
                       (logand value #xFF))))
    
    ;; 4 bytes: 1110xxxx xxxxxxxx xxxxxxxx xxxxxxxx
    ((< value #x10000000)
     (make-array 4 :element-type '(unsigned-byte 8)
                 :initial-contents
                 (list (logior #xE0 (ash value -24))
                       (logand (ash value -16) #xFF)
                       (logand (ash value -8) #xFF)
                       (logand value #xFF))))
    
    ;; 5 bytes: 11110xxx ...
    ((< value #x800000000)
     (make-array 5 :element-type '(unsigned-byte 8)
                 :initial-contents
                 (list (logior #xF0 (ash value -32))
                       (logand (ash value -24) #xFF)
                       (logand (ash value -16) #xFF)
                       (logand (ash value -8) #xFF)
                       (logand value #xFF))))
    
    ;; 6 bytes: 111110xx ...
    ((< value #x40000000000)
     (make-array 6 :element-type '(unsigned-byte 8)
                 :initial-contents
                 (list (logior #xF8 (ash value -40))
                       (logand (ash value -32) #xFF)
                       (logand (ash value -24) #xFF)
                       (logand (ash value -16) #xFF)
                       (logand (ash value -8) #xFF)
                       (logand value #xFF))))
    
    ;; 7 bytes: 1111110x ...
    ((< value #x2000000000000)
     (make-array 7 :element-type '(unsigned-byte 8)
                 :initial-contents
                 (list (logior #xFC (ash value -48))
                       (logand (ash value -40) #xFF)
                       (logand (ash value -32) #xFF)
                       (logand (ash value -24) #xFF)
                       (logand (ash value -16) #xFF)
                       (logand (ash value -8) #xFF)
                       (logand value #xFF))))
    
    ;; 8 bytes: 11111110 xxxxxxxx ... (7 data bytes, 56 bits)
    ((< value #x100000000000000)
     (make-array 8 :element-type '(unsigned-byte 8)
                 :initial-contents
                 (list #xFE
                       (logand (ash value -48) #xFF)
                       (logand (ash value -40) #xFF)
                       (logand (ash value -32) #xFF)
                       (logand (ash value -24) #xFF)
                       (logand (ash value -16) #xFF)
                       (logand (ash value -8) #xFF)
                       (logand value #xFF))))
    
    ;; 9 bytes: 11111111 xxxxxxxx ... (8 data bytes, 64 bits)
    (t
     (make-array 9 :element-type '(unsigned-byte 8)
                 :initial-contents
                 (list #xFF
                       (logand (ash value -56) #xFF)
                       (logand (ash value -48) #xFF)
                       (logand (ash value -40) #xFF)
                       (logand (ash value -32) #xFF)
                       (logand (ash value -24) #xFF)
                       (logand (ash value -16) #xFF)
                       (logand (ash value -8) #xFF)
                       (logand value #xFF))))))

(defun decode-compact (bytes &optional (offset 0))
  "Decode JAM compact-encoded natural number.
   
   JAM compact encoding (NOT SCALE!):
   Number of leading 1-bits in first byte = number of additional bytes.
   Value stored big-endian in remaining bits.
   
   Args:
     bytes: Byte array containing compact-encoded value
     offset: Starting position in bytes (default 0)
   
   Returns:
     (values decoded-value bytes-consumed)"
  (let* ((first-byte (aref bytes offset))
         (l (count-leading-ones first-byte))
         (total-bytes (1+ l)))
    (if (= l 8)
        ;; Special case: first byte = 0xFF, 8 data bytes following
        (let ((value 0))
          (loop for i from 1 to 8
                do (setf value (logior (ash value 8)
                                       (aref bytes (+ offset i)))))
          (values value 9))
        ;; General case: l leading 1s + separator 0, remaining bits + l more bytes
        (let* ((data-bits (- 7 l))
               (mask (1- (ash 1 data-bits)))
               (value (logand first-byte mask)))
          ;; Read remaining bytes in big-endian order
          (loop for i from 1 to l
                do (setf value (logior (ash value 8)
                                       (aref bytes (+ offset i)))))
          (values value total-bytes)))))

;;; ==========================================================================
;;; Sequence Encoding (with compact length prefix)
;;; ==========================================================================

(defun encode-sequence (items encoder-fn)
  "Encode a sequence with compact length prefix.
   
   Format: [compact-length] [item1] [item2] ...
   
   Args:
     items: List or vector of items to encode
     encoder-fn: Function to encode each item (item → bytes)
   
   Returns:
     Byte array"
  (let* ((length (length items))
         (length-prefix (encode-compact length))
         (encoded-items (mapcar encoder-fn (coerce items 'list))))
    (apply #'concatenate '(vector (unsigned-byte 8))
           length-prefix
           encoded-items)))

(defun decode-sequence (bytes decoder-fn &optional (offset 0))
  "Decode a sequence with compact length prefix.
   
   Args:
     bytes: Byte array
     decoder-fn: Function to decode each item (bytes offset → (values item bytes-consumed))
     offset: Starting position (default 0)
   
   Returns:
     (values items-list total-bytes-consumed)"
  (multiple-value-bind (length bytes-consumed) (decode-compact bytes offset)
    (let ((items '())
          (pos (+ offset bytes-consumed)))
      (dotimes (i length)
        (multiple-value-bind (item item-size) (funcall decoder-fn bytes pos)
          (push item items)
          (incf pos item-size)))
      (values (nreverse items) (- pos offset)))))

;;; ==========================================================================
;;; Option Encoding
;;; ==========================================================================

(defun encode-option (value encoder-fn)
  "Encode an Option<T> type.
   
   Format:
     None: [0x00]
     Some: [0x01] [encoded-value]
   
   Args:
     value: NIL for None, or actual value for Some
     encoder-fn: Function to encode the value
   
   Returns:
     Byte array"
  (if value
      (concatenate '(vector (unsigned-byte 8))
                   #(1)
                   (funcall encoder-fn value))
      #(0)))

(defun decode-option (bytes decoder-fn &optional (offset 0))
  "Decode an Option<T> type.
   
   Returns:
     (values value-or-nil bytes-consumed)"
  (if (zerop (aref bytes offset))
      (values nil 1)
      (multiple-value-bind (value size) (funcall decoder-fn bytes (1+ offset))
        (values value (1+ size)))))

;;; ==========================================================================
;;; Result Encoding
;;; ==========================================================================

(defun encode-result (value ok-encoder err-encoder)
  "Encode a Result<T, E> type.
   
   Format:
     Ok:  [0x00] [ok-value]
     Err: [0x01] [err-value]"
  (etypecase value
    (cons 
     (ecase (car value)
       (:ok  (concatenate '(vector (unsigned-byte 8)) #(0) (funcall ok-encoder (cdr value))))
       (:err (concatenate '(vector (unsigned-byte 8)) #(1) (funcall err-encoder (cdr value))))))))

;;; ==========================================================================
;;; Exports
;;; ==========================================================================

(export '(encode-fixed-le decode-fixed-le
          E1 E2 E4 E8
          encode-u8 encode-u16 encode-u32 encode-u64
          decode-u8 decode-u16 decode-u32 decode-u64
          count-leading-ones
          encode-compact decode-compact
          encode-sequence decode-sequence
          encode-option decode-option
          encode-result))
