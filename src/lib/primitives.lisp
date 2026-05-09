;;;; primitives.lisp - JAM Codec (Gray Paper Appendix C)
;;;; NOT SCALE! JAM has its own encoding, especially for compact integers.

(in-package #:jotl)

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
  (declare (optimize (speed 3) (safety 1)))
  (let ((result (make-array num-bytes :element-type '(unsigned-byte 8))))
    (loop for i fixnum from 0 below num-bytes
          do (setf (aref result i) (ldb (byte 8 (the fixnum (* 8 i))) value)))
    result))

(declaim (inline E4 E8))

(defun E4 (value)
  "Encode u32. Specialized fast path — no check-type, no expt."
  (declare (optimize (speed 3) (safety 1)))
  (let ((buf (make-array 4 :element-type '(unsigned-byte 8))))
    (setf (aref buf 0) (logand value #xFF)
          (aref buf 1) (logand (ash value -8) #xFF)
          (aref buf 2) (logand (ash value -16) #xFF)
          (aref buf 3) (logand (ash value -24) #xFF))
    buf))

(defun E8 (value)
  "Encode u64. Specialized fast path — no check-type, no expt."
  (declare (optimize (speed 3) (safety 1)))
  (let ((buf (make-array 8 :element-type '(unsigned-byte 8))))
    (setf (aref buf 0) (logand value #xFF)
          (aref buf 1) (logand (ash value -8) #xFF)
          (aref buf 2) (logand (ash value -16) #xFF)
          (aref buf 3) (logand (ash value -24) #xFF)
          (aref buf 4) (logand (ash value -32) #xFF)
          (aref buf 5) (logand (ash value -40) #xFF)
          (aref buf 6) (logand (ash value -48) #xFF)
          (aref buf 7) (logand (ash value -56) #xFF))
    buf))

(defun decode-fixed-le (bytes &optional (offset 0) (n (- (length bytes) offset)))
  "Decode little-endian bytes to natural number (Gray Paper C.12).
   When OFFSET and N are supplied, reads N bytes starting at OFFSET
   directly from BYTES, avoiding subseq allocation."
  (declare (optimize (speed 3) (safety 1)))
  (declare (type fixnum n offset))
  (let ((result 0))
    (loop for i fixnum from 0 below n
          do (setf result (logior result (ash (aref bytes (the fixnum (+ offset i)))
                                             (the fixnum (* 8 i))))))
    result))

;; Convenience aliases for common sizes (Gray Paper notation)
(defun E1 (value) "Encode u8"  (encode-fixed-le value 1))
(defun E2 (value) "Encode u16" (encode-fixed-le value 2))
;; E4 and E8 are defined above as specialized fast-path functions

;; User-friendly named aliases
(defun encode-u8 (value) "Encode u8" (encode-fixed-le value 1))
(defun encode-u16 (value) "Encode u16" (encode-fixed-le value 2))
(defun encode-u32 (value) "Encode u32" (E4 value))
(defun encode-u64 (value) "Encode u64" (E8 value))

(declaim (inline decode-u8 decode-u16 decode-u32 decode-u64))

(defun decode-u8 (bytes &optional (offset 0))
  "Decode u8 from bytes at offset. Zero-alloc.
   Returns: (values decoded-value bytes-consumed)"
  (declare (optimize (speed 3) (safety 1)))
  (values (aref bytes offset) 1))

(defun decode-u16 (bytes &optional (offset 0))
  "Decode u16 from bytes at offset. Zero-alloc.
   Returns: (values decoded-value bytes-consumed)"
  (declare (optimize (speed 3) (safety 1)))
  (values (logior (aref bytes offset)
                  (ash (aref bytes (+ offset 1)) 8))
          2))

(defun decode-u32 (bytes &optional (offset 0))
  "Decode u32 from bytes at offset. Zero-alloc.
   Returns: (values decoded-value bytes-consumed)"
  (declare (optimize (speed 3) (safety 1)))
  (values (logior (aref bytes offset)
                  (ash (aref bytes (+ offset 1)) 8)
                  (ash (aref bytes (+ offset 2)) 16)
                  (ash (aref bytes (+ offset 3)) 24))
          4))

(defun decode-u64 (bytes &optional (offset 0))
  "Decode u64 from bytes at offset. Zero-alloc.
   Returns: (values decoded-value bytes-consumed)"
  (declare (optimize (speed 3) (safety 1)))
  (values (logior (aref bytes offset)
                  (ash (aref bytes (+ offset 1)) 8)
                  (ash (aref bytes (+ offset 2)) 16)
                  (ash (aref bytes (+ offset 3)) 24)
                  (ash (aref bytes (+ offset 4)) 32)
                  (ash (aref bytes (+ offset 5)) 40)
                  (ash (aref bytes (+ offset 6)) 48)
                  (ash (aref bytes (+ offset 7)) 56))
          8))

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
  "Encode natural number in JAM compact format (Gray Paper C.5).
   
   Formula C.5:
     E(x) = [0]                                              if x = 0
     E(x) = [2⁸-2^(8-l) + ⌊x/2^(8l)⌋] ⌢ E_l(x mod 2^(8l)) if ∃l∈N₈: 2^(7l)≤x<2^(7(l+1))
     E(x) = [2⁸-1] ⌢ E₈(x)                                  otherwise (x < 2⁶⁴)
   
   Where E_l is little-endian fixed-length encoding (C.12).
   
   Leading 1-bits in first byte = number of additional bytes.
   Header byte contains high bits of value.
   Remaining bytes are the LOW part in LITTLE-ENDIAN order.
   
   Args:
     value: Natural number (0 to 2^64-1)
   
   Returns:
     Byte array (1-9 bytes)"
  (check-type value (integer 0 *))
  
  ;; Find l: the smallest l in {0..7} such that 2^(7l) ≤ value < 2^(7(l+1))
  ;; Special cases: value=0 → [0], value≥2^56 → 9 bytes with 0xFF header
  (if (zerop value)
      (make-array 1 :element-type '(unsigned-byte 8) :initial-contents '(0))
      (let ((l (loop for ll from 0 to 7
                     when (and (>= value (expt 2 (* 7 ll)))
                               (< value (expt 2 (* 7 (1+ ll)))))
                       return ll)))
        (if l
            ;; General case: header byte + l bytes in little-endian
            ;; header = (2^8 - 2^(8-l)) + ⌊x / 2^(8l)⌋
            ;; remaining = E_l(x mod 2^(8l)) = little-endian of low 8l bits
            (let* ((total-bytes (1+ l))
                   (low-part (mod value (expt 2 (* 8 l))))
                   (high-part (floor value (expt 2 (* 8 l))))
                   (header (+ (- 256 (expt 2 (- 8 l))) high-part))
                   (result (make-array total-bytes :element-type '(unsigned-byte 8))))
              (setf (aref result 0) header)
              ;; Write remaining l bytes in LITTLE-ENDIAN (E_l from C.12)
              (loop for i from 1 to l
                    do (setf (aref result i) (logand low-part #xFF))
                       (setf low-part (ash low-part -8)))
              result)
            ;; Overflow case: x ≥ 2^56 → [0xFF] ⌢ E₈(x) (8 bytes little-endian)
            (let ((result (make-array 9 :element-type '(unsigned-byte 8)))
                  (v value))
              (setf (aref result 0) #xFF)
              (loop for i from 1 to 8
                    do (setf (aref result i) (logand v #xFF))
                       (setf v (ash v -8)))
              result)))))

(defun decode-compact (bytes &optional (offset 0))
  "Decode JAM compact-encoded natural number (Gray Paper C.5).
   
   Formula C.5 inverse:
     First byte determines l (number of leading 1-bits = additional bytes).
     Header byte high bits → rem = high part of value.
     Following l bytes → little-endian low part of value.
     value = low_part + (rem << (8*l))
   
   Args:
     bytes: Byte array containing compact-encoded value
     offset: Starting position in bytes (default 0)
   
   Returns:
     (values decoded-value bytes-consumed)"
  (let* ((first-byte (aref bytes offset))
         (l (count-leading-ones first-byte))
         (total-bytes (1+ l))
         ;; Unified formula — works for all l ∈ {0..8}
         ;; l=8 (0xFF): data-bits=0, mask=0, rem=0 → pure 8-byte LE
         (data-bits (max 0 (- 7 l)))
         (mask (1- (ash 1 data-bits)))
         (rem (logand first-byte mask))
         (low-part 0))
    ;; Read l remaining bytes as LITTLE-ENDIAN (E_l from C.12)
    (loop for i from 1 to l
          do (setf low-part (logior low-part
                                    (ash (aref bytes (+ offset i))
                                         (* 8 (1- i))))))
    (values (+ low-part (ash rem (* 8 l)))
            total-bytes)))

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
;;; Byte Coercion
;;; ==========================================================================

(defun ensure-bytes (value)
  "Coerce VALUE to a (simple-array (unsigned-byte 8) (*)).
   Accepts: byte arrays (passthrough), hex strings (via FFI), other vectors (coerce).
   This factorizes the etypecase pattern used across codec/block/stf code."
  (etypecase value
    ((simple-array (unsigned-byte 8) (*)) value)
    (string (jam.ffi:hex-string-to-bytes value))
    (vector (coerce value '(simple-array (unsigned-byte 8) (*))))))

;;; Exports managed in package.lisp
