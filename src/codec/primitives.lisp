;;;; codec.lisp - JAM Codec (Gray Paper Appendix C)
;;;; NOT exactly SCALE - JAM has its own encoding!

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

;; Convenience aliases for common sizes
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
;;; C.1.8 - Variable-Length Integer Encoding (Compact)
;;; ==========================================================================
;;;
;;; Used EXCLUSIVELY for length prefixes of variable-length sequences
;;; (Gray Paper note after definition)
;;;
;;; Similar to SCALE compact encoding but with JAM-specific rules

(defun encode-compact (value)
  "Encode natural number in compact (variable-length) format.
   Used for sequence length prefixes.
   
   Encoding rules:
   - 0..63:       1 byte:  [xx]
   - 64..16383:   2 bytes: [01 xx xx]
   - 16384..2^30: 4 bytes: [10 xx xx xx xx]
   - 2^30+:       5+ bytes: [11 nn xx xx ...]
   
   Args:
     value: Natural number (usually a length)
   
   Returns:
     Byte array (1-9 bytes)"
  (check-type value (integer 0 *))
  
  (cond
    ;; Single byte mode: 0-63
    ((<= value 63)
     (make-array 1 :element-type '(unsigned-byte 8)
                 :initial-contents (list (logior #b00000000 value))))
    
    ;; Two byte mode: 64-16383
    ((<= value 16383)
     (let ((bytes (make-array 2 :element-type '(unsigned-byte 8))))
       (setf (aref bytes 0) (logior #b01000000 (ldb (byte 6 0) value)))
       (setf (aref bytes 1) (ldb (byte 8 6) value))
       bytes))
    
    ;; Four byte mode: 16384 - 2^30-1
    ((< value (expt 2 30))
     (let ((bytes (make-array 4 :element-type '(unsigned-byte 8))))
       (setf (aref bytes 0) (logior #b10000000 (ldb (byte 6 0) value)))
       (setf (aref bytes 1) (ldb (byte 8 6) value))
       (setf (aref bytes 2) (ldb (byte 8 14) value))
       (setf (aref bytes 3) (ldb (byte 8 22) value))
       bytes))
    
    ;; Big integer mode: 2^30+
    (t
     (let* ((num-bytes (ceiling (integer-length value) 8))
            (result (make-array (1+ num-bytes) :element-type '(unsigned-byte 8))))
       (setf (aref result 0) (logior #b11000000 (- num-bytes 4)))
       (loop for i from 0 below num-bytes
             do (setf (aref result (1+ i)) (ldb (byte 8 (* 8 i)) value)))
       result))))

(defun decode-compact (bytes &optional (offset 0))
  "Decode compact-encoded natural number.
   
   Args:
     bytes: Byte array containing compact-encoded value
     offset: Starting position in bytes (default 0)
   
   Returns:
     (values decoded-value bytes-consumed)"
  (let ((first-byte (aref bytes offset)))
    (case (logand first-byte #b11000000)
      ;; Single byte mode
      (#b00000000
       (values (logand first-byte #b00111111) 1))
      
      ;; Two byte mode
      (#b01000000
       (values (logior (logand first-byte #b00111111)
                       (ash (aref bytes (1+ offset)) 6))
               2))
      
      ;; Four byte mode
      (#b10000000
       (values (logior (logand first-byte #b00111111)
                       (ash (aref bytes (+ offset 1)) 6)
                       (ash (aref bytes (+ offset 2)) 14)
                       (ash (aref bytes (+ offset 3)) 22))
               4))
      
      ;; Big integer mode
      (#b11000000
       (let* ((num-bytes (+ (logand first-byte #b00111111) 4))
              (value 0))
         (loop for i from 0 below num-bytes
               do (setf value (logior value (ash (aref bytes (+ offset 1 i)) (* 8 i)))))
         (values value (1+ num-bytes)))))))

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
          encode-compact decode-compact
          encode-sequence decode-sequence
          encode-option decode-option
          encode-result))
