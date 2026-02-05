;;;; fixed-length-integer-encoding.lisp
;;;; Fixed-Length Integer Encoding for JAM codec primitives
;;;; Implements C.12 from graypaper

(in-package :jotl-codec)

;;; Fixed-length integer encoding in little-endian format
;;; El : N_{2^{8l}} -> B_l

(defun encode-fixed-integer (value octet-length)
  "Encode an integer with fixed octet-length in little-endian format.
   Implements C.12: El(x) from graypaper.
   
   Args:
     value: Natural number to encode (must be < 2^(8*octet-length))
     octet-length: Number of octets in the output sequence
   
   Returns:
     List of octets (0-255) representing the value in little-endian"
  (cond
    ;; Base case: l = 0
    ((zerop octet-length) '())
    ;; Recursive case: [x mod 256] ⌢ El-1(⌊x/256⌋)
    (t
     (cons (mod value 256)
           (encode-fixed-integer (floor value 256)
                                 (1- octet-length))))))

(defun decode-fixed-integer (octets &optional (octet-length (length octets)))
  "Decode a little-endian octet sequence into a natural number.
   Inverse of encode-fixed-integer.
   
   Args:
     octets: List of octets (0-255)
     octet-length: Expected length (defaults to length of octets)
   
   Returns:
     Natural number decoded from the octet sequence"
  (if (null octets)
      0
      (+ (first octets)
         (* 256 (decode-fixed-integer (rest octets)
                                       (1- octet-length))))))

;;; Convenience functions for common sizes

(defun e1 (value)
  "Encode as 1 octet (8 bits, max 255)"
  (encode-fixed-integer value 1))

(defun e2 (value)
  "Encode as 2 octets (16 bits, max 65535)"
  (encode-fixed-integer value 2))

(defun e4 (value)
  "Encode as 4 octets (32 bits, max ~4.3 billion)"
  (encode-fixed-integer value 4))

(defun e8 (value)
  "Encode as 8 octets (64 bits, max 2^64-1)"
  (encode-fixed-integer value 8))

;;; Symmetric aliases for consistency with decode-eN functions

(defun encode-e1 (value)
  "Encode as 1 octet. Alias for e1 for symmetry with decode-e1."
  (e1 value))

(defun encode-e2 (value)
  "Encode as 2 octets. Alias for e2 for symmetry with decode-e2."
  (e2 value))

(defun encode-e4 (value)
  "Encode as 4 octets. Alias for e4 for symmetry with decode-e4."
  (e4 value))

(defun encode-e8 (value)
  "Encode as 8 octets. Alias for e8 for symmetry with decode-e8."
  (e8 value))

;;; For tuples/sequences with fixed-length elements
;;; C.13-C.15: El for non-natural arguments

(defun encode-fixed-tuple (tuple octet-length)
  "Encode a tuple where each element uses El recursively.
   Implements C.14: El((a,b,...)) ≡ El(a) ⌢ El(b) ⌢ ..."
  (apply #'append
         (mapcar (lambda (elem)
                   (encode-fixed-integer elem octet-length))
                 tuple)))

(defun encode-fixed-sequence (sequence octet-length)
  "Encode a sequence where each element uses El recursively.
   Implements C.15: El([i0,i1,...]) ≡ El(i0) ⌢ El(i1) ⌢ ..."
  (apply #'append
         (mapcar (lambda (elem)
                   (encode-fixed-integer elem octet-length))
                 sequence)))
