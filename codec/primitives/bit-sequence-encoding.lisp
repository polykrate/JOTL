;;;; bit-sequence-encoding.lisp
;;;; Bit Sequence Encoding for JAM codec primitives
;;;; Implements C.9 from graypaper

(in-package :jotl-codec)

;;; C.1.4. Bit Sequence Encoding
;;;
;;; A sequence of bits b ∈ 𝔹 is a special case since encoding each individual
;;; bit as an octet would be very wasteful. We instead pack the bits into octets
;;; in order of least significant to most, and arrange into an octet stream.
;;; In the case of a variable length sequence, then the length is prefixed
;;; as in the general case.

;;; C.9: E(b ∈ 𝔹) = 
;;;   [] if b = []
;;;   [Σ_{i<min(8,|b|)} bi·2^i] ⌢ E(b_{8...}) otherwise

(defun encode-bit-sequence (bits)
  "Encode a sequence of bits into octets.
   Implements C.9 from graypaper.
   
   Bits are packed into octets from least significant to most significant.
   Each octet packs up to 8 bits.
   
   Args:
     bits: List/sequence of 0s and 1s
   
   Returns:
     List of octets
   
   Examples:
     E([]) = []
     E([1]) = [1]                              ; 0b00000001
     E([1,0,1]) = [5]                          ; 0b00000101
     E([1,0,1,0,1,0,1,0]) = [85]              ; 0b01010101
     E([1,1,1,1,1,1,1,1,1]) = [255, 1]        ; 9 bits"
  (if (null bits)
      '()
      (let* ((chunk-size (min 8 (length bits)))
             (chunk (subseq bits 0 chunk-size))
             (rest-bits (if (> (length bits) 8)
                           (subseq bits 8)
                           '()))
             ;; Pack bits: Σ bi·2^i for i < chunk-size
             (octet (loop for bit in chunk
                         for i from 0
                         sum (* bit (expt 2 i)))))
        (cons octet (encode-bit-sequence rest-bits)))))

(defun decode-bit-sequence (octets &optional total-bits)
  "Decode a bit sequence from octets.
   
   Args:
     octets: List of octets
     total-bits: Optional total number of bits (for proper length when not multiple of 8)
   
   Returns:
     List of bits (0s and 1s)
   
   Examples:
     decode([85]) = [1,0,1,0,1,0,1,0]
     decode([255, 1], 9) = [1,1,1,1,1,1,1,1,1]"
  (if (null octets)
      '()
      (let* ((octet (first octets))
             (bits-in-octet (if (and total-bits (< total-bits 8))
                               total-bits
                               8))
             (bits (loop for i from 0 below bits-in-octet
                        collect (if (logbitp i octet) 1 0)))
             (remaining-bits (if total-bits (- total-bits bits-in-octet) nil)))
        (append bits
                (decode-bit-sequence (rest octets) remaining-bits)))))

(defun encode-bit-sequence-with-length (bits)
  "Encode a variable-length bit sequence with length prefix.
   
   For variable-length bit sequences, the length is prefixed as in the general case.
   This means: E(|bits|) ⌢ E(bits)
   
   Args:
     bits: List/sequence of 0s and 1s
   
   Returns:
     Length-prefixed encoded bit sequence
   
   Example:
     E(↕[1,0,1,0,1,0,1,0,1]) = E(9) ⌢ E([1,0,1,0,1,0,1,0,1])
                               = [9] ⌢ [85, 1]
                               = [9, 85, 1]"
  (let ((encoded-bits (encode-bit-sequence bits)))
    (concat-octets (encode-natural (length bits))
                   encoded-bits)))

(defun decode-bit-sequence-with-length (octets &optional (start 0))
  "Decode a length-prefixed bit sequence.
   
   Returns (values bit-sequence bytes-consumed)
   
   Args:
     octets: The octet sequence to decode from
     start: Starting position in octets
   
   Returns:
     values: (bit-sequence bytes-consumed)"
  (multiple-value-bind (num-bits length-bytes)
      (decode-natural octets start)
    (let* ((value-start (+ start length-bytes))
           (num-octets (ceiling num-bits 8))
           (encoded-bits (subseq octets value-start (+ value-start num-octets)))
           (bits (decode-bit-sequence encoded-bits num-bits)))
      (values bits (+ length-bytes num-octets)))))
