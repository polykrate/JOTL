;;;; sequence-encoding.lisp
;;;; Sequence Encoding for JAM codec primitives
;;;; Implements C.6 from graypaper

(in-package :jotl-codec)

;;; C.6: E([i0, i1, ...]) ≡ E(i0) ⌢ E(i1) ⌢ ...
;;; Simply concatenate serializations of each element in sequence

(defun encode-sequence (sequence)
  "Encode a sequence by concatenating the encoding of each element.
   Implements C.6: E([i0, i1, ...]) ≡ E(i0) ⌢ E(i1) ⌢ ...
   
   Note: Fixed-length octet sequences (e.g. hashes H) have identity serialization
   because they are already octet sequences and C.2 applies: E(x ∈ B) ≡ x
   
   Args:
     sequence: List/vector of values to encode
   
   Returns:
     Concatenated octet sequence
   
   Examples:
     E([]) = []
     E([0, 1, 255]) = [0] ⌢ [1] ⌢ [128, 255] = [0, 1, 128, 255]
     E([hash32bytes]) = hash32bytes (identity for fixed-length octets)"
  (if (null sequence)
      '()
      (apply #'concat-octets
             (mapcar #'encode sequence))))

(defun decode-sequence (octets element-decoder &optional count)
  "Decode a sequence from octets.
   
   Since sequences are just concatenated encodings without length prefix,
   you need to either:
   - Know the number of elements (count parameter)
   - Have element-decoder that can determine element boundaries
   
   Args:
     octets: The octet sequence to decode
     element-decoder: Function (octets start) -> (values element bytes-consumed)
     count: Optional number of elements to decode (if nil, decode until exhausted)
   
   Returns:
     List of decoded elements
   
   Example:
     (decode-sequence '(0 1 127) #'decode-natural 3) => (0 1 127)"
  (let ((result '())
        (pos 0))
    (loop
      (when (or (>= pos (length octets))
                (and count (<= count 0)))
        (return (nreverse result)))
      (multiple-value-bind (element consumed)
          (funcall element-decoder octets pos)
        (push element result)
        (incf pos consumed)
        (when count (decf count))))))

(defun encode-length-prefixed-sequence (sequence &key (pre-encoded nil))
  "Encode a length-prefixed sequence.
   Implements C.7 + C.6: ↕x where x is a sequence
   E(↕x) = E(|x|) ⌢ E(x) = E(count) ⌢ E(elem0) ⌢ E(elem1) ⌢ ...
   
   Args:
     sequence: List/vector of elements
     pre-encoded: If t, elements are already encoded (lists of octets),
                  just concatenate them. If nil, encode each element first.
   
   Returns:
     Length-prefixed encoded sequence
   
   Examples:
     E(↕[hash1, hash2]) = E(2) ⌢ hash1 ⌢ hash2
     
   Note: Use pre-encoded=t when elements are already encoded to avoid
         double-encoding (which would flatten nested lists incorrectly)."
  (concat-octets 
   (encode-natural (length sequence))
   (if pre-encoded
       ;; Elements are already encoded, just concatenate
       (apply #'concat-octets sequence)
       ;; Elements need encoding first
       (encode-sequence sequence))))

(defun decode-length-prefixed-sequence (octets element-decoder &optional (start 0))
  "Decode a length-prefixed sequence.
   Implements C.7 + C.6: ↕x where x is a sequence
   
   First reads the count (number of elements), then decodes that many elements.
   
   Args:
     octets: The octet sequence to decode from
     element-decoder: Function (octets start) -> (values element bytes-consumed)
     start: Starting position in octets
   
   Returns:
     values: (decoded-sequence total-bytes-consumed)
   
   Examples:
     Decode ↕[hash1, hash2] where each hash is 32 bytes:
     [2, ...hash1 32bytes..., ...hash2 32bytes...]"
  (multiple-value-bind (count count-bytes)
      (decode-natural octets start)
    (let ((pos (+ start count-bytes))
          (result '()))
      (dotimes (i count)
        (multiple-value-bind (element consumed)
            (funcall element-decoder octets pos)
          (push element result)
          (incf pos consumed)))
      (values (nreverse result) (- pos start)))))
