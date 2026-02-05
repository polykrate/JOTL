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
