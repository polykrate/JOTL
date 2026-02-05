;;;; discriminator-encoding.lisp
;;;; Discriminator Encoding for JAM codec primitives
;;;; Implements C.7-C.8 from graypaper

(in-package :jotl-codec)

;;; C.1.3. Discriminator Encoding
;;;
;;; When we have sets of heterogeneous items (union of different kinds of tuples
;;; or sequences of different length), we require a discriminator to determine
;;; the nature of the encoded item for successful deserialization.

;;; C.7: Length discriminator ↕x
;;; ↕x ≡ (|x|, x) thus E(↕x) ≡ E(|x|) ⌢ E(x)
;;;
;;; We generally use a length discriminator when serializing sequence terms
;;; which have variable length (e.g. general blobs B or unbound numeric
;;; sequences ⟦N⟧), though this is omitted for fixed-length terms (e.g. hashes H).

(defun encode-with-length (value)
  "Encode a value prefixed with its length discriminator.
   Implements C.7: ↕x ≡ (|x|, x) thus E(↕x) ≡ E(|x|) ⌢ E(x)
   
   The notation ↕x means the term of value x is variable in size and
   requires a length discriminator.
   
   For some term y ∈ (x ∈ B, ...), we would generally define its
   serialized form to be E(|x|) ⌢ E(x) ⌢ ...
   
   Args:
     value: The value to encode (typically a sequence/blob)
   
   Returns:
     Length-prefixed encoding: E(|value|) ⌢ E(value)
   
   Examples:
     E(↕[1,2,3]) = E(3) ⌢ E([1,2,3]) = [3, 1, 2, 3]
     E(↕[]) = E(0) ⌢ [] = [0]"
  (let ((encoded-value (encode value)))
    (concat-octets (encode-natural (length encoded-value))
                   encoded-value)))

(defun decode-with-length (octets &optional (start 0))
  "Decode a length-prefixed value.
   Returns (values decoded-value total-bytes-consumed)
   
   Args:
     octets: The octet sequence to decode from
     start: Starting position in octets
   
   Returns:
     values: (decoded-value bytes-consumed)"
  (multiple-value-bind (length length-bytes)
      (decode-natural octets start)
    (let* ((value-start (+ start length-bytes))
           (value-octets (subseq octets value-start (+ value-start length))))
      (values value-octets (+ length-bytes length)))))

;;; C.8: Optional discriminator ¿x
;;; For terms defined by some serializable set in union with ∅
;;; (generally denoted for some set S as S?):
;;;
;;;   ¿x ≡ 0       if x = ∅
;;;   ¿x ≡ (1, x)  otherwise

(defun encode-optional (value)
  "Encode an optional value (S?).
   Implements C.8: ¿x
   
   Convenient discriminator operator specifically for terms defined by
   some serializable set in union with ∅ (denoted S?).
   
   - If x = ∅ → encode as 0
   - Otherwise → encode as (1, x)
   
   Args:
     value: The value to encode (or +empty+ for ∅)
   
   Returns:
     Discriminated encoding
   
   Examples:
     E(¿∅) = [0]
     E(¿42) = E(1, 42) = [1, 42]
   
   Note: This uses the generic encode function. For custom structures,
         use encode-optional-with and provide an explicit encoder."
  (if (eq value +empty+)
      (encode-natural 0)
      (concat-octets (encode-natural 1)
                     (encode value))))

(defun encode-optional-with (value encoder)
  "Encode an optional value with a custom encoder function.
   Implements C.8: ¿x with explicit encoder for custom types.
   
   This is needed when encoding optional structures that the generic
   encode function doesn't know how to handle (e.g. custom defstructs).
   
   - If x = ∅ → encode as 0
   - Otherwise → encode as (1, encoder(x))
   
   Args:
     value: The value to encode (or +empty+ for ∅)
     encoder: Function to encode the value (if not empty)
   
   Returns:
     Discriminated encoding
   
   Examples:
     (encode-optional-with epoch-marker #'encode-epoch-marker)
     (encode-optional-with +empty+ #'encode-anything) => [0]"
  (if (eq value +empty+)
      (list 0)
      (concat-octets (list 1)
                     (funcall encoder value))))

(defun decode-optional (octets element-decoder &optional (start 0))
  "Decode an optional value.
   
   Args:
     octets: The octet sequence to decode from
     element-decoder: Function (octets start) -> (values element bytes-consumed)
     start: Starting position in octets
   
   Returns:
     values: (value bytes-consumed) where value is +empty+ or the decoded element
   
   Examples:
     (decode-optional '(0) ...) => (values +empty+ 1)
     (decode-optional '(1 42) #'decode-natural) => (values 42 2)"
  (multiple-value-bind (discriminator disc-bytes)
      (decode-natural octets start)
    (if (zerop discriminator)
        (values +empty+ disc-bytes)
        (multiple-value-bind (element elem-bytes)
            (funcall element-decoder octets (+ start disc-bytes))
          (values element (+ disc-bytes elem-bytes))))))

;;; Generic discriminator encoding
;;; For tagged unions/variants beyond just optional

(defun encode-discriminated (tag value)
  "Encode a value with a discriminator tag.
   General form: E(tag) ⌢ E(value)
   
   Used for tagged unions/variants where tag indicates which variant.
   
   Args:
     tag: Natural number indicating the variant type
     value: The value to encode
   
   Returns:
     E(tag) ⌢ E(value)
   
   Example:
     encode-discriminated(2, data) for variant #2"
  (concat-octets (encode-natural tag)
                 (encode value)))

(defun decode-discriminator (octets &optional (start 0))
  "Decode a discriminator tag from octets.
   
   Returns (values tag bytes-consumed)
   
   This is just an alias for decode-natural but with clearer semantics."
  (decode-natural octets start))
