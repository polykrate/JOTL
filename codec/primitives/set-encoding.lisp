;;;; set-encoding.lisp
;;;; Set Encoding for JAM codec primitives
;;;; Implements C.11 from graypaper

(in-package :jotl-codec)

;;; C.1.6. Set Encoding
;;;
;;; For any values which are sets and don't already have a defined encoding,
;;; we define the serialization of a set as the serialization of the set's
;;; elements in proper order.

;;; C.11: E({ a, b, c, ... }) ≡ E(a) ⌢ E(b) ⌢ E(c) ⌢ ... where a < b < c < ...

(defun encode-set (set &key (encoder #'encode))
  "Encode a set as the concatenation of its elements in proper order.
   Implements C.11 from graypaper.
   
   The set is serialized as its elements in sorted order (by encoded representation).
   No length prefix is included - the set must have a known size or be
   determined by context.
   
   Args:
     set: List of unique elements (will be sorted)
     encoder: Function to encode each element (default: encode)
   
   Returns:
     Concatenated encoding of sorted elements
   
   Examples:
     E({}) = []
     E({3, 1, 2}) = E(1) ⌢ E(2) ⌢ E(3) = [1, 2, 3]
     E({255, 0, 127}) = E(0) ⌢ E(127) ⌢ E(255) = [0, 127, 128, 255]"
  (if (null set)
      '()
      (let* ((sorted-set (sort-set-elements set))
             (encoded-elements
              (mapcar encoder sorted-set)))
        (apply #'concat-octets encoded-elements))))

(defun sort-set-elements (set)
  "Sort set elements by their encoded representation (proper order).
   
   The 'proper order' means lexicographic order of the encoded forms.
   This is the same < relation used in the graypaper.
   
   Args:
     set: List of elements
   
   Returns:
     Sorted list of elements"
  (sort (copy-list set) #'encoded-less-than))

(defun encoded-less-than (elem1 elem2)
  "Compare two elements by their encoded representation (lexicographic order).
   
   This implements the < operator for proper ordering in C.11."
  (let ((e1 (encode elem1))
        (e2 (encode elem2)))
    (lexicographic-less-than e1 e2)))

(defun decode-set (octets element-decoder &optional count)
  "Decode a set from octets.
   
   Since sets are just concatenated encodings without length prefix,
   you need to either:
   - Know the number of elements (count parameter)
   - Have element-decoder that can determine element boundaries
   - Decode until octets are exhausted
   
   Args:
     octets: The octet sequence to decode from
     element-decoder: Function (octets start) -> (values element bytes-consumed)
     count: Optional number of elements to decode
   
   Returns:
     List of decoded elements (in the order they were encoded)
   
   Note: The result is a list, not a true set data structure. You may want
   to convert it to your preferred set representation."
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

(defun encode-set-with-length (set &key (encoder #'encode))
  "Encode a set with a length prefix (variable-length set).
   
   This is useful when the set size is not known from context.
   The encoding is: E(|encoded-set|) ⌢ E(set)
   
   Args:
     set: List of unique elements
     encoder: Function to encode each element
   
   Returns:
     Length-prefixed encoded set
   
   Example:
     E(↕{1, 2, 3}) = E(3) ⌢ E({1,2,3}) = [3, 1, 2, 3]"
  (let ((encoded-set (encode-set set :encoder encoder)))
    (concat-octets (encode-natural (length encoded-set))
                   encoded-set)))

(defun decode-set-with-length (octets element-decoder &optional (start 0))
  "Decode a length-prefixed set.
   
   Returns (values set-elements bytes-consumed)
   
   Args:
     octets: The octet sequence to decode from
     element-decoder: Function (octets start) -> (values element bytes-consumed)
     start: Starting position in octets
   
   Returns:
     values: (list-of-elements bytes-consumed)"
  (multiple-value-bind (length length-bytes)
      (decode-natural octets start)
    (let ((value-start (+ start length-bytes))
          (value-end (+ start length-bytes length)))
      (let ((elements (decode-set (subseq octets value-start value-end)
                                  element-decoder)))
        (values elements (+ length-bytes length))))))

;;; Utility functions for working with sets

(defun jam-make-set (elements)
  "Create a set (represented as a sorted list with unique elements)."
  (remove-duplicates (sort-set-elements elements) :test #'equal))

(defun jam-set-member-p (element set)
  "Check if element is in the set."
  (member element set :test #'equal))

(defun jam-set-union (set1 set2)
  "Return the union of two sets."
  (jam-make-set (append set1 set2)))

(defun jam-set-intersection (set1 set2)
  "Return the intersection of two sets."
  (remove-if-not (lambda (elem) (jam-set-member-p elem set2)) set1))

(defun jam-set-difference (set1 set2)
  "Return elements in set1 but not in set2."
  (remove-if (lambda (elem) (jam-set-member-p elem set2)) set1))
