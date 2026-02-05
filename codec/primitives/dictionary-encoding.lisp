;;;; dictionary-encoding.lisp
;;;; Dictionary Encoding for JAM codec primitives
;;;; Implements C.10 from graypaper

(in-package :jotl-codec)

;;; C.1.5. Dictionary Encoding
;;;
;;; In general, dictionaries are placed in the Merkle trie directly
;;; (see appendix E for details). However, small dictionaries may reasonably
;;; be encoded as a sequence of pairs ordered by the key.

;;; C.10: ∀K, V : E(d ∈ ⦃K → V⦄) ≡ E(↕[(E(k), E(d[k])) | k ∈ K(d) ^^ k])
;;;
;;; Translation: A dictionary is encoded as a length-prefixed sequence
;;; of (key, value) pairs, where pairs are ordered by key in ascending order.

(defun encode-dictionary (dict &key (key-encoder #'encode) (value-encoder #'encode))
  "Encode a dictionary/hash-map as a sequence of pairs ordered by key.
   Implements C.10 from graypaper.
   
   The dictionary is encoded as:
   E(↕[(E(k), E(d[k])) | k ∈ K(d) ^^ k])
   
   That is: a length-prefixed sequence of (encoded-key, encoded-value) pairs,
   ordered by the encoded key.
   
   Args:
     dict: Hash table or alist ((key . value) ...)
     key-encoder: Function to encode keys (default: encode)
     value-encoder: Function to encode values (default: encode)
   
   Returns:
     Encoded dictionary as octet sequence
   
   Example:
     d = {1 → 100, 2 → 200, 0 → 0}
     Sorted by key: [(0,0), (1,100), (2,200)]
     E(d) = E(↕[(E(0), E(0)), (E(1), E(100)), (E(2), E(200))])
          = E(↕[[0,0], [1,100], [2,128,200]])
          = length prefix + concatenated pairs"
  (let* ((pairs (dict-to-sorted-pairs dict))
         (encoded-pairs
          (mapcar (lambda (pair)
                    (let ((k (car pair))
                          (v (cdr pair)))
                      (concat-octets (funcall key-encoder k)
                                     (funcall value-encoder v))))
                  pairs))
         (concatenated (apply #'concat-octets encoded-pairs)))
    ;; Length-prefix the result
    (concat-octets (encode-natural (length concatenated))
                   concatenated)))

(defun dict-to-sorted-pairs (dict)
  "Convert a dictionary to a sorted list of (key . value) pairs.
   
   Args:
     dict: Either a hash table or an alist
   
   Returns:
     List of (key . value) pairs sorted by encoded key"
  (let ((pairs (cond
                 ;; Hash table
                 ((hash-table-p dict)
                  (let ((result '()))
                    (maphash (lambda (k v) (push (cons k v) result)) dict)
                    result))
                 ;; Alist
                 ((listp dict)
                  dict)
                 (t
                  (error "Dictionary must be hash-table or alist")))))
    ;; Sort by encoded key (lexicographic order of octets)
    (sort pairs #'encoded-key-less-than :key #'car)))

(defun encoded-key-less-than (k1 k2)
  "Compare two keys by their encoded representation (lexicographic order).
   
   This implements the ^^ operator from the graypaper (proper ordering)."
  (let ((e1 (encode k1))
        (e2 (encode k2)))
    (lexicographic-less-than e1 e2)))

(defun lexicographic-less-than (seq1 seq2)
  "Lexicographic comparison of two octet sequences."
  (cond
    ((null seq1) (not (null seq2)))  ; [] < [anything]
    ((null seq2) nil)                 ; [anything] >= []
    ((< (first seq1) (first seq2)) t)
    ((> (first seq1) (first seq2)) nil)
    (t (lexicographic-less-than (rest seq1) (rest seq2)))))

(defun decode-dictionary (octets key-decoder value-decoder &optional (start 0))
  "Decode a dictionary from octets.
   
   Args:
     octets: The octet sequence to decode from
     key-decoder: Function (octets start) -> (values key bytes-consumed)
     value-decoder: Function (octets start) -> (values value bytes-consumed)
     start: Starting position in octets
   
   Returns:
     values: (alist-of-pairs bytes-consumed)
   
   The result is an alist of (key . value) pairs."
  (multiple-value-bind (length length-bytes)
      (decode-natural octets start)
    (let ((pairs '())
          (pos (+ start length-bytes))
          (end-pos (+ start length-bytes length)))
      (loop while (< pos end-pos) do
        (multiple-value-bind (key key-bytes)
            (funcall key-decoder octets pos)
          (incf pos key-bytes)
          (multiple-value-bind (value value-bytes)
              (funcall value-decoder octets pos)
            (incf pos value-bytes)
            (push (cons key value) pairs))))
      (values (nreverse pairs) (+ length-bytes length)))))

;;; Utility: Create hash table from alist
(defun alist-to-hash (alist &key (test 'equal))
  "Convert an alist to a hash table."
  (let ((ht (make-hash-table :test test)))
    (dolist (pair alist)
      (setf (gethash (car pair) ht) (cdr pair)))
    ht))
