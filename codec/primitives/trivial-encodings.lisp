;;;; trivial-encodings.lisp
;;;; Trivial Encodings for JAM codec primitives
;;;; Implements C.1-C.5 from graypaper

(in-package :jotl-codec)

;;; Constants
(defconstant +empty+ :empty
  "Represents ∅ (empty/nothing)")

;;; Utility: concatenate octet sequences
(defun concat-octets (&rest sequences)
  "Concatenate multiple octet sequences (lists)"
  (apply #'append sequences))

;;; C.1: E(∅) ≡ []
(defun encode-empty ()
  "Encode the empty value ∅ as empty sequence"
  '())

;;; C.2: E(x ∈ B) ≡ x
(defun encode-octet-sequence (octets)
  "An octet sequence encodes as itself"
  octets)

;;; C.3: E((a,b,...)) ≡ E(a) ⌢ E(b) ⌢ ...
(defun encode-tuple (tuple)
  "Encode a tuple as concatenation of encoded elements"
  (apply #'concat-octets
         (mapcar #'encode tuple)))

;;; C.4: E(a,b,...) ≡ E((a,b,...))
;;; This is handled by the main encode function accepting multiple args

;;; C.5: General natural number encoding N_{2^64} -> B_{1:9}
(defun encode-natural (x)
  "Encode a natural number up to 2^64 with variable-length prefix.
   Implements C.5 from graypaper.
   
   Three cases:
   1. x = 0 → [0]
   2. ∃l ∈ N8 : 2^(7l) ≤ x < 2^(7(l+1)) 
      → [2^8 - 2^(8-l) + ⌊x/2^(8l)⌋] ⌢ El(x mod 2^(8l))
   3. otherwise if x < 2^64 → [2^8 - 1] ⌢ E8(x)"
  (cond
    ;; Case 1: x = 0
    ((zerop x) '(0))
    
    ;; Case 2: find appropriate l where 2^(7l) ≤ x < 2^(7(l+1))
    (t
     (let ((l (find-encoding-length x)))
       (if (null l)
           ;; Case 3: fallback for large numbers >= 2^56
           (cons 255  ; 2^8 - 1
                 (encode-fixed-integer x 8))
           ;; Case 2: standard encoding
           (let* ((delta (* 8 l))  ; δ = 8l bits
                  (prefix (+ (- 256 (expt 2 (- 8 l)))  ; 2^8 - 2^(8-l)
                            (floor x (expt 2 delta))))  ; ⌊x/2^δ⌋
                  (remainder (mod x (expt 2 delta))))   ; x mod 2^δ
             (if (zerop l)
                 ;; Special case l=0: no remainder bytes
                 (list prefix)
                 (cons prefix
                       (encode-fixed-integer remainder l)))))))))

(defun find-encoding-length (x)
  "Find l such that 2^(7l) ≤ x < 2^(7(l+1)), where l ∈ N8 = {0,1,2,3,4,5,6,7}
   Note: l=0 covers range [1, 128), l=1 covers [128, 16384), etc."
  (cond
    ((< x 1) (error "Natural must be >= 0"))
    ;; l=0: 2^0=1 ≤ x < 2^7=128
    ((< x 128) 0)
    ;; l=1: 2^7=128 ≤ x < 2^14=16384
    ((< x 16384) 1)
    ;; l=2: 2^14=16384 ≤ x < 2^21=2097152
    ((< x 2097152) 2)
    ;; l=3: 2^21 ≤ x < 2^28=268435456
    ((< x 268435456) 3)
    ;; l=4: 2^28 ≤ x < 2^35
    ((< x (expt 2 35)) 4)
    ;; l=5: 2^35 ≤ x < 2^42
    ((< x (expt 2 42)) 5)
    ;; l=6: 2^42 ≤ x < 2^49
    ((< x (expt 2 49)) 6)
    ;; l=7: 2^49 ≤ x < 2^56
    ((< x (expt 2 56)) 7)
    ;; Otherwise use fallback [255] + E8
    (t nil)))

;;; Main encode function (generic dispatcher)
(defun encode (value &rest more-values)
  "Main encoding function E.
   Dispatches based on value type.
   
   - E(∅) = []
   - E(x ∈ B) = x (octet sequence)
   - E((a,b,...)) = E(a) ⌢ E(b) ⌢ ...
   - E(a,b,...) = E((a,b,...))
   - E(x ∈ N) = encode-natural(x)"
  (cond
    ;; Multiple arguments → tuple (C.4)
    (more-values
     (encode-tuple (cons value more-values)))
    
    ;; Empty value (C.1)
    ((eq value +empty+)
     (encode-empty))
    
    ;; Octet sequence (list of integers 0-255) (C.2)
    ((and (listp value)
          (every (lambda (x) (and (integerp x) (<= 0 x 255))) value))
     (encode-octet-sequence value))
    
    ;; Tuple (nested list or explicitly marked)
    ((and (listp value) (not (null value)))
     (encode-tuple value))
    
    ;; Natural number (C.5)
    ((and (integerp value) (>= value 0))
     (encode-natural value))
    
    ;; Unknown type
    (t
     (error "Cannot encode value of type ~A: ~A" (type-of value) value))))

;;; Decode functions
(defun decode-natural (octets &optional (start 0))
  "Decode a natural number encoded with encode-natural.
   Returns (values number bytes-consumed)"
  (let ((first-octet (nth start octets)))
    (cond
      ;; Case 1: x = 0
      ((zerop first-octet)
       (values 0 1))
      
      ;; Case 3: [255] prefix for large numbers
      ((= first-octet 255)
       (let* ((remaining-octets (nthcdr (1+ start) octets))
              (value-octets (subseq remaining-octets 0 (min 8 (length remaining-octets)))))
         (values (decode-fixed-integer value-octets)
                 9)))
      
      ;; Case 2: variable length encoding
      (t
       (let* ((l (decode-length-from-prefix first-octet))
              (delta (* 8 l))
              (prefix-bits (expt 2 (- 8 l)))
              (high-bits (- first-octet (- 256 prefix-bits))))
         (if (zerop l)
             ;; l=0: value is just the prefix itself
             (values first-octet 1)
             ;; l>0: read l additional octets
             (let* ((remaining-octets (nthcdr (1+ start) octets))
                    (low-octets (subseq remaining-octets 0 (min l (length remaining-octets))))
                    (low-bits (decode-fixed-integer low-octets))
                    (value (+ (* high-bits (expt 2 delta)) low-bits)))
               (values value (1+ l)))))))))

(defun decode-length-from-prefix (prefix-octet)
  "Given a prefix octet, determine the length l.
   l=0: [1..127]   -> 2^8 - 2^8 = 0, so prefix in [0, 127] but 0 is reserved for 0
   l=1: [128..191] -> 2^8 - 2^7 = 128
   l=2: [192..223] -> 2^8 - 2^6 = 192
   etc."
  (cond
    ((< prefix-octet 128) 0)  ; 2^8 - 2^8 = 0, but [1..127] for l=0
    ((< prefix-octet 192) 1)  ; 2^8 - 2^7 = 128
    ((< prefix-octet 224) 2)  ; 2^8 - 2^6 = 192
    ((< prefix-octet 240) 3)  ; 2^8 - 2^5 = 224
    ((< prefix-octet 248) 4)  ; 2^8 - 2^4 = 240
    ((< prefix-octet 252) 5)  ; 2^8 - 2^3 = 248
    ((< prefix-octet 254) 6)  ; 2^8 - 2^2 = 252
    ((< prefix-octet 255) 7)  ; 2^8 - 2^1 = 254
    (t 8)))
