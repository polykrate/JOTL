;;;; disputes.lisp
;;;; JAM Disputes (ED)
;;;; Graypaper references: Appendix C.21

(in-package :jotl-bloc)

;;; System parameters for test vectors
;;; ASN.1: validators-super-majority = ceil(validators-count * 2/3 + 1)
(defconstant +validators-super-majority-tiny+ 5
  "Validators super-majority for tiny test vectors")

(defconstant +validators-super-majority-full+ 683
  "Validators super-majority for full test vectors")

(defparameter *validators-super-majority* +validators-super-majority-tiny+
  "Current validators super-majority (defaults to tiny)")

;;; Disputes structure
;;;
;;; Graypaper Appendix C.21:
;;; ED((v, c, f)) = E(↕[(r, E4(a), [(v, E2(i), s) | (v, i, s) ← j]) | (r, a, j) ← v], ↕c, ↕f)
;;;
;;; Disputes consist of three parts:
;;; 1. v: verdicts - sequence of verdict entries, where each entry is (r, a, j):
;;;    - r: report data/hash (blob)
;;;    - a: age (4 bytes, E4)
;;;    - j: judgements, sequence of (v, i, s):
;;;      - v: validator (blob)
;;;      - i: index (2 bytes, E2)
;;;      - s: signature (FIXED 64 bytes!)
;;; 2. c: culprits - sequence of (target, key, signature):
;;;    - target: hash (FIXED 32 bytes)
;;;    - key: hash (FIXED 32 bytes)
;;;    - signature: FIXED 64 bytes
;;; 3. f: faults - sequence of (target, vote, key, signature):
;;;    - target: hash (FIXED 32 bytes)
;;;    - vote: boolean (1 byte)
;;;    - key: hash (FIXED 32 bytes)
;;;    - signature: FIXED 64 bytes

;;; Helper functions for culprits and faults

(defun encode-culprit (culprit)
  "Encode a culprit: (target, key, signature)."
  (concat-octets
   (culprit-target culprit)       ; 32 bytes hash
   (culprit-key culprit)          ; 32 bytes hash
   (culprit-signature culprit)))  ; 64 bytes signature

(defun decode-culprit (octets &optional (start 0))
  "Decode a culprit from octets."
  (let ((pos start))
    (decode>> (octets pos)
      (target (decode-hash octets pos))          ; 32 bytes
      (key (decode-hash octets pos))             ; 32 bytes
      (signature (decode-fixed-bytes octets pos 64))  ; 64 bytes
      
      (values
       (make-culprit
        :target target
        :key key
        :signature signature)
       (- pos start)))))

(defun encode-fault (fault)
  "Encode a fault: (target, vote, key, signature)."
  (concat-octets
   (fault-target fault)                        ; 32 bytes hash
   (list (if (fault-vote fault) 1 0))         ; 1 byte boolean
   (fault-key fault)                          ; 32 bytes hash
   (fault-signature fault)))                  ; 64 bytes signature

(defun decode-fault (octets &optional (start 0))
  "Decode a fault from octets."
  (let ((pos start))
    (decode>> (octets pos)
      (target (decode-hash octets pos))          ; 32 bytes
      (vote-byte (decode-e1 octets pos))         ; 1 byte
      (key (decode-hash octets pos))             ; 32 bytes
      (signature (decode-fixed-bytes octets pos 64))  ; 64 bytes
      
      (values
       (make-fault
        :target target
        :vote (not (zerop vote-byte))
        :key key
        :signature signature)
       (- pos start)))))

(defun encode-disputes (disputes)
  "Encode disputes (ED).
   
   Graypaper Appendix C.21: ED((v, c, f)) = E(↕[...], ↕c, ↕f)
   
   Uses dynamic *validators-super-majority* for fixed-size judgement sequences.
   
   Args:
     disputes: A disputes structure
   
   Returns:
     Encoded octet sequence"
  (concat-octets
   ;; ↕[(r, E4(a), [...]) | ...] : verdicts
   (let ((verdicts (disputes-verdicts disputes)))
     (encode-length-prefixed-sequence
      (mapcar (lambda (verdict)
                (concat-octets
                 ;; target : hash (FIXED 32 bytes!)
                 (verdict-entry-target verdict)
                 ;; E4(a) : age (4 bytes)
                 (e4 (verdict-entry-age verdict))
                 ;; FIXED SIZE SEQUENCE of judgements (NO count!)
                 ;; ASN.1: votes SEQUENCE (SIZE(validators-super-majority)) OF Judgement
                 ;; Note: v is a BOOLEAN vote (1 byte), NOT a blob!
                 (apply #'concat-octets
                        (mapcar (lambda (judgement)
                                  (destructuring-bind (vote idx sig) judgement
                                    (concat-octets
                                     (list (if vote 1 0))  ; vote: boolean (1 byte)
                                     (e2 idx)              ; index (E2)
                                     sig)))                ; signature (64 bytes)
                                (verdict-entry-judgement verdict)))))
              verdicts)
      :pre-encoded t))
   
   ;; ↕c : culprits (length-prefixed sequence of culprit structures)
   (encode-length-prefixed-sequence
    (mapcar #'encode-culprit (disputes-culprits disputes))
    :pre-encoded t)
   
   ;; ↕f : faults (length-prefixed sequence of fault structures)
   (encode-length-prefixed-sequence
    (mapcar #'encode-fault (disputes-faults disputes))
    :pre-encoded t)))

(defun decode-disputes (octets &optional (start 0))
  "Decode disputes from octets.
   
   Inverse of encode-disputes (Appendix C.21).
   Uses dynamic *validators-super-majority* for fixed-size judgement sequences.
   
   Args:
     octets: Encoded disputes data
     start: Starting position
   
   Returns:
     values: (disputes bytes-consumed)"
  (let ((pos start))
    (decode>> (octets pos)
      ;; ↕[(r, E4(a), [...]) | ...] : verdicts
      (verdicts
       (decode-length-prefixed-sequence
        octets
        (lambda (o s)
          ;; Decode verdict with judgement count from system parameter
          ;; ASN.1: votes SEQUENCE (SIZE(validators-super-majority)) OF Judgement
          (let ((p s))
            ;; target : hash (FIXED 32 bytes!)
            (multiple-value-bind (target tc) (decode-hash o p)
              (incf p tc)
              ;; age : E4 (4 bytes)
              (multiple-value-bind (age ac) (decode-e4 o p)
                (incf p ac)
                
                ;; Decode FIXED SIZE sequence of judgements
                ;; Number determined by *validators-super-majority* dynamic variable
                (let ((judgements '()))
                  (dotimes (i *validators-super-majority*)
                    (multiple-value-bind (vote-byte vc) (decode-e1 o p)
                      (incf p vc)
                      (multiple-value-bind (idx ic) (decode-e2 o p)
                        (incf p ic)
                        (multiple-value-bind (sig sc) (decode-fixed-bytes o p 64)
                          (incf p sc)
                          (push (list (not (zerop vote-byte)) idx sig) judgements)))))
                  
                  (values
                   (make-verdict-entry
                    :target target
                    :age age
                    :judgement (nreverse judgements))
                   (- p s)))))))
        pos))
      
      ;; ↕c : culprits (length-prefixed sequence of culprit structures)
      (culprits (decode-length-prefixed-sequence octets #'decode-culprit pos))
      
      ;; ↕f : faults (length-prefixed sequence of fault structures)
      (faults (decode-length-prefixed-sequence octets #'decode-fault pos))
      
      (values
       (make-disputes
        :verdicts verdicts
        :culprits culprits
        :faults faults)
       (- pos start)))))

