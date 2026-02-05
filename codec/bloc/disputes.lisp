;;;; disputes.lisp
;;;; JAM Disputes (ED)
;;;; Graypaper references: Appendix C.21

(in-package :jotl-bloc)

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
                 ;; ↕[(v, E2(i), s) | ...] : judgements (length-prefixed sequence!)
                 ;; Note: v is a BOOLEAN vote (1 byte), NOT a blob!
                 (encode-length-prefixed-sequence
                  (mapcar (lambda (judgement)
                            (destructuring-bind (vote idx sig) judgement
                              (concat-octets
                               (list (if vote 1 0))  ; vote: boolean (1 byte)
                               (e2 idx)              ; index (E2)
                               sig)))                ; signature (64 bytes)
                          (verdict-entry-judgement verdict))
                  :pre-encoded t)))
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
          (let ((pos2 s))
            (decode>> (o pos2)
              ;; target : hash (FIXED 32 bytes!)
              (target (decode-hash o pos2))
              ;; E4(a) : age (4 bytes)
              (age (decode-e4 o pos2))
              ;; ↕[(v, E2(i), s) | ...] : judgements (length-prefixed sequence!)
              ;; Note: v is a BOOLEAN vote (1 byte), NOT a blob!
              (judgement
               (decode-length-prefixed-sequence
                o
                (lambda (o3 s3)
                  (let ((p3 s3))
                    (decode>> (o3 p3)
                      (vote-byte (decode-e1 o3 p3))      ; vote: boolean (1 byte)
                      (idx (decode-e2 o3 p3))            ; index (E2)
                      (sig (decode-fixed-bytes o3 p3 64)) ; signature (FIXED 64 bytes!)
                      (values (list (not (zerop vote-byte)) idx sig) (- p3 s3)))))
                pos2))
              
              (values
               (make-verdict-entry
                :target target
                :age age
                :judgement judgement)
               (- pos2 s)))))
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

