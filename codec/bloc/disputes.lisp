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
;;;      - s: signature (blob)
;;; 2. c: culprits (↕c means length-discriminated blob)
;;; 3. f: faults (↕f means length-discriminated blob)

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
                 ;; r : report data (length-prefixed)
                 (encode-with-length (verdict-entry-report-data verdict))
                 ;; E4(a) : age (4 bytes)
                 (e4 (verdict-entry-age verdict))
                 ;; [(v, E2(i), s) | ...] : judgements (no length prefix for inner sequence)
                 (apply #'concat-octets
                        (mapcar (lambda (judgement)
                                  (destructuring-bind (v i s) judgement
                                    (concat-octets
                                     (encode-with-length v)  ; validator
                                     (e2 i)                  ; index
                                     (encode-with-length s)))) ; signature
                                (verdict-entry-judgement verdict)))))
              verdicts)))
   
   ;; ↕c : culprits (length-prefixed)
   (encode-with-length (disputes-culprits disputes))
   
   ;; ↕f : faults (length-prefixed)
   (encode-with-length (disputes-faults disputes))))

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
              ;; r : report data (length-prefixed)
              (report-data (decode-with-length o pos2))
              ;; E4(a) : age (4 bytes)
              (age (decode-e4 o pos2))
              ;; [(v, E2(i), s) | ...] : judgements
              ;; Note: no length prefix, decode until end of this verdict entry
              ;; For now, we'll use a helper to decode the remaining bytes as judgements
              (judgement (decode-judgements o pos2 (- (length o) pos2)))
              
              (values
               (make-verdict-entry
                :report-data report-data
                :age age
                :judgement judgement)
               (- pos2 s)))))
        pos))
      
      ;; ↕c : culprits (length-prefixed)
      (culprits (decode-with-length octets pos))
      
      ;; ↕f : faults (length-prefixed)
      (faults (decode-with-length octets pos))
      
      (values
       (make-disputes
        :verdicts verdicts
        :culprits culprits
        :faults faults)
       (- pos start)))))

(defun decode-judgements (octets start max-bytes)
  "Decode judgements from octets.
   
   Helper for decode-disputes. Decodes (v, E2(i), s) tuples.
   
   Args:
     octets: Encoded data
     start: Starting position
     max-bytes: Maximum bytes to consume
   
   Returns:
     List of judgements (v i s)"
  (let ((judgements '())
        (pos start)
        (end-pos (+ start max-bytes)))
    (loop while (< pos end-pos) do
      (multiple-value-bind (v v-consumed)
          (decode-with-length octets pos)
        (incf pos v-consumed)
        (multiple-value-bind (i i-consumed)
            (decode-e2 octets pos)
          (incf pos i-consumed)
          (multiple-value-bind (s s-consumed)
              (decode-with-length octets pos)
            (incf pos s-consumed)
            (push (list v i s) judgements)))))
    (nreverse judgements)))
