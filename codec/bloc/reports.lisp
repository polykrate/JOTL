;;;; reports.lisp
;;;; JAM Reports (EG)
;;;; Graypaper references: Appendix C.19

(in-package :jotl-bloc)

;;; Report structure
;;;
;;; Graypaper Appendix C.19:
;;; EG(EG) = E(↕[(r, E4(t), ↕[(E2(v), s) | (v,s) ← a]) | (r, t, a) ← EG])
;;;
;;; Each report is a tuple (r, t, a) where:
;;; - r: report data/package hash (blob)
;;; - t: timeslot (4 bytes, E4)
;;; - a: authorizer-guarantor data, sequence of pairs (v, s) where:
;;;   - v: validator index (2 bytes, E2)
;;;   - s: signature (blob)
;;;
;;; Reports are encoded as a length-prefixed sequence of (report-data, timeslot, assurances).

(defun encode-reports (reports)
  "Encode reports (EG).
   
   Graypaper Appendix C.19: EG(EG) = E(↕[(r, E4(t), ↕[(E2(v), s) | (v,s) ← a]) | (r, t, a) ← EG])
   
   Args:
     reports: List of report structures
   
   Returns:
     Encoded octet sequence"
  (let ((encoded-reports
         (mapcar (lambda (report)
                   (concat-octets
                    ;; r : report data/hash (blob, length-prefixed)
                    (encode-with-length (report-report-data report))
                    ;; E4(t) : timeslot (4 bytes)
                    (e4 (report-timeslot report))
                    ;; ↕[(E2(v), s) | ...] : authorizer-guarantor pairs
                    (let ((pairs (report-authorizer-guarantor report)))
                      (encode-length-prefixed-sequence
                       (mapcar (lambda (pair)
                                 (destructuring-bind (v s) pair
                                   (concat-octets
                                    (e2 v)  ; validator index
                                    (encode-with-length s))))  ; signature
                               pairs)))))
                 reports)))
    ;; ↕[...] : length-prefixed sequence
    (encode-length-prefixed-sequence encoded-reports)))

(defun decode-reports (octets &optional (start 0))
  "Decode reports from octets.
   
   Inverse of encode-reports (Appendix C.19).
   
   Args:
     octets: Encoded reports data
     start: Starting position
   
   Returns:
     values: (list-of-report bytes-consumed)"
  (decode-length-prefixed-sequence
   octets
   (lambda (o s)
     (let ((pos s))
       (decode>> (o pos)
         ;; r : report data (length-prefixed)
         (report-data (decode-with-length o pos))
         ;; E4(t) : timeslot (4 bytes)
         (timeslot (decode-e4 o pos))
         ;; ↕[(E2(v), s) | ...] : authorizer-guarantor pairs
         (authorizer-guarantor
          (decode-length-prefixed-sequence
           o
           (lambda (o2 s2)
             (let ((pos2 s2))
               (decode>> (o2 pos2)
                 ;; E2(v) : validator index (2 bytes)
                 (v (decode-e2 o2 pos2))
                 ;; s : signature (length-prefixed)
                 (s (decode-with-length o2 pos2))
                 
                 (values (list v s) (- pos2 s2)))))
           pos))
         
         (values
          (make-report
           :report-data report-data
           :timeslot timeslot
           :authorizer-guarantor authorizer-guarantor)
          (- pos s)))))
   start))
