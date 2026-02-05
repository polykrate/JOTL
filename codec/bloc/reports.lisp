;;;; reports.lisp
;;;; JAM Reports/Guarantees (EG)
;;;; Graypaper references: Appendix C.19

(in-package :jotl-bloc)

;;; Guarantees (Reports) structure
;;;
;;; Graypaper Appendix C.19:
;;; EG(EG) = E(↕[(r, E4(t), ↕[(E2(v), s) | (v,s) ← a]) | (r, t, a) ← EG])
;;;
;;; Where EG is a sequence of guarantees, each containing:
;;; - r: work report (complete work-report structure from work.lisp)
;;; - t: timeslot (4 bytes, E4)
;;; - a: authorizer-guarantor data, sequence of pairs (v, s) where:
;;;   - v: validator index (2 bytes, E2)
;;;   - s: signature (length-prefixed blob)
;;;
;;; Note: The "r" (report) here is actually a complete work-report structure
;;;       containing package-spec, context, results, etc.

(defun encode-reports (reports)
  "Encode reports/guarantees (EG).
   
   Graypaper Appendix C.19: EG(EG) = E(↕[(r, E4(t), ↕[(E2(v), s) | (v,s) ← a]) | (r, t, a) ← EG])
   
   Args:
     reports: List of guarantee structures (from work.lisp)
   
   Returns:
     Encoded octet sequence"
  (let ((encoded-guarantees
         (mapcar (lambda (guarantee)
                   (concat-octets
                    ;; r : work report (complete structure)
                    (encode-work-report (guarantee-report guarantee))
                    ;; E4(t) : timeslot (4 bytes)
                    (e4 (guarantee-slot guarantee))
                    ;; ↕[(E2(v), s) | ...] : signatures
                    (encode-length-prefixed-sequence
                     (mapcar (lambda (sig-pair)
                               (destructuring-bind (validator-index signature) sig-pair
                                 (concat-octets
                                  (e2 validator-index)  ; validator index
                                  (encode-with-length signature))))  ; signature
                             (guarantee-signatures guarantee)))))
                 reports)))
    ;; ↕[...] : length-prefixed sequence
    (encode-length-prefixed-sequence encoded-guarantees)))

(defun decode-reports (octets &optional (start 0))
  "Decode reports/guarantees from octets.
   
   Inverse of encode-reports (Appendix C.19).
   
   Args:
     octets: Encoded reports/guarantees data
     start: Starting position
   
   Returns:
     values: (list-of-guarantee bytes-consumed)"
  (decode-length-prefixed-sequence
   octets
   (lambda (o s)
     (let ((pos s))
       (decode>> (o pos)
         ;; r : work report (complete structure)
         (work-report (decode-work-report o pos))
         ;; E4(t) : timeslot (4 bytes)
         (slot (decode-e4 o pos))
         ;; ↕[(E2(v), s) | ...] : signatures
         (signatures
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
          (make-guarantee
           :report work-report
           :slot slot
           :signatures signatures)
          (- pos s)))))
   start))
