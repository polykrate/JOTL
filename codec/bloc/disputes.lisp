;;;; disputes.lisp
;;;; JAM Disputes (ED) - Validator dispute information
;;;; Graypaper references: Section 4.2, Appendix C.21

(in-package :jotl-bloc)

;;; Disputes ED
;;;
;;; Graypaper Section 4.2: The Block (extrinsic data component)
;;; Information relating to disputes between validators
;;; over the validity of reports.

(defstruct disputes
  "Disputes structure (v, c, f).
   
   Contains information about disputes between validators
   concerning the validity of reports.
   - v: sequence of verdict entries (r, a, j)
   - c: culprits (length-prefixed)
   - f: faults (length-prefixed)"
  
  (verdicts nil :type list)   ; v: list of (r, a, j) triples
  (culprits nil :type list)   ; c
  (faults nil :type list))    ; f

(defstruct verdict-entry
  "A verdict entry (r, a, j).
   - r: report data
   - a: encoded on 4 octets
   - j: sequence of (v, i, s) triples"
  (report-data nil :type t)        ; r
  (component-a nil :type (or null natural))  ; a
  (judgments nil :type list))      ; j: list of (v, i, s)

;;; Encoding
;;; Graypaper Appendix C.21: ED((v, c, f)) = E(↕[(r, E4(a), [(v, E2(i), s) | (v,i,s) ∈ j]) | (r,a,j) ∈ v], ↕c, ↕f)
;;;
;;; Tuple of three components:
;;; - ↕[verdict entries]: sequence of (r, E4(a), [...])
;;; - ↕c: culprits (length-prefixed)
;;; - ↕f: faults (length-prefixed)

(defun encode-disputes (disputes)
  "Encode disputes (ED).
   
   Graypaper Appendix C.21: ED((v, c, f)) = E(↕[...], ↕c, ↕f)
   
   Args:
     disputes: A disputes structure
   
   Returns:
     Encoded octet sequence"
  (let* ((v (disputes-verdicts disputes))
         (c (disputes-culprits disputes))
         (f (disputes-faults disputes))
         ;; Encode verdicts: ↕[(r, E4(a), [(v, E2(i), s) | ...]) | ...]
         (encoded-verdicts
          (mapcar (lambda (verdict)
                    (let* ((r (verdict-entry-report-data verdict))
                           (a (verdict-entry-component-a verdict))
                           (j (verdict-entry-judgments verdict))
                           ;; [(v, E2(i), s) | (v,i,s) ∈ j]
                           (encoded-judgments
                            (mapcar (lambda (judgment)
                                      (let ((v-val (first judgment))
                                            (i-val (second judgment))
                                            (s-val (third judgment)))
                                        (concat-octets (encode v-val)
                                                       (e2 i-val)
                                                       (encode s-val))))
                                    j))
                           (judgments-concat (apply #'concat-octets encoded-judgments)))
                      ;; (r, E4(a), [...])
                      (concat-octets (encode r)
                                     (e4 a)
                                     judgments-concat)))
                  v))
         (verdicts-concat (apply #'concat-octets encoded-verdicts)))
    ;; E(↕verdicts, ↕c, ↕f)
    (concat-octets (encode-with-length verdicts-concat)
                   (encode-with-length c)
                   (encode-with-length f))))

(defun decode-disputes (octets &optional (start 0))
  "Decode disputes from octets.
   
   Graypaper Appendix C.21: ED((v, c, f)) = E(↕[...], ↕c, ↕f)
   
   Args:
     octets: Encoded disputes data
     start: Starting position
   
   Returns:
     values: (disputes bytes-consumed)"
  (let ((pos start))
    ;; ↕verdicts : length-prefixed sequence of verdict entries
    (multiple-value-bind (verdicts-length verdicts-length-bytes)
        (decode-natural octets pos)
      (incf pos verdicts-length-bytes)
      
      (let ((verdicts '())
            (verdicts-end (+ pos verdicts-length)))
        ;; Parse each verdict: (r, E4(a), [(v, E2(i), s) | ...])
        (loop while (< pos verdicts-end) do
          ;; r : report data
          (multiple-value-bind (r r-consumed)
              (decode-with-length octets pos)
            (incf pos r-consumed)
            
            ;; E4(a) : component a (4 bytes)
            (let* ((a-octets (subseq octets pos (+ pos 4)))
                   (a (decode-fixed-integer a-octets 4)))
              (incf pos 4)
              
              ;; [(v, E2(i), s) | ...] : judgments (NOT length-prefixed in C.21)
              ;; TODO: Need to know how to determine end of judgments
              ;; For now, decode as length-prefixed
              (multiple-value-bind (judgments-length judgments-length-bytes)
                  (decode-natural octets pos)
                (incf pos judgments-length-bytes)
                
                (let ((judgments '())
                      (judgments-end (+ pos judgments-length)))
                  ;; Parse each judgment: (v, E2(i), s)
                  (loop while (< pos judgments-end) do
                    ;; v : value/data
                    (multiple-value-bind (v v-consumed)
                        (decode-with-length octets pos)
                      (incf pos v-consumed)
                      
                      ;; E2(i) : index (2 bytes)
                      (let* ((i-octets (subseq octets pos (+ pos 2)))
                             (i (decode-fixed-integer i-octets 2)))
                        (incf pos 2)
                        
                        ;; s : signature
                        (multiple-value-bind (s s-consumed)
                            (decode-with-length octets pos)
                          (incf pos s-consumed)
                          
                          ;; Add judgment as list (v i s)
                          (push (list v i s) judgments)))))
                  
                  ;; Create verdict entry
                  (push (make-verdict-entry
                         :report-data r
                         :component-a a
                         :judgments (nreverse judgments))
                        verdicts))))))
        
        ;; ↕c : culprits
        (multiple-value-bind (culprits culprits-consumed)
            (decode-with-length octets pos)
          (incf pos culprits-consumed)
          
          ;; ↕f : faults
          (multiple-value-bind (faults faults-consumed)
              (decode-with-length octets pos)
            (incf pos faults-consumed)
            
            ;; Create disputes structure
            (values
             (make-disputes
              :verdicts (nreverse verdicts)
              :culprits culprits
              :faults faults)
             (- pos start))))))))
