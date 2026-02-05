;;;; reports.lisp
;;;; JAM Reports/Guarantees (EG or EC) - Completed workload reports
;;;; Graypaper references: Section 4.2, Appendix C.19

(in-package :jotl-bloc)

;;; Reports EG (called EC in encoding specs)
;;;
;;; Graypaper Section 4.2: The Block (extrinsic data component)
;;; Reports of newly completed workloads whose accuracy is guaranteed
;;; by specific validators.

(defstruct jam-report
  "A workload completion report (r, t, a).
   
   Reports newly completed workloads, with accuracy guaranteed
   by specific validators.
   - r: report data/hash
   - t: timeslot (encoded on 4 octets)
   - a: sequence of (validator_index, signature) pairs"
  
  (report-data nil :type t)           ; r
  (timeslot nil :type (or null natural))  ; t
  (assurances nil :type list))         ; a: list of (v, s) pairs

(deftype jam-reports ()
  "Sequence of reports/guarantees (EG)"
  'list)

;;; Encoding
;;; Graypaper Appendix C.19: EC(EG) = E(↕[(r, E4(t), ↕[(E2(v), s) | (v,s) ∈ a]) | (r,t,a) ∈ EG])
;;;
;;; Length-prefixed sequence of report entries where each is:
;;; (r, E4(t), ↕[(E2(v), s) | (v,s) ∈ a])

(defun encode-reports (reports)
  "Encode reports/guarantees (EG).
   
   Graypaper Appendix C.19: EC(EG) = E(↕[(r, E4(t), ↕[(E2(v), s) | (v,s) ∈ a]) | (r,t,a) ∈ EG])
   
   Args:
     reports: List of jam-report structures
   
   Returns:
     Encoded octet sequence"
  (let ((encoded-reports
         (mapcar (lambda (report)
                   (let* ((r (jam-report-report-data report))
                          (t-val (jam-report-timeslot report))
                          (a (jam-report-assurances report))
                          ;; ↕[(E2(v), s) | (v,s) ∈ a]
                          (encoded-assurances
                           (mapcar (lambda (assurance)
                                     (let ((v (car assurance))  ; validator index
                                           (s (cdr assurance))) ; signature
                                       (concat-octets (e2 v) (encode s))))
                                   a))
                          (assurances-concat (apply #'concat-octets encoded-assurances)))
                     ;; (r, E4(t), ↕[...])
                     (concat-octets (encode r)
                                    (e4 t-val)
                                    (encode-with-length assurances-concat))))
                 reports)))
    ;; ↕[...] : length-prefixed sequence
    (let ((concatenated (apply #'concat-octets encoded-reports)))
      (concat-octets (encode-natural (length concatenated))
                     concatenated))))

(defun decode-reports (octets &optional (start 0))
  "Decode reports from octets.
   
   Graypaper Appendix C.19: EC(EG) = E(↕[(r, E4(t), ↕[(E2(v), s) | (v,s) ∈ a]) | (r,t,a) ∈ EG])
   
   Args:
     octets: Encoded reports data
     start: Starting position
   
   Returns:
     values: (list-of-reports bytes-consumed)"
  ;; ↕[...] : length-prefixed sequence
  (multiple-value-bind (total-length length-bytes)
      (decode-natural octets start)
    (if (zerop total-length)
        ;; Empty reports list
        (values nil length-bytes)
        ;; Parse reports
        (let ((reports '())
              (pos (+ start length-bytes))
              (end (+ start length-bytes total-length)))
          (loop while (< pos end) do
            ;; Each report is: (r, E4(t), ↕[(E2(v), s) | (v,s) ∈ a])
            
            ;; r : report data (depends on type - for now decode as octets)
            ;; TODO: define precise report data structure
            (multiple-value-bind (r r-consumed)
                (decode-with-length octets pos)
              (incf pos r-consumed)
              
              ;; E4(t) : timeslot (4 bytes)
              (let* ((timeslot-octets (subseq octets pos (+ pos 4)))
                     (timeslot (decode-fixed-integer timeslot-octets 4)))
                (incf pos 4)
                
                ;; ↕[(E2(v), s) | (v,s) ∈ a] : length-prefixed assurances
                (multiple-value-bind (assurances-length assurances-length-bytes)
                    (decode-natural octets pos)
                  (incf pos assurances-length-bytes)
                  
                  (let ((assurances '())
                        (assurances-end (+ pos assurances-length)))
                    ;; Parse each (E2(v), s) pair
                    (loop while (< pos assurances-end) do
                      ;; E2(v) : validator index (2 bytes)
                      (let* ((v-octets (subseq octets pos (+ pos 2)))
                             (v (decode-fixed-integer v-octets 2)))
                        (incf pos 2)
                        
                        ;; s : signature (depends on type - for now read as octets)
                        ;; TODO: define precise signature type
                        (multiple-value-bind (s s-consumed)
                            (decode-with-length octets pos)
                          (incf pos s-consumed)
                          
                          ;; Add assurance pair (v . s)
                          (push (cons v s) assurances))))
                    
                    ;; Create report
                    (push (make-jam-report
                           :report-data r
                           :timeslot timeslot
                           :assurances (nreverse assurances))
                          reports))))))
          
          (values (nreverse reports) (- pos start))))))
