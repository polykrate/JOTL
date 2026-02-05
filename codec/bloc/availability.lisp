;;;; availability.lisp
;;;; JAM Availability Assurances (EA) - Validator data storage guarantees
;;;; Graypaper references: Section 4.2, Appendix C.20

(in-package :jotl-bloc)

;;; Availability EA
;;;
;;; Graypaper Section 4.2: The Block (extrinsic data component)
;;; Assurances by each validator concerning which of the input data
;;; of workloads they have correctly received and are storing locally.

(defstruct availability-assurance
  "An availability assurance (a, f, v, s).
   
   Indicates that a validator has correctly received and is storing
   workload input data locally.
   - a: assurance data (first component)
   - f: second component
   - v: validator index (encoded on 2 octets)
   - s: signature"
  
  (assurance-a nil :type t)           ; a
  (component-f nil :type t)           ; f
  (validator-index nil :type (or null natural))  ; v
  (signature nil :type t))            ; s

(deftype jam-availability ()
  "Sequence of availability assurances (EA)"
  'list)

;;; Encoding
;;; Graypaper Appendix C.20: EA(EA) = E(↕[(a, f, E2(v), s) | (a,f,v,s) ∈ EA])
;;;
;;; Length-prefixed sequence of (a, f, E2(v), s) tuples

(defun encode-availability (availability)
  "Encode availability assurances (EA).
   
   Graypaper Appendix C.20: EA(EA) = E(↕[(a, f, E2(v), s) | (a,f,v,s) ∈ EA])
   
   Args:
     availability: List of availability-assurance structures
   
   Returns:
     Encoded octet sequence"
  (let ((encoded-assurances
         (mapcar (lambda (assurance)
                   (let ((a (availability-assurance-assurance-a assurance))
                         (f (availability-assurance-component-f assurance))
                         (v (availability-assurance-validator-index assurance))
                         (s (availability-assurance-signature assurance)))
                     ;; (a, f, E2(v), s)
                     (concat-octets (encode a)
                                    (encode f)
                                    (e2 v)
                                    (encode s))))
                 availability)))
    ;; ↕[...] : length-prefixed sequence
    (let ((concatenated (apply #'concat-octets encoded-assurances)))
      (concat-octets (encode-natural (length concatenated))
                     concatenated))))

(defun decode-availability (octets &optional (start 0))
  "Decode availability assurances from octets.
   
   Graypaper Appendix C.20: EA(EA) = E(↕[(a, f, E2(v), s) | (a,f,v,s) ∈ EA])
   
   Args:
     octets: Encoded availability data
     start: Starting position
   
   Returns:
     values: (list-of-assurances bytes-consumed)"
  ;; ↕[...] : length-prefixed sequence
  (multiple-value-bind (total-length length-bytes)
      (decode-natural octets start)
    (if (zerop total-length)
        ;; Empty availability list
        (values nil length-bytes)
        ;; Parse assurances
        (let ((assurances '())
              (pos (+ start length-bytes))
              (end (+ start length-bytes total-length)))
          (loop while (< pos end) do
            ;; Each assurance is: (a, f, E2(v), s)
            
            ;; a : first component (depends on type - decode as octets)
            ;; TODO: define precise structure for 'a'
            (multiple-value-bind (a a-consumed)
                (decode-with-length octets pos)
              (incf pos a-consumed)
              
              ;; f : second component (depends on type - decode as octets)
              ;; TODO: define precise structure for 'f'
              (multiple-value-bind (f f-consumed)
                  (decode-with-length octets pos)
                (incf pos f-consumed)
                
                ;; E2(v) : validator index (2 bytes)
                (let* ((v-octets (subseq octets pos (+ pos 2)))
                       (v (decode-fixed-integer v-octets 2)))
                  (incf pos 2)
                  
                  ;; s : signature (depends on type - decode as octets)
                  ;; TODO: define precise signature type
                  (multiple-value-bind (s s-consumed)
                      (decode-with-length octets pos)
                    (incf pos s-consumed)
                    
                    ;; Create assurance
                    (push (make-availability-assurance
                           :assurance-a a
                           :component-f f
                           :validator-index v
                           :signature s)
                          assurances))))))
          
          (values (nreverse assurances) (- pos start))))))
