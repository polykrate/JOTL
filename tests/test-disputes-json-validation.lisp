;;;; test-disputes-json-validation.lisp
;;;; Test ED (Disputes) decode against JSON values

(ql:quickload '(:jotl :cl-json) :silent t)

(defun hex-string-equal (a b)
  "Compare two hex strings (case-insensitive, with or without 0x prefix)."
  (let ((clean-a (string-downcase (string-trim "0x" (if (stringp a) a (jam.ffi:bytes-to-hex-string a)))))
        (clean-b (string-downcase (string-trim "0x" (if (stringp b) b (jam.ffi:bytes-to-hex-string b))))))
    (string= clean-a clean-b)))

(defun bytes-to-hex (bytes)
  "Convert bytes to hex string for display."
  (jam.ffi:bytes-to-hex-string bytes))

(defun test-disputes-json-validation ()
  "Test ED (Disputes) decoding against JSON values."
  (format t "~%╔════════════════════════════════════════════════════════╗~%")
  (format t "║  ED (Disputes) - JSON Validation Test                 ║~%")
  (format t "╚════════════════════════════════════════════════════════╝~%~%")
  
  ;; Load binary and JSON
  (let* ((bin-path "/home/polycrate/Projets/JOTL/tests/jamtestvectors/codec/tiny/disputes_extrinsic.bin")
         (json-path "/home/polycrate/Projets/JOTL/tests/jamtestvectors/codec/tiny/disputes_extrinsic.json")
         (bin-data (with-open-file (stream bin-path :element-type '(unsigned-byte 8))
                     (let ((data (make-array (file-length stream) :element-type '(unsigned-byte 8))))
                       (read-sequence data stream)
                       data)))
         (json-data (with-open-file (stream json-path)
                      (cl-json:decode-json stream))))
    
    (format t "Binary: ~a bytes~%" (length bin-data))
    (format t "JSON loaded: ~a~%~%" json-data)
    
    ;; Decode binary
    (multiple-value-bind (disputes bytes-consumed)
        (jotl:decode-disputes-extrinsic bin-data 0)
      
      (format t "Decoded: ~a bytes~%~%" bytes-consumed)
      
      ;; Extract JSON sections
      (let ((json-verdicts (cdr (assoc :verdicts json-data)))
            (json-culprits (cdr (assoc :culprits json-data)))
            (json-faults (cdr (assoc :faults json-data)))
            (decoded-verdicts (getf disputes :verdicts))
            (decoded-culprits (getf disputes :culprits))
            (decoded-faults (getf disputes :faults)))
        
        (format t "╔════════════════════════════════════════════════════════╗~%")
        (format t "║  Verdicts Validation                                   ║~%")
        (format t "╚════════════════════════════════════════════════════════╝~%")
        (format t "JSON verdicts count: ~a~%" (length json-verdicts))
        (format t "Decoded verdicts count: ~a~%~%" (length decoded-verdicts))
        
        ;; Validate first verdict
        (when (and (> (length json-verdicts) 0)
                   (> (length decoded-verdicts) 0))
          (let ((json-v (first json-verdicts))
                (decoded-v (first decoded-verdicts)))
            (format t "Verdict 0:~%")
            (format t "  JSON target: ~a~%" (cdr (assoc :target json-v)))
            (format t "  Decoded:     ~a~%" (bytes-to-hex (getf decoded-v :target)))
            (format t "  Match: ~a~%~%" 
                    (hex-string-equal (cdr (assoc :target json-v))
                                      (getf decoded-v :target)))
            
            (format t "  JSON age: ~a~%" (cdr (assoc :age json-v)))
            (format t "  Decoded:  ~a~%" (getf decoded-v :age))
            (format t "  Match: ~a~%~%" 
                    (= (cdr (assoc :age json-v))
                       (getf decoded-v :age)))
            
            (let ((json-votes (cdr (assoc :votes json-v)))
                  (decoded-votes (getf decoded-v :votes)))
              (format t "  Votes count: JSON=~a, Decoded=~a~%"
                      (length json-votes) (length decoded-votes))
              
              ;; Validate first vote
              (when (and (> (length json-votes) 0)
                         (> (length decoded-votes) 0))
                (let ((json-vote (first json-votes))
                      (decoded-vote (first decoded-votes)))
                  (format t "~%  Vote 0:~%")
                  (format t "    JSON vote: ~a~%" 
                          (cdr (assoc :vote json-vote)))
                  (format t "    Decoded:   ~a~%" 
                          (getf decoded-vote :vote))
                  (format t "    Match: ~a~%~%" 
                          (eq (cdr (assoc :vote json-vote))
                              (getf decoded-vote :vote)))
                  
                  (format t "    JSON index: ~a~%" (cdr (assoc :index json-vote)))
                  (format t "    Decoded:    ~a~%" (getf decoded-vote :index))
                  (format t "    Match: ~a~%~%" 
                          (= (cdr (assoc :index json-vote))
                             (getf decoded-vote :index)))
                  
                  (format t "    JSON signature: ~a~%" (cdr (assoc :signature json-vote)))
                  (format t "    Decoded:        ~a~%" (bytes-to-hex (getf decoded-vote :signature)))
                  (format t "    Match: ~a~%" 
                          (hex-string-equal (cdr (assoc :signature json-vote))
                                            (getf decoded-vote :signature))))))))
        
        (format t "~%╔════════════════════════════════════════════════════════╗~%")
        (format t "║  Culprits Validation                                   ║~%")
        (format t "╚════════════════════════════════════════════════════════╝~%")
        (format t "JSON culprits count: ~a~%" (length json-culprits))
        (format t "Decoded culprits count: ~a~%~%" (length decoded-culprits))
        
        ;; Validate first culprit
        (when (and (> (length json-culprits) 0)
                   (> (length decoded-culprits) 0))
          (let ((json-c (first json-culprits))
                (decoded-c (first decoded-culprits)))
            (format t "Culprit 0:~%")
            (format t "  JSON target: ~a~%" (cdr (assoc :target json-c)))
            (format t "  Decoded:     ~a~%" (bytes-to-hex (getf decoded-c :target)))
            (format t "  Match: ~a~%~%" 
                    (hex-string-equal (cdr (assoc :target json-c))
                                      (getf decoded-c :target)))))
        
        (format t "~%╔════════════════════════════════════════════════════════╗~%")
        (format t "║  Faults Validation                                     ║~%")
        (format t "╚════════════════════════════════════════════════════════╝~%")
        (format t "JSON faults count: ~a~%" (length json-faults))
        (format t "Decoded faults count: ~a~%~%" (length decoded-faults))
        
        ;; Validate first fault
        (when (and (> (length json-faults) 0)
                   (> (length decoded-faults) 0))
          (let ((json-f (first json-faults))
                (decoded-f (first decoded-faults)))
            (format t "Fault 0:~%")
            (format t "  JSON target: ~a~%" (cdr (assoc :target json-f)))
            (format t "  Decoded:     ~a~%" (bytes-to-hex (getf decoded-f :target)))
            (format t "  Match: ~a~%~%" 
                    (hex-string-equal (cdr (assoc :target json-f))
                                      (getf decoded-f :target)))
            
            (format t "  JSON vote: ~a~%" (cdr (assoc :vote json-f)))
            (format t "  Decoded:   ~a~%" (getf decoded-f :vote))
            (format t "  Match: ~a~%" 
                    (eq (cdr (assoc :vote json-f))
                        (getf decoded-f :vote)))))
        
        (format t "~%╔════════════════════════════════════════════════════════╗~%")
        (format t "║  ✅ JSON Validation Complete!                         ║~%")
        (format t "╚════════════════════════════════════════════════════════╝~%")))))

;; Run the test
(test-disputes-json-validation)
