;;;; test-all-extrinsics-json.lisp
;;;; Complete JSON validation for ALL extrinsic components

(ql:quickload '(:jotl :cl-json) :silent t)

(defun hex-string-equal (a b)
  "Compare two hex strings (case-insensitive, with or without 0x prefix)."
  (let ((clean-a (string-downcase (string-trim "0x" (if (stringp a) a (jam.ffi:bytes-to-hex-string a)))))
        (clean-b (string-downcase (string-trim "0x" (if (stringp b) b (jam.ffi:bytes-to-hex-string b))))))
    (string= clean-a clean-b)))

(defun bytes-to-hex (bytes)
  "Convert bytes to hex string for display."
  (jam.ffi:bytes-to-hex-string bytes))

(defun test-component (name bin-path json-path decoder-fn)
  "Generic test for an extrinsic component."
  (format t "~%╔════════════════════════════════════════════════════════╗~%")
  (format t "║  ~a - JSON Validation~a║~%" 
          name (make-string (max 0 (- 42 (length name))) :initial-element #\Space))
  (format t "╚════════════════════════════════════════════════════════╝~%~%")
  
  ;; Load binary and JSON
  (let* ((bin-data (with-open-file (stream bin-path :element-type '(unsigned-byte 8))
                     (let ((data (make-array (file-length stream) :element-type '(unsigned-byte 8))))
                       (read-sequence data stream)
                       data)))
         (json-items (with-open-file (stream json-path)
                       (cl-json:decode-json stream))))
    
    (format t "Binary: ~a bytes~%" (length bin-data))
    (format t "JSON items: ~a~%~%" (length json-items))
    
    ;; Decode binary
    (multiple-value-bind (decoded bytes-consumed)
        (funcall decoder-fn bin-data 0)
      
      (format t "Decoded: ~a bytes~%~%" bytes-consumed)
      
      ;; Validate count
      (let ((decoded-count (length decoded)))
        (format t "Count validation:~%")
        (format t "  JSON:    ~a~%" (length json-items))
        (format t "  Decoded: ~a~%" decoded-count)
        (format t "  Match:   ~a~%~%" (= (length json-items) decoded-count))
        
        (if (= (length json-items) decoded-count)
            (progn
              (format t "✅ ~a: Count matches!~%" name)
              (values t decoded json-items))
            (progn
              (format t "❌ ~a: Count mismatch!~%" name)
              (values nil decoded json-items)))))))

;;; ==========================================================================
;;; ET (Tickets) Validation
;;; ==========================================================================

(defun test-tickets-json ()
  "Test ET (Tickets) against JSON."
  (multiple-value-bind (success decoded json-items)
      (test-component "ET (Tickets)"
                      "/home/polycrate/Projets/JOTL/tests/jamtestvectors/codec/tiny/tickets_extrinsic.bin"
                      "/home/polycrate/Projets/JOTL/tests/jamtestvectors/codec/tiny/tickets_extrinsic.json"
                      #'jotl:decode-tickets-extrinsic)
    
    (when (and success (> (length json-items) 0) (> (length decoded) 0))
      (let ((json-ticket (first json-items))
            (decoded-ticket (first decoded)))
        (format t "~%Ticket 0 validation:~%")
        (format t "  JSON attempt: ~a~%" (cdr (assoc :attempt json-ticket)))
        (format t "  Decoded:      ~a~%" (getf decoded-ticket :attempt))
        (format t "  Match:        ~a~%~%" 
                (= (cdr (assoc :attempt json-ticket))
                   (getf decoded-ticket :attempt)))
        
        (format t "  Signature match: ~a~%" 
                (hex-string-equal (cdr (assoc :signature json-ticket))
                                  (getf decoded-ticket :signature)))))
    success))

;;; ==========================================================================
;;; EP (Preimages) Validation
;;; ==========================================================================

(defun test-preimages-json ()
  "Test EP (Preimages) against JSON."
  (multiple-value-bind (success decoded json-items)
      (test-component "EP (Preimages)"
                      "/home/polycrate/Projets/JOTL/tests/jamtestvectors/codec/tiny/preimages_extrinsic.bin"
                      "/home/polycrate/Projets/JOTL/tests/jamtestvectors/codec/tiny/preimages_extrinsic.json"
                      #'jotl:decode-preimages-extrinsic)
    
    (when (and success (> (length json-items) 0) (> (length decoded) 0))
      (let ((json-preimage (first json-items))
            (decoded-preimage (first decoded)))
        (format t "~%Preimage 0 validation:~%")
        (format t "  JSON requester: ~a~%" (cdr (assoc :requester json-preimage)))
        (format t "  Decoded:        ~a~%" (getf decoded-preimage :requester))
        (format t "  Match:          ~a~%~%" 
                (= (cdr (assoc :requester json-preimage))
                   (getf decoded-preimage :requester)))
        
        (format t "  Blob match: ~a~%" 
                (hex-string-equal (cdr (assoc :blob json-preimage))
                                  (getf decoded-preimage :blob)))))
    success))

;;; ==========================================================================
;;; EA (Assurances) Validation
;;; ==========================================================================

(defun test-assurances-json ()
  "Test EA (Assurances) against JSON."
  (multiple-value-bind (success decoded json-items)
      (test-component "EA (Assurances)"
                      "/home/polycrate/Projets/JOTL/tests/jamtestvectors/codec/tiny/assurances_extrinsic.bin"
                      "/home/polycrate/Projets/JOTL/tests/jamtestvectors/codec/tiny/assurances_extrinsic.json"
                      #'jotl:decode-assurances-extrinsic)
    
    (when (and success (> (length json-items) 0) (> (length decoded) 0))
      (let ((json-assurance (first json-items))
            (decoded-assurance (first decoded)))
        (format t "~%Assurance 0 validation:~%")
        (format t "  Anchor match: ~a~%" 
                (hex-string-equal (cdr (assoc :anchor json-assurance))
                                  (getf decoded-assurance :anchor)))
        
        (format t "  Bitfield match: ~a~%" 
                (hex-string-equal (cdr (assoc :bitfield json-assurance))
                                  (getf decoded-assurance :bitfield)))
        
        ;; Handle cl-json's double-dash transformation
        (let ((json-validator-index (or (cdr (assoc :validator-index json-assurance))
                                        (cdr (assoc :validator--index json-assurance)))))
          (format t "  JSON validator-index: ~a~%" json-validator-index)
          (format t "  Decoded:              ~a~%" (getf decoded-assurance :validator-index))
          (format t "  Match:                ~a~%" 
                  (= json-validator-index
                     (getf decoded-assurance :validator-index))))))
    success))

;;; ==========================================================================
;;; ED (Disputes) Validation
;;; ==========================================================================

(defun test-disputes-json ()
  "Test ED (Disputes) against JSON."
  (format t "~%╔════════════════════════════════════════════════════════╗~%")
  (format t "║  ED (Disputes) - JSON Validation                       ║~%")
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
    
    (format t "Binary: ~a bytes~%~%" (length bin-data))
    
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
        
        ;; Validate verdicts
        (format t "Verdicts: JSON=~a, Decoded=~a, Match=~a~%"
                (length json-verdicts) (length decoded-verdicts)
                (= (length json-verdicts) (length decoded-verdicts)))
        
        (when (and (> (length json-verdicts) 0) (> (length decoded-verdicts) 0))
          (let ((json-v (first json-verdicts))
                (decoded-v (first decoded-verdicts)))
            (format t "  Verdict 0 target match: ~a~%"
                    (hex-string-equal (cdr (assoc :target json-v))
                                      (getf decoded-v :target)))
            (format t "  Verdict 0 age match: ~a~%"
                    (= (cdr (assoc :age json-v)) (getf decoded-v :age)))))
        
        ;; Validate culprits
        (format t "Culprits: JSON=~a, Decoded=~a, Match=~a~%"
                (length json-culprits) (length decoded-culprits)
                (= (length json-culprits) (length decoded-culprits)))
        
        ;; Validate faults
        (format t "Faults: JSON=~a, Decoded=~a, Match=~a~%"
                (length json-faults) (length decoded-faults)
                (= (length json-faults) (length decoded-faults)))
        
        (and (= (length json-verdicts) (length decoded-verdicts))
             (= (length json-culprits) (length decoded-culprits))
             (= (length json-faults) (length decoded-faults)))))))

;;; ==========================================================================
;;; Master Test Runner
;;; ==========================================================================

(defun test-all-extrinsics-json ()
  "Test all extrinsic components against JSON."
  (format t "~%╔════════════════════════════════════════════════════════╗~%")
  (format t "║  JOTL - Complete Extrinsic JSON Validation Suite      ║~%")
  (format t "║  Testing ALL components: ET, EP, EA, ED                ║~%")
  (format t "╚════════════════════════════════════════════════════════╝~%")
  
  (let ((results '()))
    ;; Test each component
    (push (cons "ET (Tickets)" (test-tickets-json)) results)
    (push (cons "EP (Preimages)" (test-preimages-json)) results)
    (push (cons "EA (Assurances)" (test-assurances-json)) results)
    (push (cons "ED (Disputes)" (test-disputes-json)) results)
    
    ;; Summary
    (format t "~%~%╔════════════════════════════════════════════════════════╗~%")
    (format t "║  SUMMARY                                               ║~%")
    (format t "╚════════════════════════════════════════════════════════╝~%~%")
    
    (dolist (result (reverse results))
      (format t "  ~a: ~a~%"
              (car result)
              (if (cdr result) "✅ PASS" "❌ FAIL")))
    
    (let ((passed (count-if #'cdr results))
          (total (length results)))
      (format t "~%~%╔════════════════════════════════════════════════════════╗~%")
      (if (= passed total)
          (format t "║  🎉 ALL TESTS PASSED! (~a/~a)~a║~%"
                  passed total
                  (make-string (max 0 (- 29 (length (format nil "~a/~a" passed total))))
                               :initial-element #\Space))
          (format t "║  ⚠️  SOME TESTS FAILED (~a/~a)~a║~%"
                  passed total
                  (make-string (max 0 (- 25 (length (format nil "~a/~a" passed total))))
                               :initial-element #\Space)))
      (format t "╚════════════════════════════════════════════════════════╝~%")
      
      (= passed total))))

;; Run the test
(test-all-extrinsics-json)
