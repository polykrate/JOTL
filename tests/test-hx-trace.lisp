;;;; test-hx-trace.lisp - Test HX computation against strawberry trace vectors
;;;;
;;;; These trace vectors come from jam-test-vectors/traces and are used by
;;;; strawberry (Go implementation) to validate the extrinsic hash computation.
;;;; Unlike codec test vectors, these contain REAL blocks with correct HX values.

(in-package #:jotl)

;; Load shared test helpers
(load (merge-pathnames "test-utils.lisp" *load-pathname*))

;;; ==========================================================================
;;; Encode extrinsic components from JSON data
;;; ==========================================================================

(defun encode-tickets-from-json (tickets-json)
  "Encode ET from JSON array of tickets."
  (let ((tickets (mapcar (lambda (t-obj)
                           (let ((attempt (cdr (assoc :attempt t-obj)))
                                 (sig-hex (cdr (assoc :signature t-obj))))
                             (list :attempt attempt
                                   :signature (hex-to-bytes sig-hex))))
                         tickets-json)))
    (encode-tickets-extrinsic tickets)))

(defun encode-preimages-from-json (preimages-json)
  "Encode EP from JSON array of preimages."
  (let ((preimages (mapcar (lambda (p-obj)
                             (let ((requester (cdr (assoc :requester p-obj)))
                                   (blob-hex (cdr (assoc :blob p-obj))))
                               (list :requester requester
                                     :blob (hex-to-bytes blob-hex))))
                           preimages-json)))
    (encode-preimages-extrinsic preimages)))

(defun encode-assurances-from-json (assurances-json)
  "Encode EA from JSON array of assurances."
  (let ((assurances (mapcar (lambda (a-obj)
                              (list :anchor (hex-to-bytes
                                             (cdr (assoc :anchor a-obj)))
                                    :bitfield (hex-to-bytes
                                               (cdr (assoc :bitfield a-obj)))
                                    :validator-index (cdr (assoc :validator--index a-obj))
                                    :signature (hex-to-bytes
                                                (cdr (assoc :signature a-obj)))))
                            assurances-json)))
    (encode-assurances-extrinsic assurances)))

(defun build-guarantees-from-json (guarantees-json)
  "Build guarantee summaries from JSON for HX computation.
   Returns list of guarantee plists with :report-raw-bytes :slot :signatures."
  (mapcar (lambda (g-json)
            (let* ((wr-json (cdr (assoc :report g-json)))
                   (report-bytes (encode-work-report (json-work-report wr-json)))
                   (slot (cdr (assoc :slot g-json)))
                   (sigs-json (cdr (assoc :signatures g-json)))
                   (signatures (mapcar (lambda (s-json)
                                         (list :validator-index (cdr (assoc :validator--index s-json))
                                               :signature (hex-to-bytes
                                                           (cdr (assoc :signature s-json)))))
                                       sigs-json)))
              (list :report-raw-bytes report-bytes
                    :slot slot
                    :signatures signatures)))
          guarantees-json))

;;; ==========================================================================
;;; Test Functions
;;; ==========================================================================

(defun test-hx-from-trace (trace-file)
  "Test HX computation from a trace JSON file.
   
   Args:
     trace-file: Path to trace JSON file
   
   Returns:
     T if match, NIL if not"
  (format t "~%=== Testing HX from ~a ===~%" trace-file)
  
  (let* ((trace (with-open-file (stream trace-file)
                  (cl-json:decode-json stream)))
         (block-json (cdr (assoc :block trace)))
         (header-json (cdr (assoc :header block-json)))
         (extrinsic-json (cdr (assoc :extrinsic block-json)))
         
         ;; Expected HX from header
         (expected-hx (hex-to-bytes (cdr (assoc :extrinsic--hash header-json))))
         
         ;; Extract components from JSON
         (tickets-json (cdr (assoc :tickets extrinsic-json)))
         (preimages-json (cdr (assoc :preimages extrinsic-json)))
         (guarantees-json (cdr (assoc :guarantees extrinsic-json)))
         (assurances-json (cdr (assoc :assurances extrinsic-json)))
         (disputes-json (cdr (assoc :disputes extrinsic-json))))
    
    (format t "Components: ET=~d, EP=~d, EG=~d, EA=~d, ED=(v=~d,c=~d,f=~d)~%"
            (length tickets-json)
            (length preimages-json)
            (length guarantees-json)
            (length assurances-json)
            (length (cdr (assoc :verdicts disputes-json)))
            (length (cdr (assoc :culprits disputes-json)))
            (length (cdr (assoc :faults disputes-json))))
    
    ;; Encode each component
    (let* ((encoded-et (encode-tickets-from-json tickets-json))
           (encoded-ep (encode-preimages-from-json preimages-json))
           (encoded-ea (encode-assurances-from-json assurances-json))
           (encoded-ed (encode-disputes-extrinsic (json-disputes disputes-json)))
           
           ;; Build guarantee summaries (g)
           (guarantee-plists (build-guarantees-from-json guarantees-json))
           (g (compute-guarantee-summaries guarantee-plists))
           
           ;; Compute HX
           (h-et (jam.ffi:blake2b-256 encoded-et))
           (h-ep (jam.ffi:blake2b-256 encoded-ep))
           (h-g  (jam.ffi:blake2b-256 g))
           (h-ea (jam.ffi:blake2b-256 encoded-ea))
           (h-ed (jam.ffi:blake2b-256 encoded-ed))
           
           (concatenated (concatenate '(vector (unsigned-byte 8))
                                      h-et h-ep h-g h-ea h-ed))
           (computed-hx (jam.ffi:blake2b-256 concatenated)))
      
      (format t "~%Sizes: ET=~d EP=~d g=~d EA=~d ED=~d~%"
              (length encoded-et) (length encoded-ep) (length g)
              (length encoded-ea) (length encoded-ed))
      
      (format t "~%Hashes:~%")
      (format t "  H(ET): ~a~%" (jam.ffi:bytes-to-hex-string h-et))
      (format t "  H(EP): ~a~%" (jam.ffi:bytes-to-hex-string h-ep))
      (format t "  H(g):  ~a~%" (jam.ffi:bytes-to-hex-string h-g))
      (format t "  H(EA): ~a~%" (jam.ffi:bytes-to-hex-string h-ea))
      (format t "  H(ED): ~a~%" (jam.ffi:bytes-to-hex-string h-ed))
      
      (format t "~%Computed HX: ~a~%" (jam.ffi:bytes-to-hex-string computed-hx))
      (format t "Expected HX: ~a~%" (jam.ffi:bytes-to-hex-string expected-hx))
      
      (if (equalp computed-hx expected-hx)
          (progn
            (format t "✅ HX MATCH!~%")
            t)
          (progn
            (format t "❌ HX MISMATCH!~%")
            nil)))))

(defun run-hx-trace-tests ()
  "Run HX tests against all available trace vectors."
  (let ((test-dir "tests/trace-vectors/extrinsic_hash/")
        (pass 0)
        (fail 0))
    (dolist (file (directory (merge-pathnames "*.json" test-dir)))
      (handler-case
          (if (test-hx-from-trace (namestring file))
              (incf pass)
              (incf fail))
        (error (e)
          (format t "~%ERROR in ~a: ~a~%" (namestring file) e)
          (incf fail))))
    
    (format t "~%~%========================================~%")
    (format t "HX Trace Tests: ~d passed, ~d failed~%" pass fail)
    (format t "========================================~%")
    (zerop fail)))
