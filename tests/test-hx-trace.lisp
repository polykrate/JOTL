;;;; test-hx-trace.lisp - Test HX computation against strawberry trace vectors
;;;;
;;;; These trace vectors come from jam-test-vectors/traces and are used by
;;;; strawberry (Go implementation) to validate the extrinsic hash computation.
;;;; Unlike codec test vectors, these contain REAL blocks with correct HX values.

(in-package :jotl)

(defun hex-string-to-bytes-safe (hex-str)
  "Convert hex string to byte array, handling 0x prefix."
  (jam.ffi:hex-string-to-bytes
   (if (and (stringp hex-str) (>= (length hex-str) 2)
            (string= "0x" (subseq hex-str 0 2)))
       (subseq hex-str 2)
       hex-str)))

;;; ==========================================================================
;;; Encode extrinsic components from JSON data
;;; ==========================================================================

(defun encode-tickets-from-json (tickets-json)
  "Encode ET from JSON array of tickets."
  (let ((tickets (mapcar (lambda (t-obj)
                           (let ((attempt (cdr (assoc :attempt t-obj)))
                                 (sig-hex (cdr (assoc :signature t-obj))))
                             (list :attempt attempt
                                   :signature (hex-string-to-bytes-safe sig-hex))))
                         tickets-json)))
    (encode-tickets-extrinsic tickets)))

(defun encode-preimages-from-json (preimages-json)
  "Encode EP from JSON array of preimages."
  (let ((preimages (mapcar (lambda (p-obj)
                             (let ((requester (cdr (assoc :requester p-obj)))
                                   (blob-hex (cdr (assoc :blob p-obj))))
                               (list :requester requester
                                     :blob (hex-string-to-bytes-safe blob-hex))))
                           preimages-json)))
    (encode-preimages-extrinsic preimages)))

(defun encode-assurances-from-json (assurances-json)
  "Encode EA from JSON array of assurances."
  (let ((assurances (mapcar (lambda (a-obj)
                              (list :anchor (hex-string-to-bytes-safe
                                             (cdr (assoc :anchor a-obj)))
                                    :bitfield (hex-string-to-bytes-safe
                                               (cdr (assoc :bitfield a-obj)))
                                    :validator-index (cdr (assoc :validator--index a-obj))
                                    :signature (hex-string-to-bytes-safe
                                                (cdr (assoc :signature a-obj)))))
                            assurances-json)))
    (encode-assurances-extrinsic assurances)))

(defun encode-disputes-from-json (disputes-json)
  "Encode ED from JSON object with verdicts, culprits, faults."
  (let* ((verdicts-json (cdr (assoc :verdicts disputes-json)))
         (culprits-json (cdr (assoc :culprits disputes-json)))
         (faults-json (cdr (assoc :faults disputes-json)))
         (disputes (list
                    :verdicts (mapcar (lambda (v)
                                        (list :target (hex-string-to-bytes-safe
                                                       (cdr (assoc :target v)))
                                              :age (cdr (assoc :age v))
                                              :votes (mapcar (lambda (vote)
                                                               (list :vote (cdr (assoc :vote vote))
                                                                     :index (cdr (assoc :index vote))
                                                                     :signature (hex-string-to-bytes-safe
                                                                                 (cdr (assoc :signature vote)))))
                                                             (cdr (assoc :votes v)))))
                                      (or verdicts-json '()))
                    :culprits (mapcar (lambda (c)
                                        (list :target (hex-string-to-bytes-safe
                                                       (cdr (assoc :target c)))
                                              :key (hex-string-to-bytes-safe
                                                    (cdr (assoc :key c)))
                                              :signature (hex-string-to-bytes-safe
                                                          (cdr (assoc :signature c)))))
                                      (or culprits-json '()))
                    :faults (mapcar (lambda (f)
                                      (list :target (hex-string-to-bytes-safe
                                                     (cdr (assoc :target f)))
                                            :vote (cdr (assoc :vote f))
                                            :key (hex-string-to-bytes-safe
                                                  (cdr (assoc :key f)))
                                            :signature (hex-string-to-bytes-safe
                                                        (cdr (assoc :signature f)))))
                                    (or faults-json '())))))
    (encode-disputes-extrinsic disputes)))

(defun encode-work-report-from-json (wr-json)
  "Encode a WorkReport from its JSON representation.
   Returns byte array."
  (let* ((pkg-json (cdr (assoc :package--spec wr-json)))
         (ctx-json (cdr (assoc :context wr-json)))
         (results-json (cdr (assoc :results wr-json)))
         
         ;; WorkPackageSpec
         (package-spec (list :hash (hex-string-to-bytes-safe (cdr (assoc :hash pkg-json)))
                             :length (cdr (assoc :length pkg-json))
                             :erasure-root (hex-string-to-bytes-safe (cdr (assoc :erasure--root pkg-json)))
                             :exports-root (hex-string-to-bytes-safe (cdr (assoc :exports--root pkg-json)))
                             :exports-count (cdr (assoc :exports--count pkg-json))))
         
         ;; RefineContext
         (prereqs-json (cdr (assoc :prerequisites ctx-json)))
         (context (list :anchor (hex-string-to-bytes-safe (cdr (assoc :anchor ctx-json)))
                        :state-root (hex-string-to-bytes-safe (cdr (assoc :state--root ctx-json)))
                        :beefy-root (hex-string-to-bytes-safe (cdr (assoc :beefy--root ctx-json)))
                        :lookup-anchor (hex-string-to-bytes-safe (cdr (assoc :lookup--anchor ctx-json)))
                        :lookup-anchor-slot (cdr (assoc :lookup--anchor--slot ctx-json))
                        :prerequisites (mapcar #'hex-string-to-bytes-safe
                                               (or prereqs-json '()))))
         
         ;; WorkResults
         (results (mapcar (lambda (r-json)
                            (let* ((result-val-json (cdr (assoc :result r-json)))
                                   ;; Parse enum: {"ok": "0x..."} or {"panic": null} etc.
                                   (result-val (cond
                                                 ((assoc :ok result-val-json)
                                                  (list :ok (hex-string-to-bytes-safe
                                                             (cdr (assoc :ok result-val-json)))))
                                                 ((assoc :out--of--gas result-val-json) (list :out-of-gas t))
                                                 ((assoc :panic result-val-json) (list :panic t))
                                                 ((assoc :bad--exports result-val-json) (list :bad-exports t))
                                                 ((assoc :output--oversize result-val-json) (list :output-oversize t))
                                                 ((assoc :bad--code result-val-json) (list :bad-code t))
                                                 ((assoc :code--oversize result-val-json) (list :code-oversize t))
                                                 (t (error "Unknown result variant: ~a" result-val-json))))
                                   (load-json (cdr (assoc :refine--load r-json)))
                                   (refine-load (list :gas-used (cdr (assoc :gas--used load-json))
                                                      :imports (cdr (assoc :imports load-json))
                                                      :extrinsic-count (cdr (assoc :extrinsic--count load-json))
                                                      :extrinsic-size (cdr (assoc :extrinsic--size load-json))
                                                      :exports (cdr (assoc :exports load-json)))))
                              (list :service-id (cdr (assoc :service--id r-json))
                                    :code-hash (hex-string-to-bytes-safe (cdr (assoc :code--hash r-json)))
                                    :payload-hash (hex-string-to-bytes-safe (cdr (assoc :payload--hash r-json)))
                                    :accumulate-gas (cdr (assoc :accumulate--gas r-json))
                                    :result result-val
                                    :refine-load refine-load)))
                          results-json))
         
         ;; Full WorkReport
         (work-report (list :package-spec package-spec
                            :context context
                            :core-index (cdr (assoc :core--index wr-json))
                            :authorizer-hash (hex-string-to-bytes-safe
                                              (cdr (assoc :authorizer--hash wr-json)))
                            :auth-gas-used (cdr (assoc :auth--gas--used wr-json))
                            :auth-output (hex-string-to-bytes-safe
                                          (cdr (assoc :auth--output wr-json)))
                            :segment-root-lookup (mapcar (lambda (item)
                                                           (list :work-package-hash
                                                                 (hex-string-to-bytes-safe
                                                                  (cdr (assoc :work--package--hash item)))
                                                                 :segment-tree-root
                                                                 (hex-string-to-bytes-safe
                                                                  (cdr (assoc :segment--tree--root item)))))
                                                         (or (cdr (assoc :segment--root--lookup wr-json)) '()))
                            :results results)))
    (encode-work-report work-report)))

(defun build-guarantees-from-json (guarantees-json)
  "Build guarantee summaries from JSON for HX computation.
   Returns list of guarantee plists with :report-raw-bytes :slot :signatures."
  (mapcar (lambda (g-json)
            (let* ((wr-json (cdr (assoc :report g-json)))
                   (report-bytes (encode-work-report-from-json wr-json))
                   (slot (cdr (assoc :slot g-json)))
                   (sigs-json (cdr (assoc :signatures g-json)))
                   (signatures (mapcar (lambda (s-json)
                                         (list :validator-index (cdr (assoc :validator--index s-json))
                                               :signature (hex-string-to-bytes-safe
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
         (expected-hx (hex-string-to-bytes-safe (cdr (assoc :extrinsic--hash header-json))))
         
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
           (encoded-ed (encode-disputes-from-json disputes-json))
           
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
