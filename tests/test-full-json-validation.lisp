;;;; test-full-json-validation.lisp - Exhaustive comparison: decoded binary vs JSON
;;;; For ALL extrinsic components (ET, EP, EG, EA, ED) from block.json

(in-package :jotl)

;;; ==========================================================================
;;; Helpers
;;; ==========================================================================

(defun bytes-to-hex (bytes)
  "Convert byte array to 0x-prefixed lowercase hex string."
  (jam.ffi:bytes-to-hex-string bytes))

(defun hex-match-p (decoded-bytes json-hex)
  "Compare decoded bytes with a JSON hex string like '0xabcd...'."
  (string-equal (bytes-to-hex decoded-bytes) json-hex))

(defun load-json (path)
  "Load a JSON file."
  (with-open-file (s path :direction :input)
    (cl-json:decode-json s)))

(defun load-bin (path)
  "Load a binary file."
  (with-open-file (s path :direction :input :element-type '(unsigned-byte 8))
    (let ((data (make-array (file-length s) :element-type '(unsigned-byte 8))))
      (read-sequence data s)
      data)))

(defparameter *pass-count* 0)
(defparameter *fail-count* 0)

(defun assert-equal (label expected actual)
  "Check equality and print result."
  (if (equal expected actual)
      (progn (incf *pass-count*)
             (format t "    ✅ ~a: ~a~%" label actual))
      (progn (incf *fail-count*)
             (format t "    ❌ ~a: expected ~a, got ~a~%" label expected actual))))

(defun assert-hex (label decoded-bytes json-hex)
  "Check hex match."
  (if (null decoded-bytes)
      (progn (incf *fail-count*)
             (format t "    ❌ ~a: decoded-bytes is NIL!~%" label))
      (let ((got (bytes-to-hex decoded-bytes)))
        (if (string-equal got json-hex)
            (progn (incf *pass-count*)
                   (format t "    ✅ ~a: ~a...~%" label (subseq json-hex 0 (min 20 (length json-hex)))))
            (progn (incf *fail-count*)
                   (format t "    ❌ ~a~%       expected: ~a...~%       got:      ~a...~%" 
                           label 
                           (subseq json-hex 0 (min 20 (length json-hex)))
                           (subseq got 0 (min 20 (length got)))))))))

(defun json-val (alist key)
  "Get value from cl-json alist by keyword.
   cl-json converts JSON key 'foo_bar' to Lisp keyword :FOO--BAR"
  (cdr (assoc key alist)))

;;; ==========================================================================
;;; Test ET (Tickets)
;;; ==========================================================================

(defun test-tickets (decoded-tickets json-tickets)
  (format t "~%--- ET (Tickets) ---~%")
  (assert-equal "count" (length json-tickets) (length decoded-tickets))
  (loop for d in decoded-tickets
        for j in json-tickets
        for i from 0
        do (format t "  Ticket ~a:~%" i)
           (assert-equal (format nil "  attempt") (json-val j :attempt) (getf d :attempt))
           (assert-hex (format nil "  signature") (getf d :signature) (json-val j :signature))))

;;; ==========================================================================
;;; Test EP (Preimages)
;;; ==========================================================================

(defun test-preimages (decoded-preimages json-preimages)
  (format t "~%--- EP (Preimages) ---~%")
  (assert-equal "count" (length json-preimages) (length decoded-preimages))
  (loop for d in decoded-preimages
        for j in json-preimages
        for i from 0
        do (format t "  Preimage ~a:~%" i)
           (assert-equal (format nil "  requester") (json-val j :requester) (getf d :requester))
           (let ((d-blob (getf d :blob))
                 (j-blob (json-val j :blob)))
             (if (and d-blob j-blob)
                 (assert-hex (format nil "  blob") d-blob j-blob)
                 (progn (incf *fail-count*)
                        (format t "    ❌ blob: decoded=~a json=~a~%" 
                                (if d-blob "present" "NIL")
                                (if j-blob "present" "NIL")))))))

;;; ==========================================================================
;;; Test EA (Assurances)
;;; ==========================================================================

(defun test-assurances (decoded-assurances json-assurances)
  (format t "~%--- EA (Assurances) ---~%")
  (assert-equal "count" (length json-assurances) (length decoded-assurances))
  (loop for d in decoded-assurances
        for j in json-assurances
        for i from 0
        do (format t "  Assurance ~a:~%" i)
           (assert-hex (format nil "  anchor") (getf d :anchor) (json-val j :anchor))
           (assert-hex (format nil "  bitfield") (getf d :bitfield) (json-val j :bitfield))
           ;; cl-json: validator_index → :VALIDATOR--INDEX
           (assert-equal (format nil "  validator_index") (json-val j :validator--index) (getf d :validator-index))
           (assert-hex (format nil "  signature") (getf d :signature) (json-val j :signature))))

;;; ==========================================================================
;;; Test ED (Disputes)
;;; ==========================================================================

(defun test-disputes (decoded-disputes json-disputes)
  (format t "~%--- ED (Disputes) ---~%")
  (let ((d-verdicts (getf decoded-disputes :verdicts))
        (d-culprits (getf decoded-disputes :culprits))
        (d-faults (getf decoded-disputes :faults))
        (j-verdicts (json-val json-disputes :verdicts))
        (j-culprits (json-val json-disputes :culprits))
        (j-faults (json-val json-disputes :faults)))
    
    ;; Verdicts
    (format t "  Verdicts:~%")
    (assert-equal "  count" (length j-verdicts) (length d-verdicts))
    (loop for dv in d-verdicts
          for jv in j-verdicts
          for i from 0
          do (format t "  Verdict ~a:~%" i)
             (assert-hex (format nil "    target") (getf dv :target) (json-val jv :target))
             (assert-equal (format nil "    age") (json-val jv :age) (getf dv :age))
             (format t "    votes: ~a decoded~%" (length (getf dv :votes)))
             (loop for dvote in (getf dv :votes)
                   for jvote in (json-val jv :votes)
                   for vi from 0
                   do (assert-equal (format nil "      vote[~a].vote" vi) 
                                    (json-val jvote :vote) (getf dvote :vote))
                      (assert-equal (format nil "      vote[~a].index" vi) 
                                    (json-val jvote :index) (getf dvote :index))
                      (assert-hex (format nil "      vote[~a].sig" vi) 
                                  (getf dvote :signature) (json-val jvote :signature))))
    
    ;; Culprits
    (format t "  Culprits:~%")
    (assert-equal "  count" (length j-culprits) (length d-culprits))
    (loop for dc in d-culprits
          for jc in j-culprits
          for i from 0
          do (format t "  Culprit ~a:~%" i)
             (assert-hex (format nil "    target") (getf dc :target) (json-val jc :target))
             (assert-hex (format nil "    key") (getf dc :key) (json-val jc :key))
             (assert-hex (format nil "    signature") (getf dc :signature) (json-val jc :signature)))
    
    ;; Faults
    (format t "  Faults:~%")
    (assert-equal "  count" (length j-faults) (length d-faults))
    (loop for df in d-faults
          for jf in j-faults
          for i from 0
          do (format t "  Fault ~a:~%" i)
             (assert-hex (format nil "    target") (getf df :target) (json-val jf :target))
             (assert-equal (format nil "    vote") (json-val jf :vote) (getf df :vote))
             (assert-hex (format nil "    key") (getf df :key) (json-val jf :key))
             (assert-hex (format nil "    signature") (getf df :signature) (json-val jf :signature)))))

;;; ==========================================================================
;;; Test EG (Guarantees) - the big one!
;;; ==========================================================================

(defun test-work-package-spec (decoded json-spec)
  (format t "      WorkPackageSpec:~%")
  (assert-hex "        hash" (getf decoded :hash) (json-val json-spec :hash))
  (assert-equal "        length" (json-val json-spec :length) (getf decoded :length))
  ;; cl-json: erasure_root → :ERASURE--ROOT
  (assert-hex "        erasure_root" (getf decoded :erasure-root) (json-val json-spec :erasure--root))
  (assert-hex "        exports_root" (getf decoded :exports-root) (json-val json-spec :exports--root))
  (assert-equal "        exports_count" (json-val json-spec :exports--count) (getf decoded :exports-count)))

(defun test-refine-context (decoded json-ctx)
  (format t "      RefineContext:~%")
  (assert-hex "        anchor" (getf decoded :anchor) (json-val json-ctx :anchor))
  ;; cl-json: state_root → :STATE--ROOT
  (assert-hex "        state_root" (getf decoded :state-root) (json-val json-ctx :state--root))
  (assert-hex "        beefy_root" (getf decoded :beefy-root) (json-val json-ctx :beefy--root))
  (assert-hex "        lookup_anchor" (getf decoded :lookup-anchor) (json-val json-ctx :lookup--anchor))
  (assert-equal "        lookup_anchor_slot" (json-val json-ctx :lookup--anchor--slot) (getf decoded :lookup-anchor-slot))
  ;; prerequisites: list of hashes
  (let ((d-prereqs (getf decoded :prerequisites))
        (j-prereqs (json-val json-ctx :prerequisites)))
    (assert-equal "        prerequisites count" (length j-prereqs) (length d-prereqs))
    (loop for dp in d-prereqs
          for jp in j-prereqs
          for pidx from 0
          do (assert-hex (format nil "          prereq[~a]" pidx) dp jp))))

(defun test-refine-load (decoded json-load)
  (format t "        RefineLoad:~%")
  ;; cl-json: gas_used → :GAS--USED
  (assert-equal "          gas_used" (json-val json-load :gas--used) (getf decoded :gas-used))
  (assert-equal "          imports" (json-val json-load :imports) (getf decoded :imports))
  (assert-equal "          extrinsic_count" (json-val json-load :extrinsic--count) (getf decoded :extrinsic-count))
  (assert-equal "          extrinsic_size" (json-val json-load :extrinsic--size) (getf decoded :extrinsic-size))
  (assert-equal "          exports" (json-val json-load :exports) (getf decoded :exports)))

(defun test-work-result (decoded json-result idx)
  (format t "      Result ~a:~%" idx)
  ;; cl-json: service_id → :SERVICE--ID
  (assert-equal "        service_id" (json-val json-result :service--id) (getf decoded :service-id))
  (assert-hex "        code_hash" (getf decoded :code-hash) (json-val json-result :code--hash))
  (assert-hex "        payload_hash" (getf decoded :payload-hash) (json-val json-result :payload--hash))
  ;; cl-json: accumulate_gas → :ACCUMULATE--GAS
  (assert-equal "        accumulate_gas" (json-val json-result :accumulate--gas) (getf decoded :accumulate-gas))
  ;; Result enum
  (let ((json-result-val (json-val json-result :result))
        (decoded-result (getf decoded :result)))
    ;; WorkExecResult enum: 0=ok, 1=out_of_gas, 2=panic, 3=bad_exports,
    ;; 4=output_oversize, 5=bad_code, 6=code_oversize
    ;; cl-json maps {"ok": "0x..."} → ((:OK . "0x..."))
    ;; cl-json maps {"panic": null} → ((:PANIC))
    (cond
      ;; Ok variant
      ((json-val json-result-val :ok)
       (format t "        result: Ok~%")
       (assert-hex "          ok_blob" (getf decoded-result :ok) (json-val json-result-val :ok)))
      ;; Null-payload variants: out_of_gas, panic, bad_exports, etc.
      ((assoc :panic json-result-val)
       (format t "        result: Panic~%")
       (assert-equal "          panic" t (getf decoded-result :panic)))
      ((assoc :out--of--gas json-result-val)
       (format t "        result: OutOfGas~%")
       (assert-equal "          out_of_gas" t (getf decoded-result :out-of-gas)))
      ((assoc :bad--exports json-result-val)
       (format t "        result: BadExports~%")
       (assert-equal "          bad_exports" t (getf decoded-result :bad-exports)))
      ((assoc :output--oversize json-result-val)
       (format t "        result: OutputOversize~%")
       (assert-equal "          output_oversize" t (getf decoded-result :output-oversize)))
      ((assoc :bad--code json-result-val)
       (format t "        result: BadCode~%")
       (assert-equal "          bad_code" t (getf decoded-result :bad-code)))
      ((assoc :code--oversize json-result-val)
       (format t "        result: CodeOversize~%")
       (assert-equal "          code_oversize" t (getf decoded-result :code-oversize)))
      ;; Unknown
      (t (format t "        result: Unknown ~a / decoded: ~a~%" json-result-val decoded-result))))
  ;; RefineLoad
  ;; cl-json: refine_load → :REFINE--LOAD
  (test-refine-load (getf decoded :refine-load) (json-val json-result :refine--load)))

(defun test-guarantees (decoded-guarantees json-guarantees)
  (format t "~%--- EG (Guarantees) ---~%")
  (assert-equal "count" (length json-guarantees) (length decoded-guarantees))
  (loop for dg in decoded-guarantees
        for jg in json-guarantees
        for i from 0
        do (format t "  Guarantee ~a:~%" i)
           ;; slot
           (assert-equal "    slot" (json-val jg :slot) (getf dg :slot))
           ;; signatures
           (let ((d-sigs (getf dg :signatures))
                 ;; cl-json: signatures stays :SIGNATURES
                 (j-sigs (json-val jg :signatures)))
             (assert-equal "    signatures count" (length j-sigs) (length d-sigs))
             (loop for ds in d-sigs
                   for js in j-sigs
                   for si from 0
                   ;; cl-json: validator_index → :VALIDATOR--INDEX
                   do (assert-equal (format nil "    sig[~a].validator_index" si)
                                    (json-val js :validator--index) (getf ds :validator-index))
                      (assert-hex (format nil "    sig[~a].signature" si)
                                  (getf ds :signature) (json-val js :signature))))
           ;; WorkReport
           (let ((dr (getf dg :report))
                 (jr (json-val jg :report)))
             (format t "    WorkReport:~%")
             ;; WorkPackageSpec: cl-json package_spec → :PACKAGE--SPEC
             (test-work-package-spec (getf dr :package-spec) (json-val jr :package--spec))
             ;; RefineContext
             (test-refine-context (getf dr :context) (json-val jr :context))
             ;; core_index: cl-json → :CORE--INDEX
             (assert-equal "      core_index" (json-val jr :core--index) (getf dr :core-index))
             ;; authorizer_hash: cl-json → :AUTHORIZER--HASH
             (assert-hex "      authorizer_hash" (getf dr :authorizer-hash) (json-val jr :authorizer--hash))
             ;; auth_gas_used: cl-json → :AUTH--GAS--USED
             (assert-equal "      auth_gas_used" (json-val jr :auth--gas--used) (getf dr :auth-gas-used))
             ;; auth_output: cl-json → :AUTH--OUTPUT
             (let ((d-auth (getf dr :auth-output))
                   (j-auth (json-val jr :auth--output)))
               (if (and d-auth (> (length d-auth) 0))
                   (assert-hex "      auth_output" d-auth j-auth)
                   (assert-equal "      auth_output (empty)" j-auth (bytes-to-hex (or d-auth #())))))
             ;; segment_root_lookup: cl-json → :SEGMENT--ROOT--LOOKUP
             (let ((d-seg (getf dr :segment-root-lookup))
                   (j-seg (json-val jr :segment--root--lookup)))
               (assert-equal "      segment_root_lookup count" (length j-seg) (length d-seg))
               (loop for ds in d-seg
                     for js in j-seg
                     for si from 0
                     do (assert-hex (format nil "        seg[~a].work_package_hash" si)
                                    (getf ds :work-package-hash)
                                    ;; cl-json: work_package_hash → :WORK--PACKAGE--HASH
                                    (json-val js :work--package--hash))
                        (assert-hex (format nil "        seg[~a].segment_tree_root" si)
                                    (getf ds :segment-tree-root)
                                    ;; cl-json: segment_tree_root → :SEGMENT--TREE--ROOT
                                    (json-val js :segment--tree--root))))
             ;; results
             (let ((d-results (getf dr :results))
                   (j-results (json-val jr :results)))
               (assert-equal "      results count" (length j-results) (length d-results))
               (loop for dres in d-results
                     for jres in j-results
                     for ri from 0
                     do (test-work-result dres jres ri))))))

;;; ==========================================================================
;;; Main
;;; ==========================================================================

(format t "~%========================================~%")
(format t "  EXHAUSTIVE JSON vs BINARY VALIDATION~%")
(format t "========================================~%")

(let* ((base-path "tests/jamtestvectors/codec/tiny/")
       (block-json (load-json (format nil "~ablock.json" base-path)))
       (extrinsic-json (json-val block-json :extrinsic))
       ;; Load individual binary files
       (et-bin (load-bin (format nil "~atickets_extrinsic.bin" base-path)))
       (ep-bin (load-bin (format nil "~apreimages_extrinsic.bin" base-path)))
       (eg-bin (load-bin (format nil "~aguarantees_extrinsic.bin" base-path)))
       (ea-bin (load-bin (format nil "~aassurances_extrinsic.bin" base-path)))
       (ed-bin (load-bin (format nil "~adisputes_extrinsic.bin" base-path))))
  
  ;; Decode each component and validate against JSON
  (handler-case
      (multiple-value-bind (d-tickets) (decode-tickets-extrinsic et-bin 0)
        (test-tickets d-tickets (json-val extrinsic-json :tickets)))
    (error (e) (format t "~%❌ ET DECODE ERROR: ~a~%" e) (incf *fail-count*)))
  
  (handler-case
      (multiple-value-bind (d-preimages) (decode-preimages-extrinsic ep-bin 0)
        (test-preimages d-preimages (json-val extrinsic-json :preimages)))
    (error (e) (format t "~%❌ EP DECODE ERROR: ~a~%" e) (incf *fail-count*)))
  
  (handler-case
      (multiple-value-bind (d-guarantees) (decode-guarantees-extrinsic eg-bin 0)
        (test-guarantees d-guarantees (json-val extrinsic-json :guarantees)))
    (error (e) (format t "~%❌ EG DECODE ERROR: ~a~%" e) (incf *fail-count*)))
  
  (handler-case
      (multiple-value-bind (d-assurances) (decode-assurances-extrinsic ea-bin 0)
        (test-assurances d-assurances (json-val extrinsic-json :assurances)))
    (error (e) (format t "~%❌ EA DECODE ERROR: ~a~%" e) (incf *fail-count*)))
  
  (handler-case
      (multiple-value-bind (d-disputes) (decode-disputes-extrinsic ed-bin 0)
        (test-disputes d-disputes (json-val extrinsic-json :disputes)))
    (error (e) (format t "~%❌ ED DECODE ERROR: ~a~%" e) (incf *fail-count*))))

(format t "~%========================================~%")
(format t "  RESULTS: ~a ✅ / ~a ❌~%" *pass-count* *fail-count*)
(format t "========================================~%")

(sb-ext:exit :code (if (zerop *fail-count*) 0 1))
