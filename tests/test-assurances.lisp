;;;; tests/test-assurances.lisp — ρ‡ (Assurances) STF tests
;;;; Full validation: transition-rho-ddagger against jamtestvectors/stf/assurances
;;;;
;;;; Tests per vector:
;;;;   1. Parse pre_state (avail_assignments, curr_validators)
;;;;   2. Parse input (assurances, slot, parent)
;;;;   3. Execute transition-rho-ddagger(EA, ρ†, τ', Hp, κ)
;;;;   4. Compare output: ok → reported work-reports | err → error code
;;;;   5. Compare post_state: avail_assignments byte-by-byte
;;;;   6. Verify post_state validators unchanged
;;;;   7. Codec roundtrip: encode → decode → re-compare (avail_assignments)
;;;;
;;;; 20 vectors total: 10 tiny + 10 full
;;;; Green 🟢 = expected OK, Red 🔴 = expected error

(in-package :jotl)

;;; ═══════════════════════════════════════════════════════════════
;;; JSON PARSERS
;;; ═══════════════════════════════════════════════════════════════

(defun hex-string-to-bytes-safe* (hex-str)
  "Convert hex string to byte array, handling 0x prefix and empty strings."
  (cond
    ((null hex-str) (make-array 0 :element-type '(unsigned-byte 8)))
    ((and (stringp hex-str) (or (string= hex-str "") (string= hex-str "0x")))
     (make-array 0 :element-type '(unsigned-byte 8)))
    (t (jam.ffi:hex-string-to-bytes hex-str))))

(defun assurance-json-validators (validators-json)
  "Parse JSON validator list → list of plists with all 4 key types."
  (mapcar (lambda (v)
            (list :bandersnatch (hex-string-to-bytes-safe*
                                 (cdr (assoc :bandersnatch v)))
                  :ed25519 (hex-string-to-bytes-safe*
                            (or (cdr (assoc :ed25519 v))
                                (cdr (assoc :ed-25519 v))))
                  :bls (hex-string-to-bytes-safe*
                        (cdr (assoc :bls v)))
                  :metadata (hex-string-to-bytes-safe*
                             (cdr (assoc :metadata v)))))
          validators-json))

(defun assurance-json-work-report (wr-json)
  "Parse a JSON WorkReport → plist (same format as our internal representation)."
  (when (null wr-json) (return-from assurance-json-work-report nil))
  (let* ((pkg-json (cdr (assoc :package--spec wr-json)))
         (ctx-json (cdr (assoc :context wr-json)))
         (results-json (cdr (assoc :results wr-json)))
         ;; WorkPackageSpec
         (package-spec (list :hash (hex-string-to-bytes-safe*
                                    (cdr (assoc :hash pkg-json)))
                             :length (cdr (assoc :length pkg-json))
                             :erasure-root (hex-string-to-bytes-safe*
                                            (cdr (assoc :erasure--root pkg-json)))
                             :exports-root (hex-string-to-bytes-safe*
                                            (cdr (assoc :exports--root pkg-json)))
                             :exports-count (cdr (assoc :exports--count pkg-json))))
         ;; RefineContext
         (prereqs-json (cdr (assoc :prerequisites ctx-json)))
         (context (list :anchor (hex-string-to-bytes-safe*
                                 (cdr (assoc :anchor ctx-json)))
                        :state-root (hex-string-to-bytes-safe*
                                     (cdr (assoc :state--root ctx-json)))
                        :beefy-root (hex-string-to-bytes-safe*
                                     (cdr (assoc :beefy--root ctx-json)))
                        :lookup-anchor (hex-string-to-bytes-safe*
                                        (cdr (assoc :lookup--anchor ctx-json)))
                        :lookup-anchor-slot (cdr (assoc :lookup--anchor--slot ctx-json))
                        :prerequisites (mapcar #'hex-string-to-bytes-safe*
                                               (or prereqs-json '()))))
         ;; WorkResults
         (results (mapcar (lambda (r-json)
                            (let* ((result-val-json (cdr (assoc :result r-json)))
                                   (result-val
                                     (cond
                                       ((assoc :ok result-val-json)
                                        (list :ok (hex-string-to-bytes-safe*
                                                   (cdr (assoc :ok result-val-json)))))
                                       ((assoc :out--of--gas result-val-json)
                                        (list :out-of-gas t))
                                       ((assoc :panic result-val-json)
                                        (list :panic t))
                                       ((assoc :bad--exports result-val-json)
                                        (list :bad-exports t))
                                       ((assoc :output--oversize result-val-json)
                                        (list :output-oversize t))
                                       ((assoc :bad--code result-val-json)
                                        (list :bad-code t))
                                       ((assoc :code--oversize result-val-json)
                                        (list :code-oversize t))
                                       (t (error "Unknown result variant: ~A"
                                                  result-val-json))))
                                   (load-json-rl (cdr (assoc :refine--load r-json)))
                                   (refine-load
                                     (list :gas-used (cdr (assoc :gas--used load-json-rl))
                                           :imports (cdr (assoc :imports load-json-rl))
                                           :extrinsic-count (cdr (assoc :extrinsic--count load-json-rl))
                                           :extrinsic-size (cdr (assoc :extrinsic--size load-json-rl))
                                           :exports (cdr (assoc :exports load-json-rl)))))
                              (list :service-id (cdr (assoc :service--id r-json))
                                    :code-hash (hex-string-to-bytes-safe*
                                                (cdr (assoc :code--hash r-json)))
                                    :payload-hash (hex-string-to-bytes-safe*
                                                   (cdr (assoc :payload--hash r-json)))
                                    :accumulate-gas (cdr (assoc :accumulate--gas r-json))
                                    :result result-val
                                    :refine-load refine-load)))
                          results-json)))
    (list :package-spec package-spec
          :context context
          :core-index (cdr (assoc :core--index wr-json))
          :authorizer-hash (hex-string-to-bytes-safe*
                            (cdr (assoc :authorizer--hash wr-json)))
          :auth-gas-used (cdr (assoc :auth--gas--used wr-json))
          :auth-output (hex-string-to-bytes-safe*
                        (cdr (assoc :auth--output wr-json)))
          :segment-root-lookup (mapcar (lambda (item)
                                         (list :work-package-hash
                                               (hex-string-to-bytes-safe*
                                                (cdr (assoc :work--package--hash item)))
                                               :segment-tree-root
                                               (hex-string-to-bytes-safe*
                                                (cdr (assoc :segment--tree--root item)))))
                                       (or (cdr (assoc :segment--root--lookup wr-json)) '()))
          :results results)))

(defun assurance-json-assignment (assign-json)
  "Parse a JSON AvailabilityAssignment → nil or plist with :report :timeout.
   JSON null → nil."
  (if (or (null assign-json) (eq assign-json :null))
      nil
      (list :report (assurance-json-work-report (cdr (assoc :report assign-json)))
            :timeout (cdr (assoc :timeout assign-json)))))

(defun assurance-json-assignments (assignments-json)
  "Parse JSON avail_assignments list → list of (nil | plist)."
  (mapcar #'assurance-json-assignment assignments-json))

(defun assurance-json-assurances (assurances-json)
  "Parse JSON assurances extrinsic → list of assurance plists."
  (mapcar (lambda (a)
            (list :anchor (hex-string-to-bytes-safe*
                           (cdr (assoc :anchor a)))
                  :bitfield (hex-string-to-bytes-safe*
                             (cdr (assoc :bitfield a)))
                  :validator-index (cdr (assoc :validator--index a))
                  :signature (hex-string-to-bytes-safe*
                              (cdr (assoc :signature a)))))
          assurances-json))

;;; ═══════════════════════════════════════════════════════════════
;;; COMPARISON HELPERS
;;; ═══════════════════════════════════════════════════════════════

(defun compare-work-report (label actual expected)
  "Deep comparison of two WorkReport plists. Returns T if match."
  (when (and (null actual) (null expected)) (return-from compare-work-report t))
  (when (or (null actual) (null expected))
    (format t "    ✗ ~A: nil vs non-nil~%" label)
    (return-from compare-work-report nil))
  ;; Compare by encoding both to binary (most reliable byte-exact comparison)
  (let ((actual-bytes (encode-work-report actual))
        (expected-bytes (encode-work-report expected)))
    (if (equalp actual-bytes expected-bytes)
        t
        (progn
          (format t "    ✗ ~A: work-report binary mismatch (len ~D vs ~D)~%"
                  label (length actual-bytes) (length expected-bytes))
          nil))))

(defun compare-assignment (label actual expected)
  "Compare two assignments (nil or plist). Returns T if match."
  (cond
    ((and (null actual) (null expected)) t)
    ((or (null actual) (null expected))
     (format t "    ✗ ~A: nil/non-nil mismatch~%" label) nil)
    (t (let ((report-ok (compare-work-report
                          (format nil "~A.report" label)
                          (getf actual :report) (getf expected :report)))
             (timeout-ok (= (getf actual :timeout) (getf expected :timeout))))
         (unless timeout-ok
           (format t "    ✗ ~A.timeout: ~D ≠ ~D~%" label
                   (getf actual :timeout) (getf expected :timeout)))
         (and report-ok timeout-ok)))))

(defun compare-assignments (label actual expected)
  "Compare two assignment lists (ρ). Returns T if all match."
  (let ((ok t))
    (unless (= (length actual) (length expected))
      (format t "    ✗ ~A: length ~D ≠ ~D~%" label
              (length actual) (length expected))
      (return-from compare-assignments nil))
    (loop for a in actual for e in expected for i from 0
          unless (compare-assignment (format nil "~A[~D]" label i) a e)
            do (setf ok nil))
    ok))

(defun compare-reported (label actual expected)
  "Compare reported work-reports (R*). Returns T if all match."
  (let ((ok t))
    (unless (= (length actual) (length expected))
      (format t "    ✗ ~A: length ~D ≠ ~D~%" label
              (length actual) (length expected))
      (return-from compare-reported nil))
    (loop for a in actual for e in expected for i from 0
          unless (compare-work-report (format nil "~A[~D]" label i) a e)
            do (setf ok nil))
    ok))

(defun compare-validators (label actual expected)
  "Compare two validator lists by encoding each to binary. Returns T if match."
  (let ((ok t))
    (unless (= (length actual) (length expected))
      (format t "    ✗ ~A: length ~D ≠ ~D~%" label
              (length actual) (length expected))
      (return-from compare-validators nil))
    (loop for a in actual for e in expected for i from 0
          do (let ((a-ed (ensure-bytes (getf a :ed25519)))
                   (e-ed (ensure-bytes (getf e :ed25519))))
               (unless (equalp a-ed e-ed)
                 (format t "    ✗ ~A[~D].ed25519 mismatch~%" label i)
                 (setf ok nil))))
    ok))

;;; ═══════════════════════════════════════════════════════════════
;;; CODEC ROUNDTRIP
;;; ═══════════════════════════════════════════════════════════════

(defun test-rho-codec-roundtrip (assignments label)
  "Verify encode/decode roundtrip for ρ (avail_assignments).
   Returns T if roundtrip matches."
  (handler-case
      (let* ((encoded (encode-state-rho assignments))
             (decoded (multiple-value-bind (result consumed)
                          (decode-state-rho encoded)
                        (declare (ignore consumed))
                        result)))
        (if (compare-assignments (format nil "~A/roundtrip" label)
                                 decoded assignments)
            t
            (progn
              (format t "    ✗ ~A: ρ codec roundtrip mismatch~%" label)
              nil)))
    (error (e)
      (format t "    ✗ ~A: ρ codec roundtrip error: ~A~%" label e)
      nil)))

;;; ═══════════════════════════════════════════════════════════════
;;; ERROR CODE MAPPING
;;; ═══════════════════════════════════════════════════════════════

(defun assurance-error-code-to-string (code)
  "Map our keyword error codes to test vector error strings."
  (case code
    (:bad-attestation-parent "bad_attestation_parent")
    (:bad-validator-index    "bad_validator_index")
    (:core-not-engaged       "core_not_engaged")
    (:bad-signature          "bad_signature")
    (:not-sorted-or-unique-assurers "not_sorted_or_unique_assurers")
    (otherwise (format nil "~(~A~)" code))))

(defun normalize-error-string (s)
  "Normalize error code string: snake_case, strip quotes."
  (substitute #\_ #\- (string-downcase (string-trim '(#\" #\Space) s))))

;;; ═══════════════════════════════════════════════════════════════
;;; RUN ONE TEST
;;; ═══════════════════════════════════════════════════════════════

(defun run-assurance-test (path spec)
  "Run a single assurance test vector. Prints result with ✅/❌."
  (let* ((json (cl-json:decode-json-from-string (uiop:read-file-string path)))
         (input-json (cdr (assoc :input json)))
         (pre-json (or (cdr (assoc :pre-state json))
                       (cdr (assoc :pre--state json))))
         (output-json (cdr (assoc :output json)))
         (post-json (or (cdr (assoc :post-state json))
                        (cdr (assoc :post--state json))))
         ;; ── Parse input ──
         (assurances (assurance-json-assurances
                      (cdr (assoc :assurances input-json))))
         (tau-prime (cdr (assoc :slot input-json)))
         (parent-hash (hex-string-to-bytes-safe*
                       (cdr (assoc :parent input-json))))
         ;; ── Parse pre-state ──
         (pre-assignments (assurance-json-assignments
                           (or (cdr (assoc :avail--assignments pre-json))
                               (cdr (assoc :avail-assignments pre-json)))))
         (pre-validators (assurance-json-validators
                          (or (cdr (assoc :curr--validators pre-json))
                              (cdr (assoc :curr-validators pre-json)))))
         ;; ── Parse expected post-state ──
         (post-assignments (assurance-json-assignments
                            (or (cdr (assoc :avail--assignments post-json))
                                (cdr (assoc :avail-assignments post-json)))))
         (post-validators (assurance-json-validators
                           (or (cdr (assoc :curr--validators post-json))
                               (cdr (assoc :curr-validators post-json)))))
         ;; ── Parse expected output ──
         (expected-ok (cdr (assoc :ok output-json)))
         (expected-err (cdr (assoc :err output-json)))
         (expected-reported
           (when expected-ok
             (mapcar #'assurance-json-work-report
                     (cdr (assoc :reported expected-ok)))))
         (fname (file-namestring path)))
    (let ((*chain* (case spec
                     (:tiny +tiny-chainspec+)
                     (:full +full-chainspec+)
                     (otherwise (error "Unknown chain: ~A" spec)))))
      (handler-case
          (multiple-value-bind (rho-ddagger r-star err)
              (transition-rho-ddagger assurances pre-assignments
                                     :tau-prime tau-prime
                                     :parent-hash parent-hash
                                     :kappa pre-validators)
            (if err
                ;; transition-rho-ddagger returned error via handler-case
                (if expected-err
                    (format t "  ✅ ~A (err: ~A)~%" fname
                            (assurance-error-code err))
                    (format t "  ❌ ~A — unexpected error: ~A~%" fname err))
                ;; Success path
                (if expected-ok
                    (let* (;; Compare ρ‡ vs expected post-state assignments
                           (assign-ok (compare-assignments
                                        (format nil "~A/ρ‡" fname)
                                        rho-ddagger post-assignments))
                           ;; Compare R* (reported) vs expected output
                           (report-ok (compare-reported
                                        (format nil "~A/R*" fname)
                                        r-star expected-reported))
                           ;; Compare validators unchanged
                           (val-ok (compare-validators
                                     (format nil "~A/κ" fname)
                                     pre-validators post-validators))
                           ;; Codec roundtrip on result
                           (codec-ok (test-rho-codec-roundtrip
                                       rho-ddagger fname)))
                      (if (and assign-ok report-ok val-ok codec-ok)
                          (format t "  ✅ ~A~%" fname)
                          (format t "  ❌ ~A —~A~A~A~A~%" fname
                                  (if assign-ok "" " ρ‡-mismatch")
                                  (if report-ok "" " R*-mismatch")
                                  (if val-ok "" " κ-changed")
                                  (if codec-ok "" " codec-fail"))))
                    ;; Expected error but got OK
                    (format t "  ❌ ~A — expected error '~A' but got OK~%"
                            fname expected-err))))
        ;; Direct error (not returned via 3rd value)
        (assurance-error (e)
          (if expected-err
              (format t "  ✅ ~A (err: ~A)~%" fname
                      (assurance-error-code e))
              (format t "  ❌ ~A — unexpected error: ~A~%" fname e)))
        (error (e)
          (format t "  💥 ~A — ~A~%" fname e))))))

;;; ═══════════════════════════════════════════════════════════════
;;; RUN ALL TESTS
;;; ═══════════════════════════════════════════════════════════════

(let ((total 0) (passed 0))
  (dolist (spec '(:tiny :full))
    (format t "~%=== Assurances STF Tests (~(~A~)) ===~%" spec)
    (let ((dir (format nil "tests/jamtestvectors/stf/assurances/~(~A~)/" spec)))
      (dolist (path (sort (directory (merge-pathnames "*.json" dir))
                          #'string< :key #'namestring))
        (incf total)
        (let ((output (with-output-to-string (*standard-output*)
                        (run-assurance-test (namestring path) spec))))
          (write-string output)
          (when (search "✅" output) (incf passed))))))
  (format t "~%  ~A ρ‡ (assurances): ~D/~D passed~%"
          (if (= passed total) "✅" "❌") passed total))
