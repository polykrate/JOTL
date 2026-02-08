;;;; tests/test-reports.lisp — ρ' (Guarantees / Reports) STF tests
;;;; Full validation: transition-rho against jamtestvectors/stf/reports
;;;;
;;;; Tests per vector:
;;;;   1. Parse pre_state (avail_assignments, validators, entropy,
;;;;      offenders, recent_blocks, auth_pools, accounts, statistics)
;;;;   2. Parse input (guarantees, slot)
;;;;   3. Execute transition-rho(EG, ρ‡, ...) → ρ' | guarantee-error
;;;;   4. On success: call compute-output-packages-and-reporters,
;;;;      update-cores-statistics, update-services-statistics separately
;;;;   5. Compare output: ok → reported + reporters | err → error code
;;;;   6. Compare post_state: avail_assignments, cores/services statistics
;;;;   7. Codec roundtrip for avail_assignments
;;;;
;;;; 84 vectors total: 42 tiny + 42 full
;;;; Green 🟢 = expected OK, Red 🔴 = expected error

(in-package :jotl)

;; Load shared test helpers
(load (merge-pathnames "test-utils.lisp" *load-pathname*))

;;; ═══════════════════════════════════════════════════════════════
;;; JSON PARSERS (reports-specific)
;;; ═══════════════════════════════════════════════════════════════

(defun reports-json-assignment (assign-json)
  "Parse a JSON AvailabilityAssignment → nil or plist with :report :timeout."
  (if (or (null assign-json) (eq assign-json :null))
      nil
      (list :report (json-work-report (cdr (assoc :report assign-json)))
            :timeout (cdr (assoc :timeout assign-json)))))

(defun reports-json-assignments (assignments-json)
  "Parse JSON avail_assignments list → list of (nil | plist)."
  (mapcar #'reports-json-assignment assignments-json))

(defun reports-json-guarantee (g-json)
  "Parse a single JSON guarantee → plist with :report :slot :signatures."
  (list :report (json-work-report (cdr (assoc :report g-json)))
        :slot (cdr (assoc :slot g-json))
        :signatures (mapcar (lambda (s)
                              (list :validator-index
                                    (cdr (assoc :validator--index s))
                                    :signature
                                    (hex-to-bytes (cdr (assoc :signature s)))))
                            (cdr (assoc :signatures g-json)))))

(defun reports-json-guarantees (guarantees-json)
  "Parse JSON guarantees extrinsic → list of guarantee plists."
  (mapcar #'reports-json-guarantee guarantees-json))

(defun reports-json-recent-blocks (rb-json)
  "Parse JSON recent_blocks → plist (:history :mmr).
   History records: (:header-hash :state-root :beefy-root :reported)."
  (let* ((history-json (cdr (assoc :history rb-json)))
         (mmr-json (cdr (assoc :mmr rb-json)))
         (history (mapcar (lambda (h)
                            (list :header-hash (hex-to-bytes
                                                (cdr (assoc :header--hash h)))
                                  :state-root (hex-to-bytes
                                               (cdr (assoc :state--root h)))
                                  :beefy-root (hex-to-bytes
                                               (cdr (assoc :beefy--root h)))
                                  :reported (mapcar
                                             (lambda (r)
                                               (if (or (null r) (eq r :null))
                                                   nil
                                                   (list :hash (hex-to-bytes
                                                                (cdr (assoc :hash r)))
                                                         :exports-root
                                                         (hex-to-bytes
                                                          (cdr (assoc :exports--root r))))))
                                             (or (cdr (assoc :reported h)) '()))))
                          (or history-json '())))
         (peaks-json (cdr (assoc :peaks mmr-json)))
         (peaks (mapcar (lambda (p)
                          (if (or (null p) (eq p :null))
                              nil
                              (hex-to-bytes p)))
                        (or peaks-json '()))))
    (list :history history :mmr (list :peaks peaks))))

(defun reports-json-auth-pools (pools-json)
  "Parse JSON auth_pools → list of C lists of byte-vector hashes."
  (mapcar (lambda (pool)
            (mapcar #'hex-to-bytes (or pool '())))
          (or pools-json '())))

(defun reports-json-accounts (accounts-json)
  "Parse JSON accounts → list of (:id :service (:code-hash :min-item-gas ...))."
  (mapcar (lambda (a)
            (let* ((id (cdr (assoc :id a)))
                   (data-json (cdr (assoc :data a)))
                   (svc-json (cdr (assoc :service data-json))))
              (list :id id
                    :service (list :code-hash (hex-to-bytes
                                               (cdr (assoc :code--hash svc-json)))
                                   :min-item-gas (cdr (assoc :min--item--gas svc-json))
                                   :balance (cdr (assoc :balance svc-json))))))
          (or accounts-json '())))

(defun reports-json-cores-statistics (cs-json)
  "Parse JSON cores_statistics → list of cores stat plists."
  (mapcar (lambda (cs)
            (list :da-load (or (cdr (assoc :da--load cs)) 0)
                  :popularity (or (cdr (assoc :popularity cs)) 0)
                  :imports (or (cdr (assoc :imports cs)) 0)
                  :extrinsic-count (or (cdr (assoc :extrinsic--count cs)) 0)
                  :extrinsic-size (or (cdr (assoc :extrinsic--size cs)) 0)
                  :exports (or (cdr (assoc :exports cs)) 0)
                  :bundle-size (or (cdr (assoc :bundle--size cs)) 0)
                  :gas-used (or (cdr (assoc :gas--used cs)) 0)))
          (or cs-json '())))

(defun reports-json-services-statistics (ss-json)
  "Parse JSON services_statistics → list of (:id :record ...)."
  (mapcar (lambda (ss)
            (let ((rec-json (cdr (assoc :record ss))))
              (list :id (cdr (assoc :id ss))
                    :record (list :provided-count
                                  (or (cdr (assoc :provided--count rec-json)) 0)
                                  :provided-size
                                  (or (cdr (assoc :provided--size rec-json)) 0)
                                  :refinement-count
                                  (or (cdr (assoc :refinement--count rec-json)) 0)
                                  :refinement-gas-used
                                  (or (cdr (assoc :refinement--gas--used rec-json)) 0)
                                  :imports
                                  (or (cdr (assoc :imports rec-json)) 0)
                                  :extrinsic-count
                                  (or (cdr (assoc :extrinsic--count rec-json)) 0)
                                  :extrinsic-size
                                  (or (cdr (assoc :extrinsic--size rec-json)) 0)
                                  :exports
                                  (or (cdr (assoc :exports rec-json)) 0)
                                  :accumulate-count
                                  (or (cdr (assoc :accumulate--count rec-json)) 0)
                                  :accumulate-gas-used
                                  (or (cdr (assoc :accumulate--gas--used rec-json)) 0)))))
          (or ss-json '())))

;;; ═══════════════════════════════════════════════════════════════
;;; COMPARISON HELPERS (reports-specific)
;;; ═══════════════════════════════════════════════════════════════

(defun compare-work-report-rho (label actual expected)
  "Deep comparison of two WorkReport plists via binary encoding."
  (when (and (null actual) (null expected)) (return-from compare-work-report-rho t))
  (when (or (null actual) (null expected))
    (format t "    ✗ ~A: nil vs non-nil~%" label)
    (return-from compare-work-report-rho nil))
  (let ((actual-bytes (encode-work-report actual))
        (expected-bytes (encode-work-report expected)))
    (if (equalp actual-bytes expected-bytes)
        t
        (progn
          (format t "    ✗ ~A: work-report binary mismatch (len ~D vs ~D)~%"
                  label (length actual-bytes) (length expected-bytes))
          nil))))

(defun compare-assignment-rho (label actual expected)
  "Compare two assignments (nil or plist with :report :timeout)."
  (cond
    ((and (null actual) (null expected)) t)
    ((or (null actual) (null expected))
     (format t "    ✗ ~A: nil/non-nil mismatch (got ~A, want ~A)~%"
             label (if actual "assigned" "nil") (if expected "assigned" "nil"))
     nil)
    (t (let ((report-ok (compare-work-report-rho
                          (format nil "~A.report" label)
                          (getf actual :report) (getf expected :report)))
             (timeout-ok (= (getf actual :timeout) (getf expected :timeout))))
         (unless timeout-ok
           (format t "    ✗ ~A.timeout: ~D ≠ ~D~%" label
                   (getf actual :timeout) (getf expected :timeout)))
         (and report-ok timeout-ok)))))

(defun compare-assignments-rho (label actual expected)
  "Compare two assignment lists (ρ). Returns T if all match."
  (let ((ok t))
    (unless (= (length actual) (length expected))
      (format t "    ✗ ~A: length ~D ≠ ~D~%" label
              (length actual) (length expected))
      (return-from compare-assignments-rho nil))
    (loop for a in actual for e in expected for i from 0
          unless (compare-assignment-rho (format nil "~A[~D]" label i) a e)
            do (setf ok nil))
    ok))

(defun compare-reported-packages (label actual expected)
  "Compare reported packages lists (work_package_hash + segment_tree_root)."
  (let ((ok t))
    (unless (= (length actual) (length expected))
      (format t "    ✗ ~A: length ~D ≠ ~D~%" label
              (length actual) (length expected))
      (return-from compare-reported-packages nil))
    (loop for a in actual for e in expected for i from 0
          do (let ((hash-ok (equalp (ensure-bytes (getf a :work-package-hash))
                                    (ensure-bytes (getf e :work-package-hash))))
                   (root-ok (equalp (ensure-bytes (getf a :segment-tree-root))
                                    (ensure-bytes (getf e :segment-tree-root)))))
               (unless hash-ok
                 (format t "    ✗ ~A[~D].hash mismatch~%" label i)
                 (setf ok nil))
               (unless root-ok
                 (format t "    ✗ ~A[~D].root mismatch~%" label i)
                 (setf ok nil))))
    ok))

(defun compare-reporters (label actual expected)
  "Compare reporters lists (ed25519 keys)."
  (let ((ok t))
    (unless (= (length actual) (length expected))
      (format t "    ✗ ~A: length ~D ≠ ~D~%" label
              (length actual) (length expected))
      (return-from compare-reporters nil))
    (loop for a in actual for e in expected for i from 0
          unless (equalp (ensure-bytes a) (ensure-bytes e))
          do (format t "    ✗ ~A[~D] mismatch~%" label i)
             (setf ok nil))
    ok))

(defun compare-cores-statistics (label actual expected)
  "Compare cores statistics."
  (let ((ok t))
    (unless (= (length actual) (length expected))
      (format t "    ✗ ~A: length ~D ≠ ~D~%" label
              (length actual) (length expected))
      (return-from compare-cores-statistics nil))
    (loop for a in actual for e in expected for i from 0
          do (dolist (key '(:da-load :popularity :imports :extrinsic-count
                            :extrinsic-size :exports :bundle-size :gas-used))
               (let ((av (or (getf a key) 0))
                     (ev (or (getf e key) 0)))
                 (unless (= av ev)
                   (format t "    ✗ ~A[~D].~A: ~D ≠ ~D~%" label i key av ev)
                   (setf ok nil)))))
    ok))

(defun compare-services-statistics (label actual expected)
  "Compare services statistics."
  (let ((ok t))
    (unless (= (length actual) (length expected))
      (format t "    ✗ ~A: length ~D ≠ ~D~%" label
              (length actual) (length expected))
      (return-from compare-services-statistics nil))
    (loop for a in actual for e in expected for i from 0
          do (unless (= (getf a :id) (getf e :id))
               (format t "    ✗ ~A[~D].id: ~D ≠ ~D~%" label i
                       (getf a :id) (getf e :id))
               (setf ok nil))
             (let ((ar (getf a :record))
                   (er (getf e :record)))
               (dolist (key '(:provided-count :provided-size
                              :refinement-count :refinement-gas-used
                              :imports :extrinsic-count :extrinsic-size
                              :exports :accumulate-count :accumulate-gas-used))
                 (let ((av (or (getf ar key) 0))
                       (ev (or (getf er key) 0)))
                   (unless (= av ev)
                     (format t "    ✗ ~A[~D].~A: ~D ≠ ~D~%" label i key av ev)
                     (setf ok nil))))))
    ok))

;;; ═══════════════════════════════════════════════════════════════
;;; CODEC ROUNDTRIP
;;; ═══════════════════════════════════════════════════════════════

(defun test-rho-prime-codec-roundtrip (assignments label)
  "Verify encode/decode roundtrip for ρ' (avail_assignments)."
  (handler-case
      (let* ((encoded (encode-state-rho assignments))
             (decoded (multiple-value-bind (result consumed)
                          (decode-state-rho encoded)
                        (declare (ignore consumed))
                        result)))
        (if (compare-assignments-rho (format nil "~A/roundtrip" label)
                                     decoded assignments)
            t
            (progn
              (format t "    ✗ ~A: ρ' codec roundtrip mismatch~%" label)
              nil)))
    (error (e)
      (format t "    ✗ ~A: ρ' codec roundtrip error: ~A~%" label e)
      nil)))

;;; ═══════════════════════════════════════════════════════════════
;;; ERROR CODE MAPPING
;;; ═══════════════════════════════════════════════════════════════

(defun guarantee-error-code-to-string (code)
  "Map our keyword error codes to test vector error strings."
  (case code
    (:bad-core-index               "bad_core_index")
    (:future-report-slot           "future_report_slot")
    (:report-epoch-before-last     "report_epoch_before_last")
    (:insufficient-guarantees      "insufficient_guarantees")
    (:out-of-order-guarantee       "out_of_order_guarantee")
    (:not-sorted-or-unique-guarantors "not_sorted_or_unique_guarantors")
    (:wrong-assignment             "wrong_assignment")
    (:core-engaged                 "core_engaged")
    (:anchor-not-recent            "anchor_not_recent")
    (:bad-service-id               "bad_service_id")
    (:bad-code-hash                "bad_code_hash")
    (:dependency-missing           "dependency_missing")
    (:duplicate-package            "duplicate_package")
    (:bad-state-root               "bad_state_root")
    (:bad-beefy-mmr-root           "bad_beefy_mmr_root")
    (:core-unauthorized            "core_unauthorized")
    (:bad-validator-index          "bad_validator_index")
    (:work-report-gas-too-high     "work_report_gas_too_high")
    (:service-item-gas-too-low     "service_item_gas_too_low")
    (:too-many-dependencies        "too_many_dependencies")
    (:segment-root-lookup-invalid  "segment_root_lookup_invalid")
    (:bad-signature                "bad_signature")
    (:work-report-too-big          "work_report_too_big")
    (:banned-validator             "banned_validator")
    (:lookup-anchor-not-recent     "lookup_anchor_not_recent")
    (:missing-work-results         "missing_work_results")
    (otherwise (substitute #\_ #\-
                           (string-downcase (string code))))))

(defun reports-normalize-error (s)
  "Normalize error code string: snake_case, strip quotes."
  (substitute #\_ #\- (string-downcase (string-trim '(#\" #\Space) s))))

;;; ═══════════════════════════════════════════════════════════════
;;; RUN ONE TEST
;;; ═══════════════════════════════════════════════════════════════

(defun run-report-test (path spec)
  "Run a single report test vector. Prints result with ✅/❌."
  (let* ((json (cl-json:decode-json-from-string (uiop:read-file-string path)))
         (input-json (cdr (assoc :input json)))
         (pre-json (or (cdr (assoc :pre-state json))
                       (cdr (assoc :pre--state json))))
         (output-json (cdr (assoc :output json)))
         (post-json (or (cdr (assoc :post-state json))
                        (cdr (assoc :post--state json))))
         ;; ── Parse input ──
         (guarantees (reports-json-guarantees
                      (cdr (assoc :guarantees input-json))))
         (tau-prime (cdr (assoc :slot input-json)))
         ;; known-packages is now computed internally by transition-rho
         ;; from recent-blocks via collect-known-package-hashes
         ;; ── Parse pre-state ──
         (pre-assignments (reports-json-assignments
                           (or (cdr (assoc :avail--assignments pre-json))
                               (cdr (assoc :avail-assignments pre-json)))))
         (pre-validators (json-validators
                          (or (cdr (assoc :curr--validators pre-json))
                              (cdr (assoc :curr-validators pre-json)))))
         (prev-validators (json-validators
                           (or (cdr (assoc :prev--validators pre-json))
                               (cdr (assoc :prev-validators pre-json)))))
         (entropy (mapcar #'hex-to-bytes
                          (or (cdr (assoc :entropy pre-json)) '())))
         (offenders (mapcar #'hex-to-bytes
                            (or (cdr (assoc :offenders pre-json)) '())))
         (recent-blocks (reports-json-recent-blocks
                         (or (cdr (assoc :recent--blocks pre-json))
                             (cdr (assoc :recent-blocks pre-json)))))
         (auth-pools (reports-json-auth-pools
                      (or (cdr (assoc :auth--pools pre-json))
                          (cdr (assoc :auth-pools pre-json)))))
         (accounts (reports-json-accounts
                    (or (cdr (assoc :accounts pre-json)) '())))
         (pre-cores-stats (reports-json-cores-statistics
                           (or (cdr (assoc :cores--statistics pre-json))
                               (cdr (assoc :cores-statistics pre-json)))))
         (pre-services-stats (reports-json-services-statistics
                              (or (cdr (assoc :services--statistics pre-json))
                                  (cdr (assoc :services-statistics pre-json)))))
         ;; ── Parse expected output ──
         (expected-ok (cdr (assoc :ok output-json)))
         (expected-err (cdr (assoc :err output-json)))
         (expected-reported
           (when expected-ok
             (mapcar (lambda (r)
                       (list :work-package-hash
                             (hex-to-bytes (cdr (assoc :work--package--hash r)))
                             :segment-tree-root
                             (hex-to-bytes (cdr (assoc :segment--tree--root r)))))
                     (or (cdr (assoc :reported expected-ok)) '()))))
         (expected-reporters
           (when expected-ok
             (mapcar #'hex-to-bytes
                     (or (cdr (assoc :reporters expected-ok)) '()))))
         ;; ── Parse expected post-state ──
         (post-assignments (reports-json-assignments
                            (or (cdr (assoc :avail--assignments post-json))
                                (cdr (assoc :avail-assignments post-json)))))
         (post-cores-stats (reports-json-cores-statistics
                            (or (cdr (assoc :cores--statistics post-json))
                                (cdr (assoc :cores-statistics post-json)))))
         (post-services-stats (reports-json-services-statistics
                               (or (cdr (assoc :services--statistics post-json))
                                   (cdr (assoc :services-statistics post-json)))))
         (fname (file-namestring path)))
    (let ((*chain* (case spec
                     (:tiny +tiny-chainspec+)
                     (:full +full-chainspec+)
                     (otherwise (error "Unknown chain: ~A" spec)))))
      (handler-case
          ;; transition-rho returns single value ρ' or signals guarantee-error
          (let ((rho-prime (transition-rho guarantees pre-assignments
                                          :tau-prime tau-prime
                                          :kappa pre-validators
                                          :lambda-prev prev-validators
                                          :eta entropy
                                          :offenders offenders
                                          :recent-blocks recent-blocks
                                          :auth-pools auth-pools
                                          :accounts accounts)))
            ;; ── Success path: all EG valid, ρ' computed ──
            (if expected-ok
                (multiple-value-bind (reported reporters)
                    (compute-output-packages-and-reporters
                     guarantees pre-validators prev-validators tau-prime)
                  (let* ((cores-stats-prime (update-cores-statistics
                                             pre-cores-stats guarantees))
                         (services-stats-prime (update-services-statistics
                                                pre-services-stats guarantees))
                         ;; Compare ρ' vs expected post-state assignments
                         (assign-ok (compare-assignments-rho
                                      (format nil "~A/ρ'" fname)
                                      rho-prime post-assignments))
                         ;; Compare reported packages
                         (reported-ok (compare-reported-packages
                                        (format nil "~A/reported" fname)
                                        reported expected-reported))
                         ;; Compare reporters
                         (reporters-ok (compare-reporters
                                         (format nil "~A/reporters" fname)
                                         reporters expected-reporters))
                         ;; Compare cores statistics
                         (cs-ok (compare-cores-statistics
                                  (format nil "~A/cores-stats" fname)
                                  cores-stats-prime post-cores-stats))
                         ;; Compare services statistics
                         (ss-ok (compare-services-statistics
                                  (format nil "~A/services-stats" fname)
                                  services-stats-prime post-services-stats))
                         ;; Codec roundtrip on result
                         (codec-ok (test-rho-prime-codec-roundtrip
                                     rho-prime fname)))
                    (if (and assign-ok reported-ok reporters-ok
                             cs-ok ss-ok codec-ok)
                        (format t "  ✅ ~A~%" fname)
                        (format t "  ❌ ~A —~A~A~A~A~A~A~%" fname
                                (if assign-ok "" " ρ'-mismatch")
                                (if reported-ok "" " reported-mismatch")
                                (if reporters-ok "" " reporters-mismatch")
                                (if cs-ok "" " cores-stats-mismatch")
                                (if ss-ok "" " services-stats-mismatch")
                                (if codec-ok "" " codec-fail")))))
                ;; Expected error but got OK
                (format t "  ❌ ~A — expected error '~A' but got OK~%"
                        fname expected-err)))
        ;; ── Error path: guarantee-error signaled ──
        (guarantee-error (e)
          (if expected-err
              (let* ((got-code (guarantee-error-code-to-string
                                 (guarantee-error-code e)))
                     (want-code (reports-normalize-error expected-err)))
                (if (string= got-code want-code)
                    (format t "  ✅ ~A (err: ~A)~%" fname got-code)
                    (format t "  ❌ ~A — error mismatch: got ~A, want ~A~%"
                            fname got-code want-code)))
              (format t "  ❌ ~A — unexpected error: ~A~%" fname e)))
        (error (e)
          (format t "  💥 ~A — ~A~%" fname e))))))

;;; ═══════════════════════════════════════════════════════════════
;;; RUN ALL TESTS
;;; ═══════════════════════════════════════════════════════════════

(let ((total 0) (passed 0))
  (dolist (spec '(:tiny :full))
    (format t "~%=== Reports STF Tests (~(~A~)) ===~%" spec)
    (let ((dir (format nil "tests/jamtestvectors/stf/reports/~(~A~)/" spec)))
      (dolist (path (sort (directory (merge-pathnames "*.json" dir))
                          #'string< :key #'namestring))
        (incf total)
        (let ((output (with-output-to-string (*standard-output*)
                        (run-report-test (namestring path) spec))))
          (write-string output)
          (when (search "✅" output) (incf passed))))))
  (format t "~%  ~A ρ' (reports): ~D/~D passed~%"
          (if (= passed total) "✅" "❌") passed total))
