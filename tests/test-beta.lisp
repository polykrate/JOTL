;;;; tests/test-beta.lisp — β (Recent History) STF tests
;;;; Full roundtrip: decode bin → validate vs JSON → run STF → re-encode vs bin
;;;;
;;;; Test vectors: tests/jamtestvectors/stf/history/{tiny,full}/
;;;;   1 — Empty history queue
;;;;   2 — Not empty nor full
;;;;   3 — Fill the history queue (→ 8 entries)
;;;;   4 — Shift the history queue (overflow → bounded append)

(in-package :jotl)

;; Load shared test helpers
(load (merge-pathnames "test-utils.lisp" *load-pathname*))

;;; ═══════════════════════════════════════════════════════════════
;;; BINARY CODEC — History Test Vector Format
;;; ═══════════════════════════════════════════════════════════════
;;;
;;; From history.asn + jam-types.asn:
;;;
;;; TestCase       = Input + State + Output(NULL) + State
;;; Input          = HeaderHash(32) + StateRoot(32) + OpaqueHash(32)
;;;                  + Seq<ReportedWorkPackage>
;;; State          = RecentBlocks = Seq<BlockInfo> + Seq<MmrPeak>
;;; BlockInfo      = HeaderHash(32) + OpaqueHash(32) + StateRoot(32)
;;;                  + Seq<ReportedWorkPackage>
;;; ReportedWorkPackage = Hash(32) + ExportsRoot(32)
;;; MmrPeak        = Option<OpaqueHash(32)>

;; -- Hash (fixed 32 bytes) --

(defun decode-hash32 (bytes offset)
  "Decode 32-byte hash. Returns (values hash 32)."
  (values (subseq bytes offset (+ offset 32)) 32))

(defun encode-hash32 (hash)
  "Encode 32-byte hash (identity — already bytes)."
  hash)

;; -- ReportedWorkPackage = hash(32) + exports_root(32) --

(defun decode-reported-wp (bytes offset)
  "Decode ReportedWorkPackage. Returns (values plist 64)."
  (values (list :hash (subseq bytes offset (+ offset 32))
                :exports-root (subseq bytes (+ offset 32) (+ offset 64)))
          64))

(defun encode-reported-wp (wp)
  "Encode ReportedWorkPackage."
  (concatenate '(vector (unsigned-byte 8))
               (getf wp :hash)
               (getf wp :exports-root)))

;; -- BlockInfo = header_hash(32) + beefy_root(32) + state_root(32) + Seq<ReportedWP> --

(defun decode-block-info (bytes offset)
  "Decode BlockInfo. Returns (values history-record-plist consumed)."
  (let ((start offset))
    (let ((header-hash (subseq bytes offset (+ offset 32))))
      (incf offset 32)
      (let ((beefy-root (subseq bytes offset (+ offset 32))))
        (incf offset 32)
        (let ((state-root (subseq bytes offset (+ offset 32))))
          (incf offset 32)
          (multiple-value-bind (reported consumed)
              (decode-sequence bytes #'decode-reported-wp offset)
            (values (make-history-record
                     :header-hash header-hash
                     :beefy-root beefy-root
                     :state-root state-root
                     :reported reported)
                    (+ (- offset start) consumed))))))))

(defun encode-block-info (rec)
  "Encode BlockInfo."
  (concatenate '(vector (unsigned-byte 8))
               (getf rec :header-hash)
               (getf rec :beefy-root)
               (getf rec :state-root)
               (encode-sequence (getf rec :reported) #'encode-reported-wp)))

;; -- MmrPeak = Option<Hash32> --

(defun decode-mmr-peak (bytes offset)
  "Decode MmrPeak (option). Returns (values hash-or-nil consumed)."
  (decode-option bytes #'decode-hash32 offset))

(defun encode-mmr-peak (peak)
  "Encode MmrPeak (option)."
  (encode-option peak #'encode-hash32))

;; -- RecentBlocks = Seq<BlockInfo> + Mmr(Seq<MmrPeak>) --

(defun decode-recent-blocks (bytes offset)
  "Decode RecentBlocks → make-beta closure. Returns (values beta consumed)."
  (let ((start offset))
    (multiple-value-bind (history h-consumed)
        (decode-sequence bytes #'decode-block-info offset)
      (incf offset h-consumed)
      (multiple-value-bind (peaks p-consumed)
          (decode-sequence bytes #'decode-mmr-peak offset)
        (incf offset p-consumed)
        (values (make-beta :history history
                           :mmr-peaks (coerce peaks 'vector))
                (- offset start))))))

(defun encode-recent-blocks (beta)
  "Encode RecentBlocks from beta closure."
  (concatenate '(vector (unsigned-byte 8))
               (encode-sequence (funcall beta :history) #'encode-block-info)
               (encode-sequence (coerce (funcall beta :mmr-peaks) 'list)
                                #'encode-mmr-peak)))

;; -- Input = HeaderHash(32) + StateRoot(32) + OpaqueHash(32) + Seq<ReportedWP> --

(defun decode-history-input (bytes offset)
  "Decode Input. Returns (values input-plist consumed)."
  (let ((start offset))
    (let ((header-hash (subseq bytes offset (+ offset 32))))
      (incf offset 32)
      (let ((parent-state-root (subseq bytes offset (+ offset 32))))
        (incf offset 32)
        (let ((accumulate-root (subseq bytes offset (+ offset 32))))
          (incf offset 32)
          (multiple-value-bind (work-packages consumed)
              (decode-sequence bytes #'decode-reported-wp offset)
            (values (list :header-hash header-hash
                          :parent-state-root parent-state-root
                          :accumulate-root accumulate-root
                          :work-packages work-packages)
                    (+ (- offset start) consumed))))))))

(defun encode-history-input (input)
  "Encode Input."
  (concatenate '(vector (unsigned-byte 8))
               (getf input :header-hash)
               (getf input :parent-state-root)
               (getf input :accumulate-root)
               (encode-sequence (getf input :work-packages) #'encode-reported-wp)))

;; -- Full TestCase = Input + State + Output(NULL) + State --

(defun decode-history-test-vector (bytes)
  "Decode complete history test vector from binary.
   Returns (values input pre-beta post-beta)."
  (let ((offset 0))
    (multiple-value-bind (input consumed) (decode-history-input bytes offset)
      (incf offset consumed)
      (multiple-value-bind (pre-beta consumed) (decode-recent-blocks bytes offset)
        (incf offset consumed)
        ;; Output = NULL (0 bytes)
        (multiple-value-bind (post-beta consumed) (decode-recent-blocks bytes offset)
          (incf offset consumed)
          (assert (= offset (length bytes)) ()
                  "Decoded ~D bytes but file has ~D bytes" offset (length bytes))
          (values input pre-beta post-beta))))))

(defun encode-history-test-vector (input pre-beta post-beta)
  "Encode complete history test vector to binary."
  (concatenate '(vector (unsigned-byte 8))
               (encode-history-input input)
               (encode-recent-blocks pre-beta)
               ;; Output = NULL (0 bytes)
               (encode-recent-blocks post-beta)))

;;; ═══════════════════════════════════════════════════════════════
;;; JSON PARSING (for cross-validation)
;;; ═══════════════════════════════════════════════════════════════

(defun json-work-packages (wps-json)
  "Parse JSON work-packages list → list of plists."
  (mapcar (lambda (wp)
            (list :hash (hex-to-bytes (cdr (assoc :hash wp)))
                  :exports-root (hex-to-bytes (cdr (assoc :exports--root wp)))))
          wps-json))

(defun json-history-record (rec)
  "Parse one JSON history record → make-history-record plist."
  (make-history-record
   :header-hash  (hex-to-bytes (cdr (assoc :header--hash rec)))
   :state-root   (hex-to-bytes (cdr (assoc :state--root rec)))
   :beefy-root   (hex-to-bytes (cdr (assoc :beefy--root rec)))
   :reported     (json-work-packages (cdr (assoc :reported rec)))))

(defun json-beta-to-closure (beta-json)
  "Parse JSON beta state → make-beta closure."
  (let* ((history-json (cdr (assoc :history beta-json)))
         (mmr-json     (cdr (assoc :mmr beta-json)))
         (peaks-json   (cdr (assoc :peaks mmr-json))))
    (make-beta
     :history   (mapcar #'json-history-record history-json)
     :mmr-peaks (coerce (mapcar (lambda (p)
                                  (if (or (null p) (eq p :null))
                                      nil
                                      (hex-to-bytes p)))
                                peaks-json)
                        'vector))))

(defun json-parse-test-vector (path)
  "Parse a JSON test vector file.
   Returns (values input-plist pre-beta-closure post-beta-closure)."
  (let* ((json (load-json path))
         (input-json (cdr (assoc :input json)))
         (pre-json   (cdr (assoc :beta (cdr (assoc :pre--state json)))))
         (post-json  (cdr (assoc :beta (cdr (assoc :post--state json))))))
    (values
     (list :header-hash       (hex-to-bytes (cdr (assoc :header--hash input-json)))
           :parent-state-root (hex-to-bytes (cdr (assoc :parent--state--root input-json)))
           :accumulate-root   (hex-to-bytes (cdr (assoc :accumulate--root input-json)))
           :work-packages     (json-work-packages (cdr (assoc :work--packages input-json))))
     (json-beta-to-closure pre-json)
     (json-beta-to-closure post-json))))

;;; ═══════════════════════════════════════════════════════════════
;;; COMPARISON HELPERS
;;; ═══════════════════════════════════════════════════════════════

(defun compare-input (label bin-input json-input)
  "Compare decoded binary input against JSON input."
  (let ((ok t))
    (unless (bytes= (getf bin-input :header-hash) (getf json-input :header-hash))
      (format t "  ✗ ~A: input.header_hash mismatch~%" label) (setf ok nil))
    (unless (bytes= (getf bin-input :parent-state-root) (getf json-input :parent-state-root))
      (format t "  ✗ ~A: input.parent_state_root mismatch~%" label) (setf ok nil))
    (unless (bytes= (getf bin-input :accumulate-root) (getf json-input :accumulate-root))
      (format t "  ✗ ~A: input.accumulate_root mismatch~%" label) (setf ok nil))
    (let ((bin-wps (getf bin-input :work-packages))
          (json-wps (getf json-input :work-packages)))
      (unless (= (length bin-wps) (length json-wps))
        (format t "  ✗ ~A: input.work_packages length ~D ≠ ~D~%"
                label (length bin-wps) (length json-wps))
        (setf ok nil))
      (loop for bw in bin-wps for jw in json-wps for i from 0
            do (unless (bytes= (getf bw :hash) (getf jw :hash))
                 (format t "  ✗ ~A: input.work_packages[~D].hash mismatch~%" label i)
                 (setf ok nil))
               (unless (bytes= (getf bw :exports-root) (getf jw :exports-root))
                 (format t "  ✗ ~A: input.work_packages[~D].exports_root mismatch~%" label i)
                 (setf ok nil))))
    ok))

(defun compare-beta (label actual expected)
  "Compare two beta closures field-by-field. Returns T if equal."
  (let* ((act-h (funcall actual :history))
         (exp-h (funcall expected :history))
         (act-p (funcall actual :mmr-peaks))
         (exp-p (funcall expected :mmr-peaks))
         (ok t))
    ;; History length
    (unless (= (length act-h) (length exp-h))
      (format t "  ✗ ~A: history length ~D ≠ ~D~%" label (length act-h) (length exp-h))
      (return-from compare-beta nil))
    ;; Each history record
    (loop for act-rec in act-h
          for exp-rec in exp-h
          for i from 0
          do (unless (bytes= (getf act-rec :header-hash) (getf exp-rec :header-hash))
               (format t "  ✗ ~A: history[~D].header_hash~%    got:  ~A~%    want: ~A~%"
                       label i
                       (jam.ffi:bytes-to-hex-string (getf act-rec :header-hash))
                       (jam.ffi:bytes-to-hex-string (getf exp-rec :header-hash)))
               (setf ok nil))
             (unless (bytes= (getf act-rec :state-root) (getf exp-rec :state-root))
               (format t "  ✗ ~A: history[~D].state_root~%    got:  ~A~%    want: ~A~%"
                       label i
                       (jam.ffi:bytes-to-hex-string (getf act-rec :state-root))
                       (jam.ffi:bytes-to-hex-string (getf exp-rec :state-root)))
               (setf ok nil))
             (unless (bytes= (getf act-rec :beefy-root) (getf exp-rec :beefy-root))
               (format t "  ✗ ~A: history[~D].beefy_root~%    got:  ~A~%    want: ~A~%"
                       label i
                       (jam.ffi:bytes-to-hex-string (getf act-rec :beefy-root))
                       (jam.ffi:bytes-to-hex-string (getf exp-rec :beefy-root)))
               (setf ok nil))
             (let ((act-rep (getf act-rec :reported))
                   (exp-rep (getf exp-rec :reported)))
               (unless (= (length act-rep) (length exp-rep))
                 (format t "  ✗ ~A: history[~D].reported length ~D ≠ ~D~%"
                         label i (length act-rep) (length exp-rep))
                 (setf ok nil))
               (loop for ar in act-rep for er in exp-rep for j from 0
                     do (unless (bytes= (getf ar :hash) (getf er :hash))
                          (format t "  ✗ ~A: history[~D].reported[~D].hash mismatch~%" label i j)
                          (setf ok nil))
                        (unless (bytes= (getf ar :exports-root) (getf er :exports-root))
                          (format t "  ✗ ~A: history[~D].reported[~D].exports_root mismatch~%" label i j)
                          (setf ok nil)))))
    ;; MMR peaks
    (unless (= (length act-p) (length exp-p))
      (format t "  ✗ ~A: mmr peaks length ~D ≠ ~D~%" label (length act-p) (length exp-p))
      (return-from compare-beta nil))
    (loop for i below (length act-p)
          do (let ((ap (aref act-p i))
                   (ep (aref exp-p i)))
               (cond
                 ((and (null ap) (null ep)))
                 ((or (null ap) (null ep))
                  (format t "  ✗ ~A: mmr[~D] nil mismatch (got:~A want:~A)~%"
                          label i (not (null ap)) (not (null ep)))
                  (setf ok nil))
                 ((not (bytes= ap ep))
                  (format t "  ✗ ~A: mmr[~D]~%    got:  ~A~%    want: ~A~%"
                          label i
                          (jam.ffi:bytes-to-hex-string ap)
                          (jam.ffi:bytes-to-hex-string ep))
                  (setf ok nil)))))
    ok))

;;; ═══════════════════════════════════════════════════════════════
;;; RUNNER — Full roundtrip test
;;; ═══════════════════════════════════════════════════════════════

(defun run-beta-test (spec test-num)
  "Run one β test with full roundtrip validation.
   SPEC is \"tiny\" or \"full\". TEST-NUM is 1-4.
   
   Steps:
     1. Decode .bin → (input, pre-beta, post-beta)
     2. Parse .json → (json-input, json-pre, json-post)
     3. Validate bin vs JSON (decoder correctness)
     4. Run STF on decoded input + pre-beta → actual-beta
     5. Compare actual-beta vs expected post-beta
     6. Re-encode → compare vs original .bin bytes (roundtrip)"
  (let* ((base (format nil "tests/jamtestvectors/stf/history/~A/progress_blocks_history-~D"
                       spec test-num))
         (bin-path (format nil "~A.bin" base))
         (json-path (format nil "~A.json" base))
         (label (format nil "~A/~D" spec test-num))
         (ok t))

    ;; ── Step 1: Decode bin ──
    (let ((bin-bytes (load-bin bin-path)))
      (multiple-value-bind (bin-input bin-pre bin-post)
          (decode-history-test-vector bin-bytes)

        ;; ── Step 2: Parse JSON ──
        (multiple-value-bind (json-input json-pre json-post)
            (json-parse-test-vector json-path)

          ;; ── Step 3: Validate bin vs JSON ──
          (unless (compare-input (format nil "~A/decode-input" label) bin-input json-input)
            (format t "  ✗ ~A: bin input ≠ JSON input~%" label)
            (setf ok nil))
          (unless (compare-beta (format nil "~A/decode-pre" label) bin-pre json-pre)
            (format t "  ✗ ~A: bin pre_state ≠ JSON pre_state~%" label)
            (setf ok nil))
          (unless (compare-beta (format nil "~A/decode-post" label) bin-post json-post)
            (format t "  ✗ ~A: bin post_state ≠ JSON post_state~%" label)
            (setf ok nil))

          ;; ── Step 4: Run STF ──
          (let ((actual-beta (transition-beta-from-inputs
                              (getf bin-input :header-hash)
                              (getf bin-input :parent-state-root)
                              (getf bin-input :accumulate-root)
                              (getf bin-input :work-packages)
                              bin-pre)))

            ;; ── Step 5: Compare STF result vs expected ──
            (unless (compare-beta (format nil "~A/stf" label) actual-beta bin-post)
              (format t "  ✗ ~A: STF result ≠ expected post_state~%" label)
              (setf ok nil))

            ;; ── Step 6: Roundtrip encode → compare vs original bin ──
            (let ((re-encoded (encode-history-test-vector bin-input bin-pre bin-post)))
              (unless (bytes= re-encoded bin-bytes)
                (format t "  ✗ ~A: roundtrip encode ≠ original bin (~D vs ~D bytes)~%"
                        label (length re-encoded) (length bin-bytes))
                ;; Find first diff
                (loop for i below (min (length re-encoded) (length bin-bytes))
                      when (/= (aref re-encoded i) (aref bin-bytes i))
                        do (format t "    first diff at byte ~D: got 0x~2,'0X want 0x~2,'0X~%"
                                   i (aref re-encoded i) (aref bin-bytes i))
                           (return))
                (setf ok nil)))

            ;; ── Report ──
            (if ok
                (format t "  ✓ ~A  (~D → ~D history, ~D peaks) [bin✓ json✓ stf✓ roundtrip✓]~%"
                        label
                        (length (funcall bin-pre :history))
                        (length (funcall actual-beta :history))
                        (length (funcall actual-beta :mmr-peaks)))
                (format t "  ✗ ~A  FAILED~%" label))))
        ok))))

(defun run-all-beta-tests ()
  "Run all β test vectors for both tiny and full specs."
  (format t "~%═══ β (RECENT HISTORY) STF — jamtestvectors ═══~%")
  (format t "    decode bin → validate vs JSON → STF → roundtrip~%~%")
  (let ((total 0) (passed 0))
    (dolist (spec '("tiny" "full"))
      (format t "  ─── ~A ───~%" (string-upcase spec))
      (loop for i from 1 to 4
            do (incf total)
               (when (run-beta-test spec i) (incf passed)))
      (format t "~%"))
    (format t "═══════════════════════════════════════════════════~%")
    (if (= passed total)
        (format t "  ✅ ~D / ~D passed~%" passed total)
        (format t "  ❌ ~D / ~D passed~%" passed total))
    (format t "═══════════════════════════════════════════════════~%~%")
    (= passed total)))

;;; ═══ MAIN ═══

(unless (run-all-beta-tests)
  (sb-ext:exit :code 1))
