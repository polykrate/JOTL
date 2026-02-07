;;;; tests/test-eta.lisp — η (Entropy) STF tests
;;;; Validates transition-eta against safrole test vectors (JSON only).
;;;;
;;;; The safrole test vectors contain η as part of their state.
;;;; We extract η, τ, slot, and entropy to test transition-eta in isolation.
;;;; Binary roundtrip of the full safrole state is deferred to safrole STF tests.
;;;;
;;;; Test vectors: tests/jamtestvectors/stf/safrole/{tiny,full}/

(in-package #:jotl)

;; Load shared test helpers
(load (merge-pathnames "test-utils.lisp" *load-pathname*))

;;; ═══════════════════════════════════════════════════════════════
;;; HELPERS — Extract η fields from safrole JSON
;;; ═══════════════════════════════════════════════════════════════

(defun extract-eta-from-json (state-alist)
  "Extract η (list of 4 hashes) from a safrole state JSON alist."
  (let ((eta-json (cdr (assoc :eta state-alist))))
    (mapcar #'hex-to-bytes eta-json)))

(defun extract-tau-from-json (state-alist)
  "Extract τ (timeslot number) from a safrole state JSON alist."
  (cdr (assoc :tau state-alist)))

(defun make-eta-test-header (slot entropy-source)
  "Create a minimal header closure for transition-eta testing.
   Only :slot and :entropy-source are needed."
  (lambda (msg)
    (case msg
      (:slot slot)
      (:entropy-source entropy-source)
      (otherwise (error "Test header stub: ~a" msg)))))

;;; ═══════════════════════════════════════════════════════════════
;;; CODEC — η state value encoding roundtrip
;;; ═══════════════════════════════════════════════════════════════

(defun test-eta-codec-roundtrip (eta label)
  "Verify encode/decode roundtrip for η."
  (let* ((encoded (encode-state-eta eta))
         (decoded (decode-state-eta encoded)))
    (assert (= (length encoded) 128) ()
            "~A: encode-state-eta should produce 128 bytes, got ~A" label (length encoded))
    (loop for i from 0 below 4
          do (assert (bytes= (nth i eta) (nth i decoded)) ()
                     "~A: η[~A] roundtrip mismatch" label i))
    (format t "  ✓ η codec roundtrip~%")))

;;; ═══════════════════════════════════════════════════════════════
;;; RUN ONE TEST CASE
;;; ═══════════════════════════════════════════════════════════════

(defun run-eta-test (json-path chain-name)
  "Run a single η test from a safrole JSON test vector.
   Extracts η, τ, slot, entropy; runs transition-eta; compares to post-state."
  (let* ((data (load-json json-path))
         ;; Pre-state
         (pre-state (cdr (assoc :pre--state data)))
         (eta-pre (extract-eta-from-json pre-state))
         (tau-pre (extract-tau-from-json pre-state))
         ;; Input
         (input (cdr (assoc :input data)))
         (slot (cdr (assoc :slot input)))
         (entropy (hex-to-bytes (cdr (assoc :entropy input))))
         ;; Post-state
         (post-state (cdr (assoc :post--state data)))
         (eta-expected (extract-eta-from-json post-state))
         ;; Check if output is error (bad-slot etc.) — skip those
         (output (cdr (assoc :output data)))
         (is-error (assoc :err output)))
    ;; Skip error test cases — η transition is undefined on invalid input
    (when is-error
      (format t "  ⊘ Skipped (error case: ~A)~%" (cdr is-error))
      (return-from run-eta-test t))
    ;; Run η STF
    (with-chain chain-name
      (let* ((header (make-eta-test-header slot entropy))
             (eta-prime (transition-eta header tau-pre eta-pre)))
        ;; Compare each component
        (loop for i from 0 below 4
              for computed = (nth i eta-prime)
              for expected = (nth i eta-expected)
              do (assert (bytes= computed expected) ()
                         "η[~A] MISMATCH~%  computed: ~A~%  expected: ~A"
                         i
                         (bytes-to-hex-string computed)
                         (bytes-to-hex-string expected)))
        ;; Also test codec roundtrip
        (test-eta-codec-roundtrip eta-prime (file-namestring json-path))
        (format t "  ✓ η transition correct (tau ~A→~A, ~A)~%"
                tau-pre slot
                (if (new-epoch-p tau-pre slot) "EPOCH CHANGE" "same epoch"))))))

;;; ═══════════════════════════════════════════════════════════════
;;; MAIN TEST — all safrole vectors for both chainspecs
;;; ═══════════════════════════════════════════════════════════════

(defun run-all-eta-tests ()
  "Run η tests against all safrole test vectors (tiny + full)."
  (let ((base-dir (merge-pathnames "tests/jamtestvectors/stf/safrole/"
                                    (asdf:system-source-directory :jotl)))
        (total 0) (passed 0) (skipped 0))
    (dolist (spec '((:tiny "tiny") (:full "full")))
      (let* ((chain-name (first spec))
             (dir-name (second spec))
             (dir (merge-pathnames (format nil "~A/" dir-name) base-dir))
             (json-files (sort (directory (merge-pathnames "*.json" dir))
                               #'string< :key #'namestring)))
        (format t "~%═══ η tests — ~A (~A vectors) ═══~%"
                (string-upcase dir-name) (length json-files))
        (dolist (json-path json-files)
          (incf total)
          (let ((name (file-namestring json-path)))
            (format t "~%[~A] ~A~%" dir-name name)
            (handler-case
                (progn
                  (run-eta-test (namestring json-path) chain-name)
                  (incf passed))
              (error (c)
                (format t "  ✗ FAIL: ~A~%" c))
              (simple-error (c)
                ;; Check for skipped (transition-tau assert on bad-slot)
                (if (search "Skipped" (format nil "~A" c))
                    (incf skipped)
                    (format t "  ✗ FAIL: ~A~%" c))))))))
    (format t "~%═══════════════════════════════════════~%")
    (format t "η RESULTS: ~A/~A passed (~A skipped)~%" passed total skipped)
    (format t "═══════════════════════════════════════~%")
    (values passed total)))

;;; Entry point
(run-all-eta-tests)
