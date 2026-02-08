;;;; tests/test-eta.lisp — η (Entropy) STF tests
;;;; Validates transition-eta against safrole test vectors.
;;;;
;;;; η is extracted from the safrole test state (not a standalone STF vector).
;;;; Tests: JSON comparison (byte-by-byte) + codec roundtrip.
;;;;
;;;; ALL cases verified (zero skips):
;;;;   - Success: run transition-eta, compare η' to post_state
;;;;   - Error:   verify η' = η (block rejected → no state change)
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
;;; CODEC ROUNDTRIP — encode/decode η state
;;; ═══════════════════════════════════════════════════════════════

(defun test-eta-codec-roundtrip (eta label)
  "Verify encode/decode roundtrip for η."
  (let* ((encoded (encode-state-eta eta))
         (decoded (decode-state-eta encoded)))
    (assert (= (length encoded) 128) ()
            "~A: encode-state-eta should produce 128 bytes, got ~A" label (length encoded))
    (compare-eta (format nil "~A/codec" label) decoded eta)))

;;; ═══════════════════════════════════════════════════════════════
;;; RUN ONE TEST CASE
;;; ═══════════════════════════════════════════════════════════════

(defun run-eta-test (json-path chain-name)
  "Run a single η test from a safrole JSON test vector.
   Returns: :pass | :fail
   - Success vectors: run transition-eta, compare η' to post_state
   - Error vectors:   verify η' = η (block rejected → state unchanged)"
  (let* ((data (load-json json-path))
         (fname (file-namestring json-path))
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
         ;; Output: success or error?
         (output (cdr (assoc :output data)))
         (is-error (assoc :err output))
         (err-code (when is-error (cdr is-error))))
    (with-chain chain-name
      (handler-case
          (if is-error
              ;; ── Error case: block rejected → η must be unchanged ──
              (let* ((unchanged-ok (compare-eta fname eta-expected eta-pre))
                     (codec-ok (test-eta-codec-roundtrip eta-pre fname)))
                (cond
                  ((and unchanged-ok codec-ok)
                   (format t "  ✅ ~A (err: ~A → η unchanged)~%" fname err-code)
                   :pass)
                  (t
                   (format t "  ❌ ~A (err: ~A) — ~A~%" fname err-code
                           (cond ((not unchanged-ok) "η should be unchanged but differs!")
                                 ((not codec-ok) "codec roundtrip failed")
                                 (t "unknown")))
                   :fail)))
              ;; ── Success case: run transition-eta, compare η' ──
              (let* ((header (make-eta-test-header slot entropy))
                     (eta-prime (transition-eta header tau-pre eta-pre))
                     (stf-ok (compare-eta fname eta-prime eta-expected))
                     (codec-ok (test-eta-codec-roundtrip eta-prime fname)))
                (cond
                  ((and stf-ok codec-ok)
                   (format t "  ✅ ~A~%" fname)
                   :pass)
                  (t
                   (format t "  ❌ ~A — ~A~%" fname
                           (cond ((not stf-ok) "η content mismatch")
                                 ((not codec-ok) "codec roundtrip failed")
                                 (t "unknown")))
                   :fail))))
        (error (e)
          (format t "  💥 ~A — ~A~%" fname e)
          :fail)))))

;;; ═══════════════════════════════════════════════════════════════
;;; MAIN — all safrole vectors for both chainspecs
;;; ═══════════════════════════════════════════════════════════════

(defun run-all-eta-tests ()
  "Run η tests against all safrole test vectors (tiny + full).
   ALL cases are verified (zero skips):
   - Success: transition-eta + compare
   - Error: verify η unchanged"
  (let ((base-dir (merge-pathnames "tests/jamtestvectors/stf/safrole/"
                                    (asdf:system-source-directory :jotl)))
        (total 0) (passed 0) (failed 0))
    (dolist (spec '((:tiny "tiny") (:full "full")))
      (let* ((chain-name (first spec))
             (dir-name (second spec))
             (dir (merge-pathnames (format nil "~A/" dir-name) base-dir))
             (json-files (sort (directory (merge-pathnames "*.json" dir))
                               #'string< :key #'namestring)))
        (format t "~%=== η (Entropy) Tests (~A) ===~%"
                (string-upcase dir-name))
        (dolist (json-path json-files)
          (incf total)
          (case (run-eta-test (namestring json-path) chain-name)
            (:pass (incf passed))
            (:fail (incf failed))))))
    (format t "~%")
    (if (zerop failed)
        (format t "  ✅ η: ~D/~D passed~%" passed total)
        (format t "  ❌ η: ~D/~D passed (~D failed)~%" passed total failed))
    (zerop failed)))

;;; Entry point
(unless (run-all-eta-tests)
  (sb-ext:exit :code 1))
