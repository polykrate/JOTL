;;;; tests/test-psi.lisp — ψ (Disputes) STF tests
;;;; Full validation: transition-psi against jamtestvectors/stf/disputes
;;;; Covers: verdicts, culprits, faults, signatures, ordering, age, vote split
;;;;
;;;; 56 vectors total: 28 tiny + 28 full
(in-package :jotl)

(ql:quickload :cl-json :silent t)

;; Load shared test helpers
(load (merge-pathnames "test-utils.lisp" *load-pathname*))

;;; ═══════════════════════════════════════════════════════════════
;;; JSON PARSERS (psi-specific)
;;; ═══════════════════════════════════════════════════════════════

(defun json-psi-to-plist (psi-json)
  "Convert JSON psi state to a psi closure."
  (make-psi :good (json-hashes-to-bytes (cdr (assoc :good psi-json)))
        :bad (json-hashes-to-bytes (cdr (assoc :bad psi-json)))
        :wonky (json-hashes-to-bytes (cdr (assoc :wonky psi-json)))
        :offenders (json-hashes-to-bytes (cdr (assoc :offenders psi-json)))))

;;; ═══════════════════════════════════════════════════════════════
;;; COMPARISON (psi-specific)
;;; ═══════════════════════════════════════════════════════════════

(defun compare-psi (label actual expected)
  "Deep comparison of two ψ closures (content, not just lengths)."
  (let ((ok t))
    (unless (compare-hash-sets (format nil "~A.good" label)
                               (funcall actual :good) (funcall expected :good))
      (setf ok nil))
    (unless (compare-hash-sets (format nil "~A.bad" label)
                               (funcall actual :bad) (funcall expected :bad))
      (setf ok nil))
    (unless (compare-hash-sets (format nil "~A.wonky" label)
                               (funcall actual :wonky) (funcall expected :wonky))
      (setf ok nil))
    (unless (compare-hash-sets (format nil "~A.offenders" label)
                               (funcall actual :offenders) (funcall expected :offenders))
      (setf ok nil))
    ok))

;;; ═══════════════════════════════════════════════════════════════
;;; CODEC ROUNDTRIP — encode/decode ψ state
;;; ═══════════════════════════════════════════════════════════════

(defun test-psi-codec-roundtrip (psi label)
  "Verify encode/decode roundtrip for ψ."
  (let* ((encoded (encode-state-psi psi))
         (decoded (multiple-value-bind (result consumed)
                      (decode-state-psi encoded)
                    (declare (ignore consumed))
                    result)))
    (unless (compare-psi (format nil "~A/codec-roundtrip" label)
                         decoded psi)
      (format t "    ✗ ~A: ψ codec roundtrip mismatch~%" label)
      (return-from test-psi-codec-roundtrip nil))
    t))

;;; ═══════════════════════════════════════════════════════════════
;;; RUN ONE TEST
;;; ═══════════════════════════════════════════════════════════════

(defun run-disputes-test (path spec)
  (let* ((json (cl-json:decode-json-from-string (uiop:read-file-string path)))
         (input (cdr (assoc :input json)))
         (pre (or (cdr (assoc :pre-state json))
                  (cdr (assoc :pre--state json))))
         (output (cdr (assoc :output json)))
         (post (or (cdr (assoc :post-state json))
                   (cdr (assoc :post--state json))))
         ;; Parse input
         (disputes (json-disputes (cdr (assoc :disputes input))))
         ;; Parse pre-state
         (tau (make-tau-state :value (cdr (assoc :tau pre))))
         (psi (json-psi-to-plist (cdr (assoc :psi pre))))
         (kappa (make-kappa :validators (json-validators (cdr (assoc :kappa pre)))))
         (lambda-prev (make-lambda-state :validators (json-validators (cdr (assoc :lambda pre)))))
         ;; Expected output
         (expected-ok (assoc :ok output))
         (expected-err (cdr (assoc :err output)))
         ;; File name for display
         (fname (file-namestring path)))
    (let ((*chain* (case spec
                    (:tiny +tiny-chainspec+)
                    (:full +full-chainspec+)
                    (otherwise (error "Unknown chain: ~A" spec)))))
      (handler-case
          (multiple-value-bind (psi-prime v-list)
              (transition-psi disputes psi tau kappa lambda-prev)
            (declare (ignore v-list))
            (if expected-ok
                ;; Expected success — deep content comparison of post-state ψ
                (let* ((post-psi (json-psi-to-plist (cdr (assoc :psi post))))
                       (stf-match (compare-psi fname psi-prime post-psi))
                       (codec-ok (test-psi-codec-roundtrip psi-prime fname)))
                  (if (and stf-match codec-ok)
                      (format t "  ✅ ~A~%" fname)
                      (format t "  ❌ ~A — ~A~%" fname
                              (cond ((not stf-match) "state content mismatch")
                                    ((not codec-ok) "codec roundtrip failed")
                                    (t "unknown")))))
                ;; Expected error — got success instead
                (format t "  ❌ ~A — expected error '~A' but got OK~%" fname expected-err)))
        (disputes-error (e)
          (if expected-err
              (format t "  ✅ ~A (err: ~A)~%" fname (disputes-error-code e))
              (format t "  ❌ ~A — unexpected error: ~A~%" fname e)))
        (error (e)
          (format t "  💥 ~A — ~A~%" fname e))))))

;;; Run all tests
(dolist (spec '(:tiny :full))
  (format t "~%=== Disputes STF Tests (~(~A~)) ===~%" spec)
  (let ((dir (format nil "tests/jamtestvectors/stf/disputes/~(~A~)/" spec)))
    (dolist (path (sort (directory (merge-pathnames "*.json" dir)) #'string<
                        :key #'namestring))
      (run-disputes-test (namestring path) spec))))
