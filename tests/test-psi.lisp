;;;; tests/test-psi.lisp — ψ (Disputes) STF tests
;;;; Full validation: transition-psi against jamtestvectors/stf/disputes
;;;; Covers: verdicts, culprits, faults, signatures, ordering, age, vote split
;;;;
;;;; 56 vectors total: 28 tiny + 28 full
(in-package :jotl)

(ql:quickload :cl-json :silent t)

;;; Helper: extract ed25519 key accounting for cl-json renaming
(defun json-ed25519 (validator-alist)
  "Get ed25519 key from a validator alist (cl-json renames ed25519 → ed-25519)."
  (or (cdr (assoc :ed25519 validator-alist))
      (cdr (assoc :ed-25519 validator-alist))))

;;; Helper: convert JSON validator list to our plist format
(defun json-validators-to-plists (validators-json)
  "Convert cl-json validator alists to plists with :ed25519 key."
  (mapcar (lambda (v)
            (list :ed25519 (let ((hex (json-ed25519 v)))
                             (when hex (hex-string-to-bytes hex)))
                  :bandersnatch (let ((hex (cdr (assoc :bandersnatch v))))
                                  (when hex (hex-string-to-bytes hex)))))
          validators-json))

;;; Helper: convert JSON hash list to byte-vector list
(defun json-hashes-to-bytes (hash-list)
  (mapcar #'hex-string-to-bytes hash-list))

;;; Helper: convert JSON disputes to our plist format
(defun json-disputes-to-plist (disputes-json)
  (let ((verdicts (cdr (assoc :verdicts disputes-json)))
        (culprits (cdr (assoc :culprits disputes-json)))
        (faults (cdr (assoc :faults disputes-json))))
    (list
     :verdicts (mapcar (lambda (v)
                         (list :target (hex-string-to-bytes (cdr (assoc :target v)))
                               :age (cdr (assoc :age v))
                               :votes (mapcar (lambda (vote)
                                                (list :vote (cdr (assoc :vote vote))
                                                      :index (cdr (assoc :index vote))
                                                      :signature (hex-string-to-bytes
                                                                  (cdr (assoc :signature vote)))))
                                              (cdr (assoc :votes v)))))
                       verdicts)
     :culprits (mapcar (lambda (c)
                         (list :target (hex-string-to-bytes (cdr (assoc :target c)))
                               :key (hex-string-to-bytes (cdr (assoc :key c)))
                               :signature (hex-string-to-bytes (cdr (assoc :signature c)))))
                       culprits)
     :faults (mapcar (lambda (f)
                       (list :target (hex-string-to-bytes (cdr (assoc :target f)))
                             :vote (cdr (assoc :vote f))
                             :key (hex-string-to-bytes (cdr (assoc :key f)))
                             :signature (hex-string-to-bytes (cdr (assoc :signature f)))))
                     faults))))

;;; Helper: convert JSON psi state to our plist format
(defun json-psi-to-plist (psi-json)
  (list :good (json-hashes-to-bytes (cdr (assoc :good psi-json)))
        :bad (json-hashes-to-bytes (cdr (assoc :bad psi-json)))
        :wonky (json-hashes-to-bytes (cdr (assoc :wonky psi-json)))
        :offenders (json-hashes-to-bytes (cdr (assoc :offenders psi-json)))))

;;; ═══════════════════════════════════════════════════════════════
;;; COMPARISON — deep content comparison, not just lengths
;;; ═══════════════════════════════════════════════════════════════

(defun compare-hash-sets (label actual expected)
  "Compare two lists of 32-byte hashes. Returns T if all match."
  (let ((ok t))
    (unless (= (length actual) (length expected))
      (format t "    ✗ ~A: length ~D ≠ ~D~%" label (length actual) (length expected))
      (return-from compare-hash-sets nil))
    (loop for a in actual for e in expected for i from 0
          unless (equalp a e)
            do (format t "    ✗ ~A[~D]: ~A ≠ ~A~%"
                       label i
                       (jam.ffi:bytes-to-hex-string a)
                       (jam.ffi:bytes-to-hex-string e))
               (setf ok nil))
    ok))

(defun compare-psi (label actual expected)
  "Deep comparison of two ψ plists (content, not just lengths)."
  (let ((ok t))
    (unless (compare-hash-sets (format nil "~A.good" label)
                               (getf actual :good) (getf expected :good))
      (setf ok nil))
    (unless (compare-hash-sets (format nil "~A.bad" label)
                               (getf actual :bad) (getf expected :bad))
      (setf ok nil))
    (unless (compare-hash-sets (format nil "~A.wonky" label)
                               (getf actual :wonky) (getf expected :wonky))
      (setf ok nil))
    (unless (compare-hash-sets (format nil "~A.offenders" label)
                               (getf actual :offenders) (getf expected :offenders))
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
         (disputes (json-disputes-to-plist (cdr (assoc :disputes input))))
         ;; Parse pre-state
         (tau (cdr (assoc :tau pre)))
         (psi (json-psi-to-plist (cdr (assoc :psi pre))))
         (kappa (json-validators-to-plists (cdr (assoc :kappa pre))))
         (lambda-prev (json-validators-to-plists (cdr (assoc :lambda pre))))
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
