;;;; tests/test-merkle-traces.lisp — Merkle root verification against trace vectors
;;;;
;;;; Verifies that our Merkle trie implementation produces the correct
;;;; state_root from the key-value pairs in the fallback trace vectors.

(in-package #:jotl)

(load (merge-pathnames "test-utils.lisp" *load-pathname*))

;;; ═══════════════════════════════════════════════════════════════
;;; PARSE TRACE STATE → keyvals
;;; ═══════════════════════════════════════════════════════════════

(defun parse-trace-keyvals (state-json)
  "Parse a trace state JSON → list of (key-31bytes . value-bytes) cons cells."
  (let ((kvs-json (cdr (assoc :keyvals state-json))))
    (mapcar (lambda (kv)
              (cons (hex-to-bytes (cdr (assoc :key kv)))
                    (hex-to-bytes (cdr (assoc :value kv)))))
            kvs-json)))

;;; ═══════════════════════════════════════════════════════════════
;;; GENESIS TEST
;;; ═══════════════════════════════════════════════════════════════

(defun test-merkle-genesis ()
  "Verify genesis state_root from trace keyvals."
  (format t "~%═══════════════════════════════════════════════════~%")
  (format t "  Merkle Root — Genesis~%")
  (format t "═══════════════════════════════════════════════════~%")
  (let* ((json (load-json "tests/jamtestvectors/traces/fallback/genesis.json"))
         (state-json (cdr (assoc :state json)))
         (expected-root (hex-to-bytes (cdr (assoc :state--root state-json))))
         (keyvals (parse-trace-keyvals state-json))
         (computed-root (compute-state-root keyvals)))
    (format t "  Expected: ~A~%" (bytes-to-hex-string expected-root))
    (format t "  Computed: ~A~%" (bytes-to-hex-string computed-root))
    (format t "  Keys:     ~D~%" (length keyvals))
    (if (equalp computed-root expected-root)
        (progn (format t "  ✅ MATCH~%") t)
        (progn (format t "  ❌ MISMATCH~%") nil))))

;;; ═══════════════════════════════════════════════════════════════
;;; BLOCK-BY-BLOCK TEST
;;; ═══════════════════════════════════════════════════════════════

(defun test-merkle-block (block-num)
  "Verify pre_state and post_state roots for a specific block."
  (let* ((path (format nil "tests/jamtestvectors/traces/fallback/~8,'0D.json" block-num))
         (json (load-json path))
         ;; Pre-state
         (pre-json (cdr (assoc :pre--state json)))
         (pre-expected (hex-to-bytes (cdr (assoc :state--root pre-json))))
         (pre-kvs (parse-trace-keyvals pre-json))
         (pre-computed (compute-state-root pre-kvs))
         ;; Post-state
         (post-json (cdr (assoc :post--state json)))
         (post-expected (hex-to-bytes (cdr (assoc :state--root post-json))))
         (post-kvs (parse-trace-keyvals post-json))
         (post-computed (compute-state-root post-kvs))
         (pre-ok (equalp pre-computed pre-expected))
         (post-ok (equalp post-computed post-expected)))
    (format t "  Block ~3D: pre=~A post=~A~%"
            block-num
            (if pre-ok "✓" "✗")
            (if post-ok "✓" "✗"))
    (unless pre-ok
      (format t "    pre  expected: ~A~%" (bytes-to-hex-string pre-expected))
      (format t "    pre  computed: ~A~%" (bytes-to-hex-string pre-computed)))
    (unless post-ok
      (format t "    post expected: ~A~%" (bytes-to-hex-string post-expected))
      (format t "    post computed: ~A~%" (bytes-to-hex-string post-computed)))
    (and pre-ok post-ok)))

(defun test-merkle-blocks (&key (from 1) (to 10))
  "Verify Merkle roots for a range of fallback blocks."
  (format t "~%═══════════════════════════════════════════════════~%")
  (format t "  Merkle Root — Blocks ~D to ~D~%" from to)
  (format t "═══════════════════════════════════════════════════~%")
  (let ((pass 0) (fail 0))
    (loop for b from from to to do
      (handler-case
          (if (test-merkle-block b)
              (incf pass)
              (incf fail))
        (error (e)
          (format t "  Block ~3D: ERROR ~A~%" b e)
          (incf fail))))
    (format t "~%  Results: ~D passed, ~D failed~%" pass fail)
    (zerop fail)))

;;; ═══════════════════════════════════════════════════════════════
;;; RUNNER
;;; ═══════════════════════════════════════════════════════════════

(defun run-merkle-tests ()
  "Run all Merkle trace verification tests."
  (let ((ok t))
    (unless (test-merkle-genesis) (setf ok nil))
    (unless (test-merkle-blocks :from 1 :to 20) (setf ok nil))
    ok))
