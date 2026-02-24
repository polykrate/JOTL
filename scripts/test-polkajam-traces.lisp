;;;; test-polkajam-traces.lisp — Run JOTL against polkajam fuzz-reports traces
;;;;
;;;; Each trace step is self-contained: pre_state + block + post_state.
;;;; We load pre_state, apply the block, compare with expected post_state.
;;;; This gives us the EXACT component-level diff on failure.
;;;;
;;;; Usage:
;;;;   TRACES_DIR=/path/to/traces sbcl --load scripts/load-jotl.lisp \
;;;;     --load scripts/test-polkajam-traces.lisp
;;;;
;;;; Or test a single trace:
;;;;   TRACE_ID=1766241867 TRACES_DIR=... sbcl ...

(in-package #:jotl)

(defvar *traces-dir*
  (or (uiop:getenv "TRACES_DIR")
      (let ((base (asdf:system-source-directory :jotl)))
        (namestring
         (merge-pathnames
          "../jam-conformance/fuzz-reports/0.7.2/traces/"
          base)))))

(defvar *trace-id* (uiop:getenv "TRACE_ID"))
(defvar *max-traces* (let ((v (uiop:getenv "MAX_TRACES")))
                       (when v (parse-integer v))))
(defvar *stop-on-fail* (not (equal (uiop:getenv "NO_STOP") "1")))

;;; ═══════════════════════════════════════════════════════════════
;;; TRACE DISCOVERY
;;; ═══════════════════════════════════════════════════════════════

(defun list-polkajam-traces ()
  "List all trace directories in *traces-dir*.
   Returns list of (trace-id . full-path) sorted by name."
  (let ((result nil))
    (dolist (p (directory (merge-pathnames "*/" *traces-dir*)))
      (let ((name (car (last (pathname-directory p)))))
        (when (and name (digit-char-p (char name 0)))
          (push (cons name (namestring p)) result))))
    (sort result #'string< :key #'car)))

(defun list-trace-steps (trace-dir)
  "List .bin step files in TRACE-DIR (excluding genesis.bin, report.bin).
   Returns sorted list of full pathnames."
  (let ((bins nil))
    (dolist (p (directory (merge-pathnames "*.bin" trace-dir)))
      (let ((name (pathname-name p)))
        (when (and (every #'digit-char-p name)
                   (= (length name) 8))
          (push (namestring p) bins))))
    (sort bins #'string<)))

;;; ═══════════════════════════════════════════════════════════════
;;; STEP RUNNER — self-contained step test
;;; ═══════════════════════════════════════════════════════════════

(defun test-step (step-path)
  "Load and test a single trace step.
   Returns: (values :ok nil)           — state root matches
            (values :reject nil)       — block correctly rejected (post=pre)
            (values :fail diff-list)   — state root mismatch (bad components)
            (values :bad-reject msg)   — block rejected but post≠pre (should have been accepted)
            (values :error msg)        — decode error"
  (handler-case
      (let ((bytes (alexandria:read-file-into-byte-vector step-path)))
        (multiple-value-bind (pre-sigma block-cl post-sigma pre-root post-root)
            (decode-trace-step-bin bytes)
          (let ((*chain-log-level* nil)
                (same-root (equalp pre-root post-root)))
            (handler-case
                (multiple-value-bind (sigma-prime computed-root)
                    (import-block pre-sigma block-cl)
                  (if (equalp computed-root post-root)
                      (values :ok nil)
                      ;; Mismatch — compute component diff
                      (let* ((computed-ht (make-hash-table :test 'equalp))
                             (expected-ht (make-hash-table :test 'equalp))
                             (bad-components nil))
                        (dolist (kv (funcall sigma-prime :merkle-kvs))
                          (setf (gethash (car kv) computed-ht) (cdr kv)))
                        (dolist (kv (funcall post-sigma :merkle-kvs))
                          (setf (gethash (car kv) expected-ht) (cdr kv)))
                        ;; Check segments
                        (dolist (entry +sigma-segment-order+)
                          (let* ((kw (car entry))
                                 (cn (cdr entry))
                                 (key (make-array 31 :element-type '(unsigned-byte 8)
                                                     :initial-element 0)))
                            (setf (aref key 0) cn)
                            (let ((exp (gethash key expected-ht))
                                  (got (gethash key computed-ht)))
                              (unless (equalp exp got)
                                (push kw bad-components)))))
                        ;; Check delta-kvs
                        (let ((delta-diff nil))
                          (maphash (lambda (k v)
                                     (unless (segment-key-p k)
                                       (unless (equalp v (gethash k computed-ht))
                                         (setf delta-diff t))))
                                   expected-ht)
                          (maphash (lambda (k v)
                                     (declare (ignore v))
                                     (unless (segment-key-p k)
                                       (unless (gethash k expected-ht)
                                         (setf delta-diff t))))
                                   computed-ht)
                          (when delta-diff
                            (push :delta-kvs bad-components)))
                        (values :fail (nreverse bad-components)))))
              ;; STF error (block rejected)
              (error (e)
                (if same-root
                    ;; post=pre → block SHOULD be rejected → correct!
                    (values :reject (format nil "~A" e))
                    ;; post≠pre → block should have been accepted but JOTL rejected it
                    (values :bad-reject (format nil "~A" e))))))))
    ;; Decode error
    (error (e)
      (values :error (format nil "DECODE: ~A" e)))))

;;; ═══════════════════════════════════════════════════════════════
;;; TRACE RUNNER
;;; ═══════════════════════════════════════════════════════════════

(defun test-trace (trace-id trace-dir)
  "Test all steps in a single trace.
   Returns: (values pass fail errors rejects bad-rejects)"
  (let* ((steps (list-trace-steps trace-dir))
         (nsteps (length steps))
         (pass 0) (fail 0) (errs 0) (rejects 0) (bad-rejects 0)
         (failed-detail nil))
    (format t "  ~A (~D steps) " trace-id nsteps)
    (force-output)
    (dolist (step-path steps)
      (let ((step-name (pathname-name (pathname step-path))))
        (multiple-value-bind (status detail) (test-step step-path)
          (case status
            (:ok (incf pass) (write-char #\.) (force-output))
            (:reject (incf rejects) (write-char #\r) (force-output))
            (:fail
             (incf fail)
             (write-char #\X) (force-output)
             (push (cons step-name detail) failed-detail))
            (:bad-reject
             (incf bad-rejects)
             (write-char #\!) (force-output)
             (push (cons step-name detail) failed-detail))
            (:error
             (incf errs)
             (write-char #\E) (force-output)
             (push (cons step-name detail) failed-detail))))))
    ;; Summary
    (if (and (zerop fail) (zerop errs) (zerop bad-rejects))
        (if (plusp rejects)
            (format t " ✓ ~D/~D (+~Dr)~%" pass nsteps rejects)
            (format t " ✓ ~D/~D~%" pass nsteps))
        (progn
          (format t " ✗ pass=~D fail=~D err=~D reject=~D bad-reject=~D~%"
                  pass fail errs rejects bad-rejects)
          (dolist (fd (nreverse failed-detail))
            (format t "    step ~A: ~A~%" (car fd) (cdr fd)))))
    (values pass fail errs rejects bad-rejects)))

;;; ═══════════════════════════════════════════════════════════════
;;; MAIN
;;; ═══════════════════════════════════════════════════════════════

(defun run-polkajam-tests ()
  (format t "~%═══ JOTL vs polkajam traces ═══~%")
  (format t "Traces dir: ~A~%" *traces-dir*)
  (format t "Trace ID filter: ~A~%" (or *trace-id* "(all)"))
  (format t "Max traces: ~A~%" (or *max-traces* "(unlimited)"))
  (format t "Stop on fail: ~A~%~%" *stop-on-fail*)

  (let* ((all-traces (list-polkajam-traces))
         (traces (if *trace-id*
                     (remove-if-not (lambda (t-pair)
                                      (search *trace-id* (car t-pair)))
                                    all-traces)
                     all-traces))
         (traces (if *max-traces*
                     (subseq traces 0 (min *max-traces* (length traces)))
                     traces))
         (total-pass 0) (total-fail 0) (total-err 0)
         (total-rejects 0) (total-bad-rejects 0)
         (n-traces 0)
         (t-start (get-internal-real-time)))

    (format t "Found ~D traces (~D total available)~%~%"
            (length traces) (length all-traces))

    (dolist (t-pair traces)
      (let ((tid (car t-pair))
            (tdir (cdr t-pair)))
        (multiple-value-bind (p f e r br) (test-trace tid tdir)
          (incf total-pass p)
          (incf total-fail f)
          (incf total-err e)
          (incf total-rejects (or r 0))
          (incf total-bad-rejects (or br 0))
          (incf n-traces)
          (when (and *stop-on-fail* (or (plusp f) (plusp e) (plusp (or br 0))))
            (format t "~%═══ Stopping after first failure ═══~%")
            (return)))))

    (let ((elapsed (/ (- (get-internal-real-time) t-start)
                      (float internal-time-units-per-second))))
      (format t "~%═══════════════════════════════════════~%")
      (format t "Traces: ~D   Steps: pass=~D fail=~D err=~D reject=~D bad-reject=~D~%"
              n-traces total-pass total-fail total-err total-rejects total-bad-rejects)
      (format t "Time: ~,2Fs~%" elapsed)
      (format t "Legend: .=ok r=correct-reject X=mismatch !=bad-reject E=decode-error~%")
      (if (and (zerop total-fail) (zerop total-err) (zerop total-bad-rejects))
          (format t "Result: ✓ ALL PASS~%")
          (format t "Result: ✗ FAILURES~%"))
      (format t "═══════════════════════════════════════~%"))

    (values total-pass total-fail total-err)))

(multiple-value-bind (pass fail errs) (run-polkajam-tests)
  (declare (ignore pass))
  (sb-ext:exit :code (if (and (zerop fail) (zerop errs)) 0 1)))
