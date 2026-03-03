;;;; conformance.lisp — M1 Conformance Test Runner
;;;;
;;;; Client-side test code.  Reads jamtestvectors trace files,
;;;; applies blocks through the JOTL STF, compares state roots.
;;;;
;;;; This is NOT part of the chain — it's a test harness that lives
;;;; in tests/ and uses import-block as its only entry point.
;;;;
;;;; Usage from the REPL:
;;;;   (jotl/test:run-all)                          ;; run everything
;;;;   (jotl/test:run-all :traces '("storage"))     ;; one trace
;;;;   (jotl/test:run-all :verbose t)               ;; per-block detail
;;;;
;;;; Or from shell:
;;;;   ./scripts/test.sh                    ;; all traces
;;;;   ./scripts/test.sh storage safrole    ;; specific traces
;;;;   ./scripts/test.sh -v fuzzy           ;; verbose with diff

(defpackage #:jotl/test
  (:use #:cl #:jotl)
  (:export #:run-all
           #:run-trace
           #:diagnose-block
           #:diagnose-range))

(in-package #:jotl/test)

;; Suppress SBCL style-warnings about functions defined in JOTL
;; (loaded before this file but not visible at compile time).
#+sbcl (declaim (sb-ext:muffle-conditions style-warning))

;;; ═══════════════════════════════════════════════════════════════
;;; ANSI COLORS — terminal escape sequences
;;; ═══════════════════════════════════════════════════════════════

(defparameter +esc+    (string #\Esc))
(defparameter +reset+  (format nil "~A[0m"  +esc+))
(defparameter +bold+   (format nil "~A[1m"  +esc+))
(defparameter +dim+    (format nil "~A[2m"  +esc+))
(defparameter +red+    (format nil "~A[31m" +esc+))
(defparameter +green+  (format nil "~A[32m" +esc+))
(defparameter +yellow+ (format nil "~A[33m" +esc+))
(defparameter +cyan+   (format nil "~A[36m" +esc+))
(defparameter +bred+   (format nil "~A[1;31m" +esc+))
(defparameter +bgreen+ (format nil "~A[1;32m" +esc+))
(defparameter +byellow+ (format nil "~A[1;33m" +esc+))
(defparameter +bcyan+  (format nil "~A[1;36m" +esc+))
(defparameter +bwhite+ (format nil "~A[1;37m" +esc+))

(defun c (color text)
  "Wrap TEXT with ANSI COLOR and RESET."
  (format nil "~A~A~A" color text +reset+))

;;; ═══════════════════════════════════════════════════════════════
;;; TABLE FORMATTING — build cells without ANSI alignment issues
;;; ═══════════════════════════════════════════════════════════════

(defun pad-right (str width)
  "Pad STR with spaces on the right to WIDTH visible characters.
   ANSI escape sequences are not counted."
  (let ((visible-len (loop for i = 0 then (1+ i)
                           with len = 0
                           while (< i (length str))
                           do (if (and (< (1+ i) (length str))
                                       (char= (char str i) #\Esc)
                                       (char= (char str (1+ i)) #\[))
                                  ;; skip ANSI sequence: ESC [ ... m
                                  (let ((end (position #\m str :start (+ i 2))))
                                    (when end (setf i end)))
                                  (incf len))
                           finally (return len))))
    (if (>= visible-len width)
        str
        (concatenate 'string str (make-string (- width visible-len) :initial-element #\Space)))))

(defun pad-left (str width)
  "Pad STR with spaces on the left to WIDTH visible characters."
  (let ((visible-len (loop for i = 0 then (1+ i)
                           with len = 0
                           while (< i (length str))
                           do (if (and (< (1+ i) (length str))
                                       (char= (char str i) #\Esc)
                                       (char= (char str (1+ i)) #\[))
                                  (let ((end (position #\m str :start (+ i 2))))
                                    (when end (setf i end)))
                                  (incf len))
                           finally (return len))))
    (if (>= visible-len width)
        str
        (concatenate 'string (make-string (- width visible-len) :initial-element #\Space) str))))

(defun table-row (name chain-cell step-cell err-cell p50 p90 mean p99 std-dev)
  "Build one table row with cyan borders."
  (format nil "~A║~A ~A ~A║~A ~A ~A║~A ~A ~A║~A ~A ~A║~A ~A ~A║~A ~A ~A║~A ~A ~A║~A ~A ~A║~A ~A ~A║~A"
          +bcyan+ +reset+ (pad-right name 16)
          +bcyan+ +reset+ (pad-right chain-cell 12)
          +bcyan+ +reset+ (pad-right step-cell 12)
          +bcyan+ +reset+ (pad-right err-cell 6)
          +bcyan+ +reset+ (pad-right p50 11)
          +bcyan+ +reset+ (pad-right p90 10)
          +bcyan+ +reset+ (pad-right mean 9)
          +bcyan+ +reset+ (pad-right p99 10)
          +bcyan+ +reset+ (pad-right std-dev 11)
          +bcyan+ +reset+))

(defun score-cell (pass total)
  "Format a pass/total cell with green (all pass) or red (some fail)."
  (let ((color (if (= pass total) +green+ +red+))
        (mark  (if (= pass total) "✓" "✗")))
    (format nil "~A~D/~D ~A~A" color pass total mark +reset+)))

(defun bold-score-cell (pass total)
  "Format a bold pass/total cell for the TOTAL row."
  (let ((color (if (= pass total) +bgreen+ +bred+))
        (mark  (if (= pass total) "✓" "✗")))
    (format nil "~A~D/~D ~A~A" color pass total mark +reset+)))

;;; ═══════════════════════════════════════════════════════════════
;;; COMPONENT DIFF — compare σ' per component when roots diverge
;;; ═══════════════════════════════════════════════════════════════

(defun count-byte-diffs (a b)
  "Count differing bytes between two byte vectors."
  (let ((n 0)
        (len (min (length a) (length b))))
    (dotimes (i len)
      (unless (= (aref a i) (aref b i))
        (incf n)))
    (+ n (abs (- (length a) (length b))))))

(defun component-diff (sigma-prime post-sigma)
  "Compare σ' and expected post-σ per component.
   Returns list of (:name status detail)."
  (let ((computed-ht (make-hash-table :test 'equalp))
        (expected-ht (make-hash-table :test 'equalp))
        (results nil))
    (dolist (kv (funcall sigma-prime :merkle-kvs))
      (setf (gethash (car kv) computed-ht) (cdr kv)))
    (dolist (kv (funcall post-sigma :merkle-kvs))
      (setf (gethash (car kv) expected-ht) (cdr kv)))

    ;; Check each segment C(1)..C(16)
    (dolist (entry jotl::+sigma-segment-order+)
      (let* ((kw (car entry))
             (cn (cdr entry))
             (key (make-array 31 :element-type '(unsigned-byte 8) :initial-element 0)))
        (setf (aref key 0) cn)
        (let ((exp-val (gethash key expected-ht))
              (got-val (gethash key computed-ht)))
          (cond
            ((and exp-val got-val (equalp exp-val got-val))
             (push (list kw :match nil) results))
            ((and exp-val got-val)
             (push (list kw :diff
                         (format nil "~D/~D bytes, ~D differ"
                                 (length got-val) (length exp-val)
                                 (count-byte-diffs got-val exp-val)))
                   results))
            ((and exp-val (null got-val))
             (push (list kw :missing (format nil "~D bytes expected" (length exp-val)))
                   results))
            ((and (null exp-val) got-val)
             (push (list kw :extra (format nil "~D bytes" (length got-val)))
                   results))
            (t nil)))))

    ;; Count non-segment key differences (δ service accounts)
    (let ((exp-count 0) (got-count 0) (match 0) (diff 0)
          (missing 0) (extra-new 0))
      (maphash (lambda (k v) (declare (ignore v))
                 (unless (jotl::segment-key-p k)
                   (incf exp-count)
                   (if (gethash k computed-ht)
                       (if (equalp (gethash k computed-ht) (gethash k expected-ht))
                           (incf match)
                           (incf diff))
                       (incf missing))))
               expected-ht)
      (maphash (lambda (k v) (declare (ignore v))
                 (unless (jotl::segment-key-p k)
                   (incf got-count)
                   (unless (gethash k expected-ht)
                     (incf extra-new))))
               computed-ht)
      (when (or (plusp exp-count) (plusp got-count))
        (push (list :delta-kvs
                    (if (and (zerop diff) (zerop missing) (zerop extra-new))
                        :match :diff)
                    (format nil "~D/~D entries (ok=~D diff=~D miss=~D extra=~D)"
                            got-count exp-count match diff missing extra-new))
              results)))

    (nreverse results)))

(defun print-component-diff (diff-results &key (indent "    "))
  "Pretty-print component diff with colors."
  (dolist (r diff-results)
    (destructuring-bind (name status detail) r
      (let ((sym (string-downcase (symbol-name name))))
        (ecase status
          (:match
           (format t "~A~A~A ✓~A~%" indent +dim+ sym +reset+))
          (:diff
           (format t "~A~A~A ✗~A ~A~%" indent +bred+ sym +reset+ detail))
          (:missing
           (format t "~A~A~A ⊘ MISSING~A ~A~%" indent +yellow+ sym +reset+ detail))
          (:extra
           (format t "~A~A~A ⊕ EXTRA~A ~A~%" indent +yellow+ sym +reset+ detail)))))))

(defun print-diverging-components (diff-results &key (indent "      "))
  "Print only the diverging components (compact form for step failures)."
  (dolist (r diff-results)
    (destructuring-bind (name status detail) r
      (unless (eq status :match)
        (let ((sym (string-downcase (symbol-name name))))
          (format t "~A~A✗ ~A~A ~A~A~%" indent +red+ sym +reset+ +dim+ (or detail "")))))))

;;; ═══════════════════════════════════════════════════════════════
;;; TRACE DISCOVERY
;;; ═══════════════════════════════════════════════════════════════

(defvar *trace-base-dir* "tests/jamtestvectors/traces/"
  "Base directory for trace vectors.")

;; Desired order: simple → complex (fuzzy last)
(defparameter +trace-order+
  '("fallback" "safrole" "storage_light" "storage"
    "preimages_light" "preimages" "fuzzy_light" "fuzzy")
  "Traces ordered by difficulty.  Missing ones are appended alphabetically.")

(defun list-trace-dirs ()
  "List all trace sub-directories that contain a genesis.bin, ordered by difficulty."
  (let ((all nil))
    (dolist (p (directory (merge-pathnames "*/genesis.bin" *trace-base-dir*)))
      (push (directory-namestring p) all))
    ;; Sort: known order first, then alphabetical for unknowns
    (flet ((trace-name (dir)
             (car (last (pathname-directory (pathname dir)))))
           (order-index (name)
             (or (position name +trace-order+ :test #'string=)
                 (+ (length +trace-order+) 0))))
      (sort all (lambda (a b)
                  (let ((ia (order-index (trace-name a)))
                        (ib (order-index (trace-name b))))
                    (if (= ia ib)
                        (string< (trace-name a) (trace-name b))
                        (< ia ib))))))))

;;; ═══════════════════════════════════════════════════════════════
;;; RUN-TRACE — chain + step mode for a single trace directory
;;; ═══════════════════════════════════════════════════════════════

(defun run-trace (dir &key (verbose t))
  "Run a single trace directory: chain mode with step-mode fallback.

   Returns (values chain-pass chain-fail step-pass step-fail errors (times vector) max-time-step)."
  (let* ((max-block (jotl::count-trace-blocks dir))
         (genesis-path (jotl::trace-genesis-path dir))
         (chain-pass 0) (chain-fail 0)
         (step-pass 0)  (step-fail 0)
         (errors 0)
         (sigma nil)
         (chain-ok t)
         (trace-name (car (last (pathname-directory (pathname dir)))))
         (times (make-array max-block :element-type 'single-float :fill-pointer 0))
         (max-time-step 0)
         (max-time 0.0))

    (when verbose
      (format t "~%~A━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━~A~%"
              +bcyan+ +reset+)
      (format t "  ~A~A~A  (~D blocks)~%"
              +bwhite+ trace-name +reset+ max-block)
      (format t "~A━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━~A~%"
              +bcyan+ +reset+))

    ;; Init from genesis
    (handler-case
        (multiple-value-bind (header genesis-sigma genesis-root)
            (jotl::load-genesis genesis-path)
          (declare (ignore header))
          (setf sigma genesis-sigma)
          (when verbose
            (format t "  ~AGenesis ✓~A  root=~A…~%"
                    +green+ +reset+
                    (subseq (jotl::bytes-to-hex-string genesis-root) 0 16))))
      (error (e)
        (when verbose
          (format t "  ~AGenesis FATAL~A ~A~%" +bred+ +reset+ e))
        (return-from run-trace
          (values 0 max-block 0 0 1 times 0))))

    ;; Process blocks
    (loop for b from 1 to max-block do
      (handler-case
          (let ((step-path (jotl::trace-block-path dir b)))
            (multiple-value-bind (pre-sigma block-cl post-sigma pre-root post-root)
                (jotl:prof :decode (jotl::load-trace-step step-path))
              (declare (ignore pre-root))

              ;; === CHAIN MODE ===
              (when chain-ok
                (handler-case
                    (let ((jotl::*chain-log-level* nil))
                      (declare (special jotl::*chain-log-level*))
                      (let ((t-start (get-internal-real-time)))
                        (multiple-value-bind (sigma-prime computed-root)
                            (jotl::import-block sigma block-cl)
                          (let* ((t-end (get-internal-real-time))
                                 (dt-ms (coerce (* 1000.0 (/ (- t-end t-start) internal-time-units-per-second)) 'single-float)))
                            (vector-push dt-ms times)
                            (when (> dt-ms max-time)
                              (setf max-time dt-ms
                                    max-time-step b))
                            (if (equalp computed-root post-root)
                                (progn
                                  (incf chain-pass)
                                  (setf sigma sigma-prime)
                                  (when verbose
                                    (format t "  ~A#~3D~A  chain ✓  ~Aroot=~A…~A~%"
                                            +dim+ b +reset+
                                            +green+
                                            (subseq (jotl::bytes-to-hex-string computed-root) 0 16)
                                            +reset+)))
                                (progn
                                  (incf chain-fail)
                                  (setf chain-ok nil)
                                  (when verbose
                                    (format t "  ~A#~3D  chain ✗~A~%"
                                            +bred+ b +reset+)
                                    (format t "    ~Aexp~A ~A~%"
                                            +dim+ +reset+
                                            (subseq (jotl::bytes-to-hex-string post-root) 0 16))
                                    (format t "    ~Agot~A ~A~%"
                                            +red+ +reset+
                                            (subseq (jotl::bytes-to-hex-string computed-root) 0 16))
                                    ;; Show which components differ
                                    (let ((diff (component-diff sigma-prime post-sigma)))
                                      (print-component-diff diff)))))))))
                  (error (e)
                    (incf errors)
                    (setf chain-ok nil)
                    (when verbose
                      (format t "  ~A#~3D  chain ERROR~A ~A~%"
                              +bred+ b +reset+ (type-of e))))))

              ;; === STEP MODE (only when chain failed — chain ✓ ⇒ step ✓) ===
              (if chain-ok
                  ;; Chain passed this block → step is identical, skip re-import
                  (incf step-pass)
                  ;; Chain broken — run step independently from reference pre-state
                  (let ((jotl::*chain-log-level* nil))
                    (declare (special jotl::*chain-log-level*))
                    (handler-case
                        (let ((t-start (get-internal-real-time)))
                          (multiple-value-bind (sigma-prime computed-root)
                              (jotl::import-block pre-sigma block-cl)
                            (let* ((t-end (get-internal-real-time))
                                   (dt-ms (coerce (* 1000.0 (/ (- t-end t-start) internal-time-units-per-second)) 'single-float)))
                              (vector-push dt-ms times)
                              (when (> dt-ms max-time)
                                (setf max-time dt-ms
                                      max-time-step b))
                              (if (equalp computed-root post-root)
                                  (progn
                                    (incf step-pass)
                                    (when verbose
                                      (format t "  ~A#~3D~A  step  ✓  ~Aroot=~A…~A~%"
                                              +dim+ b +reset+
                                              +green+
                                              (subseq (jotl::bytes-to-hex-string computed-root) 0 16)
                                              +reset+)))
                                  (progn
                                    (incf step-fail)
                                    (when verbose
                                      (format t "  ~A#~3D  step  ✗~A" +yellow+ b +reset+)
                                      ;; Show diverging components inline
                                      (let* ((diff (component-diff sigma-prime post-sigma))
                                             (bad (remove-if (lambda (r)
                                                               (eq (second r) :match))
                                                             diff)))
                                        (if bad
                                            (progn
                                              (format t "  →")
                                              (dolist (r bad)
                                                (format t " ~A~A~A"
                                                        +red+
                                                        (string-downcase (symbol-name (first r)))
                                                        +reset+))
                                              (format t "~%"))
                                            (format t "~%")))))))))
                      (error (e)
                        (incf step-fail)
                        (incf errors)
                        (when verbose
                          (format t "  ~A#~3D  step  ✗ ERROR~A ~A: ~A~%"
                                  +bred+ b +reset+
                                  (type-of e) e))))))))
        (error (e)
          (incf errors)
          (when verbose
            (format t "  ~A#~3D  LOAD ERROR~A ~A~%"
                    +bred+ b +reset+ (type-of e))))))

    ;; Summary line
    (when verbose
      (format t "~%  Chain: ~A   Step: ~A   Errors: ~D~%"
              (c (if (zerop chain-fail) +bgreen+ +bred+)
                 (format nil "~D/~D" chain-pass max-block))
              (c (if (zerop step-fail) +bgreen+ +bred+)
                 (format nil "~D/~D" step-pass max-block))
              errors))

    (values chain-pass chain-fail step-pass step-fail errors times max-time-step)))

(defun percentile (arr p)
  "Calculate the Pth percentile (0-100) of a single-float vector ARR."
  (let* ((len (length arr))
         (sorted (sort (copy-seq arr) #'<)))
    (if (zerop len)
        0.0
        (let* ((idx (* (/ p 100.0) (1- len)))
               (i (floor idx))
               (frac (- idx i)))
          (if (= i (1- len))
              (aref sorted i)
              (+ (* (- 1.0 frac) (aref sorted i))
                 (* frac (aref sorted (1+ i)))))))))

(defun standard-deviation (arr mean)
  "Calculate standard deviation of a single-float vector ARR."
  (let ((n (length arr)))
    (if (< n 2)
        0.0
        (sqrt (/ (loop for x across arr sum (expt (- x mean) 2)) n)))))

(defun compute-parity-score (results &key (hardware-factor 1.0))
  "Calculate Parity performance score from the results list."
  (let ((target-tests '("safrole" "fallback" "storage" "storage_light"))
        (scores nil)
        (p50s nil)
        (p90s nil))
    (dolist (test target-tests)
      (let ((r (find test results :key #'car :test #'string=)))
        (when r
          ;; name cp cf sp sf err pmin pmax mean p50 p90 p99 std-dev
          (destructuring-bind (name cp cf sp sf err pmin pmax mean p50 p90 p99 std-dev &rest rest) r
            (declare (ignore name cp cf sp sf err pmin pmax rest))
            (let ((score (+ (* p50 0.35)
                            (* p90 0.25)
                            (* mean 0.20)
                            (* p99 0.10)
                            (* std-dev 0.10))))
              (push score scores)
              (push p50 p50s)
              (push p90 p90s))))))
    (if (= (length scores) (length target-tests))
        (let* ((product (reduce #'* scores))
               (raw-final (expt product (/ 1.0 (length target-tests))))
               (avg-p50 (/ (reduce #'+ p50s) (length p50s)))
               (avg-p90 (/ (reduce #'+ p90s) (length p90s))))
          (list :score (/ raw-final hardware-factor)
                :p50 (/ avg-p50 hardware-factor)
                :p90 (/ avg-p90 hardware-factor)))
        nil)))

(defun export-json-report (dir name steps imported min mean max p50 p75 p90 p99 std-dev max-step)
  "Export Parity fuzz-perf JSON report."
  (ensure-directories-exist dir)
  (let ((path (merge-pathnames (format nil "~A.json" name) dir)))
    (with-open-file (out path :direction :output :if-exists :supersede :if-does-not-exist :create)
      (format out "{~%")
      (format out "  \"info\": {~%")
      (format out "    \"fuzz_version\": \"0.7.2\",~%")
      (format out "    \"fuzz_features\": [],~%")
      (format out "    \"jam_version\": \"0.1.0\",~%")
      (format out "    \"app_version\": \"0.1.0\",~%")
      (format out "    \"app_name\": \"JOTL\"~%")
      (format out "  },~%")
      (format out "  \"stats\": {~%")
      (format out "    \"steps\": ~D,~%" steps)
      (format out "    \"imported\": ~D,~%" imported)
      (format out "    \"import_max_step\": ~D,~%" max-step)
      (format out "    \"import_min\": ~,4F,~%" min)
      (format out "    \"import_max\": ~,4F,~%" max)
      (format out "    \"import_mean\": ~,4F,~%" mean)
      (format out "    \"import_p50\": ~,4F,~%" p50)
      (format out "    \"import_p75\": ~,4F,~%" p75)
      (format out "    \"import_p90\": ~,4F,~%" p90)
      (format out "    \"import_p99\": ~,4F,~%" p99)
      (format out "    \"import_std_dev\": ~,4F~%" std-dev)
      (format out "  }~%")
      (format out "}~%"))))

;;; ═══════════════════════════════════════════════════════════════
;;; RUN-ALL — aggregate all traces with summary table
;;; ═══════════════════════════════════════════════════════════════

(defun run-all (&key (verbose nil) (traces nil) (json-dir nil))
  "Run all traces (or a subset).  Prints a colored summary table.

   TRACES: optional list of trace names (e.g. '(\"storage\" \"safrole\")).
           NIL = all traces with a genesis.bin.
   VERBOSE: per-block detail + component diff on failures.
   JSON-DIR: optional directory to export parity-compatible fuzz-perf json reports.

   Returns plist (:chain-pass N :chain-fail N :step-pass N :step-fail N :errors N)"
  (let ((dirs (if traces
                  (mapcar (lambda (name)
                            (namestring
                             (merge-pathnames (format nil "~A/" name)
                                              *trace-base-dir*)))
                          traces)
                  (list-trace-dirs)))
        (results nil)
        (grand-cp 0) (grand-cf 0)
        (grand-sp 0) (grand-sf 0)
        (grand-err 0)
        (t-start (get-internal-real-time)))

    (dolist (dir dirs)
      (let ((name (car (last (pathname-directory (pathname dir)))))
            (jotl:*prof* (make-hash-table :test 'eq)))
        (multiple-value-bind (cp cf sp sf err times max-time-step)
            (run-trace dir :verbose verbose)
          (let* ((n (length times))
                 (mean (if (plusp n) (/ (loop for x across times sum x) n) 0.0))
                 (p50 (percentile times 50))
                 (p75 (percentile times 75))
                 (p90 (percentile times 90))
                 (p99 (percentile times 99))
                 (std-dev (standard-deviation times mean))
                 (pmax (if (plusp n) (reduce #'max times) 0.0))
                 (pmin (if (plusp n) (reduce #'min times) 0.0)))
            
            (when json-dir
              (export-json-report (pathname json-dir) name (+ cp cf sp sf err) (+ cp sp)
                                  pmin mean pmax p50 p75 p90 p99 std-dev max-time-step))
            
            (push (list name cp cf sp sf err
                        pmin pmax mean p50 p90 p99 std-dev max-time-step
                        (jotl:prof-seconds :decode)
                        (jotl:prof-seconds :stf)
                        (jotl:prof-seconds :merkle)
                        (jotl:prof-seconds :accumulate)
                        (jotl:prof-seconds :delta-save))
                  results))
          (incf grand-cp cp) (incf grand-cf cf)
          (incf grand-sp sp) (incf grand-sf sf)
          (incf grand-err err))))

    (let ((elapsed-s (/ (- (get-internal-real-time) t-start)
                        (float internal-time-units-per-second))))

      ;; Reverse results in-place once, use everywhere after
      (setf results (nreverse results))

      ;; ── Timer ──
      (format t "~%  ~A⏱  ~,2F s~A  (~D traces, ~D blocks, ~,1F ms/block)~%"
              +bcyan+ elapsed-s +reset+
              (length dirs) (+ grand-cp grand-cf)
              (if (plusp (+ grand-cp grand-cf))
                  (* 1000.0 (/ elapsed-s (+ grand-cp grand-cf)))
                  0.0))

      ;; ── Results table (at the end for easy tail) ──
      (format t "~%")
      (let ((border-top  "╔══════════════════╦══════════════╦══════════════╦════════╦═════════════╦════════════╦═══════════╦════════════╦═════════════╗")
            (border-mid  "╠══════════════════╬══════════════╬══════════════╬════════╬═════════════╬════════════╬═══════════╬════════════╬═════════════╣")
            (border-bot  "╚══════════════════╩══════════════╩══════════════╩════════╩═════════════╩════════════╩═══════════╩════════════╩═════════════╝"))
        ;; Header
        (format t "~A~A~A~%" +bcyan+ border-top +reset+)
        (format t "~A" (table-row (c +bwhite+ "Trace")
                                  (c +bwhite+ "Chain")
                                  (c +bwhite+ "Step")
                                  (c +bwhite+ "Errors")
                                  (c +bwhite+ "Median(P50)")
                                  (c +bwhite+ "90th (P90)")
                                  (c +bwhite+ "Mean (ms)")
                                  (c +bwhite+ "99th (P99)")
                                  (c +bwhite+ "Consistency")))
        (terpri)
        (format t "~A~A~A~%" +bcyan+ border-mid +reset+)

        ;; Data rows
        (dolist (r results)
          (let ((name (nth 0 r)) (cp (nth 1 r)) (cf (nth 2 r))
                (sp (nth 3 r)) (sf (nth 4 r)) (err (nth 5 r))
                (mean (nth 8 r))
                (p50 (nth 9 r))
                (p90 (nth 11 r))
                (p99 (nth 12 r))
                (std-dev (nth 13 r)))
            (let ((ct (+ cp cf))
                  (st (+ sp sf)))
              (format t "~A~%"
                      (table-row name
                                 (score-cell cp ct)
                                 (score-cell sp st)
                                 (if (zerop err)
                                     (c +dim+ "0")
                                     (c +bred+ (format nil "~D" err)))
                                 (format nil "~,2F" p50)
                                 (format nil "~,2F" p90)
                                 (format nil "~,2F" mean)
                                 (format nil "~,2F" p99)
                                 (format nil "~,2F" std-dev))))))

        ;; Total row
        (let ((ct (+ grand-cp grand-cf))
          (st (+ grand-sp grand-sf)))
          (format t "~A~A~A~%" +bcyan+ border-mid +reset+)
          (format t "~A~%"
                  (table-row (c +bwhite+ "TOTAL")
                             (bold-score-cell grand-cp ct)
                             (bold-score-cell grand-sp st)
                             (if (zerop grand-err)
                                 (c +dim+ "0")
                                 (c +bred+ (format nil "~D" grand-err)))
                             "-" "-" "-" "-" "-"))
          (format t "~A~A~A~%" +bcyan+ border-bot +reset+)))

      ;; ── Parity Performance Ranking ──
      (let ((local-score (compute-parity-score results :hardware-factor 1.0)))
        (when local-score
          (let* ((score (getf local-score :score))
                 (details (format nil "  Score: ~,1F (Geometric Mean of 4 traces)" score)))
            (format t "~%  ~A┌──────────────────────────────────────────────────────────────┐~A~%" +bcyan+ +reset+)
            (format t "  ~A│~A ~A ~A│~A~%"
                    +bcyan+ +reset+ (pad-right (c +bwhite+ "JOTL Performance Ranking (Parity Formula)") 60) +bcyan+ +reset+)
            (format t "  ~A├──────────────────────────────────────────────────────────────┤~A~%" +bcyan+ +reset+)
            (format t "  ~A│~A ~A ~A│~A~%"
                    +bcyan+ +reset+ (pad-right "Local Hardware" 60) +bcyan+ +reset+)
            (format t "  ~A│~A ~A ~A│~A~%"
                    +bcyan+ +reset+ (pad-right details 60) +bcyan+ +reset+)
            (format t "  ~A└──────────────────────────────────────────────────────────────┘~A~%" +bcyan+ +reset+))))

      ;; Result plist
      (list :chain-pass grand-cp :chain-fail grand-cf
            :step-pass grand-sp :step-fail grand-sf
            :errors grand-err))))

;;; ═══════════════════════════════════════════════════════════════
;;; DIAGNOSE-BLOCK — deep diff for a single trace step
;;; ═══════════════════════════════════════════════════════════════

(defun diagnose-block (trace-dir block-num &key (sigma nil))
  "Deep diagnostic for a single trace block.
   Compares our computed σ' key-by-key against the expected post-state."
  (let* ((step-path (jotl::trace-block-path trace-dir block-num))
         (bytes (alexandria:read-file-into-byte-vector step-path)))
    (multiple-value-bind (pre-sigma block-cl post-sigma pre-root post-root)
        (jotl::decode-trace-step-bin bytes)
      (declare (ignore pre-root))
      (let ((input-sigma (or sigma pre-sigma))
            (jotl::*chain-log-level* nil))
        (declare (special jotl::*chain-log-level*))

        (format t "~%~A━━━ DIAGNOSE Block ~D ━━━~A~%" +bcyan+ block-num +reset+)

        (handler-case
            (multiple-value-bind (sigma-prime computed-root)
                (jotl::import-block input-sigma block-cl)

              (let ((root-ok (equalp computed-root post-root)))
                (if root-ok
                    (format t "  ~ARoot ✓ MATCH~A~%" +bgreen+ +reset+)
                    (progn
                      (format t "  ~ARoot ✗ MISMATCH~A~%" +bred+ +reset+)
                      (format t "    ~Aexp~A ~A~%"
                              +dim+ +reset+ (jotl::bytes-to-hex-string post-root))
                      (format t "    ~Agot~A ~A~%"
                              +red+ +reset+ (jotl::bytes-to-hex-string computed-root))))

                ;; Component-level diff
                (let ((diff (component-diff sigma-prime post-sigma)))
                  (format t "~%  ~AComponents:~A~%" +bold+ +reset+)
                  (print-component-diff diff)
                  (let ((n-diff (count-if (lambda (r) (not (eq (second r) :match)))
                                          diff)))
                    (format t "~%  ~A~D/~D components match~A~%"
                            (if (zerop n-diff) +bgreen+ +bred+)
                            (- (length diff) n-diff)
                            (length diff)
                            +reset+)
                    (values root-ok (zerop n-diff) nil)))))

          (error (e)
            (format t "  ~AERROR~A: ~A~%" +bred+ +reset+ e)
            (values nil nil nil)))))))

(defun diagnose-range (trace-dir &key (from 1) (to 10))
  "Run diagnose-block for a range.  Stops at first failure with full diff."
  (loop for b from from to to do
    (handler-case
        (multiple-value-bind (root-ok comp-ok)
            (diagnose-block trace-dir b)
          (when (and root-ok comp-ok)
            (format t "  ~A→ Block ~D: ALL OK~A~%" +green+ b +reset+))
          (unless root-ok
            (format t "~%  ~A→ Stopping at block ~D~A~%" +yellow+ b +reset+)
            (return b)))
      (error (e)
        (format t "  ~ABlock ~D: ERROR~A ~A~%" +bred+ b +reset+ e)
        (return b)))))
