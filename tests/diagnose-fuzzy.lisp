;;;; diagnose-fuzzy.lisp — Deep diagnostic for fuzzy trace divergences
;;;;
;;;; Usage from shell:
;;;;   sbcl --load scripts/load-jotl.lisp --load tests/diagnose-fuzzy.lisp
;;;;
;;;; Or with specific block:
;;;;   TRACE=fuzzy_light BLOCK=10 sbcl --load scripts/load-jotl.lisp --load tests/diagnose-fuzzy.lisp

(in-package #:jotl)

;;; ═══════════════════════════════════════════════════════════════
;;; Configuration
;;; ═══════════════════════════════════════════════════════════════

(defvar *diag-trace* (or (uiop:getenv "TRACE") "fuzzy_light"))
(defvar *diag-block* (let ((b (uiop:getenv "BLOCK")))
                       (if b (parse-integer b) nil)))

(defvar *trace-dir* (format nil "tests/jamtestvectors/traces/~A/" *diag-trace*))

(format t "~%═══ FUZZY DIAGNOSTIC ═══~%")
(format t "Trace: ~A~%" *diag-trace*)
(when *diag-block*
  (format t "Block: ~D~%" *diag-block*))

;;; ═══════════════════════════════════════════════════════════════
;;; Host call name table
;;; ═══════════════════════════════════════════════════════════════

;; Dispatch numbering from crypto/jam-crypto/src/pvm/host_calls.rs
(defparameter +hc-names+
  '((0  . "ΩG gas")      (1  . "ΩY fetch")     (2  . "ΩL lookup")
    (3  . "ΩR read")     (4  . "ΩW write")     (5  . "ΩI info")
    (6  . "ΩH hist-lkp") (7  . "ΩE export")    (8  . "ΩM make-pvm")
    (9  . "ΩP peek-pvm") (10 . "ΩO poke-pvm")  (11 . "ΩZ pages-pvm")
    (12 . "ΩK kick-pvm") (13 . "ΩX expunge")   (14 . "ΩB empower")
    (15 . "ΩA assign")   (16 . "ΩD designate") (17 . "ΩC checkpoint")
    (18 . "ΩN new-svc")  (19 . "ΩU upgrade")   (20 . "ΩT transfer")
    (21 . "ΩJ eject")    (22 . "ΩQ query-pi")  (23 . "ΩS solicit")
    (24 . "ΩF forget")   (25 . "Ωδ yield")     (26 . "Ωp provide-pi")
    (100 . "ext_log")))

(defun hc-name (id)
  (or (cdr (assoc id +hc-names+)) (format nil "HC-~D" id)))

;;; ═══════════════════════════════════════════════════════════════
;;; Per-block diagnostic
;;; ═══════════════════════════════════════════════════════════════

(defun diagnose-one-block (block-num)
  "Run a detailed PVM-level diagnostic for BLOCK-NUM in *trace-dir*."
  (format t "~%─── Block ~D ───~%" block-num)

  (let* ((step-path (trace-block-path *trace-dir* block-num))
         (bytes (alexandria:read-file-into-byte-vector step-path)))
    (multiple-value-bind (pre-sigma block-cl post-sigma pre-root post-root)
        (decode-trace-step-bin bytes)
      (declare (ignore pre-root))

      ;; ── Inspect R* before running ──
      ;; Manually compute what transition-accumulate would see
      (let* ((h     (funcall block-cl :header))
             ;; Get rho state and compute R*
             (rho   (funcall pre-sigma :load :rho))
             (e-a   (funcall block-cl :assurances)))
        (format t "  Header slot: ~D~%" (funcall h :slot))
        (format t "  Extrinsic assurances: ~D~%" (length e-a))
        ;; Show what rho reports
        (let ((rho-dd (handler-case
                          (funcall rho :transition-ddagger
                                   :assurances e-a
                                   :tau-prime (make-tau-state :slot (funcall h :slot))
                                   :parent-hash (funcall h :parent-hash)
                                   :kappa (funcall pre-sigma :load :kappa))
                        (error (e) (format t "  rho-ddagger error: ~A~%" e) nil))))
          (when rho-dd
            (let ((reported (funcall rho-dd :reported)))
              (format t "  R* (reported): ~D reports~%" (length reported))
              (dolist (r reported)
                (let* ((pkg (getf (getf r :package-spec) :hash))
                       (results (getf r :results)))
                  (format t "    pkg=~A results=~D~%"
                          (when pkg (subseq (bytes-to-hex-string pkg) 0 16))
                          (length results))
                  (dolist (w results)
                    (let ((sid   (getf w :service-id))
                          (gas   (getf w :accumulate-gas))
                          (res   (getf w :result)))
                      (format t "      sid=~D gas=~D result-type=~A result-data-len=~A~%"
                              sid gas
                              (cond ((getf res :ok) "Ok")
                                    ((getf res :panic) "Panic")
                                    ((getf res :out-of-gas) "OOG")
                                    (t "?"))
                              (when (getf res :ok)
                                (length (getf res :ok))))))))))))

      ;; ── Pre-state storage for first service in R* ──
      (handler-case
          (let* ((h2      (funcall block-cl :header))
                 (rho2    (funcall pre-sigma :load :rho))
                 (e-a2    (funcall block-cl :assurances))
                 (rho-dd2 (funcall rho2 :transition-ddagger
                                   :assurances e-a2
                                   :tau-prime (make-tau-state :slot (funcall h2 :slot))
                                   :parent-hash (funcall h2 :parent-hash)
                                   :kappa (funcall pre-sigma :load :kappa)))
                 (r-star2 (funcall rho-dd2 :reported))
                 (first-sid (when r-star2
                              (getf (first (getf (first r-star2) :results)) :service-id))))
            (when first-sid
              (let ((svc-data (classify-service-sub-keys first-sid (funcall pre-sigma :extra-kvs))))
                (format t "  Pre-state for sid=~D:~%" first-sid)
                (format t "    metadata: ~A~%"
                        (if (getf svc-data :metadata) "present" "MISSING"))
                (format t "    code-blob: ~A~%"
                        (if (getf svc-data :code-blob)
                            (format nil "~D bytes" (length (getf svc-data :code-blob)))
                            "MISSING"))
                (format t "    storage entries: ~D~%" (length (getf svc-data :storage)))
                (when (getf svc-data :storage)
                  (dolist (s (getf svc-data :storage))
                    (format t "      key(~D)=~A val=~D~%"
                            (length (car s))
                            (bytes-to-hex-string (coerce (car s) '(vector (unsigned-byte 8))))
                            (length (cdr s))))))))
        (error (e) (format t "  Pre-state inspection error: ~A~%" e)))

      ;; ── Run with PVM tracing ──
      (let ((*debug-pvm-trace* t)
            (*debug-pvm-traces* nil)
            (*chain-log-level* nil))

        (multiple-value-bind (sigma-prime computed-root)
            (import-block pre-sigma block-cl)
          (declare (ignore sigma-prime))

          ;; Root match?
          (format t "Root: ~A~%"
                  (if (equalp computed-root post-root) "✓ MATCH" "✗ MISMATCH"))

          ;; ── Show PVM traces ──
          (if (null *debug-pvm-traces*)
              (format t "  No PVM invocations (no R*?)~%")
              (dolist (trace (reverse *debug-pvm-traces*))
                (let ((sid       (getf trace :sid))
                      (gas-limit (getf trace :gas-limit))
                      (gas-used  (getf trace :gas-used))
                      (outcome   (getf trace :outcome))
                      (hclog     (getf trace :host-call-log))
                      (glogs     (getf trace :guest-logs)))

                  (format t "~%  Service ~D: gas=~D used=~D outcome=~A~%"
                          sid gas-limit gas-used
                          (case outcome
                            (0 "Halt") (1 "Panic") (2 "OOG") (3 "Yield")
                            (t (format nil "?~D" outcome))))

                  ;; Host calls — full trace
                  (format t "    Host calls: ~D total~%" (length hclog))
                  (dolist (entry hclog)
                    (destructuring-bind (id gas-before gas-after ret-a0 sc) entry
                      (format t "      ~A  gas=~D→~D  A0=~D  sc=~D~%"
                              (hc-name id) gas-before gas-after ret-a0 sc)))

                  ;; Show yield-specific host call (HC 25)
                  (let ((yield-calls (remove-if-not (lambda (e) (= (first e) 25)) hclog)))
                    (if yield-calls
                        (format t "    *** Ωδ YIELD CALLED ~D times ***~%" (length yield-calls))
                        (format t "    *** Ωδ yield: NOT CALLED ***~%")))

                  ;; Show ΩY fetch calls (kind in A3, but we only have A0 return)
                  (let ((fetch-calls (remove-if-not (lambda (e) (= (first e) 12)) hclog)))
                    (when fetch-calls
                      (format t "    ΩY fetch calls: ~D~%" (length fetch-calls))
                      (dolist (fc fetch-calls)
                        (format t "      gas-before=~D gas-after=~D ret-A0=~D~%"
                                (second fc) (third fc) (fourth fc)))))

                  ;; Guest logs (first 10)
                  (when glogs
                    (format t "    Guest logs (~D):~%" (length glogs))
                    (dolist (g (subseq glogs 0 (min (length glogs) 10)))
                      (format t "      ~A~%" g)))

                  ;; Debug logs (Rust-side ΩI details etc)
                  (let ((dlogs (getf trace :debug-log)))
                    (when dlogs
                      (format t "    Debug logs (~D):~%" (length dlogs))
                      (dolist (d (subseq dlogs 0 (min (length dlogs) 30)))
                        (format t "      ~A~%" d)))))))

          ;; ── Compare theta ──
          (let* ((exp-theta-kv (find-if (lambda (kv)
                                          (and (segment-key-p (car kv))
                                               (= (aref (car kv) 0) 16)))
                                        (funcall post-sigma :merkle-kvs)))
                 (exp-theta-bytes (when exp-theta-kv (cdr exp-theta-kv))))
            (format t "~%  Expected θ: ~A~%"
                    (if (and exp-theta-bytes (plusp (length exp-theta-bytes)))
                        (format nil "~D bytes" (length exp-theta-bytes))
                        "empty"))
            ;; Show commitments from our PVM traces
            (let ((all-yields nil))
              (dolist (trace (reverse *debug-pvm-traces*))
                (when (= (getf trace :outcome) 3)
                  (push (getf trace :sid) all-yields)))
              (format t "  Our yields: ~A~%"
                      (if all-yields
                          (format nil "services ~{~D~^, ~}" (nreverse all-yields))
                          "NONE")))))))))

;;; ═══════════════════════════════════════════════════════════════
;;; Survey: find all failing blocks and categorize
;;; ═══════════════════════════════════════════════════════════════

(defun survey-failures ()
  "Run all blocks in step mode, report failures by category."
  (let* ((max-block (count-trace-blocks *trace-dir*))
         (beta-theta nil)
         (pi-kvs nil)
         (chi-only nil)
         (other nil)
         (pass 0))
    (format t "~%Surveying ~D blocks in ~A ...~%" max-block *diag-trace*)
    (loop for b from 1 to max-block do
      (handler-case
          (let* ((step-path (trace-block-path *trace-dir* b))
                 (step-bytes (alexandria:read-file-into-byte-vector step-path)))
            (multiple-value-bind (pre-sigma block-cl post-sigma pre-root post-root)
                (decode-trace-step-bin step-bytes)
              (declare (ignore pre-root))
              (let ((*chain-log-level* nil))
                (multiple-value-bind (sigma-prime computed-root)
                    (jotl::import-block pre-sigma block-cl)
                  (if (equalp computed-root post-root)
                      (incf pass)
                      ;; Categorize failure
                      (let ((comp-ht (make-hash-table :test 'equalp))
                            (exp-ht  (make-hash-table :test 'equalp))
                            (bad nil))
                        (dolist (kv (funcall sigma-prime :merkle-kvs))
                          (setf (gethash (car kv) comp-ht) (cdr kv)))
                        (dolist (kv (funcall post-sigma :merkle-kvs))
                          (setf (gethash (car kv) exp-ht) (cdr kv)))
                        ;; Check key segments
                        (dolist (entry +sigma-segment-order+)
                          (let* ((kw (car entry))
                                 (cn (cdr entry))
                                 (key (make-array 31 :element-type '(unsigned-byte 8) :initial-element 0)))
                            (setf (aref key 0) cn)
                            (let ((e (gethash key exp-ht))
                                  (g (gethash key comp-ht)))
                              (when (and e g (not (equalp e g)))
                                (push kw bad)))))
                        ;; Check extra-kvs
                        (let ((exp-extra 0) (got-extra 0) (diff 0))
                          (maphash (lambda (k v) (declare (ignore v))
                                     (unless (segment-key-p k)
                                       (incf exp-extra)
                                       (unless (and (gethash k comp-ht)
                                                    (equalp (gethash k comp-ht)
                                                            (gethash k exp-ht)))
                                         (incf diff))))
                                   exp-ht)
                          (maphash (lambda (k v) (declare (ignore v))
                                     (unless (segment-key-p k)
                                       (incf got-extra)
                                       (unless (gethash k exp-ht)
                                         (incf diff))))
                                   comp-ht)
                          (when (plusp diff)
                            (push :delta-kvs bad)))
                        ;; Categorize
                        (cond
                          ((member :theta bad) (push b beta-theta))
                          ((and (member :pi bad) (member :delta-kvs bad))
                           (push b pi-kvs))
                          ((member :chi bad) (push b chi-only))
                          (t (push b other)))))))))
        (error (e)
          (format t "  Block ~D: ERROR ~A~%" b (type-of e)))))

    ;; Summary
    (format t "~%─── Survey Results ───~%")
    (format t "Pass:        ~D/~D~%" pass max-block)
    (format t "beta+theta:  ~D blocks: ~{~D~^ ~}~%" (length beta-theta) (nreverse beta-theta))
    (format t "pi+kvs:      ~D blocks: ~{~D~^ ~}~%" (length pi-kvs) (nreverse pi-kvs))
    (format t "chi-only:    ~D blocks: ~{~D~^ ~}~%" (length chi-only) (nreverse chi-only))
    (format t "other:       ~D blocks: ~{~D~^ ~}~%" (length other) (nreverse other))))

;;; ═══════════════════════════════════════════════════════════════
;;; Main entry
;;; ═══════════════════════════════════════════════════════════════

(if *diag-block*
    (diagnose-one-block *diag-block*)
    (survey-failures))

(format t "~%Done.~%")
(uiop:quit)
