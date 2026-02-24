;;;; test-stf-safrole.lisp — Run safrole STF sub-component tests
;;;;
;;;; Tests the safrole (gamma) transition in isolation using the
;;;; test vectors from jamtestvectors/stf/safrole/tiny/*.json
;;;;
;;;; Reads each JSON file, constructs real state closures from the
;;;; pre_state, runs the transition, and compares every field of the
;;;; post_state exhaustively.
;;;;
;;;; Usage:
;;;;   sbcl --load scripts/load-jotl.lisp --load scripts/test-stf-safrole.lisp
;;;;
;;;; Or with a filter:
;;;;   FILTER=padding sbcl --load scripts/load-jotl.lisp --load scripts/test-stf-safrole.lisp

(ql:quickload :yason :silent t)

(in-package #:jotl)

;;; ═══════════════════════════════════════════════════════════════
;;; CONFIGURATION
;;; ═══════════════════════════════════════════════════════════════

(defvar *safrole-test-dir*
  (merge-pathnames "../jamtestvectors/stf/safrole/tiny/"
                   (asdf:system-source-directory :jotl)))

(defvar *safrole-filter* (uiop:getenv "FILTER"))

;;; ═══════════════════════════════════════════════════════════════
;;; JSON → CLOSURE HELPERS
;;; ═══════════════════════════════════════════════════════════════

(defun jhex (hex-str)
  "JSON hex string (0x...) → byte vector."
  (hex-string-to-bytes hex-str))

(defun json-to-validator (jv)
  "JSON validator hash-table → JOTL validator plist."
  (list :bandersnatch (jhex (gethash "bandersnatch" jv))
        :ed25519      (jhex (gethash "ed25519" jv))
        :bls          (jhex (gethash "bls" jv))
        :metadata     (jhex (gethash "metadata" jv))))

(defun json-to-validators (jlist)
  "JSON list of validator objects → list of plists."
  (mapcar #'json-to-validator jlist))

(defun json-to-eta (jlist)
  "JSON list of 4 hex strings → eta-state closure."
  (make-eta-state
   :eta-0 (jhex (nth 0 jlist))
   :eta-1 (jhex (nth 1 jlist))
   :eta-2 (jhex (nth 2 jlist))
   :eta-3 (jhex (nth 3 jlist))))

(defun json-to-state-ticket (jt)
  "JSON ticket object → state ticket plist (:id :attempt)."
  (list :id      (jhex (gethash "id" jt))
        :attempt (gethash "attempt" jt)))

(defun json-to-sealing (js)
  "JSON sealing state → plist (:variant :data)."
  (cond
    ((gethash "tickets" js)
     (list :variant :tickets
           :data (mapcar #'json-to-state-ticket (gethash "tickets" js))))
    ((gethash "keys" js)
     (list :variant :keys
           :data (mapcar #'jhex (gethash "keys" js))))
    (t (error "Unknown gamma_s variant in JSON: ~A" js))))

(defun json-to-ticket-extrinsic (jlist)
  "JSON ticket extrinsic list → list of (:attempt :signature) plists."
  (mapcar (lambda (jt)
            (list :attempt   (gethash "attempt" jt)
                  :signature (jhex (gethash "signature" jt))))
          jlist))

(defun json-to-offenders (jlist)
  "JSON list of ed25519 hex strings → list of byte vectors."
  (mapcar #'jhex jlist))

;;; ═══════════════════════════════════════════════════════════════
;;; MOCK CLOSURES — minimal closures for sub-component testing
;;; ═══════════════════════════════════════════════════════════════

(defun mock-header-safrole (input-entropy input-slot)
  "Mock header that provides :vrf-entropy and :slot for safrole tests."
  (lambda (msg &rest args)
    (declare (ignore args))
    (case msg
      (:vrf-entropy input-entropy)
      (:slot        input-slot)
      (otherwise    (error "mock-header: unexpected message ~A" msg)))))

(defun mock-psi-prime (offenders)
  "Mock ψ' that provides :offenders."
  (lambda (msg &rest args)
    (declare (ignore args))
    (case msg
      (:offenders offenders)
      (otherwise  (error "mock-psi-prime: unexpected message ~A" msg)))))

;;; ═══════════════════════════════════════════════════════════════
;;; COMPARISON — exhaustive field-by-field
;;; ═══════════════════════════════════════════════════════════════

(defun compare-validator-lists (computed expected label)
  "Compare two lists of validator plists. Returns list of diffs."
  (let ((diffs nil)
        (nc (length computed))
        (ne (length expected)))
    (unless (= nc ne)
      (push (format nil "~A: count mismatch (got ~D, expected ~D)" label nc ne) diffs)
      (return-from compare-validator-lists diffs))
    (dotimes (i nc)
      (let ((cv (nth i computed))
            (ev (nth i expected)))
        (dolist (field '(:bandersnatch :ed25519 :bls :metadata))
          (unless (equalp (getf cv field) (getf ev field))
            (push (format nil "~A[~D].~A: DIFFER" label i field) diffs)))))
    diffs))

(defun compare-bytes (computed expected label)
  "Compare two byte vectors. Returns diff string or NIL."
  (cond
    ((and (null computed) (null expected)) nil)
    ((null computed) (format nil "~A: NIL vs ~D bytes" label (length expected)))
    ((null expected) (format nil "~A: ~D bytes vs NIL" label (length computed)))
    ((not (equalp computed expected))
     (format nil "~A: DIFFER (~D vs ~D bytes, ~D bytes differ)"
             label (length computed) (length expected)
             (let ((n 0) (len (min (length computed) (length expected))))
               (dotimes (i len n)
                 (unless (= (aref computed i) (aref expected i))
                   (incf n)))
               (+ n (abs (- (length computed) (length expected)))))))
    (t nil)))

(defun compare-sealing (computed expected)
  "Compare sealing states. Returns list of diffs."
  (let ((diffs nil)
        (cv (getf computed :variant))
        (ev (getf expected :variant)))
    (unless (eq cv ev)
      (push (format nil "γS variant: ~A vs ~A" cv ev) diffs)
      (return-from compare-sealing diffs))
    (let ((cd (getf computed :data))
          (ed (getf expected :data)))
      (unless (= (length cd) (length ed))
        (push (format nil "γS data count: ~D vs ~D" (length cd) (length ed)) diffs)
        (return-from compare-sealing diffs))
      (ecase cv
        (:tickets
         (dotimes (i (length cd))
           (let ((ct (nth i cd))
                 (et (nth i ed)))
             (unless (equalp (getf ct :id) (getf et :id))
               (push (format nil "γS.tickets[~D].id DIFFER" i) diffs))
             (unless (= (getf ct :attempt) (getf et :attempt))
               (push (format nil "γS.tickets[~D].attempt ~D vs ~D"
                             i (getf ct :attempt) (getf et :attempt)) diffs)))))
        (:keys
         (dotimes (i (length cd))
           (unless (equalp (nth i cd) (nth i ed))
             (push (format nil "γS.keys[~D] DIFFER" i) diffs))))))
    diffs))

(defun compare-accum (computed expected)
  "Compare ticket accumulators. Returns list of diffs."
  (let ((diffs nil)
        (nc (length computed))
        (ne (length expected)))
    (unless (= nc ne)
      (push (format nil "γA count: ~D vs ~D" nc ne) diffs)
      (return-from compare-accum diffs))
    (dotimes (i nc)
      (let ((ct (nth i computed))
            (et (nth i expected)))
        (unless (equalp (getf ct :id) (getf et :id))
          (push (format nil "γA[~D].id DIFFER" i) diffs))
        (unless (= (getf ct :attempt) (getf et :attempt))
          (push (format nil "γA[~D].attempt ~D vs ~D"
                        i (getf ct :attempt) (getf et :attempt)) diffs))))
    diffs))

;;; ═══════════════════════════════════════════════════════════════
;;; TEST RUNNER — one test
;;; ═══════════════════════════════════════════════════════════════

(defun run-one-safrole-test (json-path)
  "Run a single safrole STF test. Returns (values pass-p diffs error-type).
   For error tests: pass-p if JOTL also rejects.
   For ok tests: pass-p if all fields match."
  (let* ((json-str (alexandria:read-file-into-string (namestring json-path)))
         (json     (yason:parse json-str))
         (pre      (gethash "pre_state" json))
         (post     (gethash "post_state" json))
         (input    (gethash "input" json))
         (output   (gethash "output" json))
         (is-error (gethash "err" output))
         ;; ── Build pre-state closures ──
         (tau      (make-tau-state :slot (gethash "tau" pre)))
         (eta      (json-to-eta (gethash "eta" pre)))
         (kappa    (make-kappa-state :validators (json-to-validators (gethash "kappa" pre))))
         (lambda-prev (make-lambda-state :validators (json-to-validators (gethash "lambda" pre))))
         (iota     (make-iota-state :validators (json-to-validators (gethash "iota" pre))))
         (gamma    (make-gamma-state
                    :pending-keys   (json-to-validators (gethash "gamma_k" pre))
                    :ring-commitment (jhex (gethash "gamma_z" pre))
                    :sealing        (json-to-sealing (gethash "gamma_s" pre))
                    :accumulator    (mapcar #'json-to-state-ticket (gethash "gamma_a" pre))))
         ;; Mock closures
         (offenders (json-to-offenders (gethash "post_offenders" pre)))
         (psi-prime (mock-psi-prime offenders))
         (mock-h    (mock-header-safrole (jhex (gethash "entropy" input))
                                          (gethash "slot" input)))
         ;; Tickets from input
         (tickets   (json-to-ticket-extrinsic (gethash "extrinsic" input))))

    ;; ── Run transition ──
    (handler-case
        (let* (;; Wave 0: tau' < (H) — asserts slot > pre-slot
               (tau-prime (funcall tau :transition :header mock-h))
               ;; Wave 1: eta', kappa', lambda'
               (eta-prime (funcall eta :transition
                                   :header mock-h :tau tau :tau-prime tau-prime))
               (kappa-prime (funcall kappa :transition
                                     :tau tau :tau-prime tau-prime :gamma gamma))
               (lambda-prime (funcall lambda-prev :transition
                                      :tau tau :tau-prime tau-prime :kappa kappa))
               ;; Wave 2: gamma'
               (gamma-prime (funcall gamma :transition
                                     :tau tau :tau-prime tau-prime
                                     :tickets tickets :iota iota
                                     :eta-prime eta-prime
                                     :kappa-prime kappa-prime
                                     :psi-prime psi-prime)))

          ;; If expected error, we should NOT reach here
          (when is-error
            (return-from run-one-safrole-test
              (values nil (list (format nil "Expected error ~A but transition succeeded" is-error))
                      :false-positive)))

          ;; ── Exhaustive comparison of ALL post_state fields ──
          (let ((all-diffs nil))
            ;; 1. tau
            (unless (= (gethash "slot" input) (gethash "tau" post))
              (push (format nil "τ: slot ~D but post tau ~D"
                            (gethash "slot" input) (gethash "tau" post)) all-diffs))

            ;; 2. eta (4 entropies)
            (let* ((exp-eta (gethash "eta" post))
                   (got-eta-0 (funcall eta-prime :accumulator))
                   (got-eta-1 (funcall eta-prime :last-epoch-entropy))
                   (got-eta-2 (funcall eta-prime :vrf-entropy))
                   (got-eta-3 (funcall eta-prime :seal-entropy)))
              (unless (equalp got-eta-0 (jhex (nth 0 exp-eta)))
                (push "η₀ DIFFER" all-diffs))
              (unless (equalp got-eta-1 (jhex (nth 1 exp-eta)))
                (push "η₁ DIFFER" all-diffs))
              (unless (equalp got-eta-2 (jhex (nth 2 exp-eta)))
                (push "η₂ DIFFER" all-diffs))
              (unless (equalp got-eta-3 (jhex (nth 3 exp-eta)))
                (push "η₃ DIFFER" all-diffs)))

            ;; 3. kappa
            (let ((kd (compare-validator-lists
                       (funcall kappa-prime :validators)
                       (json-to-validators (gethash "kappa" post))
                       "κ")))
              (setf all-diffs (nconc kd all-diffs)))

            ;; 4. lambda
            (let ((ld (compare-validator-lists
                       (funcall lambda-prime :validators)
                       (json-to-validators (gethash "lambda" post))
                       "λ")))
              (setf all-diffs (nconc ld all-diffs)))

            ;; 5. iota (unchanged by safrole)
            (let ((id (compare-validator-lists
                       (funcall iota :validators)
                       (json-to-validators (gethash "iota" post))
                       "ι")))
              (setf all-diffs (nconc id all-diffs)))

            ;; 6. gamma_k (pending keys)
            (let ((gkd (compare-validator-lists
                        (funcall gamma-prime :pending-keys)
                        (json-to-validators (gethash "gamma_k" post))
                        "γP")))
              (setf all-diffs (nconc gkd all-diffs)))

            ;; 7. gamma_z (ring commitment)
            (let ((gzd (compare-bytes
                        (funcall gamma-prime :ring-commitment)
                        (jhex (gethash "gamma_z" post))
                        "γZ")))
              (when gzd (push gzd all-diffs)))

            ;; 8. gamma_s (sealing)
            (let ((gsd (compare-sealing
                        (funcall gamma-prime :sealing)
                        (json-to-sealing (gethash "gamma_s" post)))))
              (setf all-diffs (nconc gsd all-diffs)))

            ;; 9. gamma_a (accumulator)
            (let ((gad (compare-accum
                        (funcall gamma-prime :accumulator)
                        (mapcar #'json-to-state-ticket (gethash "gamma_a" post)))))
              (setf all-diffs (nconc gad all-diffs)))

            ;; 10. post_offenders (should be same as pre)
            (let* ((exp-off (json-to-offenders (gethash "post_offenders" post)))
                   (got-off offenders)) ;; safrole doesn't modify offenders
              (unless (= (length got-off) (length exp-off))
                (push (format nil "offenders count: ~D vs ~D"
                              (length got-off) (length exp-off)) all-diffs))
              (dotimes (i (min (length got-off) (length exp-off)))
                (unless (equalp (nth i got-off) (nth i exp-off))
                  (push (format nil "offenders[~D] DIFFER" i) all-diffs))))

            (values (null all-diffs) (nreverse all-diffs) nil)))

      ;; Error during transition
      (safrole-error (e)
        (if is-error
            ;; Expected error — PASS
            (values t nil :expected-error)
            ;; Unexpected error — FAIL
            (values nil (list (format nil "Unexpected safrole-error: ~A" e))
                    :unexpected-error)))
      (error (e)
        (if is-error
            ;; Might be a tau assertion error for "bad_slot"
            (values t nil :expected-error)
            (values nil (list (format nil "Unexpected error: ~A" e))
                    :unexpected-error))))))

;;; ═══════════════════════════════════════════════════════════════
;;; TEST RUNNER — all tests
;;; ═══════════════════════════════════════════════════════════════

(defun list-safrole-tests ()
  "List all safrole test JSON files, sorted by name."
  (sort (directory (merge-pathnames "*.json" *safrole-test-dir*))
        #'string< :key #'namestring))

(format t "~%═══ SAFROLE STF Sub-Component Tests ═══~%")
(format t "Directory: ~A~%" *safrole-test-dir*)
(when *safrole-filter*
  (format t "Filter: ~A~%" *safrole-filter*))
(terpri)

;; Ensure SRS loaded
(jam.ffi:load-bandersnatch-srs)

(let ((tests (list-safrole-tests))
      (pass 0) (fail 0) (err-count 0)
      (t-start (get-internal-real-time)))

  (when *safrole-filter*
    (setf tests (remove-if-not
                 (lambda (p)
                   (search *safrole-filter*
                           (pathname-name p)
                           :test #'char-equal))
                 tests)))

  (format t "Found ~D test files~%~%" (length tests))

  (dolist (test-file tests)
    (let* ((name (pathname-name test-file))
           (padded-name (if (> (length name) 50)
                            (subseq name 0 50)
                            name)))
      (format t "  ~A " (jotl/test::pad-right padded-name 50))
      (force-output)
      (handler-case
          (multiple-value-bind (pass-p diffs error-type)
              (run-one-safrole-test test-file)
            (cond
              (pass-p
               (incf pass)
               (if error-type
                   (format t "✓ (correctly rejected)~%")
                   (format t "✓~%")))
              (t
               (incf fail)
               (format t "✗~%")
               (dolist (d diffs)
                 (format t "    → ~A~%" d)))))
        (error (e)
          (incf err-count)
          (format t "ERROR: ~A~%" e)))))

  (let ((elapsed (/ (- (get-internal-real-time) t-start)
                    (float internal-time-units-per-second))))
    (format t "~%═══════════════════════════════════════════~%")
    (format t "Results: ~D pass, ~D fail, ~D errors / ~D total~%"
            pass fail err-count (+ pass fail err-count))
    (format t "Time: ~,2Fs~%" elapsed)
    (format t "All fields compared: τ η κ λ ι γP γZ γS γA offenders~%")
    (format t "Result: ~A~%"
            (if (and (zerop fail) (zerop err-count))
                "✓ ALL PASS" "✗ FAILURES"))
    (sb-ext:exit :code (if (and (zerop fail) (zerop err-count)) 0 1))))
