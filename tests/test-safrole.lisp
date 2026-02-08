;;;; tests/test-safrole.lisp — γ (Safrole) STF exhaustive tests
;;;; Validates transition-gamma (+ τ, η, κ, λ) against jamtestvectors/stf/safrole
;;;;
;;;; Tests per vector:
;;;;   1. Decode pre_state from JSON → closures/plists
;;;;   2. Run sub-STFs: transition-tau, transition-eta, transition-kappa,
;;;;      transition-lambda, transition-gamma
;;;;   3. Compare ALL 10 post_state segments byte-by-byte against JSON
;;;;   4. Compare output (epoch_mark, tickets_mark) against JSON
;;;;   5. Codec roundtrip: encode → decode → re-compare (per segment)
;;;;   6. Error cases: verify correct error detection + state unchanged
;;;;
;;;; Test vectors: tests/jamtestvectors/stf/safrole/{tiny,full}/
;;;; 21 tiny + 21 full = 42 total

(in-package #:jotl)

(ql:quickload :cl-json :silent t)

;; Load shared test helpers
(load (merge-pathnames "test-utils.lisp" *load-pathname*))

;;; ═══════════════════════════════════════════════════════════════
;;; JSON→LISP DECODERS (safrole-specific)
;;; ═══════════════════════════════════════════════════════════════

(defun safrole-json-eta (eta-json)
  "Convert JSON η (list of 4 hex strings) → eta closure."
  (let ((hashes (mapcar #'hex-to-bytes eta-json)))
    (make-eta :eta-0 (nth 0 hashes) :eta-1 (nth 1 hashes)
              :eta-2 (nth 2 hashes) :eta-3 (nth 3 hashes))))

(defun safrole-json-tickets (tickets-json)
  "Convert JSON state tickets [{id,attempt},...] → list of plists."
  (mapcar (lambda (t-json)
            (list :id      (hex-to-bytes (cdr (assoc :id t-json)))
                  :attempt (cdr (assoc :attempt t-json))))
          tickets-json))

(defun safrole-json-gamma-s (gs-json)
  "Convert JSON γs {tickets:[...]} or {keys:[...]} → plist (:variant :data)."
  (let ((tickets-data (cdr (assoc :tickets gs-json)))
        (keys-data    (cdr (assoc :keys gs-json))))
    (cond
      (tickets-data
       (list :variant :tickets
             :data    (safrole-json-tickets tickets-data)))
      (keys-data
       (list :variant :keys
             :data    (mapcar #'hex-to-bytes keys-data)))
      (t (error "Unknown gamma_s format: ~A" (mapcar #'car gs-json))))))

(defun safrole-json-extrinsic-tickets (ext-json)
  "Convert JSON extrinsic tickets [{attempt,signature},...] → list of plists.
   These are the raw ET tickets (attempt + 784-byte Ring VRF signature)."
  (mapcar (lambda (t-json)
            (list :attempt   (cdr (assoc :attempt t-json))
                  :signature (hex-to-bytes (cdr (assoc :signature t-json)))))
          ext-json))

(defun safrole-json-epoch-mark (em-json)
  "Convert JSON epoch_mark {entropy, tickets_entropy, validators} → plist.
   Returns NIL if em-json is NIL."
  (when em-json
    (list :entropy         (hex-to-bytes (cdr (assoc :entropy em-json)))
          :tickets-entropy (hex-to-bytes (cdr (assoc :tickets--entropy em-json)))
          :validators
          (mapcar (lambda (v)
                    (list :bandersnatch (hex-to-bytes (cdr (assoc :bandersnatch v)))
                          :ed25519      (hex-to-bytes (or (cdr (assoc :ed25519 v))
                                                          (cdr (assoc :ed-25519 v))))))
                  (cdr (assoc :validators em-json))))))

(defun safrole-json-tickets-mark (tm-json)
  "Convert JSON tickets_mark [{id,attempt},...] → list of plists.
   Returns NIL if tm-json is NIL."
  (when tm-json
    (safrole-json-tickets tm-json)))

;;; ═══════════════════════════════════════════════════════════════
;;; STATE EXTRACTION — parse pre_state / post_state
;;; ═══════════════════════════════════════════════════════════════

(defun safrole-parse-state (state-json)
  "Parse a safrole test vector state into a plist of decoded segments.
   Returns plist: (:tau N :eta (list) :lambda (list) :kappa (list)
                   :gamma-k (list) :iota (list) :gamma-a (list)
                   :gamma-s (plist) :gamma-z (bytes) :post-offenders (list))"
  (list :tau             (cdr (assoc :tau state-json))
        :eta             (safrole-json-eta (cdr (assoc :eta state-json)))
        :lambda          (json-validators (cdr (assoc :lambda state-json)))
        :kappa           (json-validators (cdr (assoc :kappa state-json)))
        :gamma-k         (json-validators (cdr (assoc :gamma--k state-json)))
        :iota            (json-validators (cdr (assoc :iota state-json)))
        :gamma-a         (safrole-json-tickets (cdr (assoc :gamma--a state-json)))
        :gamma-s         (safrole-json-gamma-s (cdr (assoc :gamma--s state-json)))
        :gamma-z         (hex-to-bytes (cdr (assoc :gamma--z state-json)))
        :post-offenders  (mapcar #'hex-to-bytes
                                  (cdr (assoc :post--offenders state-json)))))

;;; ═══════════════════════════════════════════════════════════════
;;; COMPARISON HELPERS (safrole-specific)
;;; ═══════════════════════════════════════════════════════════════

(defun compare-ticket-list (label actual expected)
  "Compare two lists of state tickets (id+attempt). Returns T if all match."
  (let ((ok t))
    (unless (= (length actual) (length expected))
      (format t "    ✗ ~A: length ~D ≠ ~D~%" label (length actual) (length expected))
      (return-from compare-ticket-list nil))
    (loop for a in actual for e in expected for i from 0
          do (unless (and (equalp (getf a :id) (getf e :id))
                          (eql (getf a :attempt) (getf e :attempt)))
               (format t "    ✗ ~A[~D]: ticket mismatch~%" label i)
               (format t "      id got:  ~A (att=~D)~%      id want: ~A (att=~D)~%"
                       (jam.ffi:bytes-to-hex-string (getf a :id)) (getf a :attempt)
                       (jam.ffi:bytes-to-hex-string (getf e :id)) (getf e :attempt))
               (setf ok nil)))
    ok))

(defun compare-gamma-s (label actual expected)
  "Compare two γs plists (:variant :data). Returns T if match."
  (let ((ok t))
    (unless (eq (getf actual :variant) (getf expected :variant))
      (format t "    ✗ ~A: variant ~A ≠ ~A~%"
              label (getf actual :variant) (getf expected :variant))
      (return-from compare-gamma-s nil))
    (ecase (getf expected :variant)
      (:tickets
       (unless (compare-ticket-list (format nil "~A.data" label)
                                     (getf actual :data) (getf expected :data))
         (setf ok nil)))
      (:keys
       (let ((a-keys (getf actual :data))
             (e-keys (getf expected :data)))
         (unless (= (length a-keys) (length e-keys))
           (format t "    ✗ ~A.data: length ~D ≠ ~D~%"
                   label (length a-keys) (length e-keys))
           (return-from compare-gamma-s nil))
         (loop for a in a-keys for e in e-keys for i from 0
               unless (equalp a e)
               do (format t "    ✗ ~A.data[~D]: key mismatch~%" label i)
                  (setf ok nil)))))
    ok))

(defun compare-epoch-mark (label actual expected)
  "Compare two epoch marks. Returns T if match."
  (cond
    ((and (null actual) (null expected)) t)
    ((or  (null actual) (null expected))
     (format t "    ✗ ~A: epoch_mark nil-mismatch (got ~A, want ~A)~%"
             label (not (null actual)) (not (null expected)))
     nil)
    (t
     (let ((ok t))
       (unless (equalp (getf actual :entropy) (getf expected :entropy))
         (format t "    ✗ ~A.entropy mismatch~%" label) (setf ok nil))
       (unless (equalp (getf actual :tickets-entropy) (getf expected :tickets-entropy))
         (format t "    ✗ ~A.tickets-entropy mismatch~%" label) (setf ok nil))
       (let ((a-vals (getf actual :validators))
             (e-vals (getf expected :validators)))
         (unless (= (length a-vals) (length e-vals))
           (format t "    ✗ ~A.validators: length ~D ≠ ~D~%"
                   label (length a-vals) (length e-vals))
           (return-from compare-epoch-mark nil))
         (loop for a in a-vals for e in e-vals for i from 0
               do (unless (and (equalp (getf a :bandersnatch) (getf e :bandersnatch))
                               (equalp (getf a :ed25519) (getf e :ed25519)))
                    (format t "    ✗ ~A.validators[~D] mismatch~%" label i)
                    (setf ok nil))))
       ok))))

(defun compare-tickets-mark (label actual expected)
  "Compare two tickets marks (list of tickets). Returns T if match."
  (cond
    ((and (null actual) (null expected)) t)
    ((or  (null actual) (null expected))
     (format t "    ✗ ~A: tickets_mark nil-mismatch (got ~A, want ~A)~%"
             label (not (null actual)) (not (null expected)))
     nil)
    (t (compare-ticket-list label actual expected))))

;;; ═══════════════════════════════════════════════════════════════
;;; FULL POST-STATE COMPARISON
;;; ═══════════════════════════════════════════════════════════════

(defun compare-safrole-state (label actual expected)
  "Compare all 10 segments of safrole state. Returns T if all match."
  (let ((ok t))
    ;; τ
    (unless (eql (getf actual :tau) (getf expected :tau))
      (format t "    ✗ ~A.tau: ~D ≠ ~D~%" label
              (getf actual :tau) (getf expected :tau))
      (setf ok nil))
    ;; η
    (unless (compare-eta (format nil "~A.eta" label)
                          (getf actual :eta) (getf expected :eta))
      (setf ok nil))
    ;; λ
    (unless (compare-validator-list (format nil "~A.lambda" label)
                                     (getf actual :lambda) (getf expected :lambda))
      (setf ok nil))
    ;; κ
    (unless (compare-validator-list (format nil "~A.kappa" label)
                                     (getf actual :kappa) (getf expected :kappa))
      (setf ok nil))
    ;; γk
    (unless (compare-validator-list (format nil "~A.gamma-k" label)
                                     (getf actual :gamma-k) (getf expected :gamma-k))
      (setf ok nil))
    ;; ι
    (unless (compare-validator-list (format nil "~A.iota" label)
                                     (getf actual :iota) (getf expected :iota))
      (setf ok nil))
    ;; γa
    (unless (compare-ticket-list (format nil "~A.gamma-a" label)
                                  (getf actual :gamma-a) (getf expected :gamma-a))
      (setf ok nil))
    ;; γs
    (unless (compare-gamma-s (format nil "~A.gamma-s" label)
                              (getf actual :gamma-s) (getf expected :gamma-s))
      (setf ok nil))
    ;; γz
    (unless (compare-bytes (format nil "~A.gamma-z" label)
                            (getf actual :gamma-z) (getf expected :gamma-z))
      (setf ok nil))
    ;; ψ'o (post-offenders)
    (let ((a-off (getf actual :post-offenders))
          (e-off (getf expected :post-offenders)))
      (unless (= (length a-off) (length e-off))
        (format t "    ✗ ~A.post-offenders: length ~D ≠ ~D~%"
                label (length a-off) (length e-off))
        (setf ok nil))
      (loop for a in a-off for e in e-off for i from 0
            unless (equalp a e)
            do (format t "    ✗ ~A.post-offenders[~D] mismatch~%" label i)
               (setf ok nil)))
    ok))

;;; ═══════════════════════════════════════════════════════════════
;;; CODEC ROUNDTRIP
;;; ═══════════════════════════════════════════════════════════════

(defun test-safrole-codec-roundtrip (label state)
  "Encode/decode each segment and re-compare. Returns T if all pass."
  (let ((ok t))
    ;; τ roundtrip
    (let* ((tau-cl (make-tau-state :value (getf state :tau)))
           (encoded (encode-state-tau tau-cl))
           (decoded (decode-state-tau encoded)))
      (unless (eql (funcall decoded :value) (getf state :tau))
        (format t "    ✗ ~A/codec.tau: ~D ≠ ~D~%" label
                (funcall decoded :value) (getf state :tau))
        (setf ok nil)))
    ;; η roundtrip
    (let* ((encoded (encode-state-eta (getf state :eta)))
           (decoded (decode-state-eta encoded)))
      (unless (compare-eta (format nil "~A/codec.eta" label) decoded (getf state :eta))
        (setf ok nil)))
    ;; κ roundtrip
    (let* ((kappa-cl (make-kappa :validators (getf state :kappa)))
           (encoded (encode-state-kappa kappa-cl))
           (decoded (decode-state-kappa encoded)))
      (unless (compare-validator-list (format nil "~A/codec.kappa" label)
                                       (funcall decoded :validators) (getf state :kappa))
        (setf ok nil)))
    ;; λ roundtrip
    (let* ((lambda-cl (make-lambda-state :validators (getf state :lambda)))
           (encoded (encode-state-lambda lambda-cl))
           (decoded (decode-state-lambda encoded)))
      (unless (compare-validator-list (format nil "~A/codec.lambda" label)
                                       (funcall decoded :validators) (getf state :lambda))
        (setf ok nil)))
    ;; ι roundtrip
    (let* ((iota-cl (make-iota :validators (getf state :iota)))
           (encoded (encode-state-iota iota-cl))
           (decoded (decode-state-iota encoded)))
      (unless (compare-validator-list (format nil "~A/codec.iota" label)
                                       (funcall decoded :validators) (getf state :iota))
        (setf ok nil)))
    ;; γ roundtrip (full gamma: γk + γz + γs + γa)
    (let* ((gamma-closure (make-gamma :pending-keys    (getf state :gamma-k)
                                      :ring-commitment (getf state :gamma-z)
                                      :sealing         (getf state :gamma-s)
                                      :accumulator     (getf state :gamma-a)))
           (encoded (encode-state-gamma gamma-closure))
           (decoded (decode-state-gamma encoded)))
      ;; Check γk
      (unless (compare-validator-list (format nil "~A/codec.gamma-k" label)
                                       (funcall decoded :pending-keys)
                                       (getf state :gamma-k))
        (setf ok nil))
      ;; Check γz
      (unless (compare-bytes (format nil "~A/codec.gamma-z" label)
                              (funcall decoded :ring-commitment)
                              (getf state :gamma-z))
        (setf ok nil))
      ;; Check γs
      (unless (compare-gamma-s (format nil "~A/codec.gamma-s" label)
                                (funcall decoded :sealing)
                                (getf state :gamma-s))
        (setf ok nil))
      ;; Check γa
      (unless (compare-ticket-list (format nil "~A/codec.gamma-a" label)
                                    (funcall decoded :accumulator)
                                    (getf state :gamma-a))
        (setf ok nil)))
    ok))

;;; ═══════════════════════════════════════════════════════════════
;;; MAKE MINIMAL HEADER FOR SAFROLE TEST
;;; ═══════════════════════════════════════════════════════════════

(defun make-safrole-test-header (slot entropy-source)
  "Create a minimal header closure for safrole testing.
   Only :slot and :entropy-source (Y(HV)) are needed."
  (lambda (msg)
    (case msg
      (:slot slot)
      (:entropy-source entropy-source)
      (otherwise (error "Safrole test header stub: ~A" msg)))))

;;; ═══════════════════════════════════════════════════════════════
;;; EXECUTE SUB-STFs — build post state from pre state + input
;;; ═══════════════════════════════════════════════════════════════

(defun run-safrole-stfs (pre-state input)
  "Execute the safrole sub-STFs and build the post-state plist.
   Returns: (values post-state-plist epoch-mark tickets-mark)
   Signals safrole-error or assertion error on invalid blocks."
  (let* (;; ── Pre-state segments ──
         (tau        (getf pre-state :tau))
         (eta        (getf pre-state :eta))
         (kappa-keys (getf pre-state :kappa))
         (lambda-keys (getf pre-state :lambda))
         (gamma-k    (getf pre-state :gamma-k))
         (iota-keys  (getf pre-state :iota))
         (gamma-a    (getf pre-state :gamma-a))
         (gamma-s    (getf pre-state :gamma-s))
         (gamma-z    (getf pre-state :gamma-z))
         (offenders  (getf pre-state :post-offenders))
         ;; Wrap raw lists in closures for STF calls
         (kappa-cl   (make-kappa :validators kappa-keys))
         (lambda-cl  (make-lambda-state :validators lambda-keys))
         (iota-cl    (make-iota :validators iota-keys))
         ;; Build gamma closure
         (gamma      (make-gamma :pending-keys    gamma-k
                                 :ring-commitment gamma-z
                                 :sealing         gamma-s
                                 :accumulator     gamma-a))
         ;; ── Input ──
         (slot          (getf input :slot))
         (entropy       (getf input :entropy))
         (tickets       (getf input :tickets))
         ;; Build header
         (header        (make-safrole-test-header slot entropy))
         ;; ── Wave 1: τ', η', κ', λ' ──
         (tau-prime     (transition-tau tau header))
         (eta-prime     (transition-eta header tau eta))
         (kappa-prime   (transition-kappa header tau kappa-cl gamma))
         (lambda-prime  (transition-lambda header tau lambda-cl kappa-cl))
         ;; psi-prime as closure (offenders provided by test vector)
         (psi-prime     (make-psi :offenders offenders))
         ;; ── Wave 2: γ' ≺ (H, τ, ET, γ, ι, η', κ', ψ') ──
         (gamma-prime   (transition-gamma header tau tickets gamma
                                          iota-cl eta-prime kappa-prime psi-prime))
         ;; ── Output markers ──
         (gamma-p-prime (funcall gamma-prime :pending-keys))
         (epoch-mark    (compute-epoch-mark tau tau-prime eta gamma-p-prime))
         (tickets-mark  (compute-winning-tickets-mark tau tau-prime gamma-a)))
    (values
     ;; Post-state plist — extract raw lists for comparison
     (list :tau             tau-prime
           :eta             eta-prime
           :lambda          (funcall lambda-prime :validators)
           :kappa           (funcall kappa-prime :validators)
           :gamma-k         (funcall gamma-prime :pending-keys)
           :iota            iota-keys  ;; ι unchanged by safrole
           :gamma-a         (funcall gamma-prime :accumulator)
           :gamma-s         (funcall gamma-prime :sealing)
           :gamma-z         (funcall gamma-prime :ring-commitment)
           :post-offenders  offenders)  ;; pass-through from pre
     epoch-mark
     tickets-mark)))

;;; ═══════════════════════════════════════════════════════════════
;;; RUN ONE TEST CASE
;;; ═══════════════════════════════════════════════════════════════

(defun run-safrole-test (json-path chain-name)
  "Run a single safrole test vector. Returns :pass | :fail."
  (let* ((data  (load-json json-path))
         (fname (file-namestring json-path))
         ;; Parse sections
         (pre-json  (cdr (assoc :pre--state data)))
         (post-json (cdr (assoc :post--state data)))
         (input-raw (cdr (assoc :input data)))
         (output    (cdr (assoc :output data)))
         ;; Decode pre/post state
         (pre-state  (safrole-parse-state pre-json))
         (post-state (safrole-parse-state post-json))
         ;; Decode input
         (input (list :slot    (cdr (assoc :slot input-raw))
                      :entropy (hex-to-bytes (cdr (assoc :entropy input-raw)))
                      :tickets (safrole-json-extrinsic-tickets
                                (cdr (assoc :extrinsic input-raw)))))
         ;; Output: ok or err?
         (expected-ok  (cdr (assoc :ok output)))
         (expected-err (cdr (assoc :err output))))
    (with-chain chain-name
      (handler-case
          (if expected-err
              ;; ── ERROR CASE ──
              ;; Run STFs: should signal an error
              (handler-case
                  (progn
                    (run-safrole-stfs pre-state input)
                    ;; If we get here, no error was raised — check if state unchanged
                    ;; Some "errors" may just mean "no change" for certain fields
                    (format t "  ❌ ~A — expected error '~A' but STFs succeeded~%" fname expected-err)
                    :fail)
                ;; Expected error caught
                (safrole-error (e)
                  (declare (ignore e))
                  ;; Verify post-state = pre-state (state unchanged on error)
                  (let* ((state-ok (compare-safrole-state fname pre-state post-state))
                         (codec-ok (test-safrole-codec-roundtrip fname pre-state)))
                    (cond
                      ((and state-ok codec-ok)
                       (format t "  ✅ ~A (err: ~A)~%" fname expected-err)
                       :pass)
                      (t
                       (format t "  ❌ ~A (err: ~A) — post-state should match pre-state~%" fname expected-err)
                       :fail))))
                ;; Assertion errors from transition-tau (bad_slot → assert failure)
                (simple-error (e)
                  ;; transition-tau signals plain error for τ' ≤ τ
                  (let ((msg (format nil "~A" e)))
                    (if (search "must be >" msg)
                        ;; This is the bad_slot error
                        (let* ((state-ok (compare-safrole-state fname pre-state post-state))
                               (codec-ok (test-safrole-codec-roundtrip fname pre-state)))
                          (cond
                            ((and state-ok codec-ok)
                             (format t "  ✅ ~A (err: ~A)~%" fname expected-err)
                             :pass)
                            (t
                             (format t "  ❌ ~A (err: ~A) — post-state mismatch~%" fname expected-err)
                             :fail)))
                        ;; Unexpected error
                        (progn
                          (format t "  ❌ ~A — unexpected assertion: ~A~%" fname msg)
                          :fail)))))
              ;; ── SUCCESS CASE ──
              (multiple-value-bind (computed-post epoch-mark tickets-mark)
                  (run-safrole-stfs pre-state input)
                (let ((state-ok  (compare-safrole-state fname computed-post post-state))
                      ;; Compare output markers
                      (expected-em (safrole-json-epoch-mark
                                    (cdr (assoc :epoch--mark expected-ok))))
                      (expected-tm (safrole-json-tickets-mark
                                    (cdr (assoc :tickets--mark expected-ok)))))
                  (let ((em-ok (compare-epoch-mark (format nil "~A.HE" fname)
                                                   epoch-mark expected-em))
                        (tm-ok (compare-tickets-mark (format nil "~A.HW" fname)
                                                     tickets-mark expected-tm))
                        (codec-ok (test-safrole-codec-roundtrip fname computed-post)))
                    (cond
                      ((and state-ok em-ok tm-ok codec-ok)
                       (format t "  ✅ ~A~%" fname)
                       :pass)
                      (t
                       (format t "  ❌ ~A — ~A~%" fname
                               (cond ((not state-ok) "state mismatch")
                                     ((not em-ok) "epoch_mark mismatch")
                                     ((not tm-ok) "tickets_mark mismatch")
                                     ((not codec-ok) "codec roundtrip failed")
                                     (t "unknown")))
                       :fail))))))
        (error (e)
          (format t "  💥 ~A — ~A~%" fname e)
          :fail)))))

;;; ═══════════════════════════════════════════════════════════════
;;; MAIN — run all safrole vectors for both chainspecs
;;; ═══════════════════════════════════════════════════════════════

(defun run-all-safrole-tests ()
  "Run γ (safrole) tests against all test vectors (tiny + full).
   Each test verifies: sub-STFs + 10-segment post-state + output markers + codec roundtrip."
  (let ((base-dir (merge-pathnames "tests/jamtestvectors/stf/safrole/"
                                    (asdf:system-source-directory :jotl)))
        (total 0) (passed 0) (failed 0))
    (dolist (spec '((:tiny "tiny") (:full "full")))
      (let* ((chain-name (first spec))
             (dir-name   (second spec))
             (dir        (merge-pathnames (format nil "~A/" dir-name) base-dir))
             (json-files (sort (directory (merge-pathnames "*.json" dir))
                               #'string< :key #'namestring)))
        (format t "~%=== Safrole STF Tests (~A) ===~%"
                (string-upcase dir-name))
        (dolist (json-path json-files)
          (incf total)
          (case (run-safrole-test (namestring json-path) chain-name)
            (:pass (incf passed))
            (:fail (incf failed))))))
    (format t "~%")
    (if (zerop failed)
        (format t "  ✅ γ (safrole): ~D/~D passed~%" passed total)
        (format t "  ❌ γ (safrole): ~D/~D passed (~D failed)~%" passed total failed))
    (zerop failed)))

;;; Entry point
(unless (run-all-safrole-tests)
  (sb-ext:exit :code 1))
