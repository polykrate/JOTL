;;;; stf/psi.lisp — ψ (Judgments) & ρ† (Disputes → Assignments)
;;;; Gray Paper §10
;;;;
;;;; Disputes STF:
;;;;   transition-psi(ED, ψ, τ, κ, λ) → ψ'
;;;;   transition-rho-dagger(ED, ρ) → ρ†
;;;;
;;;; ψ = (good, bad, wonky, offenders)
;;;;   good     — set of work-report hashes judged valid
;;;;   bad      — set of work-report hashes judged invalid
;;;;   wonky    — set of work-report hashes with mixed votes
;;;;   offenders — set of Ed25519 keys banned from validator set
;;;;
;;;; ED = (verdicts, culprits, faults)
;;;;   verdict  — (target: H, age: u32, votes: [(vote: bool, index: u16, sig: [64])])
;;;;   culprit  — (target: H, key: H, sig: [64])     — guarantor who backed a bad report
;;;;   fault    — (target: H, vote: bool, key: H, sig: [64]) — auditor who voted wrong

(in-package #:jotl)

;;; ═════════════════════════════════════════════════════════════════
;;; CONSTANTS
;;; ═════════════════════════════════════════════════════════════════

(defun super-majority ()
  "⌊2V/3⌋ + 1 — quorum for verdicts. GP §10."
  (1+ (floor (* 2 (num-validators)) 3)))

;;; ═════════════════════════════════════════════════════════════════
;;; HELPERS
;;; ═════════════════════════════════════════════════════════════════

(defun hash< (a b)
  "Lexicographic comparison of two 32-byte hashes."
  (loop for i from 0 below 32
        when (< (aref a i) (aref b i)) return t
        when (> (aref a i) (aref b i)) return nil
        finally (return nil)))

(defun sorted-unique-p (list key-fn cmp-fn)
  "Check that LIST is strictly sorted by KEY-FN using CMP-FN.
   i.e. for all consecutive pairs (a, b): (funcall cmp-fn (funcall key-fn a) (funcall key-fn b))."
  (loop for (a b) on list
        while b
        always (funcall cmp-fn (funcall key-fn a) (funcall key-fn b))))

(defun member-hash (hash hash-list)
  "Check if HASH (byte-array) is in HASH-LIST (list of byte-arrays)."
  (some (lambda (h) (equalp hash h)) hash-list))

(defun classify-verdict (verdict)
  "Classify a verdict based on its vote split.
   Returns: :good | :bad | :wonky

   GP §10: A verdict is:
     good  — ⌊2V/3⌋+1 or more positive votes (all/most say valid)
     bad   — ⌊2V/3⌋+1 or more negative votes (all/most say invalid)
     wonky — neither super-majority (mixed, but enough to form verdict)"
  ;; STUB — TODO: count positive/negative votes, apply thresholds
  (let* ((votes (getf verdict :votes))
         (positive (count-if (lambda (v) (getf v :vote)) votes))
         (negative (- (length votes) positive))
         (threshold (super-majority)))
    (cond
      ((>= positive threshold) :good)
      ((>= negative threshold) :bad)
      (t :wonky))))

(defun verdict-signing-context (target vote)
  "Construct the signing context (message) for a judgment signature.
   GP §10: The message signed is a context-dependent hash.

   Args: target (H, 32 bytes), vote (boolean)
   Returns: byte array (the message that was signed)"
  ;; STUB — TODO: GP §10 equation for judgment signing context
  ;; $jam_valid or $jam_invalid ++ target
  (declare (ignore vote))
  target)

(defun validator-ed25519-key (index age kappa lambda-prev)
  "Get the Ed25519 key for validator at INDEX.
   age=0 → use κ (current epoch), age=1 → use λ (previous epoch).

   GP §10: ke = κ[v]_e if age=0, λ[v]_e if age=1
   Returns: 32-byte Ed25519 public key, or NIL if invalid."
  ;; STUB — TODO: extract :ed25519 from validator record at index
  (let ((validators (if (= age 0) kappa lambda-prev)))
    (when (and validators (< index (length validators)))
      (let ((validator (nth index validators)))
        ;; Validator is a plist with :ed25519 and :bandersnatch
        (getf validator :ed25519)))))

;;; ═════════════════════════════════════════════════════════════════
;;; VALIDATION — §10 equations, one per function
;;; ═════════════════════════════════════════════════════════════════
;;; Each returns T on success, or signals a DISPUTES-ERROR condition.

(define-condition disputes-error (error)
  ((code :initarg :code :reader disputes-error-code)
   (detail :initarg :detail :reader disputes-error-detail :initform nil))
  (:report (lambda (c s)
             (format s "Disputes error: ~A~@[ — ~A~]"
                     (disputes-error-code c) (disputes-error-detail c)))))

(defun reject-disputes (code &optional detail)
  "Signal a disputes validation error."
  (error 'disputes-error :code code :detail detail))

;;; ----- Verdicts Validation -----

(defun validate-verdicts-sorted-unique (verdicts)
  "GP §10: Verdicts must be sorted and unique by target hash.
   Error: verdicts_not_sorted_unique"
  ;; STUB — TODO: check sorted-unique-p on :target
  (unless (or (null verdicts)
              (sorted-unique-p verdicts
                               (lambda (v) (getf v :target))
                               #'hash<))
    (reject-disputes :verdicts-not-sorted-unique)))

(defun validate-judgements-sorted-unique (verdict)
  "GP §10: Votes within a verdict must be sorted and unique by index.
   Error: judgements_not_sorted_unique"
  ;; STUB — TODO: check sorted-unique-p on :index within votes
  (let ((votes (getf verdict :votes)))
    (unless (or (null votes)
                (sorted-unique-p votes
                                 (lambda (v) (getf v :index))
                                 #'<))
      (reject-disputes :judgements-not-sorted-unique))))

(defun validate-judgement-age (verdict tau)
  "GP §10: Verdict age must be 0 (current validators) or 1 (previous).
   Error: bad_judgement_age"
  ;; STUB — TODO: check age validity against current epoch
  (declare (ignore tau))
  (let ((age (getf verdict :age)))
    (unless (member age '(0 1))
      (reject-disputes :bad-judgement-age
                       (format nil "age=~A" age)))))

(defun validate-vote-split (verdict)
  "GP §10: Vote count must reach super-majority for good/bad.
   Wonky = sufficient to form verdict but not super-majority on either side.
   Error: bad_vote_split"
  ;; STUB — TODO: check that total votes = ⌊2V/3⌋+1
  ;; and that the split is valid
  (let* ((votes (getf verdict :votes))
         (expected-count (super-majority)))
    (unless (= (length votes) expected-count)
      (reject-disputes :bad-vote-split
                       (format nil "expected ~A votes, got ~A"
                               expected-count (length votes))))))

(defun validate-verdict-not-already-judged (verdict psi)
  "GP §10: Target must not already be in ψ.good ∪ ψ.bad ∪ ψ.wonky.
   Error: already_judged"
  ;; STUB — TODO: check target against existing judgments
  (let ((target (getf verdict :target))
        (good (getf psi :good))
        (bad (getf psi :bad))
        (wonky (getf psi :wonky)))
    (when (or (member-hash target good)
              (member-hash target bad)
              (member-hash target wonky))
      (reject-disputes :already-judged))))

(defun validate-verdict-signatures (verdict age kappa lambda-prev)
  "GP §10: Each vote's Ed25519 signature must verify.
   Error: bad_signature"
  ;; STUB — TODO: for each vote, verify ed25519 signature
  ;; message = verdict-signing-context(target, vote)
  ;; key = validator-ed25519-key(index, age, kappa, lambda)
  (let ((target (getf verdict :target)))
    (dolist (vote (getf verdict :votes))
      (let* ((index (getf vote :index))
             (vote-bool (getf vote :vote))
             (signature (getf vote :signature))
             (key (validator-ed25519-key index age kappa lambda-prev))
             (message (verdict-signing-context target vote-bool)))
        (declare (ignore message signature key))
        ;; STUB — TODO: actually verify
        ;; (unless (ed25519-verify key message signature)
        ;;   (reject-disputes :bad-signature))
        nil))))

;;; ----- Culprits Validation -----

(defun validate-culprits-sorted-unique (culprits)
  "GP §10: Culprits must be sorted and unique by (target, key).
   Error: culprits_not_sorted_unique"
  ;; STUB — TODO: check sorted-unique on composite key
  (declare (ignore culprits))
  t)

(defun validate-culprit-verdict-is-bad (culprit classified-verdicts)
  "GP §10: A culprit's target must reference a bad verdict.
   Error: culprits_verdict_not_bad"
  ;; STUB — TODO: check that culprit :target is in bad verdicts
  (declare (ignore culprit classified-verdicts))
  t)

(defun validate-culprit-not-already-offender (culprit psi)
  "GP §10: Culprit key must not already be in ψ.offenders.
   Error: offender_already_reported"
  ;; STUB — TODO: check against existing offenders
  (declare (ignore culprit psi))
  t)

(defun validate-culprit-key (culprit kappa lambda-prev)
  "GP §10: Culprit key must be a known guarantor key.
   Error: bad_guarantor_key"
  ;; STUB — TODO: check key is in validator set
  (declare (ignore culprit kappa lambda-prev))
  t)

(defun validate-culprit-signature (culprit)
  "GP §10: Culprit's guarantee signature must verify.
   Error: bad_signature"
  ;; STUB — TODO: verify ed25519 signature on guarantee
  (declare (ignore culprit))
  t)

(defun validate-enough-culprits (bad-verdicts culprits)
  "GP §10: Each bad verdict must have at least 2 culprits (guarantors).
   Error: not_enough_culprits"
  ;; STUB — TODO: for each bad verdict, count matching culprits
  (declare (ignore bad-verdicts culprits))
  t)

;;; ----- Faults Validation -----

(defun validate-faults-sorted-unique (faults)
  "GP §10: Faults must be sorted and unique by (target, key).
   Error: faults_not_sorted_unique"
  ;; STUB — TODO: check sorted-unique on composite key
  (declare (ignore faults))
  t)

(defun validate-fault-verdict-correct (fault classified-verdicts)
  "GP §10: Fault's vote must contradict the verdict.
   For a good verdict, the fault must have voted false.
   Error: fault_verdict_wrong"
  ;; STUB — TODO: check fault vote vs verdict classification
  (declare (ignore fault classified-verdicts))
  t)

(defun validate-fault-not-already-offender (fault psi)
  "GP §10: Fault key must not already be in ψ.offenders.
   Error: offender_already_reported"
  ;; STUB — TODO: check against existing offenders
  (declare (ignore fault psi))
  t)

(defun validate-fault-key (fault kappa lambda-prev)
  "GP §10: Fault key must be a known auditor key.
   Error: bad_auditor_key"
  ;; STUB — TODO: check key is in validator set
  (declare (ignore fault kappa lambda-prev))
  t)

(defun validate-fault-signature (fault)
  "GP §10: Fault's judgment signature must verify.
   Error: bad_signature"
  ;; STUB — TODO: verify ed25519 signature
  (declare (ignore fault))
  t)

(defun validate-enough-faults (good-verdicts faults)
  "GP §10: Each good/wonky verdict must have at least 1 fault.
   Error: not_enough_faults"
  ;; STUB — TODO: for each good verdict, count matching faults
  (declare (ignore good-verdicts faults))
  t)

;;; ═════════════════════════════════════════════════════════════════
;;; ψ' — TRANSITION (GP §10)
;;; ═════════════════════════════════════════════════════════════════

(defun transition-psi (disputes psi tau kappa lambda-prev)
  "GP §10 — Judgments state transition.
   ψ' = ψ updated with new verdicts, culprits, faults.

   Returns: ψ' (plist with :good :bad :wonky :offenders)
   Signals: DISPUTES-ERROR on validation failure.

   Validation order (from test vectors):
     1. verdicts sorted & unique
     2. per verdict: judgements sorted & unique
     3. per verdict: age valid
     4. per verdict: vote split valid
     5. per verdict: not already judged
     6. per verdict: signatures valid
     7. culprits: enough for each bad verdict
     8. culprits: sorted & unique
     9. per culprit: verdict is bad
    10. per culprit: not already offender
    11. per culprit: key is valid guarantor
    12. per culprit: signature valid
    13. faults: enough for each good/wonky verdict
    14. faults: sorted & unique
    15. per fault: vote contradicts verdict
    16. per fault: not already offender
    17. per fault: key is valid auditor
    18. per fault: signature valid"
  (let* ((verdicts (getf disputes :verdicts))
         (culprits (getf disputes :culprits))
         (faults   (getf disputes :faults))
         ;; Current ψ segments
         (good      (getf psi :good))
         (bad       (getf psi :bad))
         (wonky     (getf psi :wonky))
         (offenders (getf psi :offenders)))

    ;; ── Step 1: Validate verdicts ──
    (validate-verdicts-sorted-unique verdicts)

    (dolist (verdict verdicts)
      (validate-judgements-sorted-unique verdict)
      (validate-judgement-age verdict tau)
      (validate-vote-split verdict)
      (validate-verdict-not-already-judged verdict psi)
      (validate-verdict-signatures verdict (getf verdict :age)
                                   kappa lambda-prev))

    ;; ── Step 2: Classify verdicts ──
    (let ((classified (mapcar (lambda (v)
                                (cons (classify-verdict v) v))
                              verdicts)))
      (let ((new-good  (mapcar #'cdr (remove-if-not (lambda (c) (eq (car c) :good))  classified)))
            (new-bad   (mapcar #'cdr (remove-if-not (lambda (c) (eq (car c) :bad))   classified)))
            (new-wonky (mapcar #'cdr (remove-if-not (lambda (c) (eq (car c) :wonky)) classified))))

        ;; ── Step 3: Validate culprits ──
        (validate-enough-culprits new-bad culprits)
        (validate-culprits-sorted-unique culprits)
        (dolist (culprit culprits)
          (validate-culprit-verdict-is-bad culprit classified)
          (validate-culprit-not-already-offender culprit psi)
          (validate-culprit-key culprit kappa lambda-prev)
          (validate-culprit-signature culprit))

        ;; ── Step 4: Validate faults ──
        (validate-enough-faults new-good faults)
        (validate-faults-sorted-unique faults)
        (dolist (fault faults)
          (validate-fault-verdict-correct fault classified)
          (validate-fault-not-already-offender fault psi)
          (validate-fault-key fault kappa lambda-prev)
          (validate-fault-signature fault))

        ;; ── Step 5: Build ψ' ──
        (let* ((new-offender-keys
                 (append (mapcar (lambda (c) (getf c :key)) culprits)
                         (mapcar (lambda (f) (getf f :key)) faults)))
               ;; STUB — TODO: merge & sort offenders
               (offenders-prime (append offenders new-offender-keys))
               (good-prime  (append good  (mapcar (lambda (v) (getf v :target)) new-good)))
               (bad-prime   (append bad   (mapcar (lambda (v) (getf v :target)) new-bad)))
               (wonky-prime (append wonky (mapcar (lambda (v) (getf v :target)) new-wonky))))
          (list :good good-prime
                :bad bad-prime
                :wonky wonky-prime
                :offenders offenders-prime))))))

;;; ═════════════════════════════════════════════════════════════════
;;; OFFENDERS MARK — for header validation
;;; ═════════════════════════════════════════════════════════════════

(defun compute-offenders-mark (psi-prime psi)
  "Compute the new offenders added by this block.
   HO = ψ'.offenders \\ ψ.offenders (set difference).
   Returns: sorted list of new offender keys."
  ;; STUB — TODO: set difference, sorted
  (let ((old (getf psi :offenders))
        (new (getf psi-prime :offenders)))
    (remove-if (lambda (k) (member-hash k old)) new)))

;;; ═════════════════════════════════════════════════════════════════
;;; STATE CODECS — C(5) ↦ ψ
;;; ═════════════════════════════════════════════════════════════════

(defun decode-state-psi (bytes offset)
  "Decode ψ from state binary.
   GP C(5): E(↕[x ∈ ψG ^^ x], ↕[x ∈ ψB ^^ x], ↕[x ∈ ψW ^^ x], ↕[x ∈ ψO ^^ x])
   = 4 sorted sequences of H(32).
   Returns: (values psi-plist bytes-consumed)"
  ;; STUB — TODO: decode 4 sequences of 32-byte hashes
  (let ((pos offset))
    (multiple-value-bind (good good-size)
        (decode-sequence bytes pos (lambda (b o) (values (subseq b o (+ o 32)) 32)))
      (incf pos good-size)
      (multiple-value-bind (bad bad-size)
          (decode-sequence bytes pos (lambda (b o) (values (subseq b o (+ o 32)) 32)))
        (incf pos bad-size)
        (multiple-value-bind (wonky wonky-size)
            (decode-sequence bytes pos (lambda (b o) (values (subseq b o (+ o 32)) 32)))
          (incf pos wonky-size)
          (multiple-value-bind (offenders offenders-size)
              (decode-sequence bytes pos (lambda (b o) (values (subseq b o (+ o 32)) 32)))
            (incf pos offenders-size)
            (values (list :good good :bad bad :wonky wonky :offenders offenders)
                    (- pos offset))))))))

(defun encode-state-psi (psi)
  "Encode ψ to state binary.
   Returns: byte array"
  ;; STUB — TODO: encode 4 sorted sequences of 32-byte hashes
  (let ((good      (getf psi :good))
        (bad       (getf psi :bad))
        (wonky     (getf psi :wonky))
        (offenders (getf psi :offenders)))
    (concatenate '(vector (unsigned-byte 8))
                 (encode-sequence good #'encode-hash-32)
                 (encode-sequence bad #'encode-hash-32)
                 (encode-sequence wonky #'encode-hash-32)
                 (encode-sequence offenders #'encode-hash-32))))

;;; Exports managed in package.lisp
