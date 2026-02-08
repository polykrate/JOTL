;;;; stf/psi.lisp — ψ (Judgments)
;;;; Gray Paper §10
;;;;
;;;; Disputes STF:
;;;;   transition-psi(ED, ψ, τ, κ, λ) → ψ'
;;;;
;;;; (10.1) ψ ≡ (ψG, ψB, ψW, ψO)
;;;;   ψG good     — set of H: work-reports judged valid
;;;;   ψB bad      — set of H: work-reports judged invalid
;;;;   ψW wonky    — set of H: impossible to judge
;;;;   ψO offenders — set of Ed25519 keys banned
;;;;
;;;; (10.2) ED ≡ (EV, EC, EF)
;;;;   EV verdicts — [(r:H, a:N₂, j:[(v:bool, i:Nv, s:V̄)]_{⌊2V/3⌋+1})]
;;;;   EC culprits — [(r:H, f:H̄, s:V̄)]
;;;;   EF faults   — [(r:H, v:bool, f:H̄, s:V̄)]
;;;;
;;;; (10.3) k = κ if a=⌊τ/E⌋, λ otherwise
;;;; (10.4) X_τ ≡ $jam_valid, X_⊥ ≡ $jam_invalid
;;;; (10.5) ∀(r,f,s) ∈ EC: r∈ψ'B, f∈k, s∈V̄f(XG~r)
;;;; (10.6) ∀(r,v,f,s) ∈ EF: r∈ψ'B ⇔ r∉ψ'G ⇔ v, f∈k, s∈V̄f(Xv~r)
;;;;   where k = {ie | i ∈ λ∪κ} \ ψO
;;;; (10.7) EV ordered by r
;;;; (10.8) EC ordered by f, EF ordered by f
;;;; (10.9) {r|(r,a,j)∈EV} ∤ ψG ∪ ψB ∪ ψW
;;;; (10.10) ∀(r,a,j) ∈ EV: j = [(v,i,s) ∈ j ‖ i]  (votes sorted by index)
;;;; (10.11) v ∈ [(ℍ, {0, ⌊⅓V⌋, ⌊⅔V⌋+1})]  (positive count exact)
;;;; (10.12) v = [(r, Σv) | (r,a,j) ∈ EV]  (sum of positive votes)
;;;; (10.13) ∀(r, ⌊⅔V⌋+1) ∈ v: ∃(r,...) ∈ EF  (good → ≥1 fault)
;;;; (10.14) ∀(r, 0) ∈ v: |{(r,...) ∈ EC}| ≥ 2  (bad → ≥2 culprits)
;;;; (10.15) ρ†[c] = ∅ if (H(ρ[c]r),t) ∈ v, t < ⌊⅔V⌋  (clear bad/wonky)
;;;; (10.16) ψ'G ≡ ψG ∪ {r | (r, ⌊⅔V⌋+1) ∈ v}
;;;; (10.17) ψ'B ≡ ψB ∪ {r | (r, 0) ∈ v}
;;;; (10.18) ψ'W ≡ ψW ∪ {r | (r, ⌊⅓V⌋) ∈ v}
;;;; (10.19) ψ'O ≡ ψO ∪ {f|(f,...)∈EC} ∪ {f|(f,...)∈EF}

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
  "(10.11-12) Classify verdict by positive vote count.
   Returns: :good | :bad | :wonky

   positive = ⌊2V/3⌋+1 → good  (unanimous positive)
   positive = 0         → bad   (unanimous negative)
   positive = ⌊V/3⌋    → wonky (exact split)"
  (let* ((votes (getf verdict :votes))
         (positive (count-if (lambda (v) (getf v :vote)) votes)))
    (cond
      ((= positive (super-majority)) :good)
      ((zerop positive)              :bad)
      (t                             :wonky))))

(defun judgment-signing-context (target vote)
  "(10.4) Xv(r) — signing context for a judgment.
   vote=true  → 'jam_valid'  ++ r
   vote=false → 'jam_invalid' ++ r
   (GP notation: $foo means string literal 'foo', $ is not part of the bytes.)

   Args: target (H, 32 bytes), vote (boolean)
   Returns: byte array"
  (let ((prefix (if vote +ctx-valid+ +ctx-invalid+)))
    (concatenate '(vector (unsigned-byte 8)) prefix target)))

(defun guarantee-signing-context (target)
  "(10.5) XG(r) — signing context for a guarantee.
   'jam_guarantee' ++ r

   Args: target (H, 32 bytes)
   Returns: byte array"
  (concatenate '(vector (unsigned-byte 8)) +ctx-guarantee+ target))

(defun validator-ed25519-key (index age tau kappa lambda-prev)
  "(10.3) Get Ed25519 key for validator at INDEX.
   age is the absolute epoch number:
     a = ⌊τ/E⌋ → κ (current), otherwise → λ (previous).
   Returns: 32-byte Ed25519 public key, or NIL if invalid."
  (let* ((current-epoch (timeslot-epoch tau))
         (validators (if (= age current-epoch) kappa lambda-prev)))
    (when (and validators (< index (length validators)))
      (let ((validator (elt validators index)))
        (getf validator :ed25519)))))

(defun build-valid-key-set (kappa lambda-prev offenders)
  "Build k = {ie | i ∈ λ ∪ κ} \\ ψO — GP §10.
   All Ed25519 keys from current + previous validators, minus offenders.
   Returns: list of 32-byte Ed25519 keys."
  (let ((all-keys '()))
    (dolist (v kappa)
      (when v (let ((k (getf v :ed25519)))
                (when k (push k all-keys)))))
    (dolist (v lambda-prev)
      (when v (let ((k (getf v :ed25519)))
                (when k (push k all-keys)))))
    ;; Remove offenders and duplicates
    (remove-duplicates
     (remove-if (lambda (k) (member-hash k offenders)) all-keys)
     :test #'equalp)))

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
  "(10.7) EV ordered by r — verdicts sorted & unique by target hash."
  (unless (or (null verdicts)
              (sorted-unique-p verdicts
                               (lambda (v) (getf v :target))
                               #'hash<))
    (reject-disputes :verdicts-not-sorted-unique)))

(defun validate-judgements-sorted-unique (verdict)
  "Votes within a verdict must be sorted and unique by validator index."
  (let ((votes (getf verdict :votes)))
    (unless (or (null votes)
                (sorted-unique-p votes
                                 (lambda (v) (getf v :index))
                                 #'<))
      (reject-disputes :judgements-not-sorted-unique))))

(defun validate-judgement-age (verdict tau)
  "(10.3) a ∈ {⌊τ/E⌋, ⌊τ/E⌋-1} — epoch must be current or previous.
   age field is the absolute epoch number, not an offset."
  (let* ((age (getf verdict :age))
         (current-epoch (timeslot-epoch tau)))
    (unless (or (= age current-epoch)
                (= age (1- current-epoch)))
      (reject-disputes :bad-judgement-age
                       (format nil "age=~A, current-epoch=~A" age current-epoch)))))

(defun validate-vote-split (verdict)
  "(10.11) v ∈ [(ℍ, {0, ⌊⅓V⌋, ⌊⅔V⌋+1})]
   (10.12) v = [(r, Σv) | (r,a,j) ∈ EV]
   Vote count must equal ⌊2V/3⌋+1, and the positive vote sum
   must be exactly one of {0, ⌊V/3⌋, ⌊2V/3⌋+1}:
     ⌊2V/3⌋+1 = good (unanimous positive)
     0         = bad  (unanimous negative)
     ⌊V/3⌋    = wonky (exact split)"
  (let* ((votes (getf verdict :votes))
         (expected-count (super-majority))
         (total (length votes))
         (V (num-validators)))
    (unless (= total expected-count)
      (reject-disputes :bad-vote-split
                       (format nil "expected ~A votes, got ~A"
                               expected-count total)))
    (let ((positive (count-if (lambda (v) (getf v :vote)) votes))
          (allowed (list 0 (floor V 3) (1+ (floor (* 2 V) 3)))))
      (unless (member positive allowed)
        (reject-disputes :bad-vote-split
                         (format nil "positive=~A, allowed=~A" positive allowed))))))

(defun validate-verdict-not-already-judged (verdict psi)
  "(10.9) {r|(r,a,j)∈EV} ∤ ψG ∪ ψB ∪ ψW — no duplicate report hashes."
  (let ((target (getf verdict :target))
        (good (getf psi :good))
        (bad (getf psi :bad))
        (wonky (getf psi :wonky)))
    (when (or (member-hash target good)
              (member-hash target bad)
              (member-hash target wonky))
      (reject-disputes :already-judged))))

(defun validate-verdict-signatures (verdict age tau kappa lambda-prev)
  "(10.3) Each vote's Ed25519 signature must verify: s ∈ V̄_{k[i]e}(Xv ~ r).
   message = Xv(r) = judgment-signing-context(target, vote)
   key = κ[i]e if a=⌊τ/E⌋, λ[i]e otherwise."
  (let ((target (getf verdict :target)))
    (dolist (vote (getf verdict :votes))
      (let* ((index (getf vote :index))
             (vote-bool (getf vote :vote))
             (signature (getf vote :signature))
             (key (validator-ed25519-key index age tau kappa lambda-prev))
             (message (judgment-signing-context target vote-bool)))
        (unless key
          (reject-disputes :bad-validator-index
                           (format nil "no key for validator ~A age ~A" index age)))
        (let ((sig-bytes (etypecase signature
                           ((simple-array (unsigned-byte 8) (*)) signature)
                           (string (jam.ffi:hex-string-to-bytes signature))
                           (vector (coerce signature '(simple-array (unsigned-byte 8) (*))))))
              (key-bytes (etypecase key
                           ((simple-array (unsigned-byte 8) (*)) key)
                           (string (jam.ffi:hex-string-to-bytes key))
                           (vector (coerce key '(simple-array (unsigned-byte 8) (*)))))))
          (unless (jam.ffi:ed25519-verify key-bytes message sig-bytes)
            (reject-disputes :bad-signature
                             (format nil "verdict sig failed: idx=~A vote=~A" index vote-bool))))))))

;;; ----- Culprits Validation (10.5) -----
;;; ∀(r,f,s) ∈ EC: r∈ψ'B, f∈k, s∈V̄f(XG~r)

(defun validate-culprits-sorted-unique (culprits)
  "(10.8) EC ordered by f — culprits sorted & unique by key."
  (unless (or (null culprits)
              (sorted-unique-p culprits
                               (lambda (c) (getf c :key))
                               #'hash<))
    (reject-disputes :culprits-not-sorted-unique)))

(defun validate-culprit-verdict-is-bad (culprit psi-bad-targets)
  "(10.5) r ∈ ψ'B — culprit target must be a bad verdict."
  (let ((target (getf culprit :target)))
    (unless (member-hash target psi-bad-targets)
      (reject-disputes :culprits-verdict-not-bad))))

(defun validate-culprit-not-already-offender (culprit offenders)
  "Culprit key must not already be in ψO.
   Implicit in k = ... \\ ψO."
  (let ((key (getf culprit :key)))
    (when (member-hash key offenders)
      (reject-disputes :offender-already-reported))))

(defun validate-culprit-key (culprit valid-keys)
  "(10.5) f ∈ k — culprit key must be in valid key set."
  (let ((key (getf culprit :key)))
    (unless (member-hash key valid-keys)
      (reject-disputes :bad-guarantor-key))))

(defun validate-culprit-signature (culprit)
  "(10.5) s ∈ V̄f(XG ~ r) — guarantee signature must verify.
   message = XG(r) = guarantee-signing-context(target)"
  (let* ((target (getf culprit :target))
         (key (getf culprit :key))
         (signature (getf culprit :signature))
         (message (guarantee-signing-context target))
         (sig-bytes (etypecase signature
                      ((simple-array (unsigned-byte 8) (*)) signature)
                      (string (jam.ffi:hex-string-to-bytes signature))
                      (vector (coerce signature '(simple-array (unsigned-byte 8) (*))))))
         (key-bytes (etypecase key
                      ((simple-array (unsigned-byte 8) (*)) key)
                      (string (jam.ffi:hex-string-to-bytes key))
                      (vector (coerce key '(simple-array (unsigned-byte 8) (*)))))))
    (unless (jam.ffi:ed25519-verify key-bytes message sig-bytes)
      (reject-disputes :bad-signature "culprit guarantee sig failed"))))

(defun validate-enough-culprits (bad-verdict-targets culprits)
  "Each bad verdict must have ≥ 2 culprits (guarantors).
   Error: not_enough_culprits"
  (dolist (target bad-verdict-targets)
    (let ((count (count-if (lambda (c) (equalp (getf c :target) target))
                           culprits)))
      (when (< count 2)
        (reject-disputes :not-enough-culprits
                         (format nil "bad verdict needs ≥2 culprits, got ~A" count))))))

;;; ----- Faults Validation (10.6) -----
;;; ∀(r,v,f,s) ∈ EF: r∈ψ'B ⇔ r∉ψ'G ⇔ v, f∈k, s∈V̄f(Xv~r)

(defun validate-faults-sorted-unique (faults)
  "(10.8) EF ordered by f — faults sorted & unique by key."
  (unless (or (null faults)
              (sorted-unique-p faults
                               (lambda (f) (getf f :key))
                               #'hash<))
    (reject-disputes :faults-not-sorted-unique)))

(defun validate-fault-verdict-correct (fault good-targets bad-targets)
  "(10.6) r∈ψ'B ⇔ r∉ψ'G ⇔ v
   If v=true  (voted valid): target must be in bad-set (they were wrong)
   If v=false (voted invalid): target must be in good-set (they were wrong)"
  (let ((target (getf fault :target))
        (vote   (getf fault :vote)))
    (cond
      ;; Voted valid (v=true) → target must be bad (they guaranteed/approved a bad report)
      ((and vote (not (member-hash target bad-targets)))
       (reject-disputes :fault-verdict-wrong "voted valid but target not bad"))
      ;; Voted invalid (v=false) → target must be good (they rejected a good report)
      ((and (not vote) (not (member-hash target good-targets)))
       (reject-disputes :fault-verdict-wrong "voted invalid but target not good")))))

(defun validate-fault-not-already-offender (fault offenders)
  "Fault key must not already be in ψO.
   Implicit in k = ... \\ ψO."
  (let ((key (getf fault :key)))
    (when (member-hash key offenders)
      (reject-disputes :offender-already-reported))))

(defun validate-fault-key (fault valid-keys)
  "(10.6) f ∈ k — fault key must be in valid key set."
  (let ((key (getf fault :key)))
    (unless (member-hash key valid-keys)
      (reject-disputes :bad-auditor-key))))

(defun validate-fault-signature (fault)
  "(10.6) s ∈ V̄f(Xv ~ r) — judgment signature must verify.
   message = Xv(r) = judgment-signing-context(target, vote)"
  (let* ((target (getf fault :target))
         (vote   (getf fault :vote))
         (key (getf fault :key))
         (signature (getf fault :signature))
         (message (judgment-signing-context target vote))
         (sig-bytes (etypecase signature
                      ((simple-array (unsigned-byte 8) (*)) signature)
                      (string (jam.ffi:hex-string-to-bytes signature))
                      (vector (coerce signature '(simple-array (unsigned-byte 8) (*))))))
         (key-bytes (etypecase key
                      ((simple-array (unsigned-byte 8) (*)) key)
                      (string (jam.ffi:hex-string-to-bytes key))
                      (vector (coerce key '(simple-array (unsigned-byte 8) (*)))))))
    (unless (jam.ffi:ed25519-verify key-bytes message sig-bytes)
      (reject-disputes :bad-signature "fault judgment sig failed"))))

(defun validate-enough-faults (good-verdict-targets faults)
  "Each good verdict must have ≥ 1 fault (validator who voted wrong).
   Wonky verdicts don't require faults (no clear correct answer).
   Error: not_enough_faults"
  (dolist (target good-verdict-targets)
    (let ((count (count-if (lambda (f) (equalp (getf f :target) target))
                           faults)))
      (when (< count 1)
        (reject-disputes :not-enough-faults
                         (format nil "good verdict needs ≥1 fault, got ~A" count))))))

;;; ═════════════════════════════════════════════════════════════════
;;; ψ' — TRANSITION (GP §10)
;;; ═════════════════════════════════════════════════════════════════

(defun transition-psi (disputes psi tau kappa lambda-prev)
  "GP §10 — Judgments state transition.
   ψ' = ψ updated with new verdicts, culprits, faults.

   Args: disputes (plist :verdicts :culprits :faults)
         psi      (plist :good :bad :wonky :offenders)
         tau      (integer, current timeslot)
         kappa    (list of validator plists, current epoch)
         lambda-prev (list of validator plists, previous epoch)
   Returns: (values ψ' v-list)
     ψ'     (plist :good :bad :wonky :offenders) — (10.16-19)
     v-list (list of (target . positive-count))  — (10.12) for ρ† (10.15)
   Signals: DISPUTES-ERROR on validation failure."
  (let* ((verdicts  (getf disputes :verdicts))
         (culprits  (getf disputes :culprits))
         (faults    (getf disputes :faults))
         ;; Current ψ segments
         (good      (getf psi :good))
         (bad       (getf psi :bad))
         (wonky     (getf psi :wonky))
         (offenders (getf psi :offenders))
         ;; k = {ie | i ∈ λ∪κ} \ ψO
         (valid-keys (build-valid-key-set kappa lambda-prev offenders)))

    ;; ── (10.7) Verdicts sorted by r ──
    (validate-verdicts-sorted-unique verdicts)

    ;; ── Per-verdict validation ──
    (dolist (verdict verdicts)
      (validate-judgements-sorted-unique verdict)
      (validate-judgement-age verdict tau)
      (validate-vote-split verdict)
      ;; (10.9) no duplicates against prior judgments
      (validate-verdict-not-already-judged verdict psi)
      ;; (10.3) Signature verification per vote
      (validate-verdict-signatures verdict (getf verdict :age)
                                   tau kappa lambda-prev))

    ;; ── (10.12) Build v = [(r, Σv) | (r,a,j) ∈ EV] ──
    (let* ((v-list (mapcar (lambda (verdict)
                             (let* ((target (getf verdict :target))
                                    (votes (getf verdict :votes))
                                    (positive (count-if (lambda (v) (getf v :vote)) votes)))
                               (cons target positive)))
                           verdicts))
           ;; ── (10.16-18) Classify by positive count ──
           (new-good-targets  (mapcar #'car (remove-if-not
                                             (lambda (vp) (= (cdr vp) (super-majority)))
                                             v-list)))
           (new-bad-targets   (mapcar #'car (remove-if-not
                                             (lambda (vp) (zerop (cdr vp)))
                                             v-list)))
           (new-wonky-targets (mapcar #'car (remove-if-not
                                             (lambda (vp) (= (cdr vp) (floor (num-validators) 3)))
                                             v-list)))
           ;; ψ' sets (prior ∪ new)
           (good-prime  (append good  new-good-targets))
           (bad-prime   (append bad   new-bad-targets))
           (wonky-prime (append wonky new-wonky-targets)))

      ;; ── (10.5) Culprits: r∈ψ'B, f∈k, s∈V̄f(XG~r) ──
      (validate-enough-culprits new-bad-targets culprits)
      (validate-culprits-sorted-unique culprits)     ;; (10.8)
      (dolist (culprit culprits)
        (validate-culprit-verdict-is-bad culprit bad-prime)
        (validate-culprit-not-already-offender culprit offenders)
        (validate-culprit-key culprit valid-keys)
        (validate-culprit-signature culprit))

      ;; ── (10.6) Faults: r∈ψ'B⇔r∉ψ'G⇔v, f∈k, s∈V̄f(Xv~r) ──
      ;; Faults only required for good verdicts (wonky has no clear correct answer)
      (validate-enough-faults new-good-targets faults)
      (validate-faults-sorted-unique faults)         ;; (10.8)
      (dolist (fault faults)
        (validate-fault-verdict-correct fault good-prime bad-prime)
        (validate-fault-not-already-offender fault offenders)
        (validate-fault-key fault valid-keys)
        (validate-fault-signature fault))

      ;; ── (10.19) Build ψ'O = ψO ∪ {f|(f,...)∈EC} ∪ {f|(f,...)∈EF} ──
      (let* ((new-offender-keys
               (append (mapcar (lambda (c) (getf c :key)) culprits)
                       (mapcar (lambda (f) (getf f :key)) faults)))
             (offenders-prime
               (sort (remove-duplicates
                      (append offenders new-offender-keys)
                      :test #'equalp)
                     #'hash<))
             (psi-prime (list :good  good-prime
                              :bad   bad-prime
                              :wonky wonky-prime
                              :offenders offenders-prime)))
        ;; Return ψ' and v (10.12) for use by ρ† (10.15)
        (values psi-prime v-list)))))

;;; ═════════════════════════════════════════════════════════════════
;;; OFFENDERS MARK — for header validation
;;; ═════════════════════════════════════════════════════════════════

(defun compute-offenders-mark (culprits faults)
  "(10.20) HO = [f | (f,...) ∈ EC] ~ [f | (f,...) ∈ EF]
   The offenders marker in the header is the culprit keys
   concatenated with the fault keys, preserving their order
   (both already sorted by f per (10.8)).
   Returns: list of Ed25519 keys (ordered: culprits then faults)."
  (append (mapcar (lambda (c) (getf c :key)) culprits)
          (mapcar (lambda (f) (getf f :key)) faults)))

;;; ═════════════════════════════════════════════════════════════════
;;; STATE CODECS — C(5) ↦ ψ
;;; ═════════════════════════════════════════════════════════════════

(defun decode-state-psi (bytes &optional (offset 0))
  "Decode ψ from state binary.
   GP C(5): E(↕[x ∈ ψG ^^ x], ↕[x ∈ ψB ^^ x], ↕[x ∈ ψW ^^ x], ↕[x ∈ ψO ^^ x])
   = 4 sorted sequences of H(32).
   Returns: (values psi-plist bytes-consumed)"
  (let ((hash-decoder (lambda (b o) (values (subseq b o (+ o 32)) 32)))
        (pos offset))
    (multiple-value-bind (good good-size)
        (decode-sequence bytes hash-decoder pos)
      (incf pos good-size)
      (multiple-value-bind (bad bad-size)
          (decode-sequence bytes hash-decoder pos)
        (incf pos bad-size)
        (multiple-value-bind (wonky wonky-size)
            (decode-sequence bytes hash-decoder pos)
          (incf pos wonky-size)
          (multiple-value-bind (offenders offenders-size)
              (decode-sequence bytes hash-decoder pos)
            (incf pos offenders-size)
            (values (list :good good :bad bad :wonky wonky :offenders offenders)
                    (- pos offset))))))))

(defun encode-state-psi (psi)
  "Encode ψ to state binary.
   Returns: byte array"
  ;; C(5): 4 sorted sequences of 32-byte hashes
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
