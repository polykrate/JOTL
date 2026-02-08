;;;; stf/rho.lisp — ρ (Core Assignments / Availability)
;;;; Gray Paper §10 (ρ†), §11 (ρ‡, R*), §11-12 (ρ')
;;;;
;;;; ρ ∈ ⟦Option<(r: WorkReport, t: U32)>⟧:C   (C = num-cores)
;;;;
;;;; Three transformations across the waves:
;;;;   WAVE 1: ρ† = transition-rho-dagger(v, ρ)      — disputes invalidate (10.15)
;;;;   WAVE 2: (4.13) ρ‡ ≺ (EA, ρ†)                   — assurances (§11)
;;;;           (4.15) R* ≺ (EA, ρ†)                   — ready reports (§11)
;;;;   WAVE 3: (4.14) ρ' ≺ (EG, ρ‡, κ, τ')           — guarantees (§11-12)
;;;;
;;;; State key: C(10)
;;;; Encoding: E([¿(r, E4(t)) | (r, t) ← ρ])  — fixed-size array of Options

(in-package #:jotl)

;;; ═════════════════════════════════════════════════════════════════
;;; VALUE OBJECT
;;; ═════════════════════════════════════════════════════════════════

(define-value-object rho
  ((assignments '()))
  (:core-count (length assignments)))

;;; ═════════════════════════════════════════════════════════════════
;;; CODECS — State key C(10)
;;; ═════════════════════════════════════════════════════════════════
;;;
;;; AvailabilityAssignment = WorkReport || E4(timeout)
;;; AvailabilityAssignments = [Option<AvailabilityAssignment>] × C
;;; Option: 0x00 = None, 0x01 = Some(data)

(defun encode-rho-assignment (assignment)
  "Encode a single core assignment (Option).
   nil → [0x00], plist → [0x01] || encode-work-report(report) || E4(timeout)"
  (if (null assignment)
      #(0)
      (concatenate '(vector (unsigned-byte 8))
                   #(1)
                   (encode-work-report (getf assignment :report))
                   (encode-u32 (getf assignment :timeout)))))

(defun decode-rho-assignment (bytes offset)
  "Decode a single core assignment (Option).
   Returns: (values assignment-or-nil bytes-consumed)"
  (let ((tag (aref bytes offset)))
    (if (zerop tag)
        (values nil 1)
        (let ((pos (1+ offset)))
          (multiple-value-bind (report report-size)
              (decode-work-report bytes pos)
            (incf pos report-size)
            (multiple-value-bind (timeout timeout-size)
                (decode-u32 bytes pos)
              (incf pos timeout-size)
              (values (list :report report :timeout timeout)
                      (- pos offset))))))))

(defun encode-state-rho (assignments)
  "Encode ρ to state binary — fixed-size array of C Option assignments.
   Args: assignments — list of C items (nil or plist with :report :timeout)
   Returns: byte array"
  (apply #'concatenate '(vector (unsigned-byte 8))
         (mapcar #'encode-rho-assignment assignments)))

(defun decode-state-rho (bytes &optional (offset 0))
  "Decode ρ from state binary — reads exactly num-cores Option assignments.
   Returns: (values assignments-list total-bytes-consumed)"
  (let ((assignments '())
        (pos offset)
        (c (num-cores)))
    (dotimes (i c)
      (multiple-value-bind (assignment size)
          (decode-rho-assignment bytes pos)
        (push assignment assignments)
        (incf pos size)))
    (values (nreverse assignments) (- pos offset))))

;;; ═════════════════════════════════════════════════════════════════
;;; HELPERS
;;; ═════════════════════════════════════════════════════════════════

(defun assignment-report-hash (assignment)
  "Compute H(ρ[c]r) — blake2b-256 of the encoded work-report.
   Returns nil if assignment is nil or has no report."
  (when assignment
    (let ((report (getf assignment :report)))
      (when report
        (blake2b-256 (encode-work-report report))))))

;;; ═════════════════════════════════════════════════════════════════
;;; WAVE 1: ρ† — ASSIGNMENTS AFTER DISPUTES (GP §10)
;;; ═════════════════════════════════════════════════════════════════

(defun transition-rho-dagger (v-list rho)
  "(10.15) ρ†[c] = ∅ if ∃(r,t) ∈ v: H(ρ[c]r) = r ∧ t < ⌊2V/3⌋+1
   Clear cores whose work-report was judged invalid (bad) or uncertain (wonky).
   Good verdicts (t = ⌊2V/3⌋+1) do NOT clear assignments.

   Args: v-list — list of (target . positive-count) from (10.12)
         rho — list of core assignments (nil or plist with :report :timeout)
   Returns: ρ† (same structure, with invalidated cores set to nil)"
  (if (null v-list)
      rho
      ;; Threshold: ⌊2V/3⌋+1 — verdicts with t below this are bad/wonky
      (let ((threshold (1+ (floor (* 2 (num-validators)) 3))))
        ;; Collect targets with t < threshold (bad or wonky, not good)
        (let ((invalidated-targets
                (loop for (target . pos-count) in v-list
                      when (< pos-count threshold)
                      collect target)))
          (if (null invalidated-targets)
              rho
              (mapcar (lambda (assignment)
                        (let ((h (assignment-report-hash assignment)))
                          (if (and h (member-hash h invalidated-targets))
                              nil
                              assignment)))
                      rho))))))

;;; ═════════════════════════════════════════════════════════════════
;;; WAVE 2: ρ‡, R* — ASSURANCES (GP §11)
;;; ═════════════════════════════════════════════════════════════════
;;;
;;; Full STF for availability assurances.
;;;
;;; Inputs:
;;;   EA — assurances extrinsic (list of {anchor, bitfield, validator_index, signature})
;;;   τ' — block timeslot (from header HT)
;;;   Hp — parent header hash
;;;   ρ† — core assignments after disputes
;;;   κ  — current validator keys
;;;
;;; Outputs:
;;;   ρ‡ — assignments with available/stale cores cleared
;;;   R* — list of WorkReports that achieved availability supermajority
;;;
;;; Error codes (from test vectors, NOT specified in GP):
;;;   bad-attestation-parent          — anchor ≠ Hp
;;;   bad-validator-index             — validator_index ≥ V
;;;   core-not-engaged                — bitfield flags core with ρ†[c] = ∅
;;;   bad-signature                   — Ed25519 signature verification failed
;;;   not-sorted-or-unique-assurers   — EA not sorted by validator_index / duplicates
;;;
;;; Equations:
;;;   (11.10) EA structure: (anchor, bitfield, validator_index, signature)
;;;   (11.11) ∀a ∈ EA : a_a = H_P
;;;   (11.12) ∀i : EA[i-1]_v < EA[i]_v
;;;   (11.13) a_s ∈ V̄_{κ[a_v]_e}⟨X_A ~ H(E(H_P, a_f))⟩
;;;   (11.14) X_A ≡ $jam_available
;;;   (11.15) a_f[c] ⇒ ρ†[c] ≠ ∅
;;;   (11.16) R = [ρ†[c]_r | c < C, Σ a_f[c] > ⅔V]
;;;   (11.17) ρ‡[c] = ∅ if ρ[c]_r ∈ R ∨ H_T ≥ ρ†[c]_t + U ; ρ†[c] otherwise

;;; ─────────────────────────────────────────────────────────────────
;;; Error condition (same pattern as disputes-error in psi.lisp)
;;; ─────────────────────────────────────────────────────────────────

(define-condition assurance-error (error)
  ((code   :initarg :code   :reader assurance-error-code)
   (detail :initarg :detail :reader assurance-error-detail
           :initform nil))
  (:report (lambda (c s)
             (format s "Assurance error ~A~@[: ~A~]"
                     (assurance-error-code c)
                     (assurance-error-detail c)))))

(defun reject-assurance (code &optional detail)
  "Signal an assurance validation error."
  (error 'assurance-error :code code :detail detail))

;;; ─────────────────────────────────────────────────────────────────
;;; Signing context
;;; ─────────────────────────────────────────────────────────────────

(defun assurance-signing-payload (parent-hash bitfield)
  "(11.13)–(11.14) Assurance signing payload.
   X_A ≡ $jam_available
   message = X_A ~ H(E(H_P, a_f))
   i.e. 'jam_available' ++ blake2b-256(parent_hash ++ bitfield)

   Args: parent-hash (H, 32 bytes), bitfield (byte vector ⌈C/8⌉)
   Returns: byte array (the message that was signed)"
  (let ((inner (concatenate '(vector (unsigned-byte 8))
                            (ensure-bytes parent-hash)
                            (ensure-bytes bitfield))))
    (concatenate '(vector (unsigned-byte 8))
                 +ctx-available+
                 (blake2b-256 inner))))

;;; ─────────────────────────────────────────────────────────────────
;;; Helpers — bitfield operations
;;; ─────────────────────────────────────────────────────────────────

(defun bitfield-core-set-p (bitfield core-index)
  "Test if bit CORE-INDEX is set in BITFIELD byte-vector.
   Bit layout: byte[c/8], bit (c mod 8)."
  (let ((byte-idx (floor core-index 8))
        (bit-idx  (mod core-index 8)))
    (and (< byte-idx (length bitfield))
         (logbitp bit-idx (aref bitfield byte-idx)))))

(defun bitfield-flagged-cores (bitfield num-cores)
  "Return list of core indices flagged in BITFIELD."
  (loop for c below num-cores
        when (bitfield-core-set-p bitfield c)
        collect c))

(defun count-core-votes (assurances num-cores)
  "Count assurance votes per core from bitfields.
   Returns: vector of V integers, index = core."
  (let ((votes (make-array num-cores :initial-element 0)))
    (dolist (a assurances votes)
      (let ((bitfield (getf a :bitfield)))
        (dotimes (c num-cores)
          (when (bitfield-core-set-p bitfield c)
            (incf (aref votes c))))))))

;;; ─────────────────────────────────────────────────────────────────
;;; Validation — each function signals assurance-error or returns nil
;;; ─────────────────────────────────────────────────────────────────

(defun validate-assurances-sorted-unique (assurances)
  "(11.12) ∀i ∈ {1..|EA|}: EA[i-1]_v < EA[i]_v
   Assurances must be strictly ordered by validator index."
  (loop for (a b) on assurances while b
        do (let ((va (getf a :validator-index))
                 (vb (getf b :validator-index)))
             (unless (< va vb)
               (reject-assurance :not-sorted-or-unique-assurers
                                 (format nil "v[~A] >= v[~A]" va vb))))))

(defun validate-assurance-anchor (assurance parent-hash)
  "(11.11) ∀a ∈ EA : a_a = H_P
   Anchor must equal parent header hash."
  (let ((anchor (getf assurance :anchor)))
    (unless (equalp (ensure-bytes anchor) (ensure-bytes parent-hash))
      (reject-assurance :bad-attestation-parent))))

(defun validate-assurance-validator-index (assurance)
  "(11.10) v ∈ N_V — validator index must be < V."
  (let ((idx (getf assurance :validator-index)))
    (unless (< idx (num-validators))
      (reject-assurance :bad-validator-index
                        (format nil "index ~A >= V=~A" idx (num-validators))))))

(defun validate-assurance-cores-engaged (assurance rho-dagger)
  "(11.15) ∀a ∈ EA, c ∈ N_C : a_f[c] ⇒ ρ†[c] ≠ ∅
   Bitfield may only flag cores with an assignment."
  (let* ((bitfield (getf assurance :bitfield))
         (cores (bitfield-flagged-cores bitfield (num-cores))))
    (dolist (c cores)
      (when (null (nth c rho-dagger))
        (reject-assurance :core-not-engaged
                          (format nil "core ~A has no assignment" c))))))

(defun validate-assurance-signature (assurance kappa parent-hash)
  "(11.13) a_s ∈ V̄_{κ[a_v]_e}⟨X_A ~ H(E(H_P, a_f))⟩
   Ed25519 signature of validator κ[v] over 'jam_available' ++ H(H_P ++ bitfield)."
  (let* ((bitfield  (getf assurance :bitfield))
         (idx       (getf assurance :validator-index))
         (signature (getf assurance :signature))
         (validator (elt kappa idx))
         (ed-key    (getf validator :ed25519))
         (message   (assurance-signing-payload parent-hash bitfield))
         (sig-bytes (ensure-bytes signature))
         (key-bytes (ensure-bytes ed-key)))
    (unless (jam.ffi:ed25519-verify key-bytes message sig-bytes)
      (reject-assurance :bad-signature
                        (format nil "validator ~A" idx)))))

;;; ─────────────────────────────────────────────────────────────────
;;; Stale report detection
;;; ─────────────────────────────────────────────────────────────────

(defun report-stale-p (timeout tau-prime)
  "(11.17) H_T ≥ ρ†[c]_t + U
   A report is stale when the block timeslot reaches timeout + U.
   U = +availability-timeout+ = 5 (fixed protocol constant).
   Verified against test vectors:
     tiny: t=7,  τ'=12,  12≥12 ✓ removed
     tiny: t=11, τ'=12,  12≥16 ✗ kept
     full: t=595, τ'=600, 600≥600 ✓ removed
     full: t=599, τ'=600, 600≥604 ✗ kept"
  (>= tau-prime (+ timeout +availability-timeout+)))

;;; ─────────────────────────────────────────────────────────────────
;;; Main transition: (EA, τ', Hp, ρ†, κ) → (values ρ‡ R*)
;;; ─────────────────────────────────────────────────────────────────

(defun transition-rho-ddagger (assurances rho-dagger
                               &key tau-prime parent-hash kappa)
  "GP §11 — (4.13) ρ‡ ≺ (EA, ρ†), (4.15) R* ≺ (EA, ρ†)
   Validates EA (11.10-11.15), computes ρ‡ (11.17) and R* (11.16).
   
   Args:
     assurances   — EA (list of assurance plists)
     rho-dagger   — ρ† (list of C Option assignments)
     tau-prime    — τ' = H_T (block timeslot)
     parent-hash  — H_P (parent header hash)
     kappa        — κ (current validators)
   
   Returns: (values ρ‡ R* [error])
     ρ‡ — assignments with available/stale cores cleared (11.17)
     R* — available work-reports (11.16)
     error — assurance-error if validation failed (ρ‡=ρ†, R*=nil)"
  (handler-case
      (progn
        ;; ── Validate EA (11.10-11.15) ───────────────────────
        ;; Per-assurance checks first (detect invalid data early),
        ;; then ordering check (structural invariant).
        (dolist (a assurances)
          (validate-assurance-anchor a parent-hash)       ;; (11.11)
          (validate-assurance-validator-index a))          ;; (11.10)
        (validate-assurances-sorted-unique assurances)    ;; (11.12)
        (dolist (a assurances)
          (validate-assurance-cores-engaged a rho-dagger)  ;; (11.15)
          (validate-assurance-signature a kappa parent-hash)) ;; (11.13)
        ;; ── (11.16) R: count votes, find available cores ────
        (let* ((c (num-cores))
               (votes (count-core-votes assurances c))
               (threshold (super-majority))  ;; > ⅔V ≡ ≥ ⌊2V/3⌋+1
               ;; ── (11.17) Build ρ‡ and R* in one pass ─────
               (reported '())
               (new-assignments
                 (loop for ci below c
                       for assignment in rho-dagger
                       collect
                       (cond
                         ;; No assignment → stays nil
                         ((null assignment) nil)
                         ;; (11.16) Supermajority → available → R* + clear
                         ((>= (aref votes ci) threshold)
                          (push (getf assignment :report) reported)
                          nil)
                         ;; (11.17) Stale: H_T ≥ t + U → clear (not reported)
                         ((report-stale-p (getf assignment :timeout) tau-prime)
                          nil)
                         ;; Otherwise → keep
                         (t assignment)))))
          (values new-assignments (nreverse reported))))
    ;; ── Error path ─────────────────────────────────────────
    (assurance-error (e)
      (values rho-dagger nil e))))

(defun compute-ready-reports (assurances rho-dagger
                              &key tau-prime parent-hash kappa)
  "GP §11 — Convenience: returns only R* from transition-rho-ddagger.
   (Used when callers need just the available reports.)"
  (multiple-value-bind (rho-ddagger r-star)
      (transition-rho-ddagger assurances rho-dagger
                              :tau-prime tau-prime
                              :parent-hash parent-hash
                              :kappa kappa)
    (declare (ignore rho-ddagger))
    r-star))

;;; ═════════════════════════════════════════════════════════════════
;;; WAVE 3: ρ' — REGISTER GUARANTEES (GP §11-12)
;;; ═════════════════════════════════════════════════════════════════

(defun transition-rho (guarantees rho-ddagger kappa tau-prime)
  "GP §11-12 — Register guaranteed work-reports. STUB"
  (declare (ignore guarantees kappa tau-prime)) rho-ddagger)

;;; Exports managed in package.lisp
