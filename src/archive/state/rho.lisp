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
  (:state-key +C10+)
  (:core-count (length assignments))
  (:encoded :memo
    (apply #'concatenate '(vector (unsigned-byte 8))
           (mapcar #'encode-rho-assignment assignments))))

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

(defun encode-state-rho (rho)
  "Encode ρ to state binary — uses rho closure's memoized encoding.
   Args: rho — rho closure
   Returns: byte array"
  (funcall rho :encoded))

(defun decode-state-rho (bytes &optional (offset 0))
  "Decode ρ from state binary — reads exactly num-cores Option assignments.
   Returns: (values rho-closure total-bytes-consumed)"
  (let ((assignments '())
        (pos offset)
        (c (num-cores)))
    (dotimes (i c)
      (multiple-value-bind (assignment size)
          (decode-rho-assignment bytes pos)
        (push assignment assignments)
        (incf pos size)))
    (values (make-rho :assignments (nreverse assignments)) (- pos offset))))

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
         rho — rho closure
   Returns: ρ† rho closure (with invalidated cores set to nil)"
  (let ((assignments (funcall rho :assignments)))
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
                (make-rho :assignments
              (mapcar (lambda (assignment)
                        (let ((h (assignment-report-hash assignment)))
                          (if (and h (member-hash h invalidated-targets))
                              nil
                              assignment)))
                          assignments))))))))

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
     rho-dagger   — ρ† rho closure
     tau-prime    — τ' closure (tau-state)
     parent-hash  — H_P (parent header hash)
     kappa        — κ closure
   
   Returns: (values ρ‡-closure R* [error])
     ρ‡ — rho closure with available/stale cores cleared (11.17)
     R* — available work-reports (11.16)
     error — assurance-error if validation failed (ρ‡=ρ†, R*=nil)"
  (let* ((tau-prime-val (funcall tau-prime :value))   ;; raw number for arithmetic
         (assignments (funcall rho-dagger :assignments))
         (kappa-keys (funcall kappa :validators)))
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
            (validate-assurance-cores-engaged a assignments)  ;; (11.15)
          (validate-assurance-signature a kappa-keys parent-hash)) ;; (11.13)
        ;; ── (11.16) R: count votes, find available cores ────
        (let* ((c (num-cores))
               (votes (count-core-votes assurances c))
               (threshold (super-majority))  ;; > ⅔V ≡ ≥ ⌊2V/3⌋+1
               ;; ── (11.17) Build ρ‡ and R* in one pass ─────
               (reported '())
               (new-assignments
                 (loop for ci below c
                         for assignment in assignments
                       collect
                       (cond
                         ;; No assignment → stays nil
                         ((null assignment) nil)
                         ;; (11.16) Supermajority → available → R* + clear
                         ((>= (aref votes ci) threshold)
                          (push (getf assignment :report) reported)
                          nil)
                        ;; (11.17) Stale: H_T ≥ t + U → clear (not reported)
                        ((report-stale-p (getf assignment :timeout) tau-prime-val)
                         nil)
                         ;; Otherwise → keep
                         (t assignment)))))
            (values (make-rho :assignments new-assignments) (nreverse reported))))
    ;; ── Error path ─────────────────────────────────────────
    (assurance-error (e)
        (values rho-dagger nil e)))))

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
;;;
;;; Full STF for guarantee registration.
;;;
;;; Inputs:
;;;   EG — guarantees extrinsic (list of {report, slot, signatures})
;;;   ρ‡ — core assignments after assurances
;;;   κ  — current validator keys   λ — previous validator keys
;;;   η  — entropy (4 hashes)       ψO — offenders (ed25519 keys)
;;;   β  — recent blocks (history + mmr)
;;;   α  — auth pools (C lists of hashes)
;;;   δ  — accounts (list of {id, data})
;;;   τ' — block timeslot
;;;   known-packages — set of previously seen work-package hashes
;;;
;;; Outputs:
;;;   ρ' — assignments with new guarantees registered
;;;   reported — list of (:work-package-hash h :segment-tree-root r)
;;;   reporters — flat list of guarantor ed25519 keys
;;;   cores-statistics-prime — updated cores statistics
;;;   services-statistics-prime — updated services statistics
;;;
;;; Error codes (from test vectors / ASN schema):
;;;   bad-core-index (0)        future-report-slot (1)
;;;   report-epoch-before-last (2)  insufficient-guarantees (3)
;;;   out-of-order-guarantee (4)    not-sorted-or-unique-guarantors (5)
;;;   wrong-assignment (6)          core-engaged (7)
;;;   anchor-not-recent (8)         bad-service-id (9)
;;;   bad-code-hash (10)            dependency-missing (11)
;;;   duplicate-package (12)        bad-state-root (13)
;;;   bad-beefy-mmr-root (14)       core-unauthorized (15)
;;;   bad-validator-index (16)      work-report-gas-too-high (17)
;;;   service-item-gas-too-low (18) too-many-dependencies (19)
;;;   segment-root-lookup-invalid (20)  bad-signature (21)
;;;   work-report-too-big (22)      banned-validator (23)
;;;   lookup-anchor-not-recent (24) missing-work-results (25)

;;; ─────────────────────────────────────────────────────────────────
;;; Error condition
;;; ─────────────────────────────────────────────────────────────────

(define-condition guarantee-error (error)
  ((code   :initarg :code   :reader guarantee-error-code)
   (detail :initarg :detail :reader guarantee-error-detail
           :initform nil))
  (:report (lambda (c s)
             (format s "Guarantee error ~A~@[: ~A~]"
                     (guarantee-error-code c)
                     (guarantee-error-detail c)))))

(defun reject-guarantee (code &optional detail)
  "Signal a guarantee validation error."
  (error 'guarantee-error :code code :detail detail))

;;; ─────────────────────────────────────────────────────────────────
;;; Guarantee signing payload (GP 11.26)
;;; ─────────────────────────────────────────────────────────────────

(defun guarantee-signing-payload (report-hash)
  "(11.26) Guarantee signing payload.
   X_G ≡ $jam_guarantee
   message = X_G ~ H(E(w))
   i.e. 'jam_guarantee' ++ blake2b-256(encoded-work-report)
   
   Args: report-hash — H(E(w)), blake2b-256 of encoded work report (32 bytes)
   Returns: byte array (the message that was signed)"
  (concatenate '(vector (unsigned-byte 8))
               +ctx-guarantee+
               (ensure-bytes report-hash)))

;;; ─────────────────────────────────────────────────────────────────
;;; Guarantor Assignments M/M* (GP 11.18-11.22)
;;; ─────────────────────────────────────────────────────────────────

(defun phi-filter (validators offenders)
  "(11.21) Φ(k)_v ≡ {v | v ∈ N_V, k[v]_e ∉ ψ_O}
   Returns the set of non-banned validator indices.
   Args: validators — list of full validator plists
         offenders — list of banned Ed25519 keys
   Returns: list of valid validator indices"
  (if (null offenders)
      ;; No offenders → all validators valid
      (loop for i from 0 below (length validators) collect i)
      (loop for v in validators
            for i from 0
            unless (member (getf v :ed25519) offenders :test #'equalp)
            collect i)))

(defun guarantor-assignments (entropy slot kappa offenders)
  "(11.19) M = P(η₂, τ'), Φ(κ)
   Compute validator-to-core assignments for the CURRENT rotation.
   
   Args: entropy — η₂ (32-byte hash)
         slot — τ' (block timeslot)
         kappa — current validators (list of plists)
         offenders — list of banned Ed25519 keys
   Returns: vector of length V where M[v] = core assigned to validator v,
            or nil for banned validators"
  (let* ((v (length kappa))
         (c (num-cores))
         (e (epoch-duration))
         (r (rotation-period))
         ;; P(entropy, slot) — raw core assignments
         (raw-assignments (compute-core-assignments
                           (ensure-bytes entropy) slot v c e r))
         ;; Φ(kappa) — non-banned validator indices
         (valid-set (phi-filter kappa offenders))
         ;; Build result: nil for banned, core index for valid
         (result (make-array v :initial-element nil)))
    (dotimes (i v)
      (when (member i valid-set)
        (setf (aref result i) (aref raw-assignments i))))
    result))

(defun guarantor-assignments-star (eta slot guarantee-slot
                                   kappa lambda-prev offenders)
  "(11.22) M*(w) — assignments for PREVIOUS rotation.
   If ⌊τ'/E⌋ ≠ ⌊t(w)/E⌋ → e = η₃, k = λ (previous epoch)
   Otherwise → e = η₂, k = κ (same epoch, previous rotation)
   
   Args: eta — full entropy closure (responds to :eta-0 .. :eta-3)
         slot — τ' (block timeslot, raw number)
         guarantee-slot — t (guarantee timeslot)
         kappa — current validators
         lambda-prev — previous validators
         offenders — list of banned Ed25519 keys
   Returns: vector of length V where M*[v] = core assigned, nil for banned"
  (let* ((block-epoch     (floor slot (epoch-duration)))
         (guarantee-epoch (floor guarantee-slot (epoch-duration)))
         ;; Choose entropy and validators based on epoch comparison
         (different-epoch-p (/= block-epoch guarantee-epoch))
         (entropy (if different-epoch-p
                      (funcall eta :eta-3)  ;; η₃ for previous epoch
                      (funcall eta :eta-2))) ;; η₂ for same epoch
         (validators (if different-epoch-p
                         lambda-prev  ;; λ for previous epoch
                         kappa))      ;; κ for same epoch
         (v (length validators))
         (c (num-cores))
         ;; P(e, t) — compute at the guarantee slot
         (raw-assignments (compute-core-assignments
                           (ensure-bytes entropy) guarantee-slot v c
                           (epoch-duration) (rotation-period)))
         ;; Φ(k) — non-banned validators
         (valid-set (phi-filter validators offenders))
         (result (make-array v :initial-element nil)))
    (dotimes (i v)
      (when (member i valid-set)
        (setf (aref result i) (aref raw-assignments i))))
    result))

(defun assignments-for-guarantee (slot guarantee-slot eta kappa lambda-prev offenders)
  "Select M or M* based on whether the guarantee is in the current rotation.
   ⌊τ'/R⌋ = ⌊t/R⌋ → current rotation → M
   Otherwise → previous rotation → M*"
  (if (= (floor slot (rotation-period)) (floor guarantee-slot (rotation-period)))
      ;; Same rotation → M = P(η₂, τ')
      (guarantor-assignments (funcall eta :eta-2) slot kappa offenders)
      ;; Different rotation → M*
      (guarantor-assignments-star eta slot guarantee-slot
                                  kappa lambda-prev offenders)))

;;; ─────────────────────────────────────────────────────────────────
;;; Validation helpers
;;; ─────────────────────────────────────────────────────────────────

(defun validate-guarantees-sorted-unique (guarantees)
  "(11.24) Guarantees must be sorted by core index (ascending, unique).
   ∀i ∈ {1..|EG|}: EG[i-1].r.c < EG[i].r.c"
  (loop for (a b) on guarantees while b
        do (let ((ca (getf (getf a :report) :core-index))
                 (cb (getf (getf b :report) :core-index)))
             (unless (< ca cb)
               (reject-guarantee :out-of-order-guarantee
                                 (format nil "core ~A >= core ~A" ca cb))))))

(defun validate-guarantee-core-index (report)
  "Core index must be < C."
  (let ((c (getf report :core-index)))
    (when (>= c (num-cores))
      (reject-guarantee :bad-core-index
                        (format nil "core ~A >= C=~A" c (num-cores))))))

(defun validate-guarantee-results-present (report)
  "Work report must have at least one result."
  (let ((results (getf report :results)))
    (when (or (null results) (zerop (length results)))
      (reject-guarantee :missing-work-results))))

(defun validate-guarantee-slot-age (guarantee-slot tau-prime-val)
  "(11.26) t ≤ τ' (not in future) AND t ≥ R·max(0,⌊τ'/R⌋-1) (not before last rotation).
   tau-prime-val is the raw τ' timeslot number."
  (when (> guarantee-slot tau-prime-val)
    (reject-guarantee :future-report-slot
                      (format nil "t=~A > τ'=~A" guarantee-slot tau-prime-val)))
  (let* ((r (rotation-period))
         (min-slot (* r (max 0 (1- (floor tau-prime-val r))))))
    (when (< guarantee-slot min-slot)
      (reject-guarantee :report-epoch-before-last
                        (format nil "t=~A < ~A" guarantee-slot min-slot)))))

(defun validate-guarantee-sufficient-signatures (signatures)
  "(11.23) |a| ≥ 2 — at least 2 guarantor signatures."
  (when (< (length signatures) 2)
    (reject-guarantee :insufficient-guarantees
                      (format nil "|sigs|=~A < 2" (length signatures)))))

(defun validate-guarantee-signatures-sorted-unique (signatures)
  "(11.25) Signatures must be sorted by validator index, strictly ascending."
  (loop for (a b) on signatures while b
        do (let ((va (getf a :validator-index))
                 (vb (getf b :validator-index)))
             (unless (< va vb)
               (reject-guarantee :not-sorted-or-unique-guarantors
                                 (format nil "v[~A] >= v[~A]" va vb))))))

(defun validate-guarantee-validator-index (signature)
  "Validator index must be < V."
  (let ((idx (getf signature :validator-index)))
    (when (>= idx (num-validators))
      (reject-guarantee :bad-validator-index
                        (format nil "index ~A >= V=~A" idx (num-validators))))))

(defun validate-guarantee-not-banned (signature kappa offenders)
  "(11.21) Validator must not be in offenders set ψ_O."
  (let* ((idx (getf signature :validator-index))
         (validator (elt kappa idx))
         (ed-key (getf validator :ed25519)))
    (when (member ed-key offenders :test #'equalp)
      (reject-guarantee :banned-validator
                        (format nil "validator ~A is banned" idx)))))

(defun validate-guarantee-core-assignment (signature core-index assignments)
  "(11.26) Validator must be assigned to this core in M or M*.
   assignments[v] = assigned core for validator v."
  (let* ((idx (getf signature :validator-index))
         (assigned-core (when (< idx (length assignments))
                          (aref assignments idx))))
    (unless (and assigned-core (= assigned-core core-index))
      (reject-guarantee :wrong-assignment
                        (format nil "v[~A] assigned to core ~A, not ~A"
                                idx assigned-core core-index)))))

(defun validate-guarantee-signature (signature report-hash kappa
                                     guarantee-slot eta lambda-prev offenders)
  "(11.26) Ed25519 signature verification.
   s ∈ V̄_{k[v]_e}(X_G ~ H(E(w)))
   Uses kappa or lambda based on epoch comparison."
  (let* ((idx (getf signature :validator-index))
         (sig-bytes (ensure-bytes (getf signature :signature)))
         ;; Determine which validator set to use
         (block-epoch (funcall *current-tau-prime* :epoch))
         (guarantee-epoch (floor guarantee-slot (epoch-duration)))
         (validators (if (/= block-epoch guarantee-epoch) lambda-prev kappa))
         (validator (elt validators idx))
         (ed-key (ensure-bytes (getf validator :ed25519)))
         (message (guarantee-signing-payload report-hash)))
    (unless (jam.ffi:ed25519-verify ed-key message sig-bytes)
      (reject-guarantee :bad-signature
                        (format nil "validator ~A" idx)))))

(defun validate-guarantee-core-not-engaged (core-index rho-ddagger)
  "Core must not already have an assignment in ρ‡."
  (when (nth core-index rho-ddagger)
    (reject-guarantee :core-engaged
                      (format nil "core ~A already assigned" core-index))))

(defun validate-guarantee-anchor (report recent-blocks)
  "Context anchor must be in recent blocks history and match state-root + beefy-root."
  (let* ((ctx (getf report :context))
         (anchor (ensure-bytes (getf ctx :anchor)))
         (state-root (ensure-bytes (getf ctx :state-root)))
         (beefy-root (ensure-bytes (getf ctx :beefy-root)))
         (history (funcall recent-blocks :history))
         ;; Find the anchor in history
         (record (find-if (lambda (rec)
                            (equalp (ensure-bytes (getf rec :header-hash)) anchor))
                          history)))
    (unless record
      (reject-guarantee :anchor-not-recent))
    ;; Validate state-root matches
    (unless (equalp (ensure-bytes (getf record :state-root)) state-root)
      (reject-guarantee :bad-state-root))
    ;; Validate beefy-root matches
    (unless (equalp (ensure-bytes (getf record :beefy-root)) beefy-root)
      (reject-guarantee :bad-beefy-mmr-root))))

(defun validate-guarantee-lookup-anchor (report tau-prime recent-blocks)
  "Lookup anchor must be recent enough and within L timeslots."
  (let* ((ctx (getf report :context))
         (lookup-anchor (ensure-bytes (getf ctx :lookup-anchor)))
         (lookup-anchor-slot (getf ctx :lookup-anchor-slot))
         (history (funcall recent-blocks :history)))
    ;; lookup-anchor must exist in recent history
    (when (and lookup-anchor-slot
               (> lookup-anchor-slot 0)
               (> (- tau-prime lookup-anchor-slot) +max-lookup-anchor-age+))
      (reject-guarantee :lookup-anchor-not-recent
                        (format nil "lookup anchor slot ~A too old (τ'=~A, L=~A)"
                                lookup-anchor-slot tau-prime +max-lookup-anchor-age+)))
    ;; If lookup-anchor is non-zero, verify it exists in history
    (when (and lookup-anchor
               (not (every #'zerop lookup-anchor))
               (not (find-if (lambda (rec)
                               (equalp (ensure-bytes (getf rec :header-hash))
                                       lookup-anchor))
                             history)))
      (reject-guarantee :lookup-anchor-not-recent))))

(defun validate-guarantee-service-ids (report accounts)
  "All service IDs in work results must exist in accounts."
  (dolist (result (getf report :results))
    (let* ((service-id (getf result :service-id))
           (account (find service-id accounts
                         :key (lambda (a) (getf a :id)))))
      (unless account
        (reject-guarantee :bad-service-id
                          (format nil "service ~A not found" service-id))))))

(defun validate-guarantee-code-hashes (report accounts)
  "Code hashes in work results must match the service's code hash."
  (dolist (result (getf report :results))
    (let* ((service-id (getf result :service-id))
           (code-hash (ensure-bytes (getf result :code-hash)))
           (account (find service-id accounts
                         :key (lambda (a) (getf a :id))))
           (expected-hash (when account
                            (ensure-bytes
                             (getf (getf account :service) :code-hash)))))
      (when (and expected-hash (not (equalp code-hash expected-hash)))
        (reject-guarantee :bad-code-hash
                          (format nil "service ~A code hash mismatch" service-id))))))

(defun validate-guarantee-authorization (report auth-pools)
  "Authorizer hash must be in the auth pool for this core."
  (let* ((core-index (getf report :core-index))
         (auth-hash (ensure-bytes (getf report :authorizer-hash)))
         (pool (when (< core-index (length auth-pools))
                 (nth core-index auth-pools))))
    (unless (member auth-hash pool :test #'equalp)
      (reject-guarantee :core-unauthorized
                        (format nil "core ~A authorizer not in pool" core-index)))))

(defun validate-guarantee-gas (report)
  "Total accumulate gas must not exceed GA (accumulation-gas)."
  (let ((total-gas (reduce #'+ (getf report :results)
                           :key (lambda (r) (getf r :accumulate-gas))
                           :initial-value 0)))
    (when (> total-gas +accumulation-gas+)
      (reject-guarantee :work-report-gas-too-high
                        (format nil "total gas ~A > GA=~A"
                                total-gas +accumulation-gas+)))))

(defun validate-guarantee-item-gas (report accounts)
  "Each work result's accumulate gas must be >= the service's min_item_gas."
  (dolist (result (getf report :results))
    (let* ((service-id (getf result :service-id))
           (acc-gas (getf result :accumulate-gas))
           (account (find service-id accounts
                         :key (lambda (a) (getf a :id))))
           (min-gas (when account
                      (getf (getf account :service) :min-item-gas))))
      (when (and min-gas (< acc-gas min-gas))
        (reject-guarantee :service-item-gas-too-low
                          (format nil "service ~A: gas ~A < min ~A"
                                  service-id acc-gas min-gas))))))

(defun validate-guarantee-dependencies-count (report)
  "Total dependencies (prerequisites + segment_root_lookup) must be ≤ J."
  (let* ((ctx (getf report :context))
         (prereqs (or (getf ctx :prerequisites) '()))
         (srl (or (getf report :segment-root-lookup) '()))
         (total (+ (length prereqs) (length srl))))
    (when (> total +max-dependencies+)
      (reject-guarantee :too-many-dependencies
                        (format nil "deps ~A > J=~A" total +max-dependencies+)))))

(defun validate-guarantee-output-size (report)
  "Total output size (auth_output + sum of OK result outputs) must be ≤ WR."
  (let ((total-size (length (ensure-bytes (getf report :auth-output)))))
    (dolist (result (getf report :results))
      (let ((result-val (getf result :result)))
        (when (and (eq (first result-val) :ok) (second result-val))
          (incf total-size (length (ensure-bytes (second result-val)))))))
    (when (> total-size +max-unbounded-blob-size+)
      (reject-guarantee :work-report-too-big
                        (format nil "output size ~A > WR=~A"
                                total-size +max-unbounded-blob-size+)))))

(defun collect-known-package-hashes (recent-blocks)
  "Collect all work-package hashes from recent blocks history reported entries."
  (let ((hashes '()))
    (dolist (record (funcall recent-blocks :history))
      (dolist (rp (getf record :reported))
        (push (ensure-bytes (getf rp :hash)) hashes)))
    hashes))

(defun validate-guarantee-not-duplicate (report known-packages seen-hashes)
  "Work package hash must not be in known-packages or already seen in this extrinsic."
  (let ((pkg-hash (ensure-bytes (getf (getf report :package-spec) :hash))))
    ;; Check against known packages from input
    (when (member pkg-hash known-packages :test #'equalp)
      (reject-guarantee :duplicate-package
                        "package in known_packages"))
    ;; Check against packages already seen in this EG batch
    (when (member pkg-hash seen-hashes :test #'equalp)
      (reject-guarantee :duplicate-package
                        "duplicate package in extrinsic"))))

(defun validate-guarantee-dependencies (report recent-blocks all-guarantees)
  "Prerequisites must be found in recent history or other guarantees in EG."
  (let* ((ctx (getf report :context))
         (prereqs (or (getf ctx :prerequisites) '()))
         ;; Collect all available hashes: from recent history + from other guarantees
         (history-hashes (collect-known-package-hashes recent-blocks))
         (eg-hashes (mapcar (lambda (g)
                              (ensure-bytes
                               (getf (getf (getf g :report) :package-spec) :hash)))
                            all-guarantees)))
    (dolist (prereq prereqs)
      (let ((h (ensure-bytes prereq)))
        (unless (or (member h history-hashes :test #'equalp)
                    (member h eg-hashes :test #'equalp))
          (reject-guarantee :dependency-missing
                            (format nil "prerequisite ~A not found"
                                    (jam.ffi:bytes-to-hex-string h))))))))

(defun validate-guarantee-segment-root-lookup (report recent-blocks all-guarantees)
  "Each segment_root_lookup entry must be satisfied by history or other guarantees.
   The work_package_hash must exist and the segment_tree_root must match exports_root."
  (let ((srl (or (getf report :segment-root-lookup) '())))
    (dolist (item srl)
      (let* ((wp-hash (ensure-bytes (getf item :work-package-hash)))
             (expected-root (ensure-bytes (getf item :segment-tree-root)))
             (found nil))
        ;; Search in other guarantees in EG
        (dolist (g all-guarantees)
          (let* ((other-report (getf g :report))
                 (other-spec (getf other-report :package-spec))
                 (other-hash (ensure-bytes (getf other-spec :hash)))
                 (other-root (ensure-bytes (getf other-spec :exports-root))))
            (when (equalp wp-hash other-hash)
              (if (equalp expected-root other-root)
                  (setf found t)
                  (reject-guarantee :segment-root-lookup-invalid
                                    "exports_root mismatch in EG")))))
        (unless found
          ;; Search in recent history
          (dolist (record (funcall recent-blocks :history))
            (dolist (rp (getf record :reported))
              (when (equalp wp-hash (ensure-bytes (getf rp :hash)))
                (if (equalp expected-root
                            (ensure-bytes (getf rp :exports-root)))
                    (setf found t)
                    (reject-guarantee :segment-root-lookup-invalid
                                      "exports_root mismatch in history"))))))
        (unless found
          (reject-guarantee :segment-root-lookup-invalid
                            "work_package_hash not found"))))))

;;; ─────────────────────────────────────────────────────────────────
;;; Output computation
;;; ─────────────────────────────────────────────────────────────────

(defun compute-output-packages-and-reporters (guarantees kappa lambda-prev tau-prime)
  "Compute reported packages and reporters from validated guarantees.
   kappa/lambda-prev are closures. tau-prime is τ' closure (tau-state).
   reported = list of (:work-package-hash h :segment-tree-root r)
   reporters = UNIQUE ed25519 keys of all guarantors, sorted lexicographically."
  (let ((reported '())
        (reporter-keys '())
        (kappa-keys (funcall kappa :validators))
        (lambda-keys (funcall lambda-prev :validators))
        (block-epoch (funcall tau-prime :epoch)))
    (dolist (g guarantees)
      (let* ((report (getf g :report))
             (spec (getf report :package-spec))
             (guarantee-slot (getf g :slot))
             (guarantee-epoch (floor guarantee-slot (epoch-duration)))
             (validators (if (/= block-epoch guarantee-epoch) lambda-keys kappa-keys)))
        ;; Add to reported
        (push (list :work-package-hash (ensure-bytes (getf spec :hash))
                    :segment-tree-root (ensure-bytes (getf spec :exports-root)))
              reported)
        ;; Collect guarantor ed25519 keys (deduplicate later)
        (dolist (sig (getf g :signatures))
          (let* ((idx (getf sig :validator-index))
                 (validator (elt validators idx))
                 (ed-key (ensure-bytes (getf validator :ed25519))))
            (unless (member ed-key reporter-keys :test #'equalp)
              (push ed-key reporter-keys))))))
    ;; Sort reporters lexicographically by raw bytes
    (let ((sorted-reporters
            (sort (nreverse reporter-keys) #'bytes<))
          ;; Sort reported lexicographically by work-package-hash
          (sorted-reported
            (sort (nreverse reported)
                  (lambda (a b)
                    (bytes< (ensure-bytes (getf a :work-package-hash))
                            (ensure-bytes (getf b :work-package-hash)))))))
      (values sorted-reported sorted-reporters))))

;;; bytes< is defined in codec/types.lisp (mutualized utility)

;;; ─────────────────────────────────────────────────────────────────
;;; Statistics computation
;;; ─────────────────────────────────────────────────────────────────

(defun update-cores-statistics (cores-statistics guarantees)
  "Update cores statistics with data from validated guarantees.
   For each guarantee, update the core's stats from refine_load data."
  (let ((result (mapcar #'copy-list (or cores-statistics '()))))
    ;; Ensure we have enough entries
    (loop while (< (length result) (num-cores))
          do (push (list :da-load 0 :popularity 0 :imports 0
                         :extrinsic-count 0 :extrinsic-size 0
                         :exports 0 :bundle-size 0 :gas-used 0)
                   result))
    (setf result (nreverse result))
    (dolist (g guarantees)
      (let* ((report (getf g :report))
             (core-index (getf report :core-index))
             (results (getf report :results))
             (spec (getf report :package-spec))
             (core-stat (nth core-index result))
             ;; Aggregate refine_load across all results
             (total-gas 0) (total-imports 0) (total-exports 0)
             (total-ext-count 0) (total-ext-size 0))
        (dolist (r results)
          (let ((rl (getf r :refine-load)))
            (incf total-gas (or (getf rl :gas-used) 0))
            (incf total-imports (or (getf rl :imports) 0))
            (incf total-exports (or (getf rl :exports) 0))
            (incf total-ext-count (or (getf rl :extrinsic-count) 0))
            (incf total-ext-size (or (getf rl :extrinsic-size) 0))))
        ;; Update core stats
        (when core-stat
          (incf (getf core-stat :imports) total-imports)
          (incf (getf core-stat :extrinsic-count) total-ext-count)
          (incf (getf core-stat :extrinsic-size) total-ext-size)
          (incf (getf core-stat :exports) total-exports)
          (incf (getf core-stat :bundle-size) (or (getf spec :length) 0))
          (incf (getf core-stat :gas-used) total-gas))))
    result))

(defun update-services-statistics (services-statistics guarantees)
  "Update services statistics with data from validated guarantees.
   Aggregate refine_load by service_id across all work results."
  (let ((accum (make-hash-table :test 'equal)))
    ;; Initialize from existing stats
    (dolist (ss (or services-statistics '()))
      (let ((id (getf ss :id))
            (rec (getf ss :record)))
        (setf (gethash id accum)
              (list :provided-count (or (getf rec :provided-count) 0)
                    :provided-size (or (getf rec :provided-size) 0)
                    :refinement-count (or (getf rec :refinement-count) 0)
                    :refinement-gas-used (or (getf rec :refinement-gas-used) 0)
                    :imports (or (getf rec :imports) 0)
                    :extrinsic-count (or (getf rec :extrinsic-count) 0)
                    :extrinsic-size (or (getf rec :extrinsic-size) 0)
                    :exports (or (getf rec :exports) 0)
                    :accumulate-count (or (getf rec :accumulate-count) 0)
                    :accumulate-gas-used (or (getf rec :accumulate-gas-used) 0)))))
    ;; Accumulate from guarantees
    (dolist (g guarantees)
      (let ((results (getf (getf g :report) :results)))
        (dolist (r results)
          (let* ((sid (getf r :service-id))
                 (rl (getf r :refine-load))
                 (entry (or (gethash sid accum)
                            (setf (gethash sid accum)
                                  (list :provided-count 0 :provided-size 0
                                        :refinement-count 0 :refinement-gas-used 0
                                        :imports 0 :extrinsic-count 0
                                        :extrinsic-size 0 :exports 0
                                        :accumulate-count 0 :accumulate-gas-used 0)))))
            (incf (getf entry :refinement-count) 1)
            (incf (getf entry :refinement-gas-used) (or (getf rl :gas-used) 0))
            (incf (getf entry :imports) (or (getf rl :imports) 0))
            (incf (getf entry :extrinsic-count) (or (getf rl :extrinsic-count) 0))
            (incf (getf entry :extrinsic-size) (or (getf rl :extrinsic-size) 0))
            (incf (getf entry :exports) (or (getf rl :exports) 0))))))
    ;; Build sorted result
    (let ((result '()))
      (maphash (lambda (id rec)
                 (push (list :id id :record rec) result))
               accum)
      (sort result #'< :key (lambda (x) (getf x :id))))))

;;; ─────────────────────────────────────────────────────────────────
;;; Dynamic binding for tau-prime (used in signature validation)
;;; ─────────────────────────────────────────────────────────────────

(defvar *current-tau-prime* nil
  "Dynamically bound during transition-rho for use in signature verification.")

;;; ─────────────────────────────────────────────────────────────────
;;; Main: transition-rho
;;; ─────────────────────────────────────────────────────────────────

(defun transition-rho (guarantees rho-ddagger
                       &key tau-prime kappa lambda-prev eta
                            offenders recent-blocks auth-pools
                            accounts)
  "GP §11-12 — (4.14) ρ' ≺ (EG, ρ‡, κ, τ')
   Validates EG, registers guaranteed work-reports into ρ'.
   All-or-nothing: signals guarantee-error if any guarantee is invalid.

   The valid guarantees are implicitly encoded in ρ' (filled slots vs ρ‡).
   Downstream transitions derive their own outputs from EG directly:
     β' (4.17) computes reported packages from EG
     π' (4.20) computes reporters and statistics from EG
   
   Args:
     guarantees    — EG (list of guarantee plists)
     rho-ddagger   — ρ‡ rho closure
     tau-prime     — τ' closure (tau-state)
     kappa         — κ closure
     lambda-prev   — λ closure
     eta           — η closure
     offenders     — ψ_O (list of banned Ed25519 keys)
     recent-blocks — β closure (:history :mmr-peaks)
     auth-pools    — α (list of C lists of authorizer hashes)
     accounts      — δ (list of {:id :service} plists)
   
   Returns: ρ' rho closure
   Signals: guarantee-error on validation failure"
  ;; All-or-nothing: guarantee-error propagates to caller on failure.
  (let* ((*current-tau-prime* tau-prime)   ;; τ' closure, for :epoch access
         (tau-prime-val (funcall tau-prime :value))  ;; raw number for arithmetic
         ;; Extract raw validator lists from closures
         (kappa-keys (funcall kappa :validators))
         (lambda-keys (funcall lambda-prev :validators))
         (assignments (funcall rho-ddagger :assignments)))
    ;; No guarantees → ρ' = ρ‡
    (when (null guarantees)
      (return-from transition-rho rho-ddagger))
    ;; ── Phase 1: EG-level structural checks ───────────────
    (validate-guarantees-sorted-unique guarantees)
    ;; ── Phase 2: Per-guarantee validation + registration ──
    (let ((seen-hashes '())
          (known-packages (collect-known-package-hashes recent-blocks))
          (rho-prime (copy-list assignments)))
      (dolist (g guarantees)
        (let* ((report (getf g :report))
               (guarantee-slot (getf g :slot))
               (signatures (getf g :signatures))
               (core-index (getf report :core-index))
               (report-bytes (encode-work-report report))
               (report-hash (blake2b-256 report-bytes))
               ;; Compute assignments for this guarantee
               (core-assignments
                 (assignments-for-guarantee
                  tau-prime-val guarantee-slot eta kappa-keys lambda-keys offenders)))
          ;; -- Basic report checks --
          (validate-guarantee-core-index report)
          (validate-guarantee-results-present report)
          (validate-guarantee-core-not-engaged core-index assignments)
          (validate-guarantee-slot-age guarantee-slot tau-prime-val)
          ;; -- Signature checks --
          (validate-guarantee-sufficient-signatures signatures)
          (validate-guarantee-signatures-sorted-unique signatures)
          (dolist (sig signatures)
            (validate-guarantee-validator-index sig)
            (validate-guarantee-not-banned sig kappa-keys offenders)
            (validate-guarantee-core-assignment sig core-index core-assignments)
            (validate-guarantee-signature
             sig report-hash kappa-keys guarantee-slot eta lambda-keys offenders))
          ;; -- Content checks --
          (validate-guarantee-anchor report recent-blocks)
          (validate-guarantee-lookup-anchor report tau-prime-val recent-blocks)
          (validate-guarantee-service-ids report accounts)
          (validate-guarantee-code-hashes report accounts)
          (validate-guarantee-authorization report auth-pools)
          (validate-guarantee-gas report)
          (validate-guarantee-item-gas report accounts)
          (validate-guarantee-dependencies-count report)
          (validate-guarantee-output-size report)
          (validate-guarantee-not-duplicate report known-packages seen-hashes)
          (validate-guarantee-dependencies report recent-blocks guarantees)
          (validate-guarantee-segment-root-lookup report recent-blocks guarantees)
          ;; -- All checks passed: register guarantee --
          (push (ensure-bytes (getf (getf report :package-spec) :hash))
                seen-hashes)
          (setf (nth core-index rho-prime)
                (list :report report :timeout tau-prime-val))))
      (make-rho :assignments rho-prime))))

;;; Exports managed in package.lisp
