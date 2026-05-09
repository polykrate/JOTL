;;;; state/rho.lisp — ρ Core Assignments / Availability (GP §10-12)
;;;;
;;;; ρ ∈ ⟦Option<(r: WorkReport, t: U32)>⟧_C   (C = num-cores)
;;;;
;;;; Three transformation stages across waves:
;;;;   Wave 1: ρ†  < (ED, ρ)         — disputes invalidate (§10.15)
;;;;   Wave 2: ρ‡  < (EA, ρ†)        — assurances confirm  (§11.10-11.17)
;;;;           R*  < (EA, ρ†)        — available reports   (§11.16)
;;;;   Wave 3: ρ'  < (EG, ρ‡, κ, τ') — guarantees register (§11.18-12)
;;;;
;;;; State key: C(10)
;;;;
;;;; Messages:
;;;;   :assignments       → list of C slots (nil | (:report wr :timeout t))
;;;;   :core-count        → (length assignments)
;;;;   :offender-auth-hashes (disputes) → auth code hashes to ban from α (GP 4.19)
;;;;   :save              → binary encoding (memoized)
;;;;   :transition-dagger (&key v-list)
;;;;   :transition-ddagger (&key assurances tau-prime parent-hash kappa)
;;;;       → ρ‡  (R* via :reported message)
;;;;   :transition (&key guarantees tau-prime kappa lambda-prev eta
;;;;                     psi-prime recent-blocks alpha delta) 

(in-package #:jotl)

;;; ═══════════════════════════════════════════════════════════════
;;; ERROR CONDITIONS
;;; ═══════════════════════════════════════════════════════════════

(define-condition assurance-error (error)
  ((code   :initarg :code   :reader assurance-error-code)
   (detail :initarg :detail :reader assurance-error-detail
           :initform nil))
  (:report (lambda (c s)
             (format s "Assurance error: ~A~@[ — ~A~]"
                     (assurance-error-code c)
                     (assurance-error-detail c)))))

(define-condition guarantee-error (error)
  ((code   :initarg :code   :reader guarantee-error-code)
   (detail :initarg :detail :reader guarantee-error-detail
           :initform nil))
  (:report (lambda (c s)
             (format s "Guarantee error: ~A~@[ — ~A~]"
                     (guarantee-error-code c)
                     (guarantee-error-detail c)))))

(defun reject-assurance (code &optional detail)
  (error 'assurance-error :code code :detail detail))

(defun reject-guarantee (code &optional detail)
  (error 'guarantee-error :code code :detail detail))

;;; ═══════════════════════════════════════════════════════════════
;;; PER-ELEMENT CODEC — Option<(WorkReport, U32)>
;;; ═══════════════════════════════════════════════════════════════

(defun encode-rho-assignment (assignment)
  "Encode a single core assignment (Option).
   nil → [0x00], plist → [0x01] || E(report) || E4(timeout)"
  (if (null assignment)
      #(0)
      (let* ((report-bytes (encode-work-report (getf assignment :report)))
             (timeout-bytes (encode-u32 (getf assignment :timeout)))
             (buf (make-array (+ 1 (length report-bytes) (length timeout-bytes))
                              :element-type '(unsigned-byte 8))))
        (setf (aref buf 0) 1)
        (replace buf report-bytes :start1 1)
        (replace buf timeout-bytes :start1 (+ 1 (length report-bytes)))
        buf)))

(defun load-rho-assignment (bytes offset)
  "Decode a single core assignment (Option).
   Returns: (values assignment-or-nil bytes-consumed)"
  (let ((tag (aref bytes offset)))
    (if (zerop tag)
        (values nil 1)
        (let ((pos (1+ offset)))
          (multiple-value-bind (report report-size) (decode-work-report bytes pos)
            (incf pos report-size)
            (multiple-value-bind (timeout timeout-size) (decode-u32 bytes pos)
              (incf pos timeout-size)
              (values (list :report report :timeout timeout)
                      (- pos offset))))))))

;;; ═══════════════════════════════════════════════════════════════
;;; PROTOCOL HELPERS
;;; ═══════════════════════════════════════════════════════════════

(defun assignment-report-hash (assignment)
  "H(ρ[c]_r) — blake2b-256 of the encoded work-report. nil if empty."
  (when assignment
    (let ((report (getf assignment :report)))
      (when report
        (blake2b-256 (encode-work-report report))))))

(defun report-stale-p (timeout tau-prime-val)
  "(11.17) H_T ≥ ρ†[c]_t + U
   A report is stale when the block timeslot reaches timeout + U.
   U = +availability-timeout+ = 5 (fixed protocol constant).
   Verified against test vectors:
     tiny: t=7,  τ'=12,  12≥12 → removed
     tiny: t=11, τ'=12,  12≥16 → kept
     full: t=595, τ'=600, 600≥600 → removed
     full: t=599, τ'=600, 600≥604 → kept"
  (>= tau-prime-val (+ timeout +availability-timeout+)))

;;; ═══════════════════════════════════════════════════════════════
;;; BITFIELD OPERATIONS
;;; ═══════════════════════════════════════════════════════════════

(defun bitfield-core-set-p (bitfield core-index)
  "Test if bit CORE-INDEX is set in BITFIELD. Byte[c/8], bit (c mod 8)."
  (let ((byte-idx (floor core-index 8))
        (bit-idx  (mod core-index 8)))
    (and (< byte-idx (length bitfield))
         (logbitp bit-idx (aref bitfield byte-idx)))))

(defun count-core-votes (assurances num-cores)
  "Count assurance votes per core. Returns: vector of ints, index=core."
  (let ((votes (make-array num-cores :initial-element 0)))
    (dolist (a assurances votes)
      (let ((bitfield (getf a :bitfield)))
        (dotimes (c num-cores)
          (when (bitfield-core-set-p bitfield c)
            (incf (aref votes c))))))))

;;; ═══════════════════════════════════════════════════════════════
;;; ASSURANCE SIGNING (§11.13-11.14)
;;; ═══════════════════════════════════════════════════════════════

(defun assurance-signing-payload (parent-hash bitfield)
  "X_A ≡ $jam_available ; message = X_A ~ H(H_P ⌢ a_f)"
  (let* ((ph (ensure-bytes parent-hash))
         (bf (ensure-bytes bitfield))
         (inner (make-array (+ (length ph) (length bf))
                            :element-type '(unsigned-byte 8))))
    (replace inner ph)
    (replace inner bf :start1 (length ph))
    (let* ((hash (blake2b-256 inner))
           (ctx +ctx-available+)
           (buf (make-array (+ (length ctx) (length hash))
                            :element-type '(unsigned-byte 8))))
      (replace buf ctx)
      (replace buf hash :start1 (length ctx))
      buf)))

;;; ═══════════════════════════════════════════════════════════════
;;; ASSURANCE VALIDATION (§11.10-11.15)
;;; ═══════════════════════════════════════════════════════════════

(defun validate-assurances-sorted-unique (assurances)
  "(11.12) ∀i: EA[i-1]_v < EA[i]_v"
  (loop for (a b) on assurances while b
        do (unless (< (getf a :validator-index) (getf b :validator-index))
             (reject-assurance :not-sorted-or-unique-assurers))))

(defun validate-assurance-anchor (assurance parent-hash)
  "(11.11) ∀a ∈ EA : a_a = H_P"
  (unless (equalp (ensure-bytes (getf assurance :anchor))
                  (ensure-bytes parent-hash))
    (reject-assurance :bad-attestation-parent)))

(defun validate-assurance-validator-index (assurance)
  "(11.10) v ∈ N_V"
  (unless (< (getf assurance :validator-index) (num-validators))
    (reject-assurance :bad-validator-index)))

(defun validate-assurance-cores-engaged (assurance rho-assignments)
  "(11.15) a_f[c] ⇒ ρ†[c] ≠ ∅"
  (let ((bitfield (getf assurance :bitfield)))
    (dotimes (c (num-cores))
      (when (and (bitfield-core-set-p bitfield c)
                 (null (nth c rho-assignments)))
        (reject-assurance :core-not-engaged)))))

(defun validate-assurance-signature (assurance kappa parent-hash)
  "(11.13) a_s ∈ V̄_{κ[a_v]_e}⟨X_A ~ H(E(H_P, a_f))⟩
   kappa: validator closure (message :ed25519-key)."
  (let* ((idx       (getf assurance :validator-index))
         (bitfield  (getf assurance :bitfield))
         (signature (ensure-bytes (getf assurance :signature)))
         (ed-key    (ensure-bytes (funcall kappa :ed25519-key idx)))
         (message   (assurance-signing-payload parent-hash bitfield)))
    (unless (jam.ffi:ed25519-verify ed-key message signature)
      (reject-assurance :bad-signature))))

;;; NOTE: guarantee-signing-payload is in lib/protocol.lisp (shared with ψ).

;;; ═══════════════════════════════════════════════════════════════
;;; GUARANTOR ASSIGNMENTS M/M* (§11.18-11.22)
;;; ═══════════════════════════════════════════════════════════════

;; phi-filter → now a message on κ: (funcall kappa :non-banned-indices offenders)
;; See kappa.lisp for implementation.

(defun guarantor-assignments (entropy slot kappa offenders)
  "(11.19) M = P(η₂, τ'), Φ(κ)
   kappa: validator closure (messages :count, :non-banned-indices)."
  (let* ((v (funcall kappa :count))
         (c (num-cores))
         (raw (compute-core-assignments (ensure-bytes entropy) slot v c
                                        (epoch-duration) (rotation-period)))
         (valid-set (funcall kappa :non-banned-indices offenders))
         (result (make-array v :initial-element nil)))
    (dotimes (i v result)
      (when (member i valid-set)
        (setf (aref result i) (aref raw i))))))

(defun assignments-for-guarantee (tau-prime-val guarantee-slot
                                  eta kappa lambda-prev offenders)
  "Select M or M* based on rotation comparison.
   eta: entropy closure (messages :vrf-entropy, :seal-entropy).
   kappa, lambda-prev: validator closures."
  (let ((r (rotation-period)))
    (if (= (floor tau-prime-val r) (floor guarantee-slot r))
        ;; Same rotation → M = P(η₂, τ')
        (guarantor-assignments (funcall eta :vrf-entropy) tau-prime-val
                               kappa offenders)
        ;; Different rotation → M*
        (let* ((block-epoch     (floor tau-prime-val (epoch-duration)))
               (guarantee-epoch (floor guarantee-slot (epoch-duration)))
               (diff-epoch-p   (/= block-epoch guarantee-epoch))
               (entropy   (if diff-epoch-p
                              (funcall eta :seal-entropy)
                              (funcall eta :vrf-entropy)))
               (validators (if diff-epoch-p lambda-prev kappa)))
          (guarantor-assignments entropy guarantee-slot validators offenders)))))

;;; ═══════════════════════════════════════════════════════════════
;;; GUARANTEE VALIDATION (§11.23-11.35)
;;; ═══════════════════════════════════════════════════════════════

(defun validate-guarantees-sorted-unique (guarantees)
  "(11.24) Sorted by core index, ascending, unique."
  (loop for (a b) on guarantees while b
        do (unless (< (getf (getf a :report) :core-index)
                      (getf (getf b :report) :core-index))
             (reject-guarantee :out-of-order-guarantee))))

(defun validate-guarantee-core-index (report)
  (when (>= (getf report :core-index) (num-cores))
    (reject-guarantee :bad-core-index)))

(defun validate-guarantee-results-present (report)
  (when (or (null (getf report :results))
            (zerop (length (getf report :results))))
    (reject-guarantee :missing-work-results)))

(defun validate-guarantee-slot-age (guarantee-slot tau-prime-val)
  "(11.26) t ≤ τ' AND t ≥ R·max(0,⌊τ'/R⌋-1)"
  (when (> guarantee-slot tau-prime-val)
    (reject-guarantee :future-report-slot))
  (let* ((r (rotation-period))
         (min-slot (* r (max 0 (1- (floor tau-prime-val r))))))
    (when (< guarantee-slot min-slot)
      (reject-guarantee :report-epoch-before-last))))

(defun validate-guarantee-sufficient-signatures (signatures)
  "(11.23) |a| ≥ 2"
  (when (< (length signatures) 2)
    (reject-guarantee :insufficient-guarantees)))

(defun validate-guarantee-signatures-sorted-unique (signatures)
  "(11.25) Sorted by validator index, strictly ascending."
  (loop for (a b) on signatures while b
        do (unless (< (getf a :validator-index) (getf b :validator-index))
             (reject-guarantee :not-sorted-or-unique-guarantors))))

(defun validate-guarantee-validator-index (sig)
  (when (>= (getf sig :validator-index) (num-validators))
    (reject-guarantee :bad-validator-index)))

(defun validate-guarantee-not-banned (sig kappa offenders)
  "(11.21) Validator must not be in ψ_O.
   kappa: validator closure (message :ed25519-key)."
  (let* ((idx (getf sig :validator-index))
         (ed-key (funcall kappa :ed25519-key idx)))
    (when (member ed-key offenders :test #'equalp)
      (reject-guarantee :banned-validator))))

(defun validate-guarantee-core-assignment (sig core-index core-assignments)
  "(11.26) Validator must be assigned to this core."
  (let* ((idx (getf sig :validator-index))
         (assigned (when (< idx (length core-assignments))
                     (aref core-assignments idx))))
    (unless (and assigned (= assigned core-index))
      (reject-guarantee :wrong-assignment))))

(defun validate-guarantee-signature (sig report-hash kappa
                                     guarantee-slot lambda-prev
                                     block-epoch)
  "(11.26) Ed25519 sig verification.
   kappa, lambda-prev: validator closures (message :ed25519-key).
   block-epoch: pre-computed floor(τ'/E)."
  (let* ((idx (getf sig :validator-index))
         (sig-bytes (ensure-bytes (getf sig :signature)))
         ;; Choose validator set based on epoch
         (guarantee-epoch (floor guarantee-slot (epoch-duration)))
         (keyset (if (/= block-epoch guarantee-epoch) lambda-prev kappa))
         (ed-key (ensure-bytes (funcall keyset :ed25519-key idx)))
         (message (guarantee-signing-payload report-hash)))
    (unless (jam.ffi:ed25519-verify ed-key message sig-bytes)
      (reject-guarantee :bad-signature))))

(defun validate-guarantee-core-not-engaged (core-index rho-assignments)
  "Core must not already have an assignment."
  (when (nth core-index rho-assignments)
    (reject-guarantee :core-engaged)))

(defun validate-guarantee-anchor (report find-record)
  "Context anchor must be in recent history + match state/beefy roots.
   find-record: (lambda (hash) ...) → plist or NIL. Pure callback."
  (let* ((ctx (getf report :context))
         (anchor (ensure-bytes (getf ctx :anchor)))
         (state-root (ensure-bytes (getf ctx :state-root)))
         (beefy-root (ensure-bytes (getf ctx :beefy-root)))
         (record (funcall find-record anchor)))
    (unless record (reject-guarantee :anchor-not-recent))
    (unless (equalp (ensure-bytes (getf record :state-root)) state-root)
      (reject-guarantee :bad-state-root))
    (unless (equalp (ensure-bytes (getf record :beefy-root)) beefy-root)
      (reject-guarantee :bad-beefy-mmr-root))))

(defun validate-guarantee-lookup-anchor (report tau-prime-val find-record)
  "GP §11.34-11.35: Lookup anchor must be recent.
   §11.34 (slot check): xt ≥ HT - L. Always checked (only needs slot numbers).
   §11.35 (hash check): anchor in ancestry set A. Only when *ancestry-enabled*."
  (let* ((ctx (getf report :context))
         (slot (getf ctx :lookup-anchor-slot))
         (anchor (ensure-bytes (getf ctx :lookup-anchor))))
    ;; §11.34: slot-based freshness (no ancestry set needed)
    (when (and slot (> slot 0)
               (> (- tau-prime-val slot) (max-lookup-anchor-age)))
      (reject-guarantee :lookup-anchor-not-recent))
    ;; §11.35: hash-based ancestry check (requires ancestry set A)
    (when *ancestry-enabled*
      (when (and anchor (not (every #'zerop anchor))
                 (not (funcall find-record anchor)))
        (reject-guarantee :lookup-anchor-not-recent)))))

(defun validate-guarantee-service-ids (report delta)
  "Each work result's service must exist in δ."
  (dolist (r (getf report :results))
    (unless (funcall delta :account (getf r :service-id))
      (reject-guarantee :bad-service-id))))

(defun validate-guarantee-code-hashes (report delta)
  "Each work result's code hash must match δ[s].code_hash.
   GP §11.34: c_s = δ[s]_c — the work-result's code hash must equal
   the current service's code hash.  If they differ the guarantee
   extrinsic is invalid and the block must be rejected."
  (dolist (r (getf report :results))
    (let* ((sid (getf r :service-id))
           (code-hash (ensure-bytes (getf r :code-hash)))
           (account (funcall delta :account sid))
           (expected (when account
                       (ensure-bytes (getf (getf account :service) :code-hash)))))
      (when (and expected (not (equalp code-hash expected)))
        (reject-guarantee :bad-code-hash)))))

(defun validate-guarantee-authorization (report alpha)
  "Authorizer hash must be in α[core]."
  (let* ((ci (getf report :core-index))
         (auth-hash (ensure-bytes (getf report :authorizer-hash)))
         (pool (funcall alpha :pool-for-core ci)))
    (unless (member auth-hash pool :test #'equalp)
      (reject-guarantee :core-unauthorized))))

(defun validate-guarantee-gas (report)
  "Each work-report's gas must not exceed GA."
  (let ((total (reduce #'+ (getf report :results)
                           :key (lambda (r) (getf r :accumulate-gas))
                           :initial-value 0)))
    (when (> total +accumulation-gas+)
      (reject-guarantee :work-report-gas-too-high))))

(defun validate-guarantee-item-gas (report delta)
  "Each work result's gas must meet δ[s].min_item_gas."
  (dolist (r (getf report :results))
    (let* ((sid (getf r :service-id))
           (gas (getf r :accumulate-gas))
           (account (funcall delta :account sid))
           (min-gas (when account (getf (getf account :service) :min-accum-gas))))
      (when (and min-gas (< gas min-gas))
        (reject-guarantee :service-item-gas-too-low)))))

(defun validate-guarantee-dependencies-count (report)
  (let* ((ctx (getf report :context))
         (prereqs (or (getf ctx :prerequisites) '()))
         (srl (or (getf report :segment-root-lookup) '())))
    (when (> (+ (length prereqs) (length srl)) +max-dependencies+)
      (reject-guarantee :too-many-dependencies))))

(defun validate-guarantee-output-size (report)
  (let ((total (length (ensure-bytes (getf report :auth-output)))))
    (dolist (r (getf report :results))
      (let ((result-val (getf r :result)))
        (when (and (eq (first result-val) :ok) (second result-val))
          (incf total (length (ensure-bytes (second result-val)))))))
    (when (> total +max-unbounded-blob-size+)
      (reject-guarantee :work-report-too-big))))

(defun validate-guarantee-not-duplicate (report known-packages seen-hashes)
  (let ((pkg-hash (ensure-bytes (getf (getf report :package-spec) :hash))))
    (when (member pkg-hash known-packages :test #'equalp)
      (reject-guarantee :duplicate-package))
    (when (member pkg-hash seen-hashes :test #'equalp)
      (reject-guarantee :duplicate-package))))

(defun validate-guarantee-dependencies (report known-packages all-guarantees)
  "known-packages: pre-extracted list of known package hashes (raw, not a closure)."
  (let* ((ctx (getf report :context))
         (prereqs (or (getf ctx :prerequisites) '()))
         (eg-hashes (mapcar (lambda (g)
                              (ensure-bytes
                               (getf (getf (getf g :report) :package-spec) :hash)))
                            all-guarantees)))
    (dolist (prereq prereqs)
      (let ((h (ensure-bytes prereq)))
        (unless (or (member h known-packages :test #'equalp)
                    (member h eg-hashes :test #'equalp))
          (reject-guarantee :dependency-missing))))))

(defun validate-guarantee-segment-root-lookup (report find-reported-wp all-guarantees)
  "find-reported-wp: (lambda (wp-hash) ...) → plist or NIL. Pure callback."
  (dolist (item (or (getf report :segment-root-lookup) '()))
      (let* ((wp-hash (ensure-bytes (getf item :work-package-hash)))
             (expected-root (ensure-bytes (getf item :segment-tree-root)))
             (found nil))
        (dolist (g all-guarantees)
        (let* ((other (getf g :report))
               (spec (getf other :package-spec))
               (h (ensure-bytes (getf spec :hash)))
               (r (ensure-bytes (getf spec :exports-root))))
          (when (equalp wp-hash h)
            (if (equalp expected-root r)
                  (setf found t)
                (reject-guarantee :segment-root-lookup-invalid)))))
        (unless found
        (let ((rp (funcall find-reported-wp wp-hash)))
          (when rp
            (if (equalp expected-root (ensure-bytes (getf rp :exports-root)))
                    (setf found t)
                (reject-guarantee :segment-root-lookup-invalid)))))
        (unless found
        (reject-guarantee :segment-root-lookup-invalid)))))

;;; ═══════════════════════════════════════════════════════════════
;;; STATE CLOSURE — ρ
;;; ═══════════════════════════════════════════════════════════════

(define-state-closure rho-state
  ((assignments nil) (reported nil))

  (:core-count (length assignments))

  ;; GP (4.19): Derive authorization code hashes to ban from α.
  ;; Receives disputes (ED) — raw data, not a closure.
  ;; Extracts target report-hashes from culprits/faults,
  ;; scans our own assignments for matching reports,
  ;; returns their authorizer-hashes.
  (:offender-auth-hashes (disputes)
    (let* ((culprits (or (getf disputes :culprits) '()))
           (faults   (or (getf disputes :faults) '()))
           (targets  (remove-duplicates
                      (append (mapcar (lambda (c) (getf c :target)) culprits)
                              (mapcar (lambda (f) (getf f :target)) faults))
                      :test #'equalp)))
      (when targets
        (let ((result '()))
          (dolist (a assignments)
            (when a
              (let ((rh (assignment-report-hash a)))
                (when (and rh (member rh targets :test #'equalp))
                  (let ((auth-hash (getf (getf a :report) :authorizer-hash)))
                    (when auth-hash
                      (pushnew auth-hash result :test #'equalp)))))))
          result))))

  ;; R* — reported work-reports from :transition-ddagger (§11.16)
  ;; Not encoded (not part of C(10)), carried in memory for accumulate.
  ;; Accessible via auto-generated :reported field accessor.

  (:encode :memo
    (let* ((parts (mapcar #'encode-rho-assignment assignments))
           (total (reduce #'+ parts :key #'length :initial-value 0))
           (buf   (make-array total :element-type '(unsigned-byte 8))))
      (let ((pos 0))
        (dolist (p parts)
          (replace buf p :start1 pos)
          (incf pos (length p))))
      buf))

  (:decode (bytes offset)
    (let ((result '())
          (pos offset)
          (c (num-cores)))
      (dotimes (i c)
        (multiple-value-bind (assignment size) (load-rho-assignment bytes pos)
          (push assignment result)
          (incf pos size)))
      (values (make-rho-state :assignments (nreverse result))
              (- pos offset))))

  ;; ─── WAVE 1: ρ† — disputes invalidate (§10.15) ──────────────
  ;; ρ†[c] = ∅ if ∃(r,t) ∈ v: H(ρ[c]_r) = r ∧ t < ⌊2V/3⌋+1
  (:transition-dagger (&key v-list)
    (if (null v-list)
        #'self
        (let ((threshold (super-majority)))
          (let ((invalidated
                  (loop for (target . pos-count) in v-list
                        when (< pos-count threshold)
                        collect target)))
            (if (null invalidated)
                #'self
                (make-rho-state
                 :assignments
                 (mapcar (lambda (a)
                           (let ((h (assignment-report-hash a)))
                             (if (and h (member h invalidated :test #'equalp))
                                 nil
                                 a)))
                         assignments)))))))

  ;; ─── WAVE 2: ρ‡ + R* — assurances (§11.10-11.17) ───────────
  ;;
  ;; Equations:
  ;;   (11.10) EA structure: (anchor, bitfield, validator_index, signature)
  ;;   (11.11) ∀a ∈ EA : a_a = H_P
  ;;   (11.12) ∀i : EA[i-1]_v < EA[i]_v
  ;;   (11.13) a_s ∈ V̄_{κ[a_v]_e}⟨X_A ~ H(E(H_P, a_f))⟩
  ;;   (11.14) X_A ≡ $jam_available
  ;;   (11.15) a_f[c] ⇒ ρ†[c] ≠ ∅
  ;;   (11.16) R = [ρ†[c]_r | c < C, Σ a_f[c] > ⅔V]
  ;;   (11.17) ρ‡[c] = ∅ if ρ[c]_r ∈ R ∨ H_T ≥ ρ†[c]_t + U ; ρ†[c] otherwise
  ;;
  ;; Returns: ρ‡-closure (R* accessible via :reported message)
  ;; Signals assurance-error on validation failure — caller handles.
  (:transition-ddagger (&key assurances tau-prime parent-hash kappa)
    (let* ((tau-prime-val (funcall tau-prime :slot)))
      ;; Validate EA — signals assurance-error on failure
      (dolist (a assurances)
        (validate-assurance-anchor a parent-hash)
        (validate-assurance-validator-index a))
      (validate-assurances-sorted-unique assurances)
      (dolist (a assurances)
        (validate-assurance-cores-engaged a assignments)
        (validate-assurance-signature a kappa parent-hash))
      ;; (11.16) Count votes, find available cores
      (let* ((c (num-cores))
             (votes (count-core-votes assurances c))
             (threshold (super-majority))
             (reported '())
             (new-assignments
               (loop for ci below c
                     for a in assignments
                     collect
                     (cond
                       ((null a) nil)
                       ;; Supermajority → available → R* + clear
                       ((>= (aref votes ci) threshold)
                        (push (getf a :report) reported)
                        nil)
                       ;; Stale → clear (not reported)
                       ((report-stale-p (getf a :timeout) tau-prime-val)
                        nil)
                       (t a)))))
        (make-rho-state :assignments new-assignments
                        :reported (nreverse reported)))))

  ;; ─── WAVE 3: ρ' — guarantees (§11.18-12) ───────────────────
  ;;
  ;; Error codes (from ASN schema / test vectors):
  ;;   0  bad-core-index               1  future-report-slot
  ;;   2  report-epoch-before-last     3  insufficient-guarantees
  ;;   4  out-of-order-guarantee       5  not-sorted-or-unique-guarantors
  ;;   6  wrong-assignment             7  core-engaged
  ;;   8  anchor-not-recent            9  bad-service-id
  ;;   10 bad-code-hash                11 dependency-missing
  ;;   12 duplicate-package            13 bad-state-root
  ;;   14 bad-beefy-mmr-root           15 core-unauthorized
  ;;   16 bad-validator-index          17 work-report-gas-too-high
  ;;   18 service-item-gas-too-low     19 too-many-dependencies
  ;;   20 segment-root-lookup-invalid  21 bad-signature
  ;;   22 work-report-too-big          23 banned-validator
  ;;   24 lookup-anchor-not-recent     25 missing-work-results
  ;;
  ;; All-or-nothing: signals guarantee-error on any failure.
  (:transition (&key guarantees tau-prime kappa lambda-prev eta
                     psi-prime recent-blocks alpha delta)
    (let* ((tau-prime-val (funcall tau-prime :slot))
           (block-epoch   (floor tau-prime-val (epoch-duration)))
           (offenders (when psi-prime (funcall psi-prime :offenders))))
    (when (null guarantees)
        (return-from self #'self))
      ;; Phase 1: EG-level structural checks
    (validate-guarantees-sorted-unique guarantees)
      ;; Phase 2: per-guarantee validation + registration
      ;; Pre-extract + build pure callbacks for β queries
    (let ((seen-hashes '())
            (known-packages (funcall recent-blocks :known-package-hashes))
            (find-record     (lambda (h) (funcall recent-blocks :find-record h)))
            (find-reported-wp (lambda (h) (funcall recent-blocks :find-reported-wp h)))
          (rho-prime (copy-list assignments)))
      (dolist (g guarantees)
        (let* ((report (getf g :report))
               (guarantee-slot (getf g :slot))
               (signatures (getf g :signatures))
               (core-index (getf report :core-index))
               (report-bytes (encode-work-report report))
               (report-hash (blake2b-256 report-bytes))
               (core-assignments
                 (assignments-for-guarantee
                    tau-prime-val guarantee-slot
                    eta kappa lambda-prev offenders)))
            ;; Report checks
          (validate-guarantee-core-index report)
          (validate-guarantee-results-present report)
          (validate-guarantee-core-not-engaged core-index assignments)
            (validate-guarantee-slot-age guarantee-slot tau-prime-val)
            ;; Signature checks
          (validate-guarantee-sufficient-signatures signatures)
          (validate-guarantee-signatures-sorted-unique signatures)
          (dolist (sig signatures)
            (validate-guarantee-validator-index sig)
              (validate-guarantee-not-banned sig kappa offenders)
            (validate-guarantee-core-assignment sig core-index core-assignments)
            (validate-guarantee-signature
               sig report-hash kappa guarantee-slot lambda-prev
               block-epoch))
            ;; Content checks
            (validate-guarantee-anchor report find-record)
            (validate-guarantee-lookup-anchor report tau-prime-val find-record)
            (validate-guarantee-service-ids report delta)
            (validate-guarantee-code-hashes report delta)
            (validate-guarantee-authorization report alpha)
          (validate-guarantee-gas report)
            (validate-guarantee-item-gas report delta)
          (validate-guarantee-dependencies-count report)
          (validate-guarantee-output-size report)
          (validate-guarantee-not-duplicate report known-packages seen-hashes)
            (validate-guarantee-dependencies report known-packages guarantees)
            (validate-guarantee-segment-root-lookup report find-reported-wp guarantees)
            ;; All passed: register
          (push (ensure-bytes (getf (getf report :package-spec) :hash))
                seen-hashes)
          (setf (nth core-index rho-prime)
                  (list :report report :timeout tau-prime-val))))
        (make-rho-state :assignments rho-prime)))))

;;; ═══════════════════════════════════════════════════════════════
;;; OUTPUT COMPUTATION — reported packages, reporters, statistics
;;; ═══════════════════════════════════════════════════════════════
;;; These are separate from the closure because they compute π'/β'
;;; outputs, not ρ state transitions.

;;; NOTE: Core/service statistics computation moved to state/pi.lisp
;;; (compute-cores-statistics, compute-services-statistics)
