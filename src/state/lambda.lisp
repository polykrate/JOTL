;;;; state/lambda.lisp — λ Archived Validator Keys (GP §6.16)
;;;;
;;;; λ ∈ K^V — Array of V full validator keys (prior epoch)
;;;;
;;;; GP (4.10): λ' < (H, τ, λ, κ)
;;;;
;;;; Messages:
;;;;   :validators        → raw list of validator key plists (codec/internal)
;;;;   :count             → number of validators
;;;;   :validator-at idx  → full validator plist at index, or NIL
;;;;   :ed25519-key idx   → 32-byte Ed25519 key at index, or NIL
;;;;   :bandersnatch-key idx → 32-byte Bandersnatch key at index, or NIL
;;;;   :all-ed25519-keys  → list of all Ed25519 keys
;;;;   :filter-offenders offenders → Φ(k) GP (6.14): replace offending validators with null keys
;;;;   :non-banned-indices offenders → list of indices whose ed25519 ∉ offenders
;;;;   :encoded           → encoded validator sequence
;;;;   :transition :tau τ :tau-prime τ' :kappa κ → λ' closure

(in-package #:jotl)

(define-state-closure lambda-state
  ((validators nil))

  ;; ── Semantic queries ─────────────────────────────────────
  (:count (length validators))

  (:validator-at (index)
    (when (< index (length validators))
      (nth index validators)))

  (:ed25519-key (index)
    (when (< index (length validators))
      (getf (nth index validators) :ed25519)))

  (:bandersnatch-key (index)
    (when (< index (length validators))
      (getf (nth index validators) :bandersnatch)))

  (:all-ed25519-keys
    (mapcar (lambda (v) (getf v :ed25519)) validators))

  ;; ── Φ(k) — Offender filter (GP 6.14) ──────────────────
  ;; Same protocol as κ/ι: validators circulate as closures.
  (:filter-offenders (offenders)
    (if (null offenders)
        (copy-list validators)
        (loop for v in validators
              for ed = (getf v :ed25519)
              collect (if (member-hash ed offenders)
                         +null-validator-key+
                         v))))

  (:non-banned-indices (offenders)
    (if (null offenders)
        (loop for i below (length validators) collect i)
        (loop for i from 0
              for v in validators
              for ed = (getf v :ed25519)
              unless (member ed offenders :test #'equalp)
              collect i)))

  ;; ── Codec ────────────────────────────────────────────────
  (:encoded :memo (encode-full-validator-sequence validators))

  (:decode (bytes offset)
    (multiple-value-bind (vals consumed)
      (decode-full-validator-sequence bytes offset)
      (values (make-lambda-state :validators vals) consumed)))

  ;; GP §6.16: λ' = κ if epoch change, else λ
  (:transition (&key tau tau-prime kappa)
    (if (funcall tau :epoch-changed? tau-prime)
        (make-lambda-state :validators (funcall kappa :validators))
        #'self)))
