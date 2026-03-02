;;;; state/iota.lisp — ι Enqueued Validator Keys (GP §6.7)
;;;;
;;;; ι ∈ K^V — Validator keys queued for next epoch
;;;; K = (ke, kb, kbl, km) = 336 bytes per validator
;;;;
;;;; Merkle key C(7) — owned by σ (sigma), NOT by this component.
;;;;
;;;; GP (4.16): ι' comes from accumulate, NOT from safrole.
;;;;            γ reads ι but does not modify it.
;;;;
;;;; Messages:
;;;;   :validators        → raw list of full validator key plists (codec/internal)
;;;;   :count             → number of validators
;;;;   :validator-at idx  → full validator plist at index, or NIL
;;;;   :ed25519-key idx   → 32-byte Ed25519 key at index, or NIL
;;;;   :bandersnatch-key idx → 32-byte Bandersnatch key at index, or NIL
;;;;   :all-ed25519-keys  → list of all Ed25519 keys
;;;;   :filter-offenders offenders → Φ(k) GP (6.14): replace offending validators with null keys
;;;;   :save           → V × 336 bytes (memoized)
;;;;   :decode            → reconstruct from bytes
;;;;   :transition (&key new-validators) → ι' with new validators, or self if nil

(in-package #:jotl)

(define-state-closure iota-state
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
  ;; Replace validators whose ke ∈ offenders with +null-validator-key+.
  ;; Returns: new list of V validator plists.
  (:filter-offenders (offenders)
    (if (null offenders)
        (copy-list validators)
        (loop for v in validators
              for ed = (getf v :ed25519)
              collect (if (member-hash ed offenders)
                         +null-validator-key+
                         v))))

  ;; ── Transition: accept new validators from accumulate ────
  ;; If validators is non-nil, replace; otherwise return self unchanged.
  (:transition (&key new-validators)
    (if new-validators
        (make-iota-state :validators new-validators)
        #'self))

  ;; ── Codec ────────────────────────────────────────────────
  (:encode :memo (encode-full-validator-sequence validators))

  (:decode (bytes offset)
    (multiple-value-bind (vals consumed)
        (decode-full-validator-sequence bytes offset)
      (values (make-iota-state :validators vals) consumed))))
