;;;; state/kappa.lisp — κ Current Validator Keys (GP §6.15)
;;;;
;;;; κ ∈ K^V — Array of V full validator keys
;;;; K = (ke, kb, kbl, km)
;;;;
;;;; GP (4.9): κ' < (H, τ, κ, γ)
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
;;;;   :fallback-keys randomness → F(r,k) GP (6.26): E bandersnatch keys by pseudo-random index
;;;;   :save           → encoded validator sequence
;;;;   :transition :tau τ :tau-prime τ' :gamma γ → κ' closure

(in-package #:jotl)

(define-state-closure kappa-state
  ((validators nil))

  ;; ── Semantic queries ─────────────────────────────────────
  (:count (length validators))

  (:validator-at (index)
    (when (< index (length validators))
      (nth index validators)))

  (:ed25519-key (index)
    (when (< index (length validators))
      (jam-validator-ed25519 (nth index validators))))

  (:bandersnatch-key (index)
    (when (< index (length validators))
      (jam-validator-bandersnatch (nth index validators))))

  (:all-ed25519-keys
    (mapcar #'jam-validator-ed25519 validators))

  ;; ── Φ(k) — Offender filter (GP 6.14) ──────────────────
  ;; Replace validators whose ke ∈ offenders with +null-validator-key+.
  ;; Returns: new list of V validator plists.
  (:filter-offenders (offenders)
    (if (null offenders)
        (copy-list validators)
        (loop for v in validators
              for ed = (jam-validator-ed25519 v)
              collect (if (member-hash ed offenders)
                         +null-validator-key+
                         v))))

  ;; Non-banned validator indices — for guarantor assignment filtering.
  ;; Returns: list of indices i where ke(i) ∉ offenders.
  (:non-banned-indices (offenders)
    (if (null offenders)
        (loop for i below (length validators) collect i)
        (loop for i from 0
              for v in validators
              for ed = (jam-validator-ed25519 v)
              unless (member ed offenders :test #'equalp)
              collect i)))

  ;; F(r, k) — Fallback key sequence (GP 6.26).
  ;; Creates E bandersnatch keys by pseudo-randomly indexing into validators.
  ;; randomness: H (32-byte hash) = η'₂.
  ;; Returns: list of E bandersnatch public keys (32 bytes each).
  (:fallback-keys (randomness)
    (let* ((e (epoch-duration))
           (v (length validators))
           (rand-bytes (ensure-bytes randomness))
           (input-buf (make-array (+ (length rand-bytes) 4)
                                  :element-type '(unsigned-byte 8))))
      (when (zerop v)
        (error "Empty validator set (V=0) for fallback key sequence F(η'₂, κ')"))
      (replace input-buf rand-bytes)
      (loop for i below e
            for e4-i = (E4 i)
            for hash = (progn (replace input-buf e4-i :start1 (length rand-bytes))
                              (blake2b-256 input-buf))
            for idx = (mod (decode-fixed-le hash 0 4) v)
            collect (jam-validator-bandersnatch (nth idx validators)))))

  ;; ── Codec ────────────────────────────────────────────────
  (:encode :memo (encode-full-validator-sequence validators))

  (:decode (bytes offset)
    (multiple-value-bind (vals consumed)
      (decode-full-validator-sequence bytes offset)
      (values (make-kappa-state :validators vals) consumed)))

  ;; GP §6.15: κ' = γk if epoch change, else κ
  (:transition (&key tau tau-prime gamma)
    (if (funcall tau :epoch-changed? tau-prime)
        (make-kappa-state :validators (funcall gamma :pending-keys))
        #'self)))
