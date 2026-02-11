;;;; state/delta.lisp — δ Service Accounts (GP §9)
;;;;
;;;; δ[s] = service account for service index s.
;;;; Each account: (code-hash, balance, threshold, preimages, lookup, storage, ...).
;;;;
;;;; Service accounts use Merkle key C(255, s), NOT a fixed segment C(n).
;;;; They live in sigma's extra-kvs, not in a segment field.
;;;;
;;;; GP (4.18): δ' < (EP, δ†, τ')
;;;; δ† is the post-accumulation intermediate (from 4.16).
;;;; EP is the preimages extrinsic from the block.
;;;; τ' is the post-transition timeslot.
;;;;
;;;; The transition integrates on-chain preimages into service accounts:
;;;; For each (s, blob) in EP where δ†[s] exists and H(blob) is solicited:
;;;;   - Store the preimage in δ†[s].preimages
;;;;   - Update the lookup status from [] to [τ']
;;;;
;;;; Messages:
;;;;   :raw-kvs          → the underlying key-value pairs for Merkle
;;;;   :extra-kvs        → alias for :raw-kvs
;;;;   :encoded          → nil (delta doesn't encode to a single segment)
;;;;   :decode           → reconstruct from bytes (fallback)
;;;;   :transition       → GP (4.18): δ' < (EP, δ†, τ')

(in-package #:jotl)

(define-state-closure delta-state
  ((raw-kvs nil))

  ;; delta doesn't encode to a single segment byte vector.
  ;; It re-emits its key-value pairs for sigma's extra-kvs.
  (:encoded nil)

  ;; Access the underlying Merkle key-value pairs.
  (:extra-kvs raw-kvs)

  (:decode (bytes offset)
    ;; delta is not decoded from segment bytes — this is a fallback.
    ;; Real loading happens via load-delta-from-extra-kvs.
    (values (make-delta-state :raw-kvs nil) (- (length bytes) offset)))

  ;; ── Transition: δ' < (EP, δ†, τ') ────────────────────────
  ;; GP (4.18) — Preimage Integration
  ;; For now: passthrough. Full implementation requires decoding
  ;; individual service accounts from extra-kvs, which depends on
  ;; the §9 service account codec.
  ;; When EP is empty (no preimage extrinsic), this is a no-op.
  (:transition (&key preimages tau-prime)
    ;; tau-prime will be used for §12.4 preimage integration
    (let ((_timeslot (when tau-prime (funcall tau-prime :slot))))
      (if (or (null preimages) (zerop (length preimages))
              (not _timeslot))
        ;; No preimages to integrate → passthrough
        (make-delta-state :raw-kvs raw-kvs)
        ;; TODO (§12.4): For each (s, blob) in EP:
        ;;   1. Look up service s in δ† (by C(255,s) key)
        ;;   2. Decode the service account
        ;;   3. h = blake2b-256(blob), l = |blob|
        ;;   4. If a_l[(h,l)] = [] (solicited, not yet provided):
        ;;      a. Store a_p[h] = blob (add preimage)
        ;;      b. Set a_l[(h,l)] = [τ'] (mark as provided)
        ;;      c. Update footprint (balance, item count, byte count)
        ;;   5. Re-encode and update the extra-kvs entry
        ;; For now: passthrough (preimage integration is a no-op)
        (make-delta-state :raw-kvs raw-kvs)))))

(defun load-delta-from-extra-kvs (extra-kvs)
  "Build δ from sigma's extra-kvs (C(255,s) entries).
   Returns: delta-state closure."
  (make-delta-state :raw-kvs extra-kvs))
