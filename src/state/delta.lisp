;;;; state/delta.lisp — δ Service Accounts (GP §9)
;;;;
;;;; δ[s] = service account for service index s.
;;;; Each account: (code-hash, balance, threshold, preimages, lookup, storage, ...).
;;;;
;;;; Service accounts use Merkle key C(255, s), NOT a fixed segment C(n).
;;;; They live in sigma's extra-kvs, not in a segment field.
;;;;
;;;; GP (4.18): δ' < (EP, δ†, τ')
;;;; δ† is the post-accumulation intermediate from (4.16).
;;;;
;;;; For the skeleton: delta-state wraps the raw extra-kvs data.
;;;; No :transition — modified by transition-accumulate + wave 4.
;;;;
;;;; Messages:
;;;;   :raw              → raw extra-kvs list (skeleton mode)
;;;;   :encoded          → NOT a single segment — returns nil
;;;;   :extra-kvs        → the underlying key-value pairs for Merkle
;;;;   :decode           → reconstruct from extra-kvs

(in-package #:jotl)

;;; Raw extra-kvs wrapper — will be replaced with real codec when §9 is implemented.
;;; delta is NOT a regular segment — it uses C(255,s) keys in extra-kvs.
;;; :encoded returns nil (delta doesn't encode to a single segment).
;;; The actual Merkle data lives in :extra-kvs.

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
    (values (make-delta-state :raw-kvs nil) (- (length bytes) offset))))

(defun load-delta-from-extra-kvs (extra-kvs)
  "Build δ from sigma's extra-kvs (C(255,s) entries).
   Returns: delta-state closure."
  (make-delta-state :raw-kvs extra-kvs))
