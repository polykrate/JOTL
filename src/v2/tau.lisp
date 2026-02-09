;;;; v2/tau.lisp — Timeslot τ (Gray Paper §6.1-6.2)
;;;;
;;;; PROTOTYPE: first state component ported to define-state-closure.
;;;;
;;;; τ' ≡ HT                          (6.1)
;;;; let e' ℛ m' = τ'/E               (6.2)
;;;;
;;;; The closure pre-computes epoch, phase, and rotation via memoized
;;;; accessors. Transition is a built-in message. Rho-specific semantic
;;;; queries avoid exposing raw arithmetic on :slot.
;;;;
;;;; Field:
;;;;   :slot                             → raw timeslot integer (semi-public for ρ storage)
;;;;
;;;; Derived (memoized):
;;;;   :epoch                            → ⌊slot/E⌋
;;;;   :phase                            → slot mod E
;;;;   :rotation                         → ⌊slot/R⌋
;;;;   :min-allowed-slot                 → R·max(0, ⌊slot/R⌋ − 1)
;;;;   :encoded                          → E4(slot)
;;;;
;;;; Methods (queries):
;;;;   :stale? timeout                   → (11.17) slot ≥ timeout + U
;;;;   :slot>= other-slot                → slot ≥ other-slot
;;;;   :lookup-fresh? anchor-slot        → (11.26) slot − anchor ≤ L
;;;;   :epoch-changed? tau-prime         → ⌊slot/E⌋ ≠ ⌊slot'/E⌋
;;;;
;;;; Transition:
;;;;   :transition :header h             → τ' closure
;;;;
;;;; Codec:
;;;;   :decode bytes offset              → (values τ-closure consumed)

(in-package #:jotl)

;;; ═════════════════════════════════════════════════════════════════
;;; STATE CLOSURE — τ (v2: self-transforming)
;;; ═════════════════════════════════════════════════════════════════
;;;
;;; GP (4.5): τ' < (H)
;;;
;;; :slot is the raw timeslot integer. It is accessible because ρ needs
;;; to store it as a timeout value in core assignments. All other consumers
;;; should prefer the derived messages (:epoch, :phase, :rotation) or
;;; the semantic queries (:stale?, :slot>=, :lookup-fresh?).

(define-state-closure tau-state-v2
  ((slot 0))
  (:state-key +C11+)

  ;; ── Codec ────────────────────────────────────────────────────
  (:encoded :memo (E4 slot))
  (:decode (bytes offset)
    (multiple-value-bind (val consumed) (decode-u32 bytes offset)
      (values (make-tau-state-v2 :slot val) consumed)))

  ;; ── GP §6.2 — Derived time properties ───────────────────────
  (:epoch    :memo (floor slot (epoch-duration)))
  (:phase    :memo (mod slot (epoch-duration)))

  ;; ── GP §11.3 — Rotation index ───────────────────────────────
  (:rotation :memo (floor slot (rotation-period)))

  ;; ── GP §11.26 — Minimum allowed slot for guarantees ─────────
  ;; R·max(0, ⌊τ'/R⌋ − 1) — not before previous rotation start
  (:min-allowed-slot :memo
    (* (rotation-period) (max 0 (1- (floor slot (rotation-period))))))

  ;; ── Semantic queries for ρ ───────────────────────────────────

  ;; (11.17) Report stale detection: τ' ≥ timeout + U
  (:stale? (timeout)
    (>= slot (+ timeout +availability-timeout+)))

  ;; Generic comparison: is my slot ≥ other-slot?
  ;; Used by: validate-guarantee-slot-age (t ≤ τ')
  (:slot>= (other-slot)
    (>= slot other-slot))

  ;; (11.26) Lookup anchor freshness: τ' − anchor ≤ L
  (:lookup-fresh? (anchor-slot)
    (<= (- slot anchor-slot) +max-lookup-anchor-age+))

  ;; Epoch boundary detection: ⌊τ/E⌋ ≠ ⌊τ'/E⌋
  (:epoch-changed? (tau-prime)
    (/= (floor slot (epoch-duration))
        (funcall tau-prime :epoch)))

  ;; ── GP (4.5): τ' < (H) — §5.7: τ' > τ — §6.1: τ' ≡ HT ───
  (:transition (&key header)
    (let ((tau-prime-slot (funcall header :slot)))
      (assert (> tau-prime-slot slot) ()
              "GP §5.7: τ'=~D must be > τ=~D" tau-prime-slot slot)
      (make-tau-state-v2 :slot tau-prime-slot))))

;;; No external helpers needed — everything is a message on τ:
;;;   (funcall tau :epoch-changed? tau-prime)  replaces  (new-epoch-p tau tau-prime)
;;;   (funcall tau :encoded)                  replaces  (encode-state-tau tau)
;;;   (decode-state-segment +C11+ bytes 0)    replaces  (decode-state-tau bytes 0)
