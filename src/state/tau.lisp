;;;; state/tau.lisp — τ Timeslot (GP §6.1-6.2)
;;;;
;;;; τ' ≡ HT                          (6.1)
;;;; let e' ℛ m' = τ'/E               (6.2)
;;;;
;;;; GP (4.5): τ' < (H)
;;;;
;;;; Messages:
;;;;   :slot              → raw timeslot integer (semi-public for ρ timeout storage)
;;;;   :epoch             → ⌊slot/E⌋                         (6.2)
;;;;   :phase             → slot mod E                       (6.2)
;;;;   :rotation          → ⌊slot/R⌋                         (11.3)
;;;;   :min-allowed-slot  → R·max(0, ⌊slot/R⌋ − 1)          (11.26)
;;;;   :save           → E4(slot)                          (codec)
;;;;   :decode bytes off  → (values τ-closure consumed)       (codec)
;;;;   :stale? timeout    → slot ≥ timeout + U               (11.17)
;;;;   :slot>= other      → slot ≥ other
;;;;   :lookup-fresh? s   → slot − s ≤ L                     (11.26)
;;;;   :epoch-changed? τ' → ⌊slot/E⌋ ≠ ⌊slot'/E⌋
;;;;   :transition :header h → τ' closure                    (4.5)

(in-package #:jotl)

(define-state-closure tau-state
  ((slot 0))

  ;; ── Codec ────────────────────────────────────────────────────
  (:encode :memo (E4 slot))
  (:decode (bytes offset)
    (multiple-value-bind (val consumed) (decode-u32 bytes offset)
      (values (make-tau-state :slot val) consumed)))

  ;; ── GP §6.2 — Derived time ──────────────────────────────────
  (:epoch    :memo (floor slot (epoch-duration)))
  (:phase    :memo (mod slot (epoch-duration)))

  ;; ── GP §11.3 — Rotation ─────────────────────────────────────
  (:rotation :memo (floor slot (rotation-period)))

  ;; ── GP §11.26 — Min allowed slot for guarantees ─────────────
  (:min-allowed-slot :memo
    (* (rotation-period) (max 0 (1- (floor slot (rotation-period))))))

  ;; ── Semantic queries ─────────────────────────────────────────
  (:stale? (timeout)
    (>= slot (+ timeout +availability-timeout+)))

  (:slot>= (other-slot)
    (>= slot other-slot))

  (:lookup-fresh? (anchor-slot)
    (<= (- slot anchor-slot) +max-lookup-anchor-age+))

  (:epoch-changed? (tau-prime)
    (/= (floor slot (epoch-duration))
        (funcall tau-prime :epoch)))

  ;; ── Transition: τ' < (H) ────────────────────────────────────
  (:transition (&key header)
    (let ((tau-prime-slot (funcall header :slot)))
      (assert (> tau-prime-slot slot) ()
              "GP §5.7: τ'=~D must be > τ=~D" tau-prime-slot slot)
      (make-tau-state :slot tau-prime-slot))))
