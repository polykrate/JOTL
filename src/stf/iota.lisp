;;;; stf/iota.lisp — ι (Enqueued Validator Keys)
;;;; Gray Paper §8
;;;;
;;;; ι ∈ K^V — Array of V full validator keys (queued for next epoch).
;;;; K = (ke, kb, kbl, km) = ed25519(32) + bandersnatch(32) + bls(144) + metadata(128)
;;;;
;;;; State key: C(7)
;;;; Transition: ι' comes from accumulate (§8, eq 4.16), NOT safrole.
;;;;             γ' reads ι but does not modify it.

(in-package #:jotl)

;;; ═══════════════════════════════════════════════════════════════
;;; STATE CODEC — C(7) ↦ E(ι)
;;; ═══════════════════════════════════════════════════════════════

(defun encode-state-iota (iota)
  "C(7) ↦ E(ι) — V × 336 bytes (fixed size, no length prefix)."
  (encode-full-validator-sequence iota))

(defun decode-state-iota (bytes &optional (offset 0))
  "Decode ι from state binary.
   Returns: (values list-of-validators bytes-consumed)"
  (decode-full-validator-sequence bytes offset))

;;; ι transition is in transition-accumulate (stf/upsilon.lisp → future stf/accumulate.lisp)
;;; No transition-iota function needed here.
