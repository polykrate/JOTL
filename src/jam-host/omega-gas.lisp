;;;; omega-gas.lisp — Ω₀ (ΩG) Gas-remaining + ext_log
;;;;
;;;; Ported from crypto/jam-crypto/src/pvm/host_calls.rs lines 244-253.
;;;; The simplest host calls: query gas, and log (extension).

(in-package #:jam-host)

;;; ═══════════════════════════════════════════════════════════════════
;;; 0 — ΩG Gas-remaining
;;;
;;; gas() → remaining_gas
;;; φ'₇ = ϱ (current gas after the 10-unit host call charge)
;;; ═══════════════════════════════════════════════════════════════════

(defomega 0 omega-gas (vm ctx)
  "ΩG: Return remaining gas in A0."
  (declare (ignore ctx))
  (set-reg vm +a0+ (u64 (pvm-gas vm)))
  :continue)

;;; ═══════════════════════════════════════════════════════════════════
;;; 100 — ext_log  (extension, not in GP)
;;;
;;; log(ptr, len) — read guest memory and record as log entry.
;;; Registers: A0=ptr, A1=len.
;;; ═══════════════════════════════════════════════════════════════════

(defomega 100 omega-ext-log (vm ctx)
  "ext_log: Read bytes from guest memory and add to logs."
  (let* ((ptr (u32 (reg vm +a0+)))
         (len (u32 (reg vm +a1+)))
         (data (read-guest vm ptr len)))
    (if data
        (progn
          (push data (hctx-logs ctx))
          :continue)
        :fault)))
