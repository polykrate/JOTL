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
  "ext_log: log(level, target_ptr, target_len, text_ptr, text_len)
   Registers: A0=level, A1=target_ptr, A2=target_len, A3=text_ptr, A4=text_len.
   Reads text from (A3, A4), adds to ctx logs.
   Always returns :continue (even on read failure, matching Rust behavior)."
  (let* ((text-ptr (u32 (reg vm +a3+)))
         (text-len (u32 (reg vm +a4+)))
         (data (read-guest vm text-ptr text-len)))
    (when data
      (push data (hctx-logs ctx)))
    (set-reg vm +a0+ 0)  ; Rust always returns 0 in A0 for ext_log
    :continue))
