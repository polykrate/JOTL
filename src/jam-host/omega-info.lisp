;;;; omega-info.lisp — Ω₅ (ΩI) Information-on-service
;;;;
;;;; Ported from crypto/jam-crypto/src/pvm/host_calls.rs.
;;;; Returns a 96-byte encoded service account info record.

(in-package #:jam-host)

;;; ═══════════════════════════════════════════════════════════════════
;;; 5 — ΩI Information-on-service
;;;
;;; info(service, out_ptr, offset, out_len) → data_len | NONE
;;; A0=service, A1=out_ptr, A2=offset, A3=out_len
;;; ═══════════════════════════════════════════════════════════════════

(defomega 5 omega-info (vm ctx)
  "ΩI: Return encoded service account info."
  (let* ((service-raw (reg vm +a0+))
         (out-ptr     (u32 (reg vm +a1+)))
         (offset      (reg vm +a2+))
         (out-len     (reg vm +a3+)))

    ;; Resolve service account
    ;; GP B.5: a = d[s] if φ₇ = 2⁶⁴−1 (NONE), else d[φ₇]
    ;; When φ₇ = own service ID, d[φ₇] should return the ORIGINAL
    ;; directory entry.  But since we don't store self in service-accounts
    ;; (it lives in hctx-* fields), we also treat own-id as self.
    ;; TODO: separate original-state vs mutated-state for strict GP compliance.
    (let* ((is-self (or (= service-raw +hc-none+)
                        (= service-raw (u64 (hctx-service-id ctx)))))
           (account (if is-self
                        (self-account-info ctx)
                        (gethash (u32 service-raw)
                                 (hctx-service-accounts ctx)))))

      (cond
        ((null account)
         (set-reg vm +a0+ +hc-none+)
         :continue)

        (t
         ;; v = encoded info — 96 bytes
         (let* ((v (encode-service-info account))
                (data-len (length v))
                (f (min offset data-len))
                (l (min out-len (- data-len f))))
           (when (plusp l)
             (unless (write-guest vm out-ptr (subseq v f (+ f l)))
               (return-from omega-info :fault)))
           (set-reg vm +a0+ (u64 data-len))
           :continue))))))
