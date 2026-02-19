;;;; omega-export.lisp — Ω₇ (ΩE) Export segment
;;;;
;;;; Ported from crypto/jam-crypto/src/pvm/host_calls.rs lines 941-994.

(in-package #:jam-host)

;;; ═══════════════════════════════════════════════════════════════════
;;; 7 — ΩE Export segment
;;;
;;; export(ptr, len) → export_count | FULL
;;; A0=ptr, A1=len
;;;
;;; Reads z = min(φ₈, W_G) bytes, pads to W_G, appends to exports.
;;; Returns ς + |e⌢[x]| on success, FULL if ς + |e| ≥ W_X.
;;; ═══════════════════════════════════════════════════════════════════

(defomega 7 omega-export (vm ctx)
  "ΩE: Export a segment to the work result."
  (let* ((ptr     (u32 (reg vm +a0+)))
         (raw-len (u32 (reg vm +a1+)))
         (w-g     (hctx-segment-size ctx))
         (w-x     (hctx-max-exports ctx))
         (z       (min raw-len w-g)))

    ;; Read z bytes from guest
    (let ((data (read-guest vm ptr z)))
      (unless data (return-from omega-export :fault))

      ;; FULL check: ς + |e| ≥ W_X
      (let ((total-before (+ (hctx-export-base ctx)
                             (length (hctx-export-segments ctx)))))
        (when (>= total-before w-x)
          (set-reg vm +a0+ +hc-full+)
          (return-from omega-export :continue))

        ;; Pad to W_G bytes
        (let ((segment (make-array w-g :element-type '(unsigned-byte 8)
                                       :initial-element 0)))
          (replace segment data)

          ;; Append and return new count
          (push segment (hctx-export-segments ctx))
          (let ((total-after (+ (hctx-export-base ctx)
                                (length (hctx-export-segments ctx)))))
            (set-reg vm +a0+ (u64 total-after))
            :continue))))))
