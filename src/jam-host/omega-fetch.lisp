;;;; omega-fetch.lisp — Ω₁ (ΩY) Fetch data
;;;;
;;;; Implements GP Appendix B.2 (data fetch host call).
;;;; Fetches context-dependent data into guest memory.

(in-package #:jam-host)

;;; ═══════════════════════════════════════════════════════════════════
;;; Encoding helpers for work item summaries
;;; ═══════════════════════════════════════════════════════════════════

(defun encode-item-summary (w)
  "Encode S(w) = E(w_s, w_c, w_g, w_g_a) for a single work item.
   4 + 32 + 8 + 8 = 52 bytes."
  (concat-octets (encode-u32-le (wi-service-id w))
                 (wi-code-hash w)
                 (encode-u64-le (wi-gas-limit w))
                 (encode-u64-le (wi-gas-limit-accum w))))

(defun encode-items-summary-list (items)
  "Encode E({S(w)...}) — JAM compact-prefixed list of work item summaries."
  (let ((parts (list (encode-jam-compact (length items)))))
    (dolist (w items)
      (push (encode-item-summary w) parts))
    (apply #'concat-octets (nreverse parts))))

(defun encode-accumulate-items-list (items)
  "Encode accumulate items as JAM compact-prefixed list.
   ITEMS is a list of octet vectors."
  (let ((parts (list (encode-jam-compact (length items)))))
    (dolist (item items)
      (push item parts))
    (apply #'concat-octets (nreverse parts))))

;;; ═══════════════════════════════════════════════════════════════════
;;; 1 — ΩY Fetch data
;;;
;;; fetch(buffer_ptr, offset, buffer_len, kind, a, b) → data_len
;;; Registers: A0=buffer_ptr, A1=offset, A2=buffer_len,
;;;            A3=kind, A4=a, A5=b
;;; ═══════════════════════════════════════════════════════════════════

(defomega 1 omega-fetch (vm ctx)
  "ΩY: Fetch context data into guest memory buffer."
  (let* ((buffer-ptr (u32 (reg vm +a0+)))
         (offset     (reg vm +a1+))
         (buffer-len (reg vm +a2+))
         (kind       (reg vm +a3+))
         (a          (reg vm +a4+))
         (b          (reg vm +a5+)))

    ;; Build the data to return
    (let ((data (fetch-data ctx kind a b)))

      ;; Write result to guest memory
      (cond
        (data
         (let ((data-len (length data)))
           (when (and (plusp buffer-ptr) (plusp buffer-len))
             (let* ((available (max 0 (- data-len (min offset data-len))))
                    (copy-len (min available buffer-len)))
               (when (and (plusp copy-len) (< offset data-len))
                 (let ((slice (subseq data offset (+ offset copy-len))))
                   (unless (write-guest vm buffer-ptr slice)
                     (return-from omega-fetch :fault))))))
           (set-reg vm +a0+ (u64 data-len))))

        (t
         ;; v = ∅ → φ'₇ = NONE
         (set-reg vm +a0+ +hc-none+)))

      :continue)))

;;; ═══════════════════════════════════════════════════════════════════
;;; fetch-data — resolve FetchKind → data (octet vector or NIL)
;;; ═══════════════════════════════════════════════════════════════════

(defun fetch-data (ctx kind a b)
  "Resolve fetch KIND with parameters A, B from CTX.
   Returns octet vector or NIL."
  (case kind
    ;; ── Shared across all contexts ──────────────────────
    (#.+fetch-protocol-params+
     (let ((pp (hctx-protocol-params ctx)))
       (when (and pp (plusp (length pp))
                  (hctx-debug-trace ctx))
         (format *error-output*
                 "~&[FETCH-0-PP] sid=~D len=~D bytes: ~{~2,'0X~}~%"
                 (hctx-service-id ctx) (length pp) (coerce pp 'list)))
       (when (plusp (length pp)) pp)))

    (#.+fetch-entropy+
     ;; GP B.5: ω₁(κ) = η'_κ — return 32-byte entropy slice at index a.
     ;; a ∈ {0,1,2,3} selects which of the 4 entropy hashes.
     ;; a ≥ 4 → ∅ (NIL).
     (let ((result
             (when (< a 4)
               (let ((raw (hctx-entropy-raw ctx)))
                 (if (>= (length raw) 128)
                     (subseq raw (* a 32) (+ (* a 32) 32))
                     ;; Fallback: use 4×32 array
                     (let* ((ent (hctx-entropy ctx))
                            (slice (make-array 32 :element-type '(unsigned-byte 8))))
                       (dotimes (j 32 slice)
                         (setf (aref slice j) (aref ent a j)))))))))
       (when (and result (hctx-debug-trace ctx))
         (format *error-output*
                 "~&[FETCH-1-ENTROPY] sid=~D a=~D len=~D bytes: ~{~2,'0X~}~%"
                 (hctx-service-id ctx) a
                 (length result)
                 (coerce result 'list)))
       result))

    ;; ── Refine context (B.6) ────────────────────────────
    (#.+fetch-auth-trace+
     (let ((at (hctx-authorizer-trace ctx)))
       (when (plusp (length at)) at)))

    (#.+fetch-any-extrinsic+
     ;; x̄[a][b] — extrinsic segment b of work item a
     (let ((items (hctx-extrinsics ctx)))
       (when (< a (length items))
         (let ((segs (nth a items)))
           (when (< b (length segs))
             (nth b segs))))))

    (#.+fetch-our-extrinsic+
     ;; x̄[i][a] — extrinsic segment a of current work item
     (let ((items (hctx-extrinsics ctx))
           (i (hctx-work-item-index ctx)))
       (when (< i (length items))
         (let ((segs (nth i items)))
           (when (< a (length segs))
             (nth a segs))))))

    (#.+fetch-any-import+
     ;; ī[a] — import segment at index a
     (nth a (hctx-import-segments ctx)))

    (#.+fetch-our-import+
     ;; ī[i] — import segment for current work item
     (nth (hctx-work-item-index ctx) (hctx-import-segments ctx)))

    (#.+fetch-work-package+
     (let ((wp (hctx-work-package ctx)))
       (when (plusp (length wp)) wp)))

    (#.+fetch-authorizer+
     ;; p_f — authorizer code blob
     (let ((ac (hctx-authorizer-code ctx)))
       (when (plusp (length ac)) ac)))

    (#.+fetch-auth-token+
     ;; p_j — justification / authorization token
     (let ((j (hctx-justification ctx)))
       (when (plusp (length j)) j)))

    (#.+fetch-refine-context+
     ;; E(p_c) — pre-encoded work package context
     (let ((wpc (hctx-work-package-context ctx)))
       (when (plusp (length wpc)) wpc)))

    ;; ── Accumulate context (B.11) ───────────────────────
    (#.+fetch-items-summary+
     (let ((items (hctx-work-items ctx)))
       (when items (encode-items-summary-list items))))

    (#.+fetch-any-item-summary+
     ;; S(p_w[a])
     (let ((items (hctx-work-items ctx)))
       (when (< a (length items))
         (encode-item-summary (nth a items)))))

    (#.+fetch-any-payload+
     ;; p_w[a].y
     (let ((items (hctx-work-items ctx)))
       (when (< a (length items))
         (wi-payload (nth a items)))))

    (#.+fetch-accumulate-items+
     (let ((encoded (encode-accumulate-items-list (hctx-accumulate-items ctx))))
       (when (hctx-debug-trace ctx)
         (format *error-output*
                 "~&[FETCH-14] sid=~D items=~D total-len=~D~%"
                 (hctx-service-id ctx)
                 (length (hctx-accumulate-items ctx))
                 (length encoded))
         ;; Dump full payload in hex
         (format *error-output* "[FETCH-14-FULL] ~{~2,'0X~}~%" (coerce encoded 'list))
         ;; Dump each item separately
         (loop for item in (hctx-accumulate-items ctx) for i from 0 do
           (format *error-output* "[FETCH-14-ITEM-~D] len=~D hex=~{~2,'0X~}~%"
                   i (length item) (coerce item 'list))))
       encoded))

    (#.+fetch-any-accum-item+
     (nth a (hctx-accumulate-items ctx)))

    ;; Unknown kind → NIL
    (otherwise nil)))
