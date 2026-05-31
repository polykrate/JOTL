;;;; omega-preimage.lisp — Ω₂ (ΩL), Ω₆ (ΩH), Ω₂₂ (ΩQ), Ω₂₃ (ΩS), Ω₂₄ (ΩF), Ω₂₅/₂₆
;;;;
;;;; Preimage lookup, historical lookup, query, solicit, forget, yield, provide.
;;;; Implements GP Appendix B.6 (preimage lookup and yield).

(in-package #:jam-host)

;;; ═══════════════════════════════════════════════════════════════════
;;; Lazy orphan discovery — candidate lookup fallback
;;;
;;; Orphaned lookup entries (solicited but no preimage blob yet) cannot
;;; be classified from the trie because there is no matching preimage to
;;; compute lookup-trie-h from.  They are stored in hctx-candidate-lookups
;;; (h27 → encoded-value).  When the PVM queries a (hash, length) via
;;; HC22/23/24, we compute lookup-trie-h and probe this table.  On a hit
;;; the entry is promoted into hctx-lookup so subsequent calls see it.
;;; ═══════════════════════════════════════════════════════════════════

(defun %lookup-trie-h (preimage-hash preimage-length)
  "H(E4(length) . hash)[0:27] — same as jotl:lookup-trie-h but local to jam-host."
  (let ((buf (make-array (+ 4 (length preimage-hash))
                         :element-type '(unsigned-byte 8))))
    (setf (aref buf 0) (logand preimage-length #xFF)
          (aref buf 1) (logand (ash preimage-length -8) #xFF)
          (aref buf 2) (logand (ash preimage-length -16) #xFF)
          (aref buf 3) (logand (ash preimage-length -24) #xFF))
    (replace buf preimage-hash :start1 4)
    (subseq (jam.ffi:blake2b-256 buf) 0 27)))

(defun %decode-lookup-statuses (val-bytes)
  "Decode compact(n) . n*u32_LE → list of timeslot u32s.
   Returns NIL for empty/invalid encodings."
  (when (and val-bytes (plusp (length val-bytes)))
    (let* ((b0 (aref val-bytes 0))
           (count (cond ((<= b0 #xBF) b0)
                        ((<= b0 #xDF) (logior (ash (logand b0 #x1F) 8)
                                              (aref val-bytes 1)))
                        (t 0)))
           (consumed (cond ((<= b0 #xBF) 1)
                           ((<= b0 #xDF) 2)
                           (t 1))))
      (loop for i below count
            for off = consumed then (+ off 4)
            collect (logior (aref val-bytes off)
                            (ash (aref val-bytes (+ off 1)) 8)
                            (ash (aref val-bytes (+ off 2)) 16)
                            (ash (aref val-bytes (+ off 3)) 24))))))

(defun %try-discover-orphan (ctx hash-bytes z)
  "Check if (HASH-BYTES, Z) matches a candidate orphaned lookup.
   If found, promote it to hctx-lookup and return (values status-list T).
   Otherwise return (values NIL NIL)."
  (let ((cl-ht (hctx-candidate-lookups ctx)))
    (when (plusp (hash-table-count cl-ht))
      (let ((h27 (%lookup-trie-h hash-bytes z)))
        (multiple-value-bind (encoded-val found-p) (gethash h27 cl-ht)
          (when found-p
            (let ((statuses (%decode-lookup-statuses encoded-val))
                  (key (cons hash-bytes z)))
              (setf (gethash key (hctx-lookup ctx)) statuses)
              (remhash h27 cl-ht)
              (values statuses t))))))))

;;; ═══════════════════════════════════════════════════════════════════
;;; Λ(a, t, h) — Historical preimage lookup (GP §9.2)
;;; ═══════════════════════════════════════════════════════════════════

(defun lambda-lookup (preimages lookup timeslot hash)
  "Λ(a, t, h): historical preimage lookup.
   PREIMAGES: hash-table (32-byte key → octet vector).
   LOOKUP: hash-table ((hash . length) → status list of u32).
   TIMESLOT: current timeslot.
   HASH: 32-byte vector.
   Returns octet vector or NIL."
  (let ((data (gethash hash preimages)))
    (unless data (return-from lambda-lookup nil))
    (let* ((data-len (length data))
           (key (cons hash data-len))
           (status (gethash key lookup)))
      (unless status (return-from lambda-lookup nil))
      (let ((available
              (cond
                ((null status) nil)
                ((= (length status) 1) (>= timeslot (first status)))
                ((= (length status) 2)
                 (and (>= timeslot (first status))
                      (< timeslot (second status))))
                ((= (length status) 3)
                 (and (>= timeslot (first status))
                      (< timeslot (second status))))
                (t nil))))
        (when available data)))))

;;; ═══════════════════════════════════════════════════════════════════
;;; 2 — ΩL Lookup-preimage
;;; ═══════════════════════════════════════════════════════════════════

(defomega 2 omega-lookup (vm ctx)
  "ΩL: Look up a preimage by hash.
   A0=service, A1=hash_ptr, A2=out_ptr, A3=offset, A4=out_len"
  (let* ((service-raw (reg vm +a0+))
         (hash-ptr    (u32 (reg vm +a1+)))
         (out-ptr     (u32 (reg vm +a2+)))
         (offset      (reg vm +a3+))
         (out-len     (reg vm +a4+)))
    (let ((is-self (or (= service-raw (u64 (hctx-service-id ctx)))
                       (= service-raw +hc-none+))))
      (let ((hash-bytes (read-guest vm hash-ptr 32)))
        (unless hash-bytes (return-from omega-lookup :fault))
        (let ((preimage
                (if is-self
                    (gethash hash-bytes (hctx-preimages ctx))
                    (let ((acct (gethash (u32 service-raw)
                                         (hctx-service-accounts ctx))))
                      (when acct (gethash hash-bytes (sa-preimages acct)))))))
          (cond
            ((null preimage)
             (set-reg vm +a0+ +hc-none+)
             :continue)
            (t
             (let* ((data-len (length preimage))
                    (f (min offset data-len))
                    (l (min out-len (- data-len f))))
               (when (plusp l)
                 (unless (write-guest vm out-ptr (subseq preimage f (+ f l)))
                   (return-from omega-lookup :fault)))
               (set-reg vm +a0+ (u64 data-len))
               :continue))))))))

;;; ═══════════════════════════════════════════════════════════════════
;;; 6 — ΩH Historical-lookup-preimage
;;; ═══════════════════════════════════════════════════════════════════

(defomega 6 omega-historical-lookup (vm ctx)
  "ΩH: Historical preimage lookup using Λ(a, t, h).
   A0=service, A1=hash_ptr, A2=out_ptr, A3=offset, A4=out_len"
  (let* ((service-raw (reg vm +a0+))
         (hash-ptr    (u32 (reg vm +a1+)))
         (out-ptr     (u32 (reg vm +a2+)))
         (offset      (reg vm +a3+))
         (out-len     (reg vm +a4+)))
    (let ((is-self (or (= service-raw (u64 (hctx-service-id ctx)))
                       (= service-raw +hc-none+))))
      (let ((hash-bytes (read-guest vm hash-ptr 32)))
        (unless hash-bytes (return-from omega-historical-lookup :fault))
        (let* ((t-slot (hctx-timeslot ctx))
               (preimage
                 (if is-self
                     (lambda-lookup (hctx-preimages ctx)
                                    (hctx-lookup ctx)
                                    t-slot hash-bytes)
                     (let ((acct (gethash (u32 service-raw)
                                          (hctx-service-accounts ctx))))
                       (when acct
                         (lambda-lookup (sa-preimages acct)
                                        (sa-lookup acct)
                                        t-slot hash-bytes))))))
          (cond
            ((null preimage)
             (set-reg vm +a0+ +hc-none+)
             :continue)
            (t
             (let* ((data-len (length preimage))
                    (f (min offset data-len))
                    (l (min out-len (- data-len f))))
               (when (plusp l)
                 (unless (write-guest vm out-ptr (subseq preimage f (+ f l)))
                   (return-from omega-historical-lookup :fault)))
               (set-reg vm +a0+ (u64 data-len))
               :continue))))))))

;;; ═══════════════════════════════════════════════════════════════════
;;; 22 — ΩQ Query-preimage
;;;
;;; query(o, z) → (status, extra) | NONE
;;; A0=o (hash ptr), A1=z (expected length)
;;;
;;; Returns in A0, A1:
;;;   NONE,   0         if (h,z) ∉ K(a_l)
;;;   0,      0         if a_l[(h,z)] = []
;;;   1+2³²x, 0         if a_l[(h,z)] = [x]
;;;   2+2³²x, y         if a_l[(h,z)] = [x,y]
;;;   3+2³²x, y+2³²z    if a_l[(h,z)] = [x,y,z]
;;; ═══════════════════════════════════════════════════════════════════

(defomega 22 omega-query-preimage (vm ctx)
  "ΩQ: Query preimage metadata."
  (let* ((o (u32 (reg vm +a0+)))
         (z (u32 (reg vm +a1+))))
    (let ((hash-bytes (read-guest vm o 32)))
      (unless hash-bytes (return-from omega-query-preimage :fault))
      (let ((key (cons hash-bytes z)))
        ;; Try the overlay first, then candidate orphans on miss
        (multiple-value-bind (val present-p) (gethash key (hctx-lookup ctx))
          (unless present-p
            (multiple-value-bind (orphan-status discovered-p)
                (%try-discover-orphan ctx hash-bytes z)
              (declare (ignore orphan-status))
              (when discovered-p
                (setf (values val present-p)
                      (gethash key (hctx-lookup ctx))))))
          (let ((entry (if present-p val nil)))
            (cond
              ((not present-p)
               (set-reg vm +a0+ +hc-none+)
               (set-reg vm +a1+ 0))
              ((null entry)
               (set-reg vm +a0+ 0)
               (set-reg vm +a1+ 0))
              ((= (length entry) 1)
               (let ((x (u64 (first entry))))
                 (set-reg vm +a0+ (u64 (+ 1 (ash x 32))))
                 (set-reg vm +a1+ 0)))
              ((= (length entry) 2)
               (let ((x (u64 (first entry)))
                     (y (u64 (second entry))))
                 (set-reg vm +a0+ (u64 (+ 2 (ash x 32))))
                 (set-reg vm +a1+ y)))
              (t
               (let ((x (u64 (first entry)))
                     (y (u64 (second entry)))
                     (zv (u64 (third entry))))
                 (set-reg vm +a0+ (u64 (+ 3 (ash x 32))))
                 (set-reg vm +a1+ (u64 (+ y (ash zv 32)))))))))
        :continue))))

;;; ═══════════════════════════════════════════════════════════════════
;;; 23 — ΩS Solicit-preimage
;;;
;;; solicit(o, z) → OK | HUH | FULL
;;; A0=o (hash ptr), A1=z (expected length)
;;; ═══════════════════════════════════════════════════════════════════

(defomega 23 omega-solicit-preimage (vm ctx)
  "ΩS: Solicit a preimage."
  (let* ((o (u32 (reg vm +a0+)))
         (z (u32 (reg vm +a1+))))
    (let ((hash-bytes (read-guest vm o 32)))
      (unless hash-bytes (return-from omega-solicit-preimage :fault))
      (let ((key (cons hash-bytes z)))
        (multiple-value-bind (entry present-p) (gethash key (hctx-lookup ctx))
          (unless present-p
            (multiple-value-bind (orphan-status discovered-p)
                (%try-discover-orphan ctx hash-bytes z)
              (when discovered-p
                (setf entry orphan-status
                      present-p t))))
          (cond
            ;; (h,z) ∉ K(a_l) → create new [] entry
            ((not present-p)
             ;; FULL check — must use POST-mutation state (GP B.6)
             ;; New entry adds: items +2, footprint +(81+z)
             (let ((a-t (compute-threshold (+ (hctx-items-count ctx) 2)
                                           (+ (hctx-footprint ctx) 81 z)
                                           (hctx-threshold ctx))))
               (when (> a-t (hctx-balance ctx))
                 (set-reg vm +a0+ +hc-full+)
                 (return-from omega-solicit-preimage :continue)))
             (setf (gethash key (hctx-lookup ctx)) '())
             ;; items +2, footprint +(81+z)
             (incf (hctx-items-count ctx) 2)
             (incf (hctx-footprint ctx) (+ 81 z))
             (set-reg vm +a0+ +hc-ok+)
             :continue)

            ;; [x, y] → append timeslot → [x, y, t]
            ;; No items/footprint change → pre-mutation check is correct
            ((and present-p entry (= (length entry) 2))
             (let ((a-t (compute-threshold (hctx-items-count ctx)
                                           (hctx-footprint ctx)
                                           (hctx-threshold ctx))))
               (when (> a-t (hctx-balance ctx))
                 (set-reg vm +a0+ +hc-full+)
                 (return-from omega-solicit-preimage :continue)))
             (let ((new-entry (append entry (list (hctx-timeslot ctx)))))
               (setf (gethash key (hctx-lookup ctx)) new-entry))
             (set-reg vm +a0+ +hc-ok+)
             :continue)

            ;; Otherwise → HUH
            (t
             (set-reg vm +a0+ +hc-huh+)
             :continue)))))))

;;; ═══════════════════════════════════════════════════════════════════
;;; 24 — ΩF Forget-preimage
;;;
;;; forget(o, z) → OK | HUH
;;; A0=o (hash ptr), A1=z (expected length)
;;; D = min_turnaround_period
;;; ═══════════════════════════════════════════════════════════════════

(defomega 24 omega-forget-preimage (vm ctx)
  "ΩF: Forget (expunge) a preimage."
  (let* ((o (u32 (reg vm +a0+)))
         (z (u32 (reg vm +a1+)))
         (d-period (hctx-min-turnaround ctx)))
    (let ((hash-bytes (read-guest vm o 32)))
      (unless hash-bytes (return-from omega-forget-preimage :fault))
      (let ((key (cons hash-bytes z)))
        (multiple-value-bind (entry present-p) (gethash key (hctx-lookup ctx))
          (unless present-p
            (multiple-value-bind (orphan-status discovered-p)
                (%try-discover-orphan ctx hash-bytes z)
              (if discovered-p
                  (setf entry orphan-status
                        present-p t)
                  (progn
                    (set-reg vm +a0+ +hc-huh+)
                    (return-from omega-forget-preimage :continue)))))
          (let ((t-slot (hctx-timeslot ctx)))
            (cond
              ;; [] → full removal of lookup + preimage
              ((null entry)
               (remhash key (hctx-lookup ctx))
               (remhash hash-bytes (hctx-preimages ctx))
               (decf (hctx-items-count ctx) (min 2 (hctx-items-count ctx)))
               (decf (hctx-footprint ctx) (min (+ 81 z) (hctx-footprint ctx)))
               (set-reg vm +a0+ +hc-ok+)
               :continue)

              ;; [x] → transform to [x, t]
              ((= (length entry) 1)
               (setf (gethash key (hctx-lookup ctx))
                     (list (first entry) t-slot))
               (set-reg vm +a0+ +hc-ok+)
               :continue)

              ;; [x, y] → full removal if y < t − D
              ((= (length entry) 2)
               (let ((y (second entry)))
                 (if (and (>= t-slot d-period) (< y (- t-slot d-period)))
                     (progn
                       (remhash key (hctx-lookup ctx))
                       (remhash hash-bytes (hctx-preimages ctx))
                       (decf (hctx-items-count ctx)
                             (min 2 (hctx-items-count ctx)))
                       (decf (hctx-footprint ctx)
                             (min (+ 81 z) (hctx-footprint ctx)))
                       (set-reg vm +a0+ +hc-ok+)
                       :continue)
                     (progn
                       (set-reg vm +a0+ +hc-huh+)
                       :continue))))

              ;; [x, y, w] → transform to [w, t] if y < t − D
              ((>= (length entry) 3)
               (let ((y (second entry))
                     (w (third entry)))
                 (if (and (>= t-slot d-period) (< y (- t-slot d-period)))
                     (progn
                       (setf (gethash key (hctx-lookup ctx))
                             (list w t-slot))
                       (set-reg vm +a0+ +hc-ok+)
                       :continue)
                     (progn
                       (set-reg vm +a0+ +hc-huh+)
                       :continue))))

              ;; Fallback
              (t
               (set-reg vm +a0+ +hc-huh+)
               :continue))))))))

;;; ═══════════════════════════════════════════════════════════════════
;;; 25 — Yield accumulation trie result
;;;
;;; yield(o) → OK
;;; A0=o (hash ptr, 32 bytes)
;;; ═══════════════════════════════════════════════════════════════════

(defomega 25 omega-yield-hash (vm ctx)
  "Yield: Store a 32-byte hash as accumulation trie result."
  (let ((o (u32 (reg vm +a0+))))
    (let ((hash-bytes (read-guest vm o 32)))
      (unless hash-bytes (return-from omega-yield-hash :fault))
      (when (hctx-debug-trace ctx)
        (format *error-output*
                "~&[HC25-YIELD] sid=~D addr=~D hash=~{~2,'0X~}~%"
                (hctx-service-id ctx) o (coerce hash-bytes 'list)))
      (setf (hctx-yield-output ctx) hash-bytes)
      (set-reg vm +a0+ +hc-ok+)
      :continue)))

;;; ═══════════════════════════════════════════════════════════════════
;;; 26 — Provide preimage
;;;
;;; provide(s, o, z) → OK | WHO | HUH
;;; A0=service, A1=data_ptr, A2=data_len
;;; ═══════════════════════════════════════════════════════════════════

(defomega 26 omega-provide-preimage (vm ctx)
  "Provide a preimage to a service."
  (let* ((phi7 (reg vm +a0+))
         (o    (u32 (reg vm +a1+)))
         (z    (u32 (reg vm +a2+))))

    ;; Resolve service s
    (let ((s (if (= phi7 +hc-none+)
                 (hctx-service-id ctx)
                 (u32 phi7))))

      ;; Read preimage data
      (let ((data (read-guest vm o z)))
        (unless data (return-from omega-provide-preimage :fault))

        ;; Compute H(i)
        (let* ((hash (jam.ffi:blake2b-256 data)))

          ;; Look up service account
          (let* ((is-self (= s (hctx-service-id ctx)))
                 (lookup-ht (if is-self
                                (hctx-lookup ctx)
                                (let ((acct (gethash s (hctx-service-accounts ctx))))
                                  (unless acct
                                    (set-reg vm +a0+ +hc-who+)
                                    (return-from omega-provide-preimage :continue))
                                  (sa-lookup acct))))
                 (key (cons hash z)))

            ;; a_l[(H(i), z)] must be exactly []
            (multiple-value-bind (entry present-p) (gethash key lookup-ht)
              (unless present-p
                (set-reg vm +a0+ +hc-huh+)
                (return-from omega-provide-preimage :continue))
              (when entry  ; non-empty → HUH
                (set-reg vm +a0+ +hc-huh+)
                (return-from omega-provide-preimage :continue)))

            ;; Check not already provided
            (when (some (lambda (pair)
                          (and (= (first pair) s)
                               (equalp (second pair) data)))
                        (hctx-provided-preimages ctx))
              (set-reg vm +a0+ +hc-huh+)
              (return-from omega-provide-preimage :continue))

            ;; OK — GP B.6: a_l'[(H(i), |i|)] = [τ']
            ;; Update lookup entry from [] to [timeslot]
            (setf (gethash key lookup-ht) (list (hctx-timeslot ctx)))
            (push (list s data) (hctx-provided-preimages ctx))
            (set-reg vm +a0+ +hc-ok+)
            :continue))))))
