;;;; omega-storage.lisp — Ω₃ (ΩR) Read-storage + Ω₄ (ΩW) Write-storage
;;;;
;;;; Ported from crypto/jam-crypto/src/pvm/host_calls.rs.
;;;; Uses blake2b via ironclad for storage key hashing (GP Appendix D).

(in-package #:jam-host)

;;; ═══════════════════════════════════════════════════════════════════
;;; 3 — ΩR Read-storage
;;;
;;; read(service, key_ptr, key_len, out_ptr, offset, out_len)
;;;   → value_len | NONE
;;; A0=service, A1=key_ptr, A2=key_len,
;;; A3=out_ptr, A4=offset, A5=out_len
;;; ═══════════════════════════════════════════════════════════════════

(defomega 3 omega-read-storage (vm ctx)
  "ΩR: Read a value from service storage."
  (let* ((service-raw (reg vm +a0+))
         (key-ptr     (u32 (reg vm +a1+)))
         (key-len     (u32 (reg vm +a2+)))
         (out-ptr     (u32 (reg vm +a3+)))
         (offset      (reg vm +a4+))
         (out-len     (reg vm +a5+)))

    ;; Resolve s* = s if φ₇=2⁶⁴−1, else φ₇
    (let* ((s-star (if (= service-raw +hc-none+)
                       (hctx-service-id ctx)
                       (u32 service-raw)))
           (is-self (= s-star (hctx-service-id ctx))))

      ;; Read key from guest memory
      (let ((key (read-guest vm key-ptr key-len)))
        (unless key (return-from omega-read-storage :fault))

        ;; Hash key → h27 (GP Appendix D)
        (let* ((h27 (storage-hash-key key))
               ;; Look up value
               (value (if is-self
                          (gethash h27 (hctx-storage ctx))
                          (let ((acct (gethash s-star (hctx-service-accounts ctx))))
                            (when acct (gethash h27 (sa-storage acct)))))))

          (cond
            ((null value)
             (set-reg vm +a0+ +hc-none+)
             :continue)

            (t
             (let* ((data-len (length value))
                    (f (min offset data-len))
                    (l (min out-len (- data-len f))))
               (when (plusp l)
                 (unless (write-guest vm out-ptr (subseq value f (+ f l)))
                   (return-from omega-read-storage :fault)))
               (set-reg vm +a0+ (u64 data-len))
               :continue))))))))

;;; ═══════════════════════════════════════════════════════════════════
;;; 4 — ΩW Write-storage
;;;
;;; write(key_ptr, key_len, value_ptr, value_len)
;;;   → old_len | NONE | FULL
;;; A0=key_ptr, A1=key_len, A2=value_ptr, A3=value_len
;;; ═══════════════════════════════════════════════════════════════════

(defomega 4 omega-write-storage (vm ctx)
  "ΩW: Write a value to own service storage."
  (let* ((key-ptr   (u32 (reg vm +a0+)))
         (key-len   (u32 (reg vm +a1+)))
         (value-ptr (u32 (reg vm +a2+)))
         (value-len (u32 (reg vm +a3+))))

    ;; Read key from guest
    (let ((key (read-guest vm key-ptr key-len)))
      (unless key (return-from omega-write-storage :fault))

      ;; Read value if v_Z > 0
      (let ((new-value (if (zerop value-len)
                           nil  ; delete
                           (let ((v (read-guest vm value-ptr value-len)))
                             (unless v (return-from omega-write-storage :fault))
                             v))))

        ;; Hash key → h27
        (let* ((h27 (storage-hash-key key))
               ;; Old length — GP: l = |s_s[k]| or NONE
               (old-val (gethash h27 (hctx-storage ctx)))
               (old-len (if old-val (u64 (length old-val)) +hc-none+))
               (key-sz (length key)))

          ;; GP ΩW: compute hypothetical post-mutation items/footprint
          ;; for the FULL check.  a_t must be checked on the NEW state a,
          ;; not the old state s.
          (let ((post-items (hctx-items-count ctx))
                (post-foot  (hctx-footprint ctx)))
            (cond
              ;; Delete — remove key entry
              ((null new-value)
               (when old-val
                 (decf post-items)
                 (decf post-foot (+ 34 key-sz (length old-val)))))
              ;; Insert (new key)
              ((null old-val)
               (incf post-items)
               (incf post-foot (+ 34 key-sz (length new-value))))
              ;; Update (existing key, new value)
              (t
               (incf post-foot (- (length new-value) (length old-val)))))

            ;; FULL check: a_t > a_b on POST-mutation state
            (let ((a-t (compute-threshold post-items post-foot
                                          (hctx-threshold ctx))))
              (when (> a-t (hctx-balance ctx))
                (set-reg vm +a0+ +hc-full+)
                (return-from omega-write-storage :continue))))

          ;; FULL check passed — apply actual mutation
          (cond
            ;; Delete
            ((null new-value)
             (when old-val
               (remhash h27 (hctx-storage ctx))
               (decf (hctx-items-count ctx))
               (decf (hctx-footprint ctx)
                     (+ 34 key-sz (length old-val)))))

            ;; Insert/Update
            (t
             (let ((new-val-len (length new-value)))
               (if old-val
                   ;; Update: footprint delta = new - old
                   (let ((old-val-len (length old-val)))
                     (setf (gethash h27 (hctx-storage ctx)) new-value)
                     (if (>= new-val-len old-val-len)
                         (incf (hctx-footprint ctx) (- new-val-len old-val-len))
                         (decf (hctx-footprint ctx) (- old-val-len new-val-len))))
                   ;; New entry: items +1, footprint +(34+|key|+|val|)
                   (progn
                     (setf (gethash h27 (hctx-storage ctx)) new-value)
                     (incf (hctx-items-count ctx))
                     (incf (hctx-footprint ctx) (+ 34 key-sz new-val-len)))))))

          (set-reg vm +a0+ old-len)
          :continue)))))
