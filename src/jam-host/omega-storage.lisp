;;;; omega-storage.lisp — Ω₃ (ΩR) Read-storage + Ω₄ (ΩW) Write-storage
;;;;
;;;; Implements GP Appendix B.3–B.4 (storage read/write).
;;;; Uses blake2b via jam.ffi (Rust FFI) for storage key hashing (GP Appendix D).

(in-package #:jam-host)

;;; ═══════════════════════════════════════════════════════════════════
;;; 3 — ΩR Read-storage
;;;
;;; read(service, key_ptr, key_len, out_ptr, offset, out_len)
;;;   → value_len | NONE
;;; A0=service, A1=key_ptr, A2=key_len,
;;; A3=out_ptr, A4=offset, A5=out_len
;;; ═══════════════════════════════════════════════════════════════════

(defun %self-storage-lookup (ctx h27)
  "Look up h27 in self-service storage: overlay → deletes → kvs-index.
   Returns value or NIL."
  (multiple-value-bind (v found) (gethash h27 (hctx-storage ctx))
    (when found (return-from %self-storage-lookup v)))
  (when (gethash h27 (hctx-storage-deletes ctx))
    (return-from %self-storage-lookup nil))
  (gethash h27 (hctx-kvs-index ctx)))

(defomega 3 omega-read-storage (vm ctx)
  "ΩR: Read a value from service storage.
   Self-service reads use pure computation: overlay → deletes → kvs-index."
  (let* ((service-raw (reg vm +a0+))
         (key-ptr     (u32 (reg vm +a1+)))
         (key-len     (u32 (reg vm +a2+)))
         (out-ptr     (u32 (reg vm +a3+)))
         (offset      (reg vm +a4+))
         (out-len     (reg vm +a5+)))

    (let* ((s-star (if (= service-raw +hc-none+)
                       (hctx-service-id ctx)
                       (u32 service-raw)))
           (is-self (= s-star (hctx-service-id ctx))))

      (let ((key (read-guest vm key-ptr key-len)))
        (unless key (return-from omega-read-storage :fault))

        (let* ((h27 (storage-hash-key key))
               (value (if is-self
                          (%self-storage-lookup ctx h27)
                          (let ((acct (gethash s-star (hctx-service-accounts ctx))))
                            (when acct (gethash h27 (sa-storage acct)))))))

          (cond
            ((null value)
             (when (hctx-debug-trace ctx)
               (format *error-output*
                       "~&[HC3-READ] sid=~D key(~D)=~{~2,'0X~} → NONE~%"
                       (hctx-service-id ctx) (length key) (coerce key 'list)))
             (set-reg vm +a0+ +hc-none+)
             :continue)

            (t
             (let* ((data-len (length value))
                    (f (min offset data-len))
                    (l (min out-len (- data-len f))))
               (when (hctx-debug-trace ctx)
                 (let ((val-hash (jam.ffi:blake2b-256 value)))
                   (format *error-output*
                           "~&[HC3-READ] sid=~D key(~D)=~{~2,'0X~} val-len=~D read=~D first-8: ~{~2,'0X~} blake2=~{~2,'0X~}~%"
                           (hctx-service-id ctx) (length key) (coerce key 'list)
                           data-len l
                           (coerce (subseq value f (min (+ f 8) (+ f l))) 'list)
                           (coerce (subseq val-hash 0 16) 'list))))
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
  "ΩW: Write a value to own service storage.
   Uses overlay (hctx-storage) + explicit deletes (hctx-storage-deletes)
   with kvs-index as immutable base layer."
  (let* ((key-ptr   (u32 (reg vm +a0+)))
         (key-len   (u32 (reg vm +a1+)))
         (value-ptr (u32 (reg vm +a2+)))
         (value-len (u32 (reg vm +a3+))))

    (let ((key (read-guest vm key-ptr key-len)))
      (unless key (return-from omega-write-storage :fault))

      (let ((new-value (if (zerop value-len)
                           nil
                           (let ((v (read-guest vm value-ptr value-len)))
                             (unless v (return-from omega-write-storage :fault))
                             v))))

        (let* ((h27 (storage-hash-key key))
               (old-val (%self-storage-lookup ctx h27))
               (old-len (if old-val (u64 (length old-val)) +hc-none+))
               (key-sz (length key)))

          ;; FULL check: hypothetical post-mutation items/footprint
          (let ((post-items (hctx-items-count ctx))
                (post-foot  (hctx-footprint ctx)))
            (cond
              ((null new-value)
               (when old-val
                 (decf post-items)
                 (decf post-foot (+ 34 key-sz (length old-val)))))
              ((null old-val)
               (incf post-items)
               (incf post-foot (+ 34 key-sz (length new-value))))
              (t
               (incf post-foot (- (length new-value) (length old-val)))))

            (let ((a-t (compute-threshold post-items post-foot
                                          (hctx-threshold ctx))))
              (when (> a-t (hctx-balance ctx))
                (set-reg vm +a0+ +hc-full+)
                (return-from omega-write-storage :continue))))

          ;; Debug trace
          (when (hctx-debug-trace ctx)
            (let ((val-hash (when new-value (jam.ffi:blake2b-256 new-value))))
              (format *error-output*
                      "~&[HC4-WRITE] sid=~D key(~D)=~{~2,'0X~} old-len=~A new-len=~A first-8: ~{~2,'0X~} blake2=~{~2,'0X~}~%"
                      (hctx-service-id ctx) key-sz (coerce key 'list)
                      (if old-val (length old-val) "NIL")
                      (if new-value (length new-value) "DEL")
                      (if new-value (coerce (subseq new-value 0 (min 8 (length new-value))) 'list) nil)
                      (if val-hash (coerce (subseq val-hash 0 (min 16 (length val-hash))) 'list) nil))
              (when (and new-value (<= (length new-value) 128))
                (format *error-output*
                        "~&[HC4-FULL] sid=~D key(~D)=~{~2,'0X~} val(~D)=~{~2,'0X~}~%"
                        (hctx-service-id ctx) key-sz (coerce key 'list)
                        (length new-value) (coerce new-value 'list)))))

          ;; Apply mutation to overlay + deletes
          (cond
            ;; Delete
            ((null new-value)
             (when old-val
               (remhash h27 (hctx-storage ctx))
               (setf (gethash h27 (hctx-storage-deletes ctx)) t)
               (decf (hctx-items-count ctx))
               (decf (hctx-footprint ctx)
                     (+ 34 key-sz (length old-val)))))

            ;; Insert/Update
            (t
             (let ((new-val-len (length new-value)))
               (setf (gethash h27 (hctx-storage ctx)) new-value)
               (remhash h27 (hctx-storage-deletes ctx))
               (if old-val
                   (let ((old-val-len (length old-val)))
                     (if (>= new-val-len old-val-len)
                         (incf (hctx-footprint ctx) (- new-val-len old-val-len))
                         (decf (hctx-footprint ctx) (- old-val-len new-val-len))))
                   (progn
                     (incf (hctx-items-count ctx))
                     (incf (hctx-footprint ctx) (+ 34 key-sz new-val-len)))))))

          (set-reg vm +a0+ old-len)
          :continue)))))
