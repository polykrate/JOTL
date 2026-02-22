;;;; omega-service.lisp — Ω₁₈-₂₁ Service management host calls
;;;;
;;;; 18 — ΩN  New-service
;;;; 19 — ΩU  Upgrade-service
;;;; 20 — ΩT  Transfer
;;;; 21 — ΩJ  Eject-service
;;;;
;;;; Ported from crypto/jam-crypto/src/pvm/host_calls.rs.

(in-package #:jam-host)

;;; ═══════════════════════════════════════════════════════════════════
;;; B.14 — Service ID management
;;;
;;; S = 2^16 = 65536 — minimum public service index
;;; Modulus = 2³² − S − 2⁸ = 4294901504
;;; ═══════════════════════════════════════════════════════════════════

(defconstant +service-index-min+ (ash 1 16)
  "S = 2^16: minimum public service index (GP B.14).")

(defconstant +service-id-modulus+ (- (expt 2 32) +service-index-min+ 256)
  "2³² − S − 2⁸: modulus for service ID space (GP B.14).")

(defun check-service-id (candidate ctx)
  "GP B.14: Find the first unused service ID starting from CANDIDATE.
   Walks the ID ring [S, 2³² − 2⁸ − 1] until an unused ID is found."
  (let ((i candidate))
    (dotimes (_ +service-id-modulus+ i)
      (unless (or (gethash i (hctx-existing-services ctx))
                  (some (lambda (pair) (= (first pair) i))
                        (hctx-created-services ctx)))
        (return-from check-service-id i))
      ;; (i − S + 1) mod (2³² − 2⁸ − S) + S
      (setf i (+ (mod (1+ (- i +service-index-min+)) +service-id-modulus+)
                  +service-index-min+)))
    (error "check-service-id: entire ID space exhausted")))

(defun encode-compact-u32 (value)
  "JAM compact encoding for small natural numbers (GP C.5).
   For 0:                    → #(0)
   For 1..63 (l=0):          → #(value)
   For 64..8191 (l=1):       → #(0x80 | hi, lo)
   For 8192..1048575 (l=2):  → #(0xC0 | hi, mid, lo)
   For 1048576..134217727:   → #(0xE0 | b3, b2, b1, b0)
   For ≥134217728 (l=4):     → #(0xF0 | b4, b3, b2, b1, b0)
   Sufficient for u32 values used in service IDs and timeslots."
  (cond
    ((= value 0) (make-array 1 :element-type '(unsigned-byte 8) :initial-element 0))
    ((< value (ash 1 7))   ;; l=0: 1 byte
     (make-array 1 :element-type '(unsigned-byte 8) :initial-contents (list value)))
    ((< value (ash 1 14))  ;; l=1: 2 bytes
     (let ((lo (logand value #xFF))
           (hi (ash value -8)))
       (make-array 2 :element-type '(unsigned-byte 8)
                     :initial-contents (list (logior #x80 hi) lo))))
    ((< value (ash 1 21))  ;; l=2: 3 bytes
     (let ((b0 (logand value #xFF))
           (b1 (logand (ash value -8) #xFF))
           (hi (ash value -16)))
       (make-array 3 :element-type '(unsigned-byte 8)
                     :initial-contents (list (logior #xC0 hi) b0 b1))))
    ((< value (ash 1 28))  ;; l=3: 4 bytes
     (let ((b0 (logand value #xFF))
           (b1 (logand (ash value -8) #xFF))
           (b2 (logand (ash value -16) #xFF))
           (hi (ash value -24)))
       (make-array 4 :element-type '(unsigned-byte 8)
                     :initial-contents (list (logior #xE0 hi) b0 b1 b2))))
    (t  ;; l=4: 5 bytes (covers full u32 range)
     (let ((b0 (logand value #xFF))
           (b1 (logand (ash value -8) #xFF))
           (b2 (logand (ash value -16) #xFF))
           (b3 (logand (ash value -24) #xFF)))
       (make-array 5 :element-type '(unsigned-byte 8)
                     :initial-contents (list #xF0 b0 b1 b2 b3))))))

(defun raw-next-service-id (service-id entropy-0 timeslot)
  "GP B.10: Hash-derived candidate for initial next-service-id.
   i = E₄⁻¹(H(E(s, η'₀, H_T))) mod (2³² − S − 2⁸) + S
   where E(s, η'₀, H_T) = compact(s) ⌢ η'₀[0..32] ⌢ compact(H_T).
   H_T = timeslot (GP C.23: E₄(H_T) in header serialization).
   OPEN QUESTION: should H_T use E₄ instead of compact here?
   s and H_T currently use JAM compact encoding (GP C.5)."
  (let* ((enc-s  (encode-compact-u32 service-id))
         (enc-ts (encode-compact-u32 timeslot))
         (eta-len (min 32 (length entropy-0)))
         (preimage-len (+ (length enc-s) eta-len (length enc-ts)))
         (preimage (make-array preimage-len :element-type '(unsigned-byte 8) :initial-element 0))
         (pos 0))
    ;; compact(service_id)
    (replace preimage enc-s :start1 pos)
    (incf pos (length enc-s))
    ;; η'₀ (first 32 bytes of entropy)
    (dotimes (i eta-len)
      (setf (aref preimage (+ pos i)) (aref entropy-0 i)))
    (incf pos eta-len)
    ;; compact(H_T) — timeslot
    (replace preimage enc-ts :start1 pos)
    ;; H(...) = blake2b-256
    (let* ((digest (ironclad:make-digest :blake2/256))
           (_ (ironclad:update-digest digest preimage))
           (hash (ironclad:produce-digest digest))
           ;; E₄⁻¹ = first 4 bytes as u32 LE
           (raw (+ (aref hash 0)
                   (ash (aref hash 1) 8)
                   (ash (aref hash 2) 16)
                   (ash (aref hash 3) 24))))
      (declare (ignore _))
      (+ (mod raw +service-id-modulus+) +service-index-min+))))

(defun compute-next-service-id (service-id entropy-0 timeslot ctx)
  "GP B.10 + B.14: Compute initial next-service-id for accumulation.
   Combines hash-derived candidate with collision checking."
  (let ((candidate (raw-next-service-id service-id entropy-0 timeslot)))
    (check-service-id candidate ctx)))

(defun advance-service-id (current ctx)
  "GP ΩN: Advance next_service_id after non-privileged creation.
   i* = check(S + (x_i − S + 42) mod (2³² − S − 2⁸))"
  (let ((candidate (+ +service-index-min+
                      (mod (+ (- current +service-index-min+) 42)
                           +service-id-modulus+))))
    (check-service-id candidate ctx)))

;;; ═══════════════════════════════════════════════════════════════════
;;; 18 — ΩN New-service
;;;
;;; new(o, l, g, m, f, ĩ) → new_id | HUH | CASH | FULL | ♯(fault)
;;; A0=o (code hash ptr), A1=l (code length), A2=g (min accum gas),
;;; A3=m (min item gas), A4=f (balance offset / privilege flag),
;;; A5=ĩ (target index for privileged creation)
;;; ═══════════════════════════════════════════════════════════════════

(defomega 18 omega-new-service (vm ctx)
  "ΩN: Create a new service."
  (let* ((o       (u32 (reg vm +a0+)))     ; code hash pointer
         (l       (reg vm +a1+))            ; code length
         (g       (reg vm +a2+))            ; min accumulate gas (a_g)
         (m       (reg vm +a3+))            ; min memo gas (a_m)
         (f       (reg vm +a4+))            ; balance offset (a_f) + privilege flag
         (i-tilde (u32 (reg vm +a5+))))    ; target index (privileged)

    ;; ── Read code hash c (32 bytes) ──
    ;; c = ∇ if N_{o…+32} ∉ V_μ ∨ l ∉ N_{2³²}
    (when (> l +u32-max+)
      (return-from omega-new-service :fault))
    (let ((c-bytes (read-guest vm o 32)))
      (unless (and c-bytes (= (length c-bytes) 32))
        (return-from omega-new-service :fault))

      (let ((c (make-array 32 :element-type '(unsigned-byte 8))))
        (replace c c-bytes)

        ;; ── f ≠ 0 ∧ x_s ≠ (x_e)_m → HUH ──
        (when (plusp f)
          (let ((is-manager (and (hctx-empower ctx)
                                 (= (hctx-service-id ctx)
                                    (emp-manager (hctx-empower ctx))))))
            (unless is-manager
              (set-reg vm +a0+ +hc-huh+)
              (return-from omega-new-service :continue))))

        ;; ── GP B.10 ΩN: Compute a_t using the NEW service's footprint ──
        ;; The new service starts with a lookup entry {((c,l) ↦ [])}.
        ;; Per ΩS footprint rules: items += 2, bytes += (81 + l).
        ;; a_t = max(0, B_S + B_I * new_items + B_L * new_bytes - f)
        (let* ((new-items 2)                  ; 1 lookup entry + 1 preimage slot
               (new-bytes (+ 81 l))           ; 81 overhead + code length
               (a-t (compute-threshold new-items new-bytes f)))
          ;; s_b = (x_s)_b − a_t
          (when (< (hctx-balance ctx) a-t)
            (set-reg vm +a0+ +hc-cash+)
            (return-from omega-new-service :continue))

          (let ((s-b (- (hctx-balance ctx) a-t)))
            ;; s_b < (x_s)_t → CASH  (caller can't go below own threshold)
            (let ((caller-threshold (compute-threshold (hctx-items-count ctx)
                                                       (hctx-footprint ctx)
                                                       (hctx-threshold ctx))))
              (when (< s-b caller-threshold)
                (set-reg vm +a0+ +hc-cash+)
                (return-from omega-new-service :continue)))

            ;; ── Build new service account ──
            (let ((new-acct (make-service-account
                             :code-hash c
                             :balance a-t
                             :min-accum-gas g
                             :min-memo-gas m
                             :threshold f
                             :items-count new-items
                             :footprint new-bytes
                             :creation-slot (hctx-timeslot ctx))))

              ;; ── Determine creation path ──
              (let ((is-staker (and (hctx-empower ctx)
                                    (= (hctx-service-id ctx)
                                       (emp-staker (hctx-empower ctx))))))

                (if (and is-staker (< i-tilde +service-index-min+))
                    ;; ── Privileged path: ĩ < S ──
                    (let ((id-taken (or (gethash i-tilde (hctx-existing-services ctx))
                                        (some (lambda (pair) (= (first pair) i-tilde))
                                              (hctx-created-services ctx)))))
                      (when id-taken
                        (set-reg vm +a0+ +hc-full+)
                        (return-from omega-new-service :continue))

                      ;; Create at privileged index
                      (push (list i-tilde c l) (hctx-created-services ctx))
                      (setf (gethash i-tilde (hctx-service-accounts ctx)) new-acct)
                      (setf (hctx-balance ctx) s-b)
                      (set-reg vm +a0+ (u64 i-tilde))
                      :continue)

                    ;; ── Non-privileged path ──
                    (let ((new-sid (hctx-next-service-id ctx)))
                      (push (list new-sid c l) (hctx-created-services ctx))
                      (setf (gethash new-sid (hctx-service-accounts ctx)) new-acct)
                      (setf (hctx-balance ctx) s-b)

                      ;; Advance: i* = check(S + (x_i − S + 42) mod (2³² − S − 2⁸))
                      (setf (hctx-next-service-id ctx)
                            (advance-service-id new-sid ctx))

                      (set-reg vm +a0+ (u64 new-sid))
                      :continue))))))))))

;;; ═══════════════════════════════════════════════════════════════════
;;; 19 — ΩU Upgrade-service
;;;
;;; upgrade(o, g, m) → OK | ♯(fault)
;;; A0=o (code hash ptr), A1=g (min accumulate gas), A2=m (min item gas)
;;; ═══════════════════════════════════════════════════════════════════

(defomega 19 omega-upgrade (vm ctx)
  "ΩU: Upgrade service code hash and gas parameters."
  (let* ((o (u32 (reg vm +a0+)))     ; code hash pointer
         (g (reg vm +a1+))            ; min accumulate gas
         (m (reg vm +a2+)))           ; min item gas

    ;; ── Read code hash c (32 bytes) ──
    (let ((c-bytes (read-guest vm o 32)))
      (unless (and c-bytes (= (length c-bytes) 32))
        (return-from omega-upgrade :fault))

      (let ((c (make-array 32 :element-type '(unsigned-byte 8))))
        (replace c c-bytes)

        ;; ── OK: mutate (x_s)_c, (x_s)_g, (x_s)_m ──
        (setf (hctx-code-hash ctx) c
              (hctx-min-accum-gas ctx) g
              (hctx-min-memo-gas ctx) m)

        ;; Track for external collapse
        (push (list (hctx-service-id ctx) c) (hctx-upgrades ctx))

        (set-reg vm +a0+ +hc-ok+)
        :continue))))

;;; ═══════════════════════════════════════════════════════════════════
;;; 20 — ΩT Transfer
;;;
;;; transfer(d, a, l, o) → (OK, l) | WHO | LOW | CASH | ♯(fault)
;;; A0=d (dest), A1=a (amount), A2=l (gas limit), A3=o (memo ptr)
;;;
;;; W_T = 128 (transfer memo size)
;;; ═══════════════════════════════════════════════════════════════════

(defomega 20 omega-transfer (vm ctx)
  "ΩT: Transfer tokens to another service."
  (let* ((d (u32 (reg vm +a0+)))      ; destination service ID
         (a (reg vm +a1+))             ; amount
         (l (reg vm +a2+))             ; gas limit
         (o (u32 (reg vm +a3+))))     ; memo pointer

    ;; ── Read memo (W_T bytes) ──
    (let ((memo (read-guest vm o +memo-size+)))
      (unless memo (return-from omega-transfer :fault))

      ;; ── d ∉ K(d) → WHO ──
      (let ((dest-known (or (gethash d (hctx-existing-services ctx))
                            (some (lambda (pair) (= (first pair) d))
                                  (hctx-created-services ctx))
                            (= d (hctx-service-id ctx)))))
        (unless dest-known
          (set-reg vm +a0+ +hc-who+)
          (return-from omega-transfer :continue))

        ;; ── l < d[d]_m → LOW ──
        (let ((dest-min-memo (if (= d (hctx-service-id ctx))
                                 (hctx-min-memo-gas ctx)
                                 (let ((acct (gethash d (hctx-service-accounts ctx))))
                                   (if acct (sa-min-memo-gas acct) 0)))))
          (when (< l dest-min-memo)
            (set-reg vm +a0+ +hc-low+)
            (return-from omega-transfer :continue))

          ;; ── b = (x_s)_b − a; b < (x_s)_t → CASH ──
          (when (< (hctx-balance ctx) a)
            (set-reg vm +a0+ +hc-cash+)
            (return-from omega-transfer :continue))

          (let ((b (- (hctx-balance ctx) a)))
            (let ((a-t (compute-threshold (hctx-items-count ctx)
                                          (hctx-footprint ctx)
                                          (hctx-threshold ctx))))
              (when (< b a-t)
                (set-reg vm +a0+ +hc-cash+)
                (return-from omega-transfer :continue))

              ;; ── Deduct extra gas: g = 10 + l (base 10 already charged) ──
              (let ((remaining (pvm-gas vm)))
                (when (< remaining (the integer l))
                  (setf (pvm-gas vm) (- remaining l))  ; go negative → OOG
                  (return-from omega-transfer :oog))
                (decf (pvm-gas vm) l))

              ;; ── OK: apply side-effects ──
              (setf (hctx-balance ctx) b)
              (push (make-jam-transfer
                     :from-service (hctx-service-id ctx)
                     :to-service d
                     :amount a
                     :memo memo
                     :gas-limit l)
                    (hctx-transfers ctx))

              (set-reg vm +a0+ +hc-ok+)
              (set-reg vm +a1+ (u64 l))
              :continue)))))))

;;; ═══════════════════════════════════════════════════════════════════
;;; 21 — ΩJ Eject-service
;;;
;;; eject(d, o) → OK | WHO | HUH | ♯(fault)
;;; A0=d (target service ID), A1=o (code hash ptr)
;;;
;;; D = min_turnaround_period. Target must have items=2 and
;;; lookup entry [x, y] with y < t − D.
;;; ═══════════════════════════════════════════════════════════════════

(defomega 21 omega-eject (vm ctx)
  "ΩJ: Eject a service and reclaim its balance."
  (let* ((d-id (u32 (reg vm +a0+)))     ; target service ID
         (o    (u32 (reg vm +a1+)))     ; code hash pointer
         (d-period (hctx-min-turnaround ctx)))

    ;; ── Read hash h (32 bytes) ──
    (let ((h-bytes (read-guest vm o 32)))
      (unless (and h-bytes (= (length h-bytes) 32))
        (return-from omega-eject :fault))

      (let ((h (make-array 32 :element-type '(unsigned-byte 8))))
        (replace h h-bytes)

        ;; ── Look up target account ──
        ;; d = ∇ if d = x_s (can't eject self) or d ∉ K(d)
        (let ((target-acct (when (/= d-id (hctx-service-id ctx))
                             (gethash d-id (hctx-service-accounts ctx)))))

          ;; ── E₃₂(x_s): 32-byte LE encoding of calling service ID ──
          (let ((e32-xs (make-array 32 :element-type '(unsigned-byte 8)
                                       :initial-element 0)))
            (let ((sid (hctx-service-id ctx)))
              (dotimes (i 4)
                (setf (aref e32-xs i) (logand (ash sid (* -8 i)) #xFF))))

            ;; ── d = ∇ ∨ d_c ≠ E₃₂(x_s) → WHO ──
            (unless (and target-acct
                         (equalp (sa-code-hash target-acct) e32-xs))
              (set-reg vm +a0+ +hc-who+)
              (return-from omega-eject :continue))

            ;; ── l = max(81, d_o) − 81 ──
            (let* ((d-o (sa-footprint target-acct))
                   (l (- (max 81 d-o) 81)))

              ;; ── d_i ≠ 2 → HUH ──
              (unless (= (sa-items-count target-acct) 2)
                (set-reg vm +a0+ +hc-huh+)
                (return-from omega-eject :continue))

              ;; ── (h, l) ∉ d_l → HUH ──
              (let* ((key (cons h l))
                     (entry (gethash key (sa-lookup target-acct))))
                (unless entry
                  (set-reg vm +a0+ +hc-huh+)
                  (return-from omega-eject :continue))

                ;; ── d_l[h,l] = [x, y], y < t − D → OK ──
                (if (and (= (length entry) 2)
                         (let ((y (second entry))
                               (t-slot (hctx-timeslot ctx)))
                           (and (>= t-slot d-period)
                                (< y (- t-slot d-period)))))
                    ;; OK: remove target, credit balance
                    (let ((target-balance (sa-balance target-acct)))
                      (remhash d-id (hctx-service-accounts ctx))
                      (remhash d-id (hctx-existing-services ctx))
                      (incf (hctx-balance ctx) target-balance)
                      (push (list d-id (hctx-service-id ctx))
                            (hctx-ejected-services ctx))
                      (set-reg vm +a0+ +hc-ok+)
                      :continue)

                    ;; Otherwise → HUH
                    (progn
                      (set-reg vm +a0+ +hc-huh+)
                      :continue))))))))))
