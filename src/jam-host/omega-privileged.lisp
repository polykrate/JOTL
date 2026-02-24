;;;; omega-privileged.lisp — Ω₁₄-₁₇ Privileged host calls
;;;;
;;;; 14 — ΩB  Empower-service (bless)
;;;; 15 — ΩA  Assign-core
;;;; 16 — ΩD  Designate-validators
;;;; 17 — ΩC  Checkpoint
;;;;
;;;; Implements GP Appendix B.7–B.13 (privileged host calls).

(in-package #:jam-host)

;;; ═══════════════════════════════════════════════════════════════════
;;; 14 — ΩB Empower-service (bless)
;;;
;;; bless(m, a_ptr, v, r, o, n) → OK | ♯(fault)
;;; A0=m, A1=a_ptr, A2=v, A3=r, A4=o, A5=n
;;;
;;; GP B.7: Sets x_e = (m, a, v, r, z, q, l)
;;; where a = C authorization agents (4 bytes each)
;;;       z = n gas map entries (12 bytes each: E_4(sid)~E_8(gas))
;;; ═══════════════════════════════════════════════════════════════════

(defomega 14 omega-bless (vm ctx)
  "ΩB: Set privileged empower state.
   GP: (m, v, r) must all be in N³_S — i.e. valid u32 service IDs (< 2³²).
   If any raw register value ≥ 2³², return WHO."
  (let* ((m-raw (reg vm +a0+))           ; raw 64-bit register values
         (v-raw (reg vm +a2+))
         (r-raw (reg vm +a3+))
         (m     (u32 m-raw))             ; truncated for use after checks
         (a-ptr (u32 (reg vm +a1+)))     ; pointer to auth agents array
         (v     (u32 v-raw))             ; validator service
         (r     (u32 r-raw))             ; staking service
         (o     (u32 (reg vm +a4+)))     ; pointer to gas map entries
         (n     (u32 (reg vm +a5+)))     ; number of gas map entries
         (c     (hctx-core-count ctx)))  ; C = core count

    ;; ── Read a: C authorization agents (4 bytes each) ──
    (let* ((a-bytes (* 4 c))
           (a-raw (read-guest vm a-ptr a-bytes)))
      (unless a-raw (return-from omega-bless :fault))

      (let ((auth-agents (make-array c :element-type '(unsigned-byte 32))))
        (dotimes (i c)
          (let ((start (* i 4)))
            (setf (aref auth-agents i)
                  (logior (aref a-raw start)
                          (ash (aref a-raw (+ start 1)) 8)
                          (ash (aref a-raw (+ start 2)) 16)
                          (ash (aref a-raw (+ start 3)) 24)))))

        ;; ── Read z: n entries of 12 bytes (E_4(s) ~ E_8(g)) ──
        (let* ((z-total (* 12 n))
               (z-raw (read-guest vm o z-total)))
          (unless z-raw (return-from omega-bless :fault))

          (let ((gas-map (make-hash-table :test 'eql)))
            (dotimes (i n)
              (let ((base (* i 12)))
                (let ((sid (logior (aref z-raw base)
                                   (ash (aref z-raw (+ base 1)) 8)
                                   (ash (aref z-raw (+ base 2)) 16)
                                   (ash (aref z-raw (+ base 3)) 24)))
                      (gas (let ((val 0))
                             (dotimes (j 8 val)
                               (setf val (logior val
                                                 (ash (aref z-raw (+ base 4 j))
                                                      (* 8 j))))))))
                  (setf (gethash sid gas-map) gas))))

            ;; ── GP: (m, v, r) ∉ N³_S → WHO ──
            ;; Raw register values must be valid u32 (< 2³²).
            (when (or (>= m-raw (expt 2 32))
                      (>= v-raw (expt 2 32))
                      (>= r-raw (expt 2 32)))
              (set-reg vm +a0+ +hc-who+)
              (return-from omega-bless :continue))

            ;; ── Preserve existing q and l from prior ΩB ──
            (let ((prev-queues (if (hctx-empower ctx)
                                   (emp-queues (hctx-empower ctx))
                                   (make-array 0)))
                  (prev-validators (if (hctx-empower ctx)
                                       (emp-validators (hctx-empower ctx))
                                       (make-array 0))))

              ;; ── OK: set x_e = (m, a, v, r, z, q, l) ──
              (setf (hctx-empower ctx)
                    (make-empower-state
                     :manager m
                     :auth-agents auth-agents
                     :validator v
                     :staker r
                     :gas-map gas-map
                     :queues prev-queues
                     :validators prev-validators))

              (set-reg vm +a0+ +hc-ok+)
              :continue)))))))

;;; ═══════════════════════════════════════════════════════════════════
;;; 15 — ΩA Assign-core
;;;
;;; assign(c, o, a) → OK | CORE | HUH | WHO | ♯(fault)
;;; A0=c (core index), A1=o (Q hashes ptr), A2=a (new auth agent)
;;;
;;; GP: Read Q authorization hashes (32 bytes each), set queue for core c.
;;; ═══════════════════════════════════════════════════════════════════

(defomega 15 omega-assign (vm ctx)
  "ΩA: Assign authorization queue to a core.
   GP: c, a are raw 64-bit register values; c ≥ C → CORE; a ∉ N_S → WHO."
  (let* ((c-raw  (reg vm +a0+))          ; raw 64-bit core index
         (o      (u32 (reg vm +a1+)))    ; memory offset for Q hashes
         (a-raw  (reg vm +a2+))          ; raw 64-bit auth agent service ID
         (c-idx  (u32 c-raw))            ; truncated for array access
         (a      (u32 a-raw))            ; truncated for lookup
         (q-count (hctx-auth-queue-len ctx)))  ; Q

    ;; ── Read q: Q authorization hashes (32 bytes each) ──
    (let* ((q-total (* q-count 32))
           (q-raw (read-guest vm o q-total)))
      (unless q-raw (return-from omega-assign :fault))

      (let ((q (make-array q-count)))
        (dotimes (i q-count)
          (let ((start (* i 32))
                (hash (make-array 32 :element-type '(unsigned-byte 8))))
            (replace hash q-raw :start2 start :end2 (+ start 32))
            (setf (aref q i) hash)))

        ;; ── c ≥ C → CORE (use raw 64-bit value for comparison) ──
        (when (>= c-raw (hctx-core-count ctx))
          (set-reg vm +a0+ +hc-core+)
          (return-from omega-assign :continue))

        ;; ── x_s ≠ (x_e).a[c] → HUH ──
        ;; GP: x_e defaults to zero-initialized; (x_e).a = [] initially.
        ;; If no prior ΩB, emp is nil → auth-agents is empty → always HUH.
        (let* ((emp (hctx-empower ctx))
               (auth (when emp (emp-auth-agents emp))))
          (unless (and auth
                       (< c-idx (length auth))
                       (= (hctx-service-id ctx)
                          (aref auth c-idx)))
            (set-reg vm +a0+ +hc-huh+)
            (return-from omega-assign :continue))

          ;; ── a ∉ N_S → WHO (raw value must be valid u32 AND exist) ──
          (when (or (>= a-raw (expt 2 32))
                    (not (gethash a (hctx-existing-services ctx))))
            (set-reg vm +a0+ +hc-who+)
            (return-from omega-assign :continue))

          ;; ── OK: set (x_e).q[c] = q, (x_e).a[c] = a ──
          ;; Ensure queues vector is large enough
          (let ((queues (emp-queues emp)))
            (when (< (length queues) (1+ c-idx))
              (let ((new-q (make-array (1+ c-idx) :initial-element nil)))
                (dotimes (i (length queues))
                  (setf (aref new-q i) (aref queues i)))
                (setf (emp-queues emp) new-q
                      queues (emp-queues emp))))
            (setf (aref queues c-idx) q)
            (setf (aref (emp-auth-agents emp) c-idx) a))

          (set-reg vm +a0+ +hc-ok+)
          :continue)))))

;;; ═══════════════════════════════════════════════════════════════════
;;; 16 — ΩD Designate-validators
;;;
;;; designate(o) → OK | HUH | ♯(fault)
;;; A0=o (memory offset for V validator keys, 336 bytes each)
;;;
;;; GP: Read V validator keys, update (x_e)_l = v.
;;; ═══════════════════════════════════════════════════════════════════

(defomega 16 omega-designate (vm ctx)
  "ΩD: Designate validator keys.
   GP B.9: x_s ≠ (x_e)_v → HUH.
   When x_e has not been set (no prior ΩB), the GP defines the initial
   empower state as zero-initialized: (x_e)_v = 0.  Service 0 (= χ_V
   by default) can therefore call ΩD without a prior ΩB."
  (let* ((o       (u32 (reg vm +a0+)))
         (v-count (hctx-val-count ctx)))  ; V

    ;; ── Read v: V validator keys (336 bytes each) ──
    (let* ((v-total (* v-count 336))
           (v-raw (read-guest vm o v-total)))
      (unless v-raw (return-from omega-designate :fault))

      ;; ── x_s ≠ (x_e)_v → HUH ──
      ;; GP: x_e defaults to zero-initialized tuple, so (x_e)_v = 0 initially.
      ;; If no prior ΩB: emp is nil → treat (x_e)_v as 0.
      (let* ((emp (hctx-empower ctx))
             (emp-v (if emp (emp-validator emp) 0)))
        (unless (= (hctx-service-id ctx) emp-v)
          (set-reg vm +a0+ +hc-huh+)
          (return-from omega-designate :continue))

        ;; Create default empower state if ΩB was never called
        (unless emp
          (setf emp (make-empower-state))
          (setf (hctx-empower ctx) emp))

        ;; Parse validator keys
        (let ((validators (make-array v-count)))
          (dotimes (i v-count)
            (let ((start (* i 336))
                  (key (make-array 336 :element-type '(unsigned-byte 8))))
              (replace key v-raw :start2 start :end2 (+ start 336))
              (setf (aref validators i) key)))

          ;; ── OK: (x_e)_l = v ──
          (setf (emp-validators emp) validators)
          (set-reg vm +a0+ +hc-ok+)
          :continue)))))

;;; ═══════════════════════════════════════════════════════════════════
;;; 17 — ΩC Checkpoint
;;;
;;; checkpoint() → gas_remaining
;;;
;;; GP B.13: Snapshot current side-effect state.
;;; On panic/OOG, execution reverts to this snapshot.
;;; Returns gas remaining at checkpoint time.
;;; ═══════════════════════════════════════════════════════════════════

(defomega 17 omega-checkpoint (vm ctx)
  "ΩC: Take a snapshot of accumulate side-effects."
  (checkpoint-save ctx)
  (set-reg vm +a0+ (u64 (pvm-gas vm)))
  :continue)
