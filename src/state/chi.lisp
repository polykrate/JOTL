;;;; state/chi.lisp — χ Privileged Service Indices (GP §9.4)
;;;;
;;;; GP (9.9):  χ = (χ_M, χ_V, χ_R, χ_A, χ_Z)
;;;;   χ_M ∈ N_S   : manager (blessed) service index
;;;;   χ_V ∈ N_S   : designate service index (can set ι)
;;;;   χ_R ∈ N_S   : new-service-creation service (protected range)
;;;;   χ_A ∈ [N_S]_C : per-core authorizer service indices
;;;;   χ_Z ∈ (N_S → N_G) : always-accumulate services + gas map
;;;;
;;;; Merkle key: C(12).
;;;;
;;;; Encoding (state S field order: m, a, v, r, z):
;;;;   E4(χ_M)                                           (4 bytes)
;;;;   C × E4(χ_A[c])                                   (C × 4 bytes)
;;;;   E4(χ_V)                                           (4 bytes)
;;;;   E4(χ_R)                                           (4 bytes)
;;;;   compact(|χ_Z|) ⌢ |χ_Z| × (E4(sid) ⌢ E8(gas))   (variable)
;;;;
;;;; Messages:
;;;;   :raw           → raw segment bytes
;;;;   :save       → binary encoding
;;;;   :decode        → reconstruct from bytes
;;;;   :fields        → decoded plist (memoized)
;;;;   :manager       → χ_M
;;;;   :designate     → χ_V
;;;;   :creation      → χ_R
;;;;   :authorizers   → χ_A (list of C service indices)
;;;;   :always-accum  → χ_Z (alist of (service-id . gas))
;;;;   :emitted-validators → transient: new ι validators (or nil)
;;;;   :emitted-queues     → transient: new ϕ queues (or nil)
;;;;   :transition (&key delta-results phi-queues)
;;;;                      → χ' (emitted data queryable) GP 12.19-12.20

(in-package #:jotl)

;;; ═══════════════════════════════════════════════════════════════
;;; CODEC — decode / encode χ
;;; ═══════════════════════════════════════════════════════════════

(defun load-chi-fields (bytes &optional (offset 0))
  "Decode χ from raw bytes starting at OFFSET.
   Encoding follows state S field order: (m, a, v, r, z)
   i.e. χ_M, χ_A (C×u32), χ_V, χ_R, χ_Z.
   Returns: (values plist bytes-consumed)
   Plist keys: :manager :designate :creation :authorizers :always-accum"
  (let ((pos offset)
        (c (num-cores)))
    ;; χ_M — u32
    (multiple-value-bind (chi-m n) (decode-u32 bytes pos) (incf pos n)
      ;; χ_A — C × u32  (comes BEFORE v,r in state order)
      (let ((chi-a (make-list c)))
        (loop for i from 0 below c do
          (multiple-value-bind (val n) (decode-u32 bytes pos)
            (setf (nth i chi-a) val)
            (incf pos n)))
        ;; χ_V — u32
        (multiple-value-bind (chi-v n) (decode-u32 bytes pos) (incf pos n)
          ;; χ_R — u32
          (multiple-value-bind (chi-r n) (decode-u32 bytes pos) (incf pos n)
            ;; χ_Z — compact-prefixed dict of (u32 → u64)
            (multiple-value-bind (count n) (decode-compact bytes pos)
              (incf pos n)
              (let ((chi-z nil))
                (dotimes (i count)
                  (multiple-value-bind (sid n) (decode-u32 bytes pos) (incf pos n)
                    (multiple-value-bind (gas n) (decode-u64 bytes pos) (incf pos n)
                      (push (cons sid gas) chi-z))))
                (values (list :manager    chi-m
                              :designate  chi-v
                              :creation   chi-r
                              :authorizers chi-a
                              :always-accum (nreverse chi-z))
                        (- pos offset))))))))))

(defun encode-chi-fields (chi-plist)
  "Encode χ fields to bytes.
   Encoding follows state S field order: (m, a, v, r, z)
   i.e. χ_M, χ_A (C×u32), χ_V, χ_R, χ_Z.
   CHI-PLIST: (:manager u32 :designate u32 :creation u32 :authorizers list :always-accum alist)"
  (let ((parts nil))
    ;; χ_M — u32
    (push (E4 (getf chi-plist :manager))    parts)
    ;; χ_A — C × u32  (comes BEFORE v,r in state order)
    (dolist (sid (getf chi-plist :authorizers))
      (push (E4 sid) parts))
    ;; χ_V — u32
    (push (E4 (getf chi-plist :designate))  parts)
    ;; χ_R — u32
    (push (E4 (getf chi-plist :creation))   parts)
    ;; χ_Z — compact(count) + entries
    (let ((az (getf chi-plist :always-accum)))
      (push (encode-compact (length az)) parts)
      (dolist (entry az)
        (push (E4 (car entry))  parts)   ;; service-id
        (push (E8 (cdr entry))  parts))) ;; gas
    (apply #'concatenate '(vector (unsigned-byte 8)) (nreverse parts))))

;;; ═══════════════════════════════════════════════════════════════
;;; PRIVILEGE RESOLUTION — GP 12.20
;;; ═══════════════════════════════════════════════════════════════

;;; R(o, a, b) — Privilege ownership function (GP 12.20)
;;; "If the manager changed it (a≠o), use the manager's choice (a).
;;;  If the manager didn't change it (a=o), use the service's choice (b)."
(defun privilege-resolve (original manager-choice service-choice)
  "GP (12.20): R(o, a, b) = b if a = o, else a."
  (if (eql manager-choice original)
      service-choice
      manager-choice))

;;; ═══════════════════════════════════════════════════════════════
;;; STATE CLOSURE — χ
;;; ═══════════════════════════════════════════════════════════════

(define-state-closure chi-state
  ((raw nil)
   (emitted-validators nil)    ;; transient — new ι validators from :transition
   (emitted-queues nil))       ;; transient — new ϕ queues from :transition

  ;; ── Codec ──────────────────────────────────────────────────
  (:save raw)

  (:decode (bytes offset)
    (let ((segment-bytes (subseq bytes offset)))
      (values (make-chi-state :raw segment-bytes)
              (- (length bytes) offset))))

  ;; ── Memoized decode (all fields at once) ───────────────────
  (:fields :memo
    (when raw (load-chi-fields raw)))

  ;; ── Accessors ─────────────────────────────────────────────
  (:manager     (getf (self :fields) :manager))
  (:designate   (getf (self :fields) :designate))
  (:creation    (getf (self :fields) :creation))
  (:authorizers (getf (self :fields) :authorizers))
  (:always-accum (getf (self :fields) :always-accum))

  ;; ── Transition: GP 12.19-12.20 ─────────────────────────────
  ;; χ owns privilege resolution. Takes delta-results (hash-table sid→effects),
  ;; phi-queues (current authorization queues for ϕ mutation).
  ;; Returns: χ' (emitted-validators and emitted-queues accessible via queries)
  (:transition (&key delta-results phi-queues)
    (let* ((fields (self :fields))
           (m-mgr  (getf fields :manager))
           (v-des  (getf fields :designate))
           (r-stk  (getf fields :creation))
           (a-auth (getf fields :authorizers))
           (z-az   (getf fields :always-accum))
           ;; e* = Δ(m)_e — manager service's empower output
           (mgr-effects (gethash m-mgr delta-results))
           (e-star (when mgr-effects (getf mgr-effects :empower)))
           ;; (m', z') = e*_{(m,z)}
           (new-mgr (if e-star (getf e-star :manager) m-mgr))
           (new-az  (if e-star (getf e-star :gas-map) z-az))
           ;; v' = R(v, Δ(m)ₑ.v, Δ(v)ₑ.v)
           (des-effects (gethash v-des delta-results))
           (des-empower (when des-effects (getf des-effects :empower)))
           (mgr-v (if e-star (getf e-star :validator) v-des))
           (des-v (if des-empower (getf des-empower :validator) v-des))
           (new-des (privilege-resolve v-des mgr-v des-v))
           ;; i' = (Δ(v)ₑ)_i — validator keys from designate service
           ;; Source: :empower :validators (if ΩB was called)
           ;;     OR: :designated-validators (if only ΩD was called)
           (new-iota-validators
            (or (when des-empower (getf des-empower :validators))
                (when des-effects (getf des-effects :designated-validators))))
           ;; r' = R(r, Δ(m)ₑ.r, Δ(r)ₑ.r)
           (stk-effects (gethash r-stk delta-results))
           (stk-empower (when stk-effects (getf stk-effects :empower)))
           (mgr-r (if e-star (getf e-star :staker) r-stk))
           (stk-r (if stk-empower (getf stk-empower :staker) r-stk))
           (new-stk (privilege-resolve r-stk mgr-r stk-r))
           ;; a'_c and q'_c
           (new-auth (if a-auth (copy-list a-auth) nil))
           (new-phi-queues (when phi-queues (copy-list phi-queues))))
      ;; ∀c ∈ N_C: a'_c = R(a_c, (Δ(m)ₑ.a)_c, (Δ(a_c)ₑ.a)_c)
      ;; ∀c ∈ N_C: q'_c = ((Δ(a_c)ₑ)_q)_c
      (when a-auth
        (loop for c from 0 below (num-cores)
              for a-c = (nth c a-auth)
              do (let* ((ac-effects (gethash a-c delta-results))
                        (ac-empower (when ac-effects (getf ac-effects :empower)))
                        (mgr-ac (if e-star
                                    (or (nth c (getf e-star :auth-agents)) a-c)
                                    a-c))
                        (self-ac (if ac-empower
                                     (or (nth c (getf ac-empower :auth-agents)) a-c)
                                     a-c)))
                   (setf (nth c new-auth)
                         (privilege-resolve a-c mgr-ac self-ac))
                   (when (and ac-empower new-phi-queues)
                     (let ((q-c (nth c (getf ac-empower :queues))))
                       (when q-c
                         (setf (nth c new-phi-queues) q-c)))))))
      (make-chi-state
       :raw (encode-chi-fields
             (list :manager     new-mgr
                   :designate   new-des
                   :creation    new-stk
                   :authorizers new-auth
                   :always-accum new-az))
       :emitted-validators new-iota-validators
       :emitted-queues new-phi-queues))))
