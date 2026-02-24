;;;; inst-control.lisp — Control flow instructions
;;;;
;;;; A.5.1  trap(0), fallthrough(1)
;;;; A.5.2  ecalli(10)
;;;; A.5.5  jump(40)
;;;; A.5.6  jump_ind(50)
;;;; A.5.8  load_imm_jump(80), branch_*_imm(81-90)

(in-package #:jamvm)

(declaim (optimize (speed 3) (safety 1) (debug 1)))

;;; ═══════════════════════════════════════════════════════════════════
;;; A.5.1 — No arguments
;;; ═══════════════════════════════════════════════════════════════════

;; 0 = trap: ε = ♯ (panic)
(register-opcode 0 :trap :none 1)
(register-termination-opcode 0)
(definstruction :trap (vm args) :panic)

;; 1 = fallthrough: terminates basic block, advances PC
(register-opcode 1 :fallthrough :none 1)
(register-termination-opcode 1)
(definstruction :fallthrough (vm args) :continue)

;;; ═══════════════════════════════════════════════════════════════════
;;; A.5.2 — One immediate
;;; ═══════════════════════════════════════════════════════════════════

;; 10 = ecalli: host call interrupt, ε = ℏ × ν_X
;; Gas cost: 1 (polkaVM naive model: every instruction costs 1)
;; The host call handler additionally charges 10 gas per GP B.15
(register-opcode 10 :ecalli :imm 1)
(definstruction :ecalli (vm args)
  (let ((id (arg-imm args)))
    (setf (pvm-exit-arg vm) (u32 (or id 0)))
    :host-call))

;;; ═══════════════════════════════════════════════════════════════════
;;; A.5.5 — One offset
;;; ═══════════════════════════════════════════════════════════════════

;; 40 = jump: branch(ν_X, ⊤) [unconditional]
(register-opcode 40 :jump :offset 1)
(register-termination-opcode 40)
(definstruction :jump (vm args)
  (do-branch vm (arg-offset args) t))

;;; ═══════════════════════════════════════════════════════════════════
;;; A.5.6 (partial) — jump_ind
;;; ═══════════════════════════════════════════════════════════════════

;; 50 = jump_ind: djump((φ_A + ν_X) mod 2³²)
(register-opcode 50 :jump-ind :reg-imm 1)
(register-termination-opcode 50)
(definstruction :jump-ind (vm args)
  (let* ((phi-a (reg vm (arg-ra args)))
         (nu-x  (arg-imm args))
         (addr  (u32 (+ phi-a nu-x))))
    (do-djump vm addr)))

;;; ═══════════════════════════════════════════════════════════════════
;;; A.5.8 — One register + immediate + offset (branches)
;;;
;;; Format: :reg-imm-offset → (:ra r_A :imm ν_X :offset ν_Y)
;;; ═══════════════════════════════════════════════════════════════════

;; 80 = load_imm_jump: branch(ν_Y, ⊤), φ'_A = ν_X
(register-opcode 80 :load-imm-jump :reg-imm-offset 1)
(register-termination-opcode 80)
(definstruction :load-imm-jump (vm args)
  (set-reg vm (arg-ra args) (arg-imm args))
  (do-branch vm (arg-offset args) t))

;; 81 = branch_eq_imm: branch(ν_Y, φ_A = ν_X)
(register-opcode 81 :branch-eq-imm :reg-imm-offset 1)
(register-termination-opcode 81)
(definstruction :branch-eq-imm (vm args)
  (do-branch vm (arg-offset args)
             (= (reg vm (arg-ra args)) (u64 (arg-imm args)))))

;; 82 = branch_ne_imm: branch(ν_Y, φ_A ≠ ν_X)
(register-opcode 82 :branch-ne-imm :reg-imm-offset 1)
(register-termination-opcode 82)
(definstruction :branch-ne-imm (vm args)
  (do-branch vm (arg-offset args)
             (/= (reg vm (arg-ra args)) (u64 (arg-imm args)))))

;; 83 = branch_lt_u_imm: φ_A < ν_X [unsigned]
(register-opcode 83 :branch-lt-u-imm :reg-imm-offset 1)
(register-termination-opcode 83)
(definstruction :branch-lt-u-imm (vm args)
  (do-branch vm (arg-offset args)
             (< (reg vm (arg-ra args)) (u64 (arg-imm args)))))

;; 84 = branch_le_u_imm: φ_A ≤ ν_X [unsigned]
(register-opcode 84 :branch-le-u-imm :reg-imm-offset 1)
(register-termination-opcode 84)
(definstruction :branch-le-u-imm (vm args)
  (do-branch vm (arg-offset args)
             (<= (reg vm (arg-ra args)) (u64 (arg-imm args)))))

;; 85 = branch_ge_u_imm: φ_A ≥ ν_X [unsigned]
(register-opcode 85 :branch-ge-u-imm :reg-imm-offset 1)
(register-termination-opcode 85)
(definstruction :branch-ge-u-imm (vm args)
  (do-branch vm (arg-offset args)
             (>= (reg vm (arg-ra args)) (u64 (arg-imm args)))))

;; 86 = branch_gt_u_imm: φ_A > ν_X [unsigned]
(register-opcode 86 :branch-gt-u-imm :reg-imm-offset 1)
(register-termination-opcode 86)
(definstruction :branch-gt-u-imm (vm args)
  (do-branch vm (arg-offset args)
             (> (reg vm (arg-ra args)) (u64 (arg-imm args)))))

;; 87 = branch_lt_s_imm: Z₈(φ_A) < Z₈(ν_X) [signed]
(register-opcode 87 :branch-lt-s-imm :reg-imm-offset 1)
(register-termination-opcode 87)
(definstruction :branch-lt-s-imm (vm args)
  (do-branch vm (arg-offset args)
             (< (zn 8 (reg vm (arg-ra args))) (zn 8 (u64 (arg-imm args))))))

;; 88 = branch_le_s_imm: Z₈(φ_A) ≤ Z₈(ν_X) [signed]
(register-opcode 88 :branch-le-s-imm :reg-imm-offset 1)
(register-termination-opcode 88)
(definstruction :branch-le-s-imm (vm args)
  (do-branch vm (arg-offset args)
             (<= (zn 8 (reg vm (arg-ra args))) (zn 8 (u64 (arg-imm args))))))

;; 89 = branch_ge_s_imm: Z₈(φ_A) ≥ Z₈(ν_X) [signed]
(register-opcode 89 :branch-ge-s-imm :reg-imm-offset 1)
(register-termination-opcode 89)
(definstruction :branch-ge-s-imm (vm args)
  (do-branch vm (arg-offset args)
             (>= (zn 8 (reg vm (arg-ra args))) (zn 8 (u64 (arg-imm args))))))

;; 90 = branch_gt_s_imm: Z₈(φ_A) > Z₈(ν_X) [signed]
(register-opcode 90 :branch-gt-s-imm :reg-imm-offset 1)
(register-termination-opcode 90)
(definstruction :branch-gt-s-imm (vm args)
  (do-branch vm (arg-offset args)
             (> (zn 8 (reg vm (arg-ra args))) (zn 8 (u64 (arg-imm args))))))

;;; ═══════════════════════════════════════════════════════════════════
;;; A.5.11 — Two registers + one offset (register branches)
;;;
;;; (A.30) r_A = min(12, ζ_{ι+1} mod 16)   → :ra
;;;        r_B = min(12, ⌊ζ_{ι+1}/16⌋)     → :rb
;;;        l_X = min(4, max(0, ℓ−1))
;;;        ν_X = ι + Z_{l_X}(E^{-1}_{l_X}(ζ_{ι+2…+l_X}))  → :offset
;;;
;;; Format: :reg-reg-offset → (:ra r_A :rb r_B :offset ν_X)
;;; ═══════════════════════════════════════════════════════════════════

;; 170 = branch_eq: branch(ν_X, φ_A = φ_B)
(register-opcode 170 :branch-eq :reg-reg-offset 1)
(register-termination-opcode 170)
(definstruction :branch-eq (vm args)
  (do-branch vm (arg-offset args)
             (= (reg vm (arg-ra args)) (reg vm (arg-rb args)))))

;; 171 = branch_ne: branch(ν_X, φ_A ≠ φ_B)
(register-opcode 171 :branch-ne :reg-reg-offset 1)
(register-termination-opcode 171)
(definstruction :branch-ne (vm args)
  (do-branch vm (arg-offset args)
             (/= (reg vm (arg-ra args)) (reg vm (arg-rb args)))))

;; 172 = branch_lt_u: branch(ν_X, φ_A < φ_B) [unsigned]
(register-opcode 172 :branch-lt-u :reg-reg-offset 1)
(register-termination-opcode 172)
(definstruction :branch-lt-u (vm args)
  (do-branch vm (arg-offset args)
             (< (reg vm (arg-ra args)) (reg vm (arg-rb args)))))

;; 173 = branch_lt_s: branch(ν_X, Z₈(φ_A) < Z₈(φ_B)) [signed]
(register-opcode 173 :branch-lt-s :reg-reg-offset 1)
(register-termination-opcode 173)
(definstruction :branch-lt-s (vm args)
  (do-branch vm (arg-offset args)
             (< (zn 8 (reg vm (arg-ra args))) (zn 8 (reg vm (arg-rb args))))))

;; 174 = branch_ge_u: branch(ν_X, φ_A ≥ φ_B) [unsigned]
(register-opcode 174 :branch-ge-u :reg-reg-offset 1)
(register-termination-opcode 174)
(definstruction :branch-ge-u (vm args)
  (do-branch vm (arg-offset args)
             (>= (reg vm (arg-ra args)) (reg vm (arg-rb args)))))

;; 175 = branch_ge_s: branch(ν_X, Z₈(φ_A) ≥ Z₈(φ_B)) [signed]
(register-opcode 175 :branch-ge-s :reg-reg-offset 1)
(register-termination-opcode 175)
(definstruction :branch-ge-s (vm args)
  (do-branch vm (arg-offset args)
             (>= (zn 8 (reg vm (arg-ra args))) (zn 8 (reg vm (arg-rb args))))))

;;; ═══════════════════════════════════════════════════════════════════
;;; A.5.12 — Two registers + two immediates
;;;
;;; (A.31) r_A, r_B from first byte; l_X from second byte;
;;;        ν_X, ν_Y are two sign-extended immediates.
;;;
;;; Format: :reg-reg-imm-imm → (:ra r_A :rb r_B :imm1 ν_X :imm2 ν_Y)
;;; ═══════════════════════════════════════════════════════════════════

;; 180 = load_imm_jump_ind: djump((φ_B + ν_Y) mod 2³²), φ'_A = ν_X
(register-opcode 180 :load-imm-jump-ind :reg-reg-imm-imm 1)
(register-termination-opcode 180)
(definstruction :load-imm-jump-ind (vm args)
  (let ((target (u32 (+ (reg vm (arg-rb args))
                        (u64 (arg-imm2 args))))))
    ;; Set φ'_A = ν_X before jump
    (set-reg vm (arg-ra args) (u64 (arg-imm1 args)))
    (do-djump vm target)))
