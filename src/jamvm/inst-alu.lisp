;;;; inst-alu.lisp — Arithmetic & logic instructions
;;;;
;;;; A.5.10 (continued) 131-144: Two registers + immediate (32-bit ALU)
;;;; Future: more ALU ops as GP pages arrive

(in-package #:jamvm)

(declaim (optimize (speed 3) (safety 1) (debug 1)))

;;; ═══════════════════════════════════════════════════════════════════
;;; A.5.10 (continued) — Two registers + one immediate: ALU ops
;;;
;;; Format: :reg-reg-imm → (:ra r_A :rb r_B :imm ν_X)
;;;   r_A = destination (low nibble), r_B = source (high nibble)
;;;   φ_A ≡ φ_{r_A}, φ_B ≡ φ_{r_B}, ν_X = sign-extended immediate
;;;
;;; X₄(x) = sign-extend 32-bit value to u64
;;; Z₈(x) = interpret u64 as signed, Z₈⁻¹(x) = signed → u64
;;; ═══════════════════════════════════════════════════════════════════

;; 131 = add_imm_32: φ'_A = X₄((φ_B + ν_X) mod 2³²)
(register-opcode 131 :add-imm-32 :reg-reg-imm 1)
(definstruction :add-imm-32 (vm args)
  (let ((result (logand (+ (reg vm (getf args :rb)) (getf args :imm)) #xFFFFFFFF)))
    (set-reg vm (getf args :ra) (sign-extend result 4))
    :continue))

;; 132 = and_imm: φ'_A = φ_B AND ν_X  [64-bit bitwise]
(register-opcode 132 :and-imm :reg-reg-imm 1)
(definstruction :and-imm (vm args)
  (set-reg vm (getf args :ra) (logand (reg vm (getf args :rb)) (u64 (getf args :imm))))
  :continue)

;; 133 = xor_imm: φ'_A = φ_B XOR ν_X  [64-bit bitwise]
(register-opcode 133 :xor-imm :reg-reg-imm 1)
(definstruction :xor-imm (vm args)
  (set-reg vm (getf args :ra) (u64 (logxor (reg vm (getf args :rb)) (u64 (getf args :imm)))))
  :continue)

;; 134 = or_imm: φ'_A = φ_B OR ν_X  [64-bit bitwise]
(register-opcode 134 :or-imm :reg-reg-imm 1)
(definstruction :or-imm (vm args)
  (set-reg vm (getf args :ra) (logior (reg vm (getf args :rb)) (u64 (getf args :imm))))
  :continue)

;; 135 = mul_imm_32: φ'_A = X₄((φ_B · ν_X) mod 2³²)
(register-opcode 135 :mul-imm-32 :reg-reg-imm 1)
(definstruction :mul-imm-32 (vm args)
  (let ((result (logand (* (reg vm (getf args :rb)) (getf args :imm)) #xFFFFFFFF)))
    (set-reg vm (getf args :ra) (sign-extend result 4))
    :continue))

;; 136 = set_lt_u_imm: φ'_A = (φ_B < ν_X) ? 1 : 0  [unsigned]
(register-opcode 136 :set-lt-u-imm :reg-reg-imm 1)
(definstruction :set-lt-u-imm (vm args)
  (set-reg vm (getf args :ra) (if (< (reg vm (getf args :rb)) (u64 (getf args :imm))) 1 0))
  :continue)

;; 137 = set_lt_s_imm: φ'_A = (Z₈(φ_B) < Z₈(ν_X)) ? 1 : 0  [signed]
(register-opcode 137 :set-lt-s-imm :reg-reg-imm 1)
(definstruction :set-lt-s-imm (vm args)
  (set-reg vm (getf args :ra)
           (if (< (zn 8 (reg vm (getf args :rb))) (zn 8 (u64 (getf args :imm)))) 1 0))
  :continue)

;; 138 = shlo_l_imm_32: φ'_A = X₄((φ_B · 2^(ν_X mod 32)) mod 2³²)  [shift left]
(register-opcode 138 :shlo-l-imm-32 :reg-reg-imm 1)
(definstruction :shlo-l-imm-32 (vm args)
  (let* ((shift (mod (getf args :imm) 32))
         (result (logand (ash (reg vm (getf args :rb)) shift) #xFFFFFFFF)))
    (set-reg vm (getf args :ra) (sign-extend result 4))
    :continue))

;; 139 = shlo_r_imm_32: φ'_A = X₄(⌊φ_B mod 2³² ÷ 2^(ν_X mod 32)⌋)  [logical shift right]
(register-opcode 139 :shlo-r-imm-32 :reg-reg-imm 1)
(definstruction :shlo-r-imm-32 (vm args)
  (let* ((shift (mod (getf args :imm) 32))
         (v32 (logand (reg vm (getf args :rb)) #xFFFFFFFF))
         (result (ash v32 (- shift))))
    (set-reg vm (getf args :ra) (sign-extend result 4))
    :continue))

;; 140 = shar_r_imm_32: φ'_A = Z₈⁻¹(⌊Z₄(φ_B mod 2³²) ÷ 2^(ν_X mod 32)⌋)  [arithmetic shift right]
(register-opcode 140 :shar-r-imm-32 :reg-reg-imm 1)
(definstruction :shar-r-imm-32 (vm args)
  (let* ((shift (mod (getf args :imm) 32))
         (v32 (logand (reg vm (getf args :rb)) #xFFFFFFFF))
         (signed32 (zn 4 v32))                ; Z₄: 32-bit → signed
         (shifted (ash signed32 (- shift))))          ; arithmetic right shift
    (set-reg vm (getf args :ra) (zn-inv 8 shifted))  ; Z₈⁻¹: signed → u64
    :continue))

;; 141 = neg_add_imm_32: φ'_A = X₄((ν_X + 2³² − φ_B) mod 2³²)
(register-opcode 141 :neg-add-imm-32 :reg-reg-imm 1)
(definstruction :neg-add-imm-32 (vm args)
  (let ((result (logand (- (getf args :imm) (reg vm (getf args :rb))) #xFFFFFFFF)))
    (set-reg vm (getf args :ra) (sign-extend result 4))
    :continue))

;; 142 = set_gt_u_imm: φ'_A = (φ_B > ν_X) ? 1 : 0  [unsigned]
(register-opcode 142 :set-gt-u-imm :reg-reg-imm 1)
(definstruction :set-gt-u-imm (vm args)
  (set-reg vm (getf args :ra) (if (> (reg vm (getf args :rb)) (u64 (getf args :imm))) 1 0))
  :continue)

;; 143 = set_gt_s_imm: φ'_A = (Z₈(φ_B) > Z₈(ν_X)) ? 1 : 0  [signed]
(register-opcode 143 :set-gt-s-imm :reg-reg-imm 1)
(definstruction :set-gt-s-imm (vm args)
  (set-reg vm (getf args :ra)
           (if (> (zn 8 (reg vm (getf args :rb))) (zn 8 (u64 (getf args :imm)))) 1 0))
  :continue)

;; 144 = shlo_l_imm_alt_32: φ'_A = X₄((ν_X · 2^(φ_B mod 32)) mod 2³²)  [shift left, swapped]
(register-opcode 144 :shlo-l-imm-alt-32 :reg-reg-imm 1)
(definstruction :shlo-l-imm-alt-32 (vm args)
  (let* ((shift (mod (reg vm (getf args :rb)) 32))
         (result (logand (ash (u64 (getf args :imm)) shift) #xFFFFFFFF)))
    (set-reg vm (getf args :ra) (sign-extend result 4))
    :continue))

;; 145 = shlo_r_imm_alt_32: φ'_A = X₄(⌊ν_X mod 2³² ÷ 2^(φ_B mod 32)⌋)  [logical right, swapped]
(register-opcode 145 :shlo-r-imm-alt-32 :reg-reg-imm 1)
(definstruction :shlo-r-imm-alt-32 (vm args)
  (let* ((shift (mod (reg vm (getf args :rb)) 32))
         (v32 (logand (u64 (getf args :imm)) #xFFFFFFFF))
         (result (ash v32 (- shift))))
    (set-reg vm (getf args :ra) (sign-extend result 4))
    :continue))

;; 146 = shar_r_imm_alt_32: φ'_A = Z₈⁻¹(⌊Z₄(ν_X mod 2³²) ÷ 2^(φ_B mod 32)⌋)  [arith right, swapped]
(register-opcode 146 :shar-r-imm-alt-32 :reg-reg-imm 1)
(definstruction :shar-r-imm-alt-32 (vm args)
  (let* ((shift (mod (reg vm (getf args :rb)) 32))
         (v32 (logand (u64 (getf args :imm)) #xFFFFFFFF))
         (signed32 (zn 4 v32))
         (shifted (ash signed32 (- shift))))
    (set-reg vm (getf args :ra) (zn-inv 8 shifted))
    :continue))

;;; ═══════════════════════════════════════════════════════════════════
;;; A.5.10 (continued) — cmov + 64-bit ALU + rotations (147-159)
;;; ═══════════════════════════════════════════════════════════════════

;; 147 = cmov_iz_imm: φ'_A = ν_X if φ_B = 0, else φ_A  [conditional move if zero]
(register-opcode 147 :cmov-iz-imm :reg-reg-imm 1)
(definstruction :cmov-iz-imm (vm args)
  (when (zerop (reg vm (getf args :rb)))
    (set-reg vm (getf args :ra) (u64 (getf args :imm))))
  :continue)

;; 148 = cmov_nz_imm: φ'_A = ν_X if φ_B ≠ 0, else φ_A  [conditional move if non-zero]
(register-opcode 148 :cmov-nz-imm :reg-reg-imm 1)
(definstruction :cmov-nz-imm (vm args)
  (unless (zerop (reg vm (getf args :rb)))
    (set-reg vm (getf args :ra) (u64 (getf args :imm))))
  :continue)

;; 149 = add_imm_64: φ'_A = (φ_B + ν_X) mod 2⁶⁴
(register-opcode 149 :add-imm-64 :reg-reg-imm 1)
(definstruction :add-imm-64 (vm args)
  (set-reg vm (getf args :ra) (u64 (+ (reg vm (getf args :rb)) (getf args :imm))))
  :continue)

;; 150 = mul_imm_64: φ'_A = (φ_B · ν_X) mod 2⁶⁴
(register-opcode 150 :mul-imm-64 :reg-reg-imm 1)
(definstruction :mul-imm-64 (vm args)
  (set-reg vm (getf args :ra) (u64 (* (reg vm (getf args :rb)) (getf args :imm))))
  :continue)

;; 151 = shlo_l_imm_64: φ'_A = X₈((φ_B · 2^(ν_X mod 64)) mod 2⁶⁴)  [= u64 shift left]
(register-opcode 151 :shlo-l-imm-64 :reg-reg-imm 1)
(definstruction :shlo-l-imm-64 (vm args)
  (let* ((shift (mod (getf args :imm) 64)))
    (set-reg vm (getf args :ra) (u64 (ash (reg vm (getf args :rb)) shift)))
    :continue))

;; 152 = shlo_r_imm_64: φ'_A = X₈(⌊φ_B ÷ 2^(ν_X mod 64)⌋)  [logical right shift 64]
(register-opcode 152 :shlo-r-imm-64 :reg-reg-imm 1)
(definstruction :shlo-r-imm-64 (vm args)
  (let* ((shift (mod (getf args :imm) 64)))
    (set-reg vm (getf args :ra) (ash (reg vm (getf args :rb)) (- shift)))
    :continue))

;; 153 = shar_r_imm_64: φ'_A = Z₈⁻¹(⌊Z₈(φ_B) ÷ 2^(ν_X mod 64)⌋)  [arithmetic right shift 64]
(register-opcode 153 :shar-r-imm-64 :reg-reg-imm 1)
(definstruction :shar-r-imm-64 (vm args)
  (let* ((shift (mod (getf args :imm) 64))
         (signed64 (zn 8 (reg vm (getf args :rb))))
         (shifted (ash signed64 (- shift))))
    (set-reg vm (getf args :ra) (zn-inv 8 shifted))
    :continue))

;; 154 = neg_add_imm_64: φ'_A = (ν_X + 2⁶⁴ − φ_B) mod 2⁶⁴ = (ν_X − φ_B) mod 2⁶⁴
(register-opcode 154 :neg-add-imm-64 :reg-reg-imm 1)
(definstruction :neg-add-imm-64 (vm args)
  (set-reg vm (getf args :ra) (u64 (- (getf args :imm) (reg vm (getf args :rb)))))
  :continue)

;; 155 = shlo_l_imm_alt_64: φ'_A = (ν_X · 2^(φ_B mod 64)) mod 2⁶⁴  [shift left, swapped]
(register-opcode 155 :shlo-l-imm-alt-64 :reg-reg-imm 1)
(definstruction :shlo-l-imm-alt-64 (vm args)
  (let ((shift (mod (reg vm (getf args :rb)) 64)))
    (set-reg vm (getf args :ra) (u64 (ash (u64 (getf args :imm)) shift)))
    :continue))

;; 156 = shlo_r_imm_alt_64: φ'_A = ⌊ν_X ÷ 2^(φ_B mod 64)⌋  [logical right, swapped]
(register-opcode 156 :shlo-r-imm-alt-64 :reg-reg-imm 1)
(definstruction :shlo-r-imm-alt-64 (vm args)
  (let ((shift (mod (reg vm (getf args :rb)) 64)))
    (set-reg vm (getf args :ra) (ash (u64 (getf args :imm)) (- shift)))
    :continue))

;; 157 = shar_r_imm_alt_64: φ'_A = Z₈⁻¹(⌊Z₈(ν_X) ÷ 2^(φ_B mod 64)⌋)  [arith right, swapped]
(register-opcode 157 :shar-r-imm-alt-64 :reg-reg-imm 1)
(definstruction :shar-r-imm-alt-64 (vm args)
  (let* ((shift (mod (reg vm (getf args :rb)) 64))
         (signed64 (zn 8 (u64 (getf args :imm))))
         (shifted (ash signed64 (- shift))))
    (set-reg vm (getf args :ra) (zn-inv 8 shifted))
    :continue))

;; 158 = rot_r_64_imm: rotate right 64-bit by ν_X
;; B₈(φ'_A)_i = B₈(φ_B)_{(i+ν_X) mod 64}
(register-opcode 158 :rot-r-64-imm :reg-reg-imm 1)
(definstruction :rot-r-64-imm (vm args)
  (let* ((n (mod (getf args :imm) 64))
         (v (reg vm (getf args :rb))))
    (if (zerop n)
        (set-reg vm (getf args :ra) v)
        (set-reg vm (getf args :ra)
                 (u64 (logior (ash v (- n))
                              (ash v (- 64 n))))))
    :continue))

;; 159 = rot_r_64_imm_alt: rotate right 64-bit by φ_B (swapped operands)
;; B₈(φ'_A)_i = B₈(ν_X)_{(i+φ_B) mod 64}
(register-opcode 159 :rot-r-64-imm-alt :reg-reg-imm 1)
(definstruction :rot-r-64-imm-alt (vm args)
  (let* ((n (mod (reg vm (getf args :rb)) 64))
         (v (u64 (getf args :imm))))
    (if (zerop n)
        (set-reg vm (getf args :ra) v)
        (set-reg vm (getf args :ra)
                 (u64 (logior (ash v (- n))
                              (ash v (- 64 n))))))
    :continue))

;; 160 = rot_r_32_imm: rotate right 32-bit by ν_X
;; φ'_A = X₄(x) where x ∈ ℕ₂₃₂, ∀i ∈ ℕ₃₂: B₄(x)_i = B₄(φ_B)_{(i+ν_X) mod 32}
(register-opcode 160 :rot-r-32-imm :reg-reg-imm 1)
(definstruction :rot-r-32-imm (vm args)
  (let* ((n (mod (getf args :imm) 32))
         (v (logand (reg vm (getf args :rb)) #xFFFFFFFF)))
    (let ((result (if (zerop n) v
                      (logior (ash v (- n))
                              (logand (ash v (- 32 n)) #xFFFFFFFF)))))
      (set-reg vm (getf args :ra) (sign-extend result 4))
      :continue)))

;; 161 = rot_r_32_imm_alt: rotate right 32-bit by φ_B (swapped operands)
;; φ'_A = X₄(x) where x ∈ ℕ₂₃₂, ∀i ∈ ℕ₃₂: B₄(x)_i = B₄(ν_X)_{(i+φ_B) mod 32}
(register-opcode 161 :rot-r-32-imm-alt :reg-reg-imm 1)
(definstruction :rot-r-32-imm-alt (vm args)
  (let* ((n (mod (reg vm (getf args :rb)) 32))
         (v (logand (u64 (getf args :imm)) #xFFFFFFFF)))
    (let ((result (if (zerop n) v
                      (logior (ash v (- n))
                              (logand (ash v (- 32 n)) #xFFFFFFFF)))))
      (set-reg vm (getf args :ra) (sign-extend result 4))
      :continue)))

;;; ═══════════════════════════════════════════════════════════════════
;;; A.5.13 — Three registers (32-bit arithmetic)
;;;
;;; (A.32) r_A, r_B from first byte (nibbles);
;;;        r_D = min(12, ζ_{ι+2})  (full byte)
;;;
;;; φ_A = ω_{r_A}, φ_B = ω_{r_B}
;;; Mutations target φ'_D (destination = third register)
;;;
;;; Format: :reg-reg-reg → (:ra r_A :rb r_B :rd r_D)
;;; ═══════════════════════════════════════════════════════════════════

;; 190 = add_32: φ'_D = X₄((φ_A + φ_B) mod 2³²)
(register-opcode 190 :add-32 :reg-reg-reg 1)
(definstruction :add-32 (vm args)
  (set-reg vm (getf args :rd)
           (sign-extend (logand (+ (reg vm (getf args :ra))
                                   (reg vm (getf args :rb)))
                                #xFFFFFFFF)
                        4))
  :continue)

;; 191 = sub_32: φ'_D = X₄((φ_A + 2³² − (φ_B mod 2³²)) mod 2³²)
(register-opcode 191 :sub-32 :reg-reg-reg 1)
(definstruction :sub-32 (vm args)
  (let ((a (reg vm (getf args :ra)))
        (b (logand (reg vm (getf args :rb)) #xFFFFFFFF)))
    (set-reg vm (getf args :rd)
             (sign-extend (logand (+ a (- #x100000000 b)) #xFFFFFFFF) 4))
    :continue))

;; 192 = mul_32: φ'_D = X₄((φ_A · φ_B) mod 2³²)
(register-opcode 192 :mul-32 :reg-reg-reg 1)
(definstruction :mul-32 (vm args)
  (set-reg vm (getf args :rd)
           (sign-extend (logand (* (reg vm (getf args :ra))
                                   (reg vm (getf args :rb)))
                                #xFFFFFFFF)
                        4))
  :continue)

;; 193 = div_u_32: unsigned 32-bit division
;; φ'_D = { 2⁶⁴−1           if φ_B mod 2³² = 0
;;        { X₄(⌊(φ_A mod 2³²) ÷ (φ_B mod 2³²)⌋)  otherwise
(register-opcode 193 :div-u-32 :reg-reg-reg 1)
(definstruction :div-u-32 (vm args)
  (let ((a32 (logand (reg vm (getf args :ra)) #xFFFFFFFF))
        (b32 (logand (reg vm (getf args :rb)) #xFFFFFFFF)))
    (if (zerop b32)
        (set-reg vm (getf args :rd) +u64-max+)
        (set-reg vm (getf args :rd)
                 (sign-extend (floor a32 b32) 4)))
    :continue))

;; 194 = div_s_32: signed 32-bit division
;; where a = Z₄(φ_A mod 2³²), b = Z₄(φ_B mod 2³²)
;; φ'_D = { 2⁶⁴−1       if b = 0
;;        { Z₈⁻¹(a)      if a = −2³¹ ∧ b = −1
;;        { Z₈⁻¹(rtz(a ÷ b))  otherwise
(register-opcode 194 :div-s-32 :reg-reg-reg 1)
(definstruction :div-s-32 (vm args)
  (let ((a (zn 4 (logand (reg vm (getf args :ra)) #xFFFFFFFF)))
        (b (zn 4 (logand (reg vm (getf args :rb)) #xFFFFFFFF))))
    (cond
      ((zerop b)
       (set-reg vm (getf args :rd) +u64-max+))
      ((and (= a #.(- (ash 1 31))) (= b -1))
       (set-reg vm (getf args :rd) (zn-inv 8 a)))
      (t
       (set-reg vm (getf args :rd) (zn-inv 8 (truncate a b)))))
    :continue))

;; 195 = rem_u_32: unsigned 32-bit remainder
;; φ'_D = { X₄(φ_A mod 2³²)                        if φ_B mod 2³² = 0
;;        { X₄((φ_A mod 2³²) mod (φ_B mod 2³²))    otherwise
(register-opcode 195 :rem-u-32 :reg-reg-reg 1)
(definstruction :rem-u-32 (vm args)
  (let ((a32 (logand (reg vm (getf args :ra)) #xFFFFFFFF))
        (b32 (logand (reg vm (getf args :rb)) #xFFFFFFFF)))
    (if (zerop b32)
        (set-reg vm (getf args :rd) (sign-extend a32 4))
        (set-reg vm (getf args :rd) (sign-extend (mod a32 b32) 4)))
    :continue))

;; 196 = rem_s_32: signed 32-bit remainder
;; where a = Z₄(φ_A mod 2³²), b = Z₄(φ_B mod 2³²)
;; φ'_D = { 0                   if a = −2³¹ ∧ b = −1
;;        { Z₈⁻¹(smod(a, b))   otherwise
;; smod: remainder with sign of dividend (= CL rem)
(register-opcode 196 :rem-s-32 :reg-reg-reg 1)
(definstruction :rem-s-32 (vm args)
  (let ((a (zn 4 (logand (reg vm (getf args :ra)) #xFFFFFFFF)))
        (b (zn 4 (logand (reg vm (getf args :rb)) #xFFFFFFFF))))
    (cond
      ((zerop b)
       ;; GP doesn't list div-by-zero separately for rem_s_32,
       ;; but smod(a,0) is undefined; treating like rem_u: return a
       (set-reg vm (getf args :rd) (zn-inv 8 a)))
      ((and (= a #.(- (ash 1 31))) (= b -1))
       (set-reg vm (getf args :rd) 0))
      (t
       (set-reg vm (getf args :rd) (zn-inv 8 (rem a b)))))
    :continue))

;; 197 = shlo_l_32: X₄((φ_A · 2^(φ_B mod 32)) mod 2³²)
(register-opcode 197 :shlo-l-32 :reg-reg-reg 1)
(definstruction :shlo-l-32 (vm args)
  (let* ((a (reg vm (getf args :ra)))
         (n (mod (reg vm (getf args :rb)) 32))
         (result (logand (ash a n) #xFFFFFFFF)))
    (set-reg vm (getf args :rd) (sign-extend result 4))
    :continue))

;; 198 = shlo_r_32: X₄(⌊(φ_A mod 2³²) ÷ 2^(φ_B mod 32)⌋)
(register-opcode 198 :shlo-r-32 :reg-reg-reg 1)
(definstruction :shlo-r-32 (vm args)
  (let* ((a32 (logand (reg vm (getf args :ra)) #xFFFFFFFF))
         (n (mod (reg vm (getf args :rb)) 32))
         (result (ash a32 (- n))))
    (set-reg vm (getf args :rd) (sign-extend result 4))
    :continue))

;; 199 = shar_r_32: Z₈⁻¹(⌊Z₄(φ_A mod 2³²) ÷ 2^(φ_B mod 32)⌋)
(register-opcode 199 :shar-r-32 :reg-reg-reg 1)
(definstruction :shar-r-32 (vm args)
  (let* ((a-signed (zn 4 (logand (reg vm (getf args :ra)) #xFFFFFFFF)))
         (n (mod (reg vm (getf args :rb)) 32))
         (result (ash a-signed (- n))))
    (set-reg vm (getf args :rd) (zn-inv 8 result))
    :continue))

;;; ═══════════════════════════════════════════════════════════════════
;;; A.5.13 continued — 64-bit arithmetic (three registers)
;;; ═══════════════════════════════════════════════════════════════════

;; 200 = add_64: φ'_D = (φ_A + φ_B) mod 2⁶⁴
(register-opcode 200 :add-64 :reg-reg-reg 1)
(definstruction :add-64 (vm args)
  (set-reg vm (getf args :rd)
           (u64 (+ (reg vm (getf args :ra))
                   (reg vm (getf args :rb)))))
  :continue)

;; 201 = sub_64: φ'_D = (φ_A + 2⁶⁴ − φ_B) mod 2⁶⁴
(register-opcode 201 :sub-64 :reg-reg-reg 1)
(definstruction :sub-64 (vm args)
  (set-reg vm (getf args :rd)
           (u64 (- (reg vm (getf args :ra))
                   (reg vm (getf args :rb)))))
  :continue)

;; 202 = mul_64: φ'_D = (φ_A · φ_B) mod 2⁶⁴
(register-opcode 202 :mul-64 :reg-reg-reg 1)
(definstruction :mul-64 (vm args)
  (set-reg vm (getf args :rd)
           (u64 (* (reg vm (getf args :ra))
                   (reg vm (getf args :rb)))))
  :continue)

;; 203 = div_u_64: unsigned 64-bit division
;; φ'_D = { 2⁶⁴−1          if φ_B = 0
;;        { ⌊φ_A ÷ φ_B⌋    otherwise
(register-opcode 203 :div-u-64 :reg-reg-reg 1)
(definstruction :div-u-64 (vm args)
  (let ((a (reg vm (getf args :ra)))
        (b (reg vm (getf args :rb))))
    (if (zerop b)
        (set-reg vm (getf args :rd) +u64-max+)
        (set-reg vm (getf args :rd) (floor a b)))
    :continue))

;; 204 = div_s_64: signed 64-bit division
;; φ'_D = { 2⁶⁴−1                              if φ_B = 0
;;        { φ_A                                  if Z₈(φ_A) = −2⁶³ ∧ Z₈(φ_B) = −1
;;        { Z₈⁻¹(rtz(Z₈(φ_A) ÷ Z₈(φ_B)))     otherwise
(register-opcode 204 :div-s-64 :reg-reg-reg 1)
(definstruction :div-s-64 (vm args)
  (let ((a (reg vm (getf args :ra)))
        (b (reg vm (getf args :rb))))
    (cond
      ((zerop b)
       (set-reg vm (getf args :rd) +u64-max+))
      ((and (= (zn 8 a) #.(- (ash 1 63))) (= (zn 8 b) -1))
       ;; Overflow: −2⁶³ / −1 would be 2⁶³ which doesn't fit.
       ;; GP says φ'_D = φ_A (the raw unsigned value stays unchanged)
       (set-reg vm (getf args :rd) a))
      (t
       (set-reg vm (getf args :rd)
                (zn-inv 8 (truncate (zn 8 a) (zn 8 b))))))
    :continue))

;; 205 = rem_u_64: unsigned 64-bit remainder
;; φ'_D = { φ_A              if φ_B = 0
;;        { φ_A mod φ_B      otherwise
(register-opcode 205 :rem-u-64 :reg-reg-reg 1)
(definstruction :rem-u-64 (vm args)
  (let ((a (reg vm (getf args :ra)))
        (b (reg vm (getf args :rb))))
    (if (zerop b)
        (set-reg vm (getf args :rd) a)
        (set-reg vm (getf args :rd) (mod a b)))
    :continue))

;; 206 = rem_s_64: signed 64-bit remainder
;; where a = Z₈(φ_A), b = Z₈(φ_B)
;; φ'_D = { 0                          if a = −2⁶³ ∧ b = −1
;;        { Z₈⁻¹(smod(a, b))          otherwise
(register-opcode 206 :rem-s-64 :reg-reg-reg 1)
(definstruction :rem-s-64 (vm args)
  (let ((a (zn 8 (reg vm (getf args :ra))))
        (b (zn 8 (reg vm (getf args :rb)))))
    (cond
      ((zerop b)
       (set-reg vm (getf args :rd) (zn-inv 8 a)))
      ((and (= a #.(- (ash 1 63))) (= b -1))
       (set-reg vm (getf args :rd) 0))
      (t
       (set-reg vm (getf args :rd) (zn-inv 8 (rem a b)))))
    :continue))

;; 207 = shlo_l_64: (φ_A · 2^(φ_B mod 64)) mod 2⁶⁴
(register-opcode 207 :shlo-l-64 :reg-reg-reg 1)
(definstruction :shlo-l-64 (vm args)
  (let* ((a (reg vm (getf args :ra)))
         (n (mod (reg vm (getf args :rb)) 64)))
    (set-reg vm (getf args :rd) (u64 (ash a n)))
    :continue))

;; 208 = shlo_r_64: ⌊φ_A ÷ 2^(φ_B mod 64)⌋
(register-opcode 208 :shlo-r-64 :reg-reg-reg 1)
(definstruction :shlo-r-64 (vm args)
  (let* ((a (reg vm (getf args :ra)))
         (n (mod (reg vm (getf args :rb)) 64)))
    (set-reg vm (getf args :rd) (ash a (- n)))
    :continue))

;; 209 = shar_r_64: Z₈⁻¹(⌊Z₈(φ_A) ÷ 2^(φ_B mod 64)⌋)
(register-opcode 209 :shar-r-64 :reg-reg-reg 1)
(definstruction :shar-r-64 (vm args)
  (let* ((a-signed (zn 8 (reg vm (getf args :ra))))
         (n (mod (reg vm (getf args :rb)) 64)))
    (set-reg vm (getf args :rd) (zn-inv 8 (ash a-signed (- n))))
    :continue))

;;; ═══════════════════════════════════════════════════════════════════
;;; Bitwise operations (64-bit, three registers)
;;; ═══════════════════════════════════════════════════════════════════

;; 210 = and: ∀i ∈ ℕ₆₄: B₈(φ'_D)_i = B₈(φ_A)_i ∧ B₈(φ_B)_i
(register-opcode 210 :and :reg-reg-reg 1)
(definstruction :and (vm args)
  (set-reg vm (getf args :rd)
           (logand (reg vm (getf args :ra))
                   (reg vm (getf args :rb))))
  :continue)

;; 211 = xor: ∀i ∈ ℕ₆₄: B₈(φ'_D)_i = B₈(φ_A)_i ⊕ B₈(φ_B)_i
(register-opcode 211 :xor :reg-reg-reg 1)
(definstruction :xor (vm args)
  (set-reg vm (getf args :rd)
           (logxor (reg vm (getf args :ra))
                   (reg vm (getf args :rb))))
  :continue)

;; 212 = or: ∀i ∈ ℕ₆₄: B₈(φ'_D)_i = B₈(φ_A)_i ∨ B₈(φ_B)_i
(register-opcode 212 :or :reg-reg-reg 1)
(definstruction :or (vm args)
  (set-reg vm (getf args :rd)
           (logior (reg vm (getf args :ra))
                   (reg vm (getf args :rb))))
  :continue)

;;; ═══════════════════════════════════════════════════════════════════
;;; Mul upper (128-bit intermediate → high 64 bits)
;;; ═══════════════════════════════════════════════════════════════════

;; 213 = mul_upper_s_s: Z₈⁻¹(⌊(Z₈(φ_A) · Z₈(φ_B)) ÷ 2⁶⁴⌋)
(register-opcode 213 :mul-upper-s-s :reg-reg-reg 1)
(definstruction :mul-upper-s-s (vm args)
  (let* ((a (zn 8 (reg vm (getf args :ra))))
         (b (zn 8 (reg vm (getf args :rb))))
         (full (* a b))
         (hi (ash full -64)))
    (set-reg vm (getf args :rd) (zn-inv 8 hi))
    :continue))

;; 214 = mul_upper_u_u: ⌊(φ_A · φ_B) ÷ 2⁶⁴⌋
(register-opcode 214 :mul-upper-u-u :reg-reg-reg 1)
(definstruction :mul-upper-u-u (vm args)
  (let* ((a (reg vm (getf args :ra)))
         (b (reg vm (getf args :rb)))
         (hi (ash (* a b) -64)))
    (set-reg vm (getf args :rd) hi)
    :continue))

;; 215 = mul_upper_s_u: Z₈⁻¹(⌊(Z₈(φ_A) · φ_B) ÷ 2⁶⁴⌋)
(register-opcode 215 :mul-upper-s-u :reg-reg-reg 1)
(definstruction :mul-upper-s-u (vm args)
  (let* ((a (zn 8 (reg vm (getf args :ra))))
         (b (reg vm (getf args :rb)))
         (hi (ash (* a b) -64)))
    (set-reg vm (getf args :rd) (zn-inv 8 hi))
    :continue))

;;; ═══════════════════════════════════════════════════════════════════
;;; Comparisons and conditional move
;;; ═══════════════════════════════════════════════════════════════════

;; 216 = set_lt_u: φ'_D = φ_A < φ_B  (unsigned, boolean 0/1)
(register-opcode 216 :set-lt-u :reg-reg-reg 1)
(definstruction :set-lt-u (vm args)
  (set-reg vm (getf args :rd)
           (if (< (reg vm (getf args :ra))
                  (reg vm (getf args :rb)))
               1 0))
  :continue)

;; 217 = set_lt_s: φ'_D = Z₈(φ_A) < Z₈(φ_B)  (signed, boolean 0/1)
(register-opcode 217 :set-lt-s :reg-reg-reg 1)
(definstruction :set-lt-s (vm args)
  (set-reg vm (getf args :rd)
           (if (< (zn 8 (reg vm (getf args :ra)))
                  (zn 8 (reg vm (getf args :rb))))
               1 0))
  :continue)

;; 218 = cmov_iz: conditional move if zero
;; φ'_D = { φ_A    if φ_B = 0
;;        { φ_D    otherwise (unchanged)
(register-opcode 218 :cmov-iz :reg-reg-reg 1)
(definstruction :cmov-iz (vm args)
  (when (zerop (reg vm (getf args :rb)))
    (set-reg vm (getf args :rd) (reg vm (getf args :ra))))
  :continue)

;; 219 = cmov_nz: conditional move if not zero
;; φ'_D = { φ_A    if φ_B ≠ 0
;;        { φ_D    otherwise (unchanged)
(register-opcode 219 :cmov-nz :reg-reg-reg 1)
(definstruction :cmov-nz (vm args)
  (unless (zerop (reg vm (getf args :rb)))
    (set-reg vm (getf args :rd) (reg vm (getf args :ra))))
  :continue)

;;; ═══════════════════════════════════════════════════════════════════
;;; Rotations (three registers)
;;; ═══════════════════════════════════════════════════════════════════

;; 220 = rot_l_64: ∀i ∈ ℕ₆₄: B₈(φ'_D)_{(i+φ_B) mod 64} = B₈(φ_A)_i
;; Rotate left by φ_B positions (64-bit)
(register-opcode 220 :rot-l-64 :reg-reg-reg 1)
(definstruction :rot-l-64 (vm args)
  (let* ((a (reg vm (getf args :ra)))
         (n (mod (reg vm (getf args :rb)) 64)))
    (if (zerop n)
        (set-reg vm (getf args :rd) a)
        (set-reg vm (getf args :rd)
                 (u64 (logior (ash a n) (ash a (- n 64))))))
    :continue))

;; 221 = rot_l_32: X₄(x) where x ∈ ℕ_{2³²}, ∀i ∈ ℕ₃₂: B₄(x)_{(i+φ_B) mod 32} = B₄(φ_A)_i
;; Rotate left by φ_B positions (32-bit), sign-extend result
(register-opcode 221 :rot-l-32 :reg-reg-reg 1)
(definstruction :rot-l-32 (vm args)
  (let* ((a (logand (reg vm (getf args :ra)) #xFFFFFFFF))
         (n (mod (reg vm (getf args :rb)) 32)))
    (let ((result (if (zerop n) a
                      (logand (logior (ash a n) (ash a (- n 32)))
                              #xFFFFFFFF))))
      (set-reg vm (getf args :rd) (sign-extend result 4))
      :continue)))

;; 222 = rot_r_64: ∀i ∈ ℕ₆₄: B₈(φ'_D)_i = B₈(φ_A)_{(i+φ_B) mod 64}
;; Rotate right by φ_B positions (64-bit)
(register-opcode 222 :rot-r-64 :reg-reg-reg 1)
(definstruction :rot-r-64 (vm args)
  (let* ((a (reg vm (getf args :ra)))
         (n (mod (reg vm (getf args :rb)) 64)))
    (if (zerop n)
        (set-reg vm (getf args :rd) a)
        (set-reg vm (getf args :rd)
                 (u64 (logior (ash a (- n)) (ash a (- 64 n))))))
    :continue))

;; 223 = rot_r_32: X₄(x) where x ∈ ℕ_{2³²}, ∀i ∈ ℕ₃₂: B₄(x)_i = B₄(φ_A)_{(i+φ_B) mod 32}
;; Rotate right by φ_B positions (32-bit), sign-extend result
(register-opcode 223 :rot-r-32 :reg-reg-reg 1)
(definstruction :rot-r-32 (vm args)
  (let* ((a (logand (reg vm (getf args :ra)) #xFFFFFFFF))
         (n (mod (reg vm (getf args :rb)) 32)))
    (let ((result (if (zerop n) a
                      (logand (logior (ash a (- n)) (ash a (- 32 n)))
                              #xFFFFFFFF))))
      (set-reg vm (getf args :rd) (sign-extend result 4))
      :continue)))

;;; ═══════════════════════════════════════════════════════════════════
;;; Bitwise with inversion (three registers)
;;; ═══════════════════════════════════════════════════════════════════

;; 224 = and_inv: B₈(φ'_D)_i = B₈(φ_A)_i ∧ ¬B₈(φ_B)_i
(register-opcode 224 :and-inv :reg-reg-reg 1)
(definstruction :and-inv (vm args)
  (set-reg vm (getf args :rd)
           (logand (reg vm (getf args :ra))
                   (u64 (lognot (reg vm (getf args :rb))))))
  :continue)

;; 225 = or_inv: B₈(φ'_D)_i = B₈(φ_A)_i ∨ ¬B₈(φ_B)_i
(register-opcode 225 :or-inv :reg-reg-reg 1)
(definstruction :or-inv (vm args)
  (set-reg vm (getf args :rd)
           (u64 (logior (reg vm (getf args :ra))
                        (u64 (lognot (reg vm (getf args :rb)))))))
  :continue)

;; 226 = xnor: B₈(φ'_D)_i = ¬(B₈(φ_A)_i ⊕ B₈(φ_B)_i)
(register-opcode 226 :xnor :reg-reg-reg 1)
(definstruction :xnor (vm args)
  (set-reg vm (getf args :rd)
           (u64 (lognot (logxor (reg vm (getf args :ra))
                                (reg vm (getf args :rb))))))
  :continue)

;;; ═══════════════════════════════════════════════════════════════════
;;; Min / Max (three registers)
;;; ═══════════════════════════════════════════════════════════════════

;; 227 = max: Z₈⁻¹(max(Z₈(φ_A), Z₈(φ_B)))  [signed]
(register-opcode 227 :max-s :reg-reg-reg 1)
(definstruction :max-s (vm args)
  (set-reg vm (getf args :rd)
           (zn-inv 8 (max (zn 8 (reg vm (getf args :ra)))
                          (zn 8 (reg vm (getf args :rb))))))
  :continue)

;; 228 = max_u: max(φ_A, φ_B)  [unsigned]
(register-opcode 228 :max-u :reg-reg-reg 1)
(definstruction :max-u (vm args)
  (set-reg vm (getf args :rd)
           (max (reg vm (getf args :ra))
                (reg vm (getf args :rb))))
  :continue)

;; 229 = min: Z₈⁻¹(min(Z₈(φ_A), Z₈(φ_B)))  [signed]
(register-opcode 229 :min-s :reg-reg-reg 1)
(definstruction :min-s (vm args)
  (set-reg vm (getf args :rd)
           (zn-inv 8 (min (zn 8 (reg vm (getf args :ra)))
                          (zn 8 (reg vm (getf args :rb))))))
  :continue)

;; 230 = min_u: min(φ_A, φ_B)  [unsigned]
(register-opcode 230 :min-u :reg-reg-reg 1)
(definstruction :min-u (vm args)
  (set-reg vm (getf args :rd)
           (min (reg vm (getf args :ra))
                (reg vm (getf args :rb))))
  :continue)
