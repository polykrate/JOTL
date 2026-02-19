;;;; inst-reg.lisp — Register & bit-manipulation instructions
;;;;
;;;; A.5.9  move_reg(100), sbrk(101), count_set_bits(102-103),
;;;;        leading/trailing_zero_bits(104-107),
;;;;        sign_extend(108-109), zero_extend_16(110), reverse_bytes(111)

(in-package #:jamvm)

;;; ═══════════════════════════════════════════════════════════════════
;;; A.5.9 — Two registers
;;;
;;; Format: :reg-reg → (:ra r_D :rb r_A)
;;; ═══════════════════════════════════════════════════════════════════

;; 100 = move_reg: φ'_D = φ_A
(register-opcode 100 :move-reg :reg-reg 1)
(definstruction :move-reg (vm args)
  (set-reg vm (getf args :ra) (reg vm (getf args :rb)))
  :continue)

;; 101 = sbrk: allocate φ_A bytes from heap, return old heap-top
(register-opcode 101 :sbrk :reg-reg 1)
(definstruction :sbrk (vm args)
  (let* ((mem (pvm-memory vm))
         (size (reg vm (getf args :rb)))
         (h (mem-heap-base mem)))
    (if (zerop h)
        (progn (set-reg vm (getf args :ra) 0) :continue)
        (multiple-value-bind (old-top new-pages) (mem-sbrk mem (u32 size))
          (declare (ignore new-pages))
          (set-reg vm (getf args :ra) (u64 old-top))
          :continue))))

;; 102 = count_set_bits_64: popcount(φ_A)
(register-opcode 102 :count-set-bits-64 :reg-reg 1)
(definstruction :count-set-bits-64 (vm args)
  (set-reg vm (getf args :ra) (logcount (reg vm (getf args :rb))))
  :continue)

;; 103 = count_set_bits_32: popcount(φ_A mod 2³²)
(register-opcode 103 :count-set-bits-32 :reg-reg 1)
(definstruction :count-set-bits-32 (vm args)
  (set-reg vm (getf args :ra) (logcount (logand (reg vm (getf args :rb)) #xFFFFFFFF)))
  :continue)

;; 104 = leading_zero_bits_64
(register-opcode 104 :leading-zero-bits-64 :reg-reg 1)
(definstruction :leading-zero-bits-64 (vm args)
  (let ((v (reg vm (getf args :rb))))
    (set-reg vm (getf args :ra)
             (if (zerop v) 64 (- 63 (integer-length (logand v #xFFFFFFFFFFFFFFFF)) -1)))
    :continue))

;; 105 = leading_zero_bits_32
(register-opcode 105 :leading-zero-bits-32 :reg-reg 1)
(definstruction :leading-zero-bits-32 (vm args)
  (let ((v (logand (reg vm (getf args :rb)) #xFFFFFFFF)))
    (set-reg vm (getf args :ra)
             (if (zerop v) 32 (- 31 (integer-length v) -1)))
    :continue))

;; 106 = trailing_zero_bits_64
(register-opcode 106 :trailing-zero-bits-64 :reg-reg 1)
(definstruction :trailing-zero-bits-64 (vm args)
  (let ((v (reg vm (getf args :rb))))
    (set-reg vm (getf args :ra)
             (if (zerop v) 64
                 (let ((low (logand v (- v))))
                   (1- (integer-length low)))))
    :continue))

;; 107 = trailing_zero_bits_32
(register-opcode 107 :trailing-zero-bits-32 :reg-reg 1)
(definstruction :trailing-zero-bits-32 (vm args)
  (let ((v (logand (reg vm (getf args :rb)) #xFFFFFFFF)))
    (set-reg vm (getf args :ra)
             (if (zerop v) 32
                 (let ((low (logand v (- v))))
                   (1- (integer-length low)))))
    :continue))

;; 108 = sign_extend_8: Z₈⁻¹(Z₁(φ_A mod 2⁸))
(register-opcode 108 :sign-extend-8 :reg-reg 1)
(definstruction :sign-extend-8 (vm args)
  (set-reg vm (getf args :ra)
           (zn-inv 8 (zn 1 (logand (reg vm (getf args :rb)) #xFF))))
  :continue)

;; 109 = sign_extend_16: Z₈⁻¹(Z₂(φ_A mod 2¹⁶))
(register-opcode 109 :sign-extend-16 :reg-reg 1)
(definstruction :sign-extend-16 (vm args)
  (set-reg vm (getf args :ra)
           (zn-inv 8 (zn 2 (logand (reg vm (getf args :rb)) #xFFFF))))
  :continue)

;; 110 = zero_extend_16: φ_A mod 2¹⁶
(register-opcode 110 :zero-extend-16 :reg-reg 1)
(definstruction :zero-extend-16 (vm args)
  (set-reg vm (getf args :ra) (logand (reg vm (getf args :rb)) #xFFFF))
  :continue)

;; 111 = reverse_bytes: byte-swap 64-bit
(register-opcode 111 :reverse-bytes :reg-reg 1)
(definstruction :reverse-bytes (vm args)
  (let* ((v (reg vm (getf args :rb)))
         (result 0))
    (dotimes (i 8)
      (setf result (logior (ash result 8) (logand v #xFF)))
      (setf v (ash v -8)))
    (set-reg vm (getf args :ra) result)
    :continue))
