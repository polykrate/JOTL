;;;; inst-memory.lisp — Memory access instructions (loads & stores)
;;;;
;;;; A.5.3  load_imm_64(20)
;;;; A.5.4  store_imm_{u8,u16,u32,u64}(30-33)
;;;; A.5.6  load_imm(51), load_{u8..u64}(52-58), store_{u8..u64}(59-62)
;;;; A.5.7  store_imm_ind_{u8..u64}(70-73)
;;;; A.5.10 store_ind_{u8..u64}(120-123), load_ind_{u8..i32}(124-129)

(in-package #:jamvm)

;;; ═══════════════════════════════════════════════════════════════════
;;; A.5.3 — One register + extended 8-byte immediate
;;; ═══════════════════════════════════════════════════════════════════

;; 20 = load_imm_64: φ'_A = ν_X (full 64-bit immediate)
(register-opcode 20 :load-imm-64 :reg-imm64 1)
(definstruction :load-imm-64 (vm args)
  (set-reg vm (getf args :ra) (getf args :imm))
  :continue)

;;; ═══════════════════════════════════════════════════════════════════
;;; A.5.4 — Two immediates (store to absolute address)
;;; ═══════════════════════════════════════════════════════════════════

;; 30 = store_imm_u8
(register-opcode 30 :store-imm-u8 :imm-imm 1)
(definstruction :store-imm-u8 (vm args)
  (do-store vm (getf args :imm1)
            (make-array 1 :element-type '(unsigned-byte 8)
                          :initial-contents (list (logand (getf args :imm2) #xFF)))))

;; 31 = store_imm_u16
(register-opcode 31 :store-imm-u16 :imm-imm 1)
(definstruction :store-imm-u16 (vm args)
  (do-store vm (getf args :imm1) (encode-le (logand (getf args :imm2) #xFFFF) 2)))

;; 32 = store_imm_u32
(register-opcode 32 :store-imm-u32 :imm-imm 1)
(definstruction :store-imm-u32 (vm args)
  (do-store vm (getf args :imm1) (encode-le (logand (getf args :imm2) #xFFFFFFFF) 4)))

;; 33 = store_imm_u64
(register-opcode 33 :store-imm-u64 :imm-imm 1)
(definstruction :store-imm-u64 (vm args)
  (do-store vm (getf args :imm1) (encode-le (u64 (getf args :imm2)) 8)))

;;; ═══════════════════════════════════════════════════════════════════
;;; A.5.6 — One register + one immediate (loads/stores/load_imm)
;;; ═══════════════════════════════════════════════════════════════════

;; 51 = load_imm: φ'_A = ν_X
(register-opcode 51 :load-imm :reg-imm 1)
(definstruction :load-imm (vm args)
  (set-reg vm (getf args :ra) (getf args :imm))
  :continue)

;; ── Loads from absolute address ──

;; 52 = load_u8
(register-opcode 52 :load-u8 :reg-imm 1)
(definstruction :load-u8 (vm args)
  (load-reg-or-fault vm args 1))

;; 53 = load_i8 (sign-extended)
(register-opcode 53 :load-i8 :reg-imm 1)
(definstruction :load-i8 (vm args)
  (load-reg-or-fault vm args 1 (lambda (v) (sign-extend v 1))))

;; 54 = load_u16
(register-opcode 54 :load-u16 :reg-imm 1)
(definstruction :load-u16 (vm args)
  (load-reg-or-fault vm args 2))

;; 55 = load_i16 (sign-extended)
(register-opcode 55 :load-i16 :reg-imm 1)
(definstruction :load-i16 (vm args)
  (load-reg-or-fault vm args 2 (lambda (v) (sign-extend v 2))))

;; 56 = load_u32
(register-opcode 56 :load-u32 :reg-imm 1)
(definstruction :load-u32 (vm args)
  (load-reg-or-fault vm args 4))

;; 57 = load_i32 (sign-extended)
(register-opcode 57 :load-i32 :reg-imm 1)
(definstruction :load-i32 (vm args)
  (load-reg-or-fault vm args 4 (lambda (v) (sign-extend v 4))))

;; 58 = load_u64
(register-opcode 58 :load-u64 :reg-imm 1)
(definstruction :load-u64 (vm args)
  (load-reg-or-fault vm args 8))

;; ── Stores to absolute address ──

;; 59 = store_u8: μ'[ν_X] = φ_A mod 2⁸
(register-opcode 59 :store-u8 :reg-imm 1)
(definstruction :store-u8 (vm args)
  (do-store vm (getf args :imm)
            (make-array 1 :element-type '(unsigned-byte 8)
                          :initial-contents (list (logand (reg vm (getf args :ra)) #xFF)))))

;; 60 = store_u16
(register-opcode 60 :store-u16 :reg-imm 1)
(definstruction :store-u16 (vm args)
  (do-store vm (getf args :imm) (encode-le (logand (reg vm (getf args :ra)) #xFFFF) 2)))

;; 61 = store_u32
(register-opcode 61 :store-u32 :reg-imm 1)
(definstruction :store-u32 (vm args)
  (do-store vm (getf args :imm) (encode-le (logand (reg vm (getf args :ra)) #xFFFFFFFF) 4)))

;; 62 = store_u64
(register-opcode 62 :store-u64 :reg-imm 1)
(definstruction :store-u64 (vm args)
  (do-store vm (getf args :imm) (encode-le (u64 (reg vm (getf args :ra))) 8)))

;;; ═══════════════════════════════════════════════════════════════════
;;; A.5.7 — One register + two immediates (store imm indirect)
;;;
;;; Address = φ_A + ν_X, value = ν_Y
;;; ═══════════════════════════════════════════════════════════════════

;; 70 = store_imm_ind_u8
(register-opcode 70 :store-imm-ind-u8 :reg-imm-imm 1)
(definstruction :store-imm-ind-u8 (vm args)
  (let ((addr (u32 (+ (reg vm (getf args :ra)) (getf args :imm1)))))
    (do-store vm addr (make-array 1 :element-type '(unsigned-byte 8)
                                    :initial-contents (list (logand (u64 (getf args :imm2)) #xFF))))))

;; 71 = store_imm_ind_u16
(register-opcode 71 :store-imm-ind-u16 :reg-imm-imm 1)
(definstruction :store-imm-ind-u16 (vm args)
  (let ((addr (u32 (+ (reg vm (getf args :ra)) (getf args :imm1)))))
    (do-store vm addr (encode-le (logand (u64 (getf args :imm2)) #xFFFF) 2))))

;; 72 = store_imm_ind_u32
(register-opcode 72 :store-imm-ind-u32 :reg-imm-imm 1)
(definstruction :store-imm-ind-u32 (vm args)
  (let ((addr (u32 (+ (reg vm (getf args :ra)) (getf args :imm1)))))
    (do-store vm addr (encode-le (logand (u64 (getf args :imm2)) #xFFFFFFFF) 4))))

;; 73 = store_imm_ind_u64
(register-opcode 73 :store-imm-ind-u64 :reg-imm-imm 1)
(definstruction :store-imm-ind-u64 (vm args)
  (let ((addr (u32 (+ (reg vm (getf args :ra)) (getf args :imm1)))))
    (do-store vm addr (encode-le (u64 (getf args :imm2)) 8))))

;;; ═══════════════════════════════════════════════════════════════════
;;; A.5.10 — Two registers + one immediate (indirect load/store)
;;;
;;; Address = φ_B + ν_X (via ind-addr helper)
;;; ═══════════════════════════════════════════════════════════════════

;; ── Stores ──

;; 120 = store_ind_u8
(register-opcode 120 :store-ind-u8 :reg-reg-imm 1)
(definstruction :store-ind-u8 (vm args)
  (do-store vm (ind-addr vm args)
            (make-array 1 :element-type '(unsigned-byte 8)
                          :initial-contents (list (logand (reg vm (getf args :ra)) #xFF)))))

;; 121 = store_ind_u16
(register-opcode 121 :store-ind-u16 :reg-reg-imm 1)
(definstruction :store-ind-u16 (vm args)
  (do-store vm (ind-addr vm args) (encode-le (logand (reg vm (getf args :ra)) #xFFFF) 2)))

;; 122 = store_ind_u32
(register-opcode 122 :store-ind-u32 :reg-reg-imm 1)
(definstruction :store-ind-u32 (vm args)
  (do-store vm (ind-addr vm args) (encode-le (logand (reg vm (getf args :ra)) #xFFFFFFFF) 4)))

;; 123 = store_ind_u64
(register-opcode 123 :store-ind-u64 :reg-reg-imm 1)
(definstruction :store-ind-u64 (vm args)
  (do-store vm (ind-addr vm args) (encode-le (u64 (reg vm (getf args :ra))) 8)))

;; ── Loads ──

;; 124 = load_ind_u8
(register-opcode 124 :load-ind-u8 :reg-reg-imm 1)
(definstruction :load-ind-u8 (vm args)
  (multiple-value-bind (val err) (do-load vm (ind-addr vm args) 1)
    (if err err (progn (set-reg vm (getf args :ra) val) :continue))))

;; 125 = load_ind_i8 (sign-extended)
(register-opcode 125 :load-ind-i8 :reg-reg-imm 1)
(definstruction :load-ind-i8 (vm args)
  (multiple-value-bind (val err) (do-load vm (ind-addr vm args) 1)
    (if err err (progn (set-reg vm (getf args :ra) (sign-extend val 1)) :continue))))

;; 126 = load_ind_u16
(register-opcode 126 :load-ind-u16 :reg-reg-imm 1)
(definstruction :load-ind-u16 (vm args)
  (multiple-value-bind (val err) (do-load vm (ind-addr vm args) 2)
    (if err err (progn (set-reg vm (getf args :ra) val) :continue))))

;; 127 = load_ind_i16 (sign-extended)
(register-opcode 127 :load-ind-i16 :reg-reg-imm 1)
(definstruction :load-ind-i16 (vm args)
  (multiple-value-bind (val err) (do-load vm (ind-addr vm args) 2)
    (if err err (progn (set-reg vm (getf args :ra) (sign-extend val 2)) :continue))))

;; 128 = load_ind_u32
(register-opcode 128 :load-ind-u32 :reg-reg-imm 1)
(definstruction :load-ind-u32 (vm args)
  (multiple-value-bind (val err) (do-load vm (ind-addr vm args) 4)
    (if err err (progn (set-reg vm (getf args :ra) val) :continue))))

;; 129 = load_ind_i32 (sign-extended)
(register-opcode 129 :load-ind-i32 :reg-reg-imm 1)
(definstruction :load-ind-i32 (vm args)
  (multiple-value-bind (val err) (do-load vm (ind-addr vm args) 4)
    (if err err (progn (set-reg vm (getf args :ra) (sign-extend val 4)) :continue))))

;; 130 = load_ind_u64
(register-opcode 130 :load-ind-u64 :reg-reg-imm 1)
(definstruction :load-ind-u64 (vm args)
  (multiple-value-bind (val err) (do-load vm (ind-addr vm args) 8)
    (if err err (progn (set-reg vm (getf args :ra) val) :continue))))
