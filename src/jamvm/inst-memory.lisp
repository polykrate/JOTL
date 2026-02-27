;;;; inst-memory.lisp — Memory access instructions (loads & stores)
;;;;
;;;; A.5.1  memset(2)
;;;; A.5.3  load_imm_64(20)
;;;; A.5.4  store_imm_{u8,u16,u32,u64}(30-33)
;;;; A.5.6  load_imm(51), load_{u8..u64}(52-58), store_{u8..u64}(59-62)
;;;; A.5.7  store_imm_ind_{u8..u64}(70-73)
;;;; A.5.10 store_ind_{u8..u64}(120-123), load_ind_{u8..i32}(124-129)
;;;;
;;;; PERF: All loads/stores use typed zero-allocation accessors
;;;; (mem-read-uN / mem-write-uN) instead of allocating byte vectors.

(in-package #:jamvm)

(declaim (optimize (speed 3) (safety 1) (debug 1)))

;;; ═══════════════════════════════════════════════════════════════════
;;; A.5.1 — No arguments: memset
;;;
;;; 2 = memset: [A0..A0+A2] ← u8(A1)
;;; Fills A2 bytes starting at address A0 with value A1 (lowest byte).
;;; Each byte write costs 1 gas.  On page fault or OOG, execution pauses
;;; with partial progress preserved (A0, A2 reflect progress).
;;;
;;; Unlike other instructions, memset is NON-ATOMIC: on fault/OOG,
;;; registers are NOT rolled back. This is handled by returning
;;; (:partial-fault . addr) or :partial-oog, which vm-step recognises.
;;; ═══════════════════════════════════════════════════════════════════

(register-opcode 2 :memset :none 0 nil :memory-p t)
(definstruction :memset (vm args)
  (block memset-body
    (let* ((dst   (u32 (reg vm +a0+)))
           (value (logand (reg vm +a1+) #xFF))
           (count (reg vm +a2+)))
      (loop while (> count 0) do
        ;; Check gas — 1 gas per byte (check BEFORE write, like polkavm)
        (when (<= (pvm-gas vm) 0)
          (set-reg vm +a0+ dst)
          (set-reg vm +a2+ count)
          (return-from memset-body :partial-oog))
        ;; Write one byte (zero-allocation)
        (multiple-value-bind (ok fault-addr)
            (mem-write-u8 (pvm-memory vm) dst value)
          (unless ok
            (set-reg vm +a0+ dst)
            (set-reg vm +a2+ count)
            (setf (pvm-exit-arg vm) fault-addr)
            (return-from memset-body :partial-fault)))
        ;; Charge 1 gas, advance
        (decf (pvm-gas vm) 1)
        (setf dst (u32 (1+ dst)))
        (decf count))
      ;; Done — update registers
      (set-reg vm +a0+ dst)
      (set-reg vm +a2+ count)
      :continue)))

;;; ═══════════════════════════════════════════════════════════════════
;;; A.5.3 — One register + extended 8-byte immediate
;;; ═══════════════════════════════════════════════════════════════════

;; 20 = load_imm_64: φ'_A = ν_X (full 64-bit immediate)
(register-opcode 20 :load-imm-64 :reg-imm64 1)
(definstruction :load-imm-64 (vm args)
  (set-reg vm (arg-ra args) (arg-imm args))
  :continue)

;;; ═══════════════════════════════════════════════════════════════════
;;; A.5.4 — Two immediates (store to absolute address)
;;; ═══════════════════════════════════════════════════════════════════

;; 30 = store_imm_u8
(register-opcode 30 :store-imm-u8 :imm-imm 1 nil :memory-p t)
(definstruction :store-imm-u8 (vm args)
  (let ((addr (u32 (arg-imm1 args))))
    (multiple-value-bind (ok fault-addr)
        (mem-write-u8 (pvm-memory vm) addr (logand (arg-imm2 args) #xFF))
      (if ok :continue
          (progn (setf (pvm-exit-arg vm) fault-addr) :fault)))))

;; 31 = store_imm_u16
(register-opcode 31 :store-imm-u16 :imm-imm 1 nil :memory-p t)
(definstruction :store-imm-u16 (vm args)
  (let ((addr (u32 (arg-imm1 args))))
    (multiple-value-bind (ok fault-addr)
        (mem-write-u16 (pvm-memory vm) addr (logand (arg-imm2 args) #xFFFF))
      (if ok :continue
          (progn (setf (pvm-exit-arg vm) fault-addr) :fault)))))

;; 32 = store_imm_u32
(register-opcode 32 :store-imm-u32 :imm-imm 1 nil :memory-p t)
(definstruction :store-imm-u32 (vm args)
  (let ((addr (u32 (arg-imm1 args))))
    (multiple-value-bind (ok fault-addr)
        (mem-write-u32 (pvm-memory vm) addr (logand (arg-imm2 args) #xFFFFFFFF))
      (if ok :continue
          (progn (setf (pvm-exit-arg vm) fault-addr) :fault)))))

;; 33 = store_imm_u64
(register-opcode 33 :store-imm-u64 :imm-imm 1 nil :memory-p t)
(definstruction :store-imm-u64 (vm args)
  (let ((addr (u32 (arg-imm1 args))))
    (multiple-value-bind (ok fault-addr)
        (mem-write-u64 (pvm-memory vm) addr (u64 (arg-imm2 args)))
      (if ok :continue
          (progn (setf (pvm-exit-arg vm) fault-addr) :fault)))))

;;; ═══════════════════════════════════════════════════════════════════
;;; A.5.6 — One register + one immediate (loads/stores/load_imm)
;;; ═══════════════════════════════════════════════════════════════════

;; 51 = load_imm: φ'_A = ν_X
(register-opcode 51 :load-imm :reg-imm 1)
(definstruction :load-imm (vm args)
  (set-reg vm (arg-ra args) (arg-imm args))
  :continue)

;; ── Loads from absolute address (zero-allocation) ──

;; 52 = load_u8
(register-opcode 52 :load-u8 :reg-imm 1 nil :memory-p t)
(definstruction :load-u8 (vm args)
  (let ((addr (u32 (arg-imm args))))
    (multiple-value-bind (val fault-addr) (mem-read-u8 (pvm-memory vm) addr)
      (if fault-addr
          (progn (setf (pvm-exit-arg vm) fault-addr) :fault)
          (progn (set-reg vm (arg-ra args) val) :continue)))))

;; 53 = load_i8 (sign-extended)
(register-opcode 53 :load-i8 :reg-imm 1 nil :memory-p t)
(definstruction :load-i8 (vm args)
  (let ((addr (u32 (arg-imm args))))
    (multiple-value-bind (val fault-addr) (mem-read-u8 (pvm-memory vm) addr)
      (if fault-addr
          (progn (setf (pvm-exit-arg vm) fault-addr) :fault)
          (progn (set-reg vm (arg-ra args) (sign-extend val 1)) :continue)))))

;; 54 = load_u16
(register-opcode 54 :load-u16 :reg-imm 1 nil :memory-p t)
(definstruction :load-u16 (vm args)
  (let ((addr (u32 (arg-imm args))))
    (multiple-value-bind (val fault-addr) (mem-read-u16 (pvm-memory vm) addr)
      (if fault-addr
          (progn (setf (pvm-exit-arg vm) fault-addr) :fault)
          (progn (set-reg vm (arg-ra args) val) :continue)))))

;; 55 = load_i16 (sign-extended)
(register-opcode 55 :load-i16 :reg-imm 1 nil :memory-p t)
(definstruction :load-i16 (vm args)
  (let ((addr (u32 (arg-imm args))))
    (multiple-value-bind (val fault-addr) (mem-read-u16 (pvm-memory vm) addr)
      (if fault-addr
          (progn (setf (pvm-exit-arg vm) fault-addr) :fault)
          (progn (set-reg vm (arg-ra args) (sign-extend val 2)) :continue)))))

;; 56 = load_u32
(register-opcode 56 :load-u32 :reg-imm 1 nil :memory-p t)
(definstruction :load-u32 (vm args)
  (let ((addr (u32 (arg-imm args))))
    (multiple-value-bind (val fault-addr) (mem-read-u32 (pvm-memory vm) addr)
      (if fault-addr
          (progn (setf (pvm-exit-arg vm) fault-addr) :fault)
          (progn (set-reg vm (arg-ra args) val) :continue)))))

;; 57 = load_i32 (sign-extended)
(register-opcode 57 :load-i32 :reg-imm 1 nil :memory-p t)
(definstruction :load-i32 (vm args)
  (let ((addr (u32 (arg-imm args))))
    (multiple-value-bind (val fault-addr) (mem-read-u32 (pvm-memory vm) addr)
      (if fault-addr
          (progn (setf (pvm-exit-arg vm) fault-addr) :fault)
          (progn (set-reg vm (arg-ra args) (sign-extend val 4)) :continue)))))

;; 58 = load_u64
(register-opcode 58 :load-u64 :reg-imm 1 nil :memory-p t)
(definstruction :load-u64 (vm args)
  (let ((addr (u32 (arg-imm args))))
    (multiple-value-bind (val fault-addr) (mem-read-u64 (pvm-memory vm) addr)
      (if fault-addr
          (progn (setf (pvm-exit-arg vm) fault-addr) :fault)
          (progn (set-reg vm (arg-ra args) val) :continue)))))

;; ── Stores to absolute address (zero-allocation) ──

;; 59 = store_u8: μ'[ν_X] = φ_A mod 2⁸
(register-opcode 59 :store-u8 :reg-imm 1 nil :memory-p t)
(definstruction :store-u8 (vm args)
  (let ((addr (u32 (arg-imm args))))
    (multiple-value-bind (ok fault-addr)
        (mem-write-u8 (pvm-memory vm) addr (logand (reg vm (arg-ra args)) #xFF))
      (if ok :continue
          (progn (setf (pvm-exit-arg vm) fault-addr) :fault)))))

;; 60 = store_u16
(register-opcode 60 :store-u16 :reg-imm 1 nil :memory-p t)
(definstruction :store-u16 (vm args)
  (let ((addr (u32 (arg-imm args))))
    (multiple-value-bind (ok fault-addr)
        (mem-write-u16 (pvm-memory vm) addr (logand (reg vm (arg-ra args)) #xFFFF))
      (if ok :continue
          (progn (setf (pvm-exit-arg vm) fault-addr) :fault)))))

;; 61 = store_u32
(register-opcode 61 :store-u32 :reg-imm 1 nil :memory-p t)
(definstruction :store-u32 (vm args)
  (let ((addr (u32 (arg-imm args))))
    (multiple-value-bind (ok fault-addr)
        (mem-write-u32 (pvm-memory vm) addr (logand (reg vm (arg-ra args)) #xFFFFFFFF))
      (if ok :continue
          (progn (setf (pvm-exit-arg vm) fault-addr) :fault)))))

;; 62 = store_u64
(register-opcode 62 :store-u64 :reg-imm 1 nil :memory-p t)
(definstruction :store-u64 (vm args)
  (let ((addr (u32 (arg-imm args))))
    (multiple-value-bind (ok fault-addr)
        (mem-write-u64 (pvm-memory vm) addr (u64 (reg vm (arg-ra args))))
      (if ok :continue
          (progn (setf (pvm-exit-arg vm) fault-addr) :fault)))))

;;; ═══════════════════════════════════════════════════════════════════
;;; A.5.7 — One register + two immediates (store imm indirect)
;;;
;;; Address = φ_A + ν_X, value = ν_Y
;;; ═══════════════════════════════════════════════════════════════════

;; 70 = store_imm_ind_u8
(register-opcode 70 :store-imm-ind-u8 :reg-imm-imm 1 nil :memory-p t)
(definstruction :store-imm-ind-u8 (vm args)
  (let ((addr (u32 (+ (reg vm (arg-ra args)) (arg-imm1 args)))))
    (multiple-value-bind (ok fault-addr)
        (mem-write-u8 (pvm-memory vm) addr (logand (u64 (arg-imm2 args)) #xFF))
      (if ok :continue
          (progn (setf (pvm-exit-arg vm) fault-addr) :fault)))))

;; 71 = store_imm_ind_u16
(register-opcode 71 :store-imm-ind-u16 :reg-imm-imm 1 nil :memory-p t)
(definstruction :store-imm-ind-u16 (vm args)
  (let ((addr (u32 (+ (reg vm (arg-ra args)) (arg-imm1 args)))))
    (multiple-value-bind (ok fault-addr)
        (mem-write-u16 (pvm-memory vm) addr (logand (u64 (arg-imm2 args)) #xFFFF))
      (if ok :continue
          (progn (setf (pvm-exit-arg vm) fault-addr) :fault)))))

;; 72 = store_imm_ind_u32
(register-opcode 72 :store-imm-ind-u32 :reg-imm-imm 1 nil :memory-p t)
(definstruction :store-imm-ind-u32 (vm args)
  (let ((addr (u32 (+ (reg vm (arg-ra args)) (arg-imm1 args)))))
    (multiple-value-bind (ok fault-addr)
        (mem-write-u32 (pvm-memory vm) addr (logand (u64 (arg-imm2 args)) #xFFFFFFFF))
      (if ok :continue
          (progn (setf (pvm-exit-arg vm) fault-addr) :fault)))))

;; 73 = store_imm_ind_u64
(register-opcode 73 :store-imm-ind-u64 :reg-imm-imm 1 nil :memory-p t)
(definstruction :store-imm-ind-u64 (vm args)
  (let ((addr (u32 (+ (reg vm (arg-ra args)) (arg-imm1 args)))))
    (multiple-value-bind (ok fault-addr)
        (mem-write-u64 (pvm-memory vm) addr (u64 (arg-imm2 args)))
      (if ok :continue
          (progn (setf (pvm-exit-arg vm) fault-addr) :fault)))))

;;; ═══════════════════════════════════════════════════════════════════
;;; A.5.10 — Two registers + one immediate (indirect load/store)
;;;
;;; Address = φ_B + ν_X (via ind-addr helper)
;;; ═══════════════════════════════════════════════════════════════════

;; ── Stores (zero-allocation) ──

;; 120 = store_ind_u8
(register-opcode 120 :store-ind-u8 :reg-reg-imm 1 nil :memory-p t)
(definstruction :store-ind-u8 (vm args)
  (let ((addr (ind-addr vm args)))
    (multiple-value-bind (ok fault-addr)
        (mem-write-u8 (pvm-memory vm) addr (logand (reg vm (arg-ra args)) #xFF))
      (if ok :continue
          (progn (setf (pvm-exit-arg vm) fault-addr) :fault)))))

;; 121 = store_ind_u16
(register-opcode 121 :store-ind-u16 :reg-reg-imm 1 nil :memory-p t)
(definstruction :store-ind-u16 (vm args)
  (let ((addr (ind-addr vm args)))
    (multiple-value-bind (ok fault-addr)
        (mem-write-u16 (pvm-memory vm) addr (logand (reg vm (arg-ra args)) #xFFFF))
      (if ok :continue
          (progn (setf (pvm-exit-arg vm) fault-addr) :fault)))))

;; 122 = store_ind_u32
(register-opcode 122 :store-ind-u32 :reg-reg-imm 1 nil :memory-p t)
(definstruction :store-ind-u32 (vm args)
  (let ((addr (ind-addr vm args)))
    (multiple-value-bind (ok fault-addr)
        (mem-write-u32 (pvm-memory vm) addr (logand (reg vm (arg-ra args)) #xFFFFFFFF))
      (if ok :continue
          (progn (setf (pvm-exit-arg vm) fault-addr) :fault)))))

;; 123 = store_ind_u64
(register-opcode 123 :store-ind-u64 :reg-reg-imm 1 nil :memory-p t)
(definstruction :store-ind-u64 (vm args)
  (let ((addr (ind-addr vm args)))
    (multiple-value-bind (ok fault-addr)
        (mem-write-u64 (pvm-memory vm) addr (u64 (reg vm (arg-ra args))))
      (if ok :continue
          (progn (setf (pvm-exit-arg vm) fault-addr) :fault)))))

;; ── Loads (zero-allocation) ──

;; 124 = load_ind_u8
(register-opcode 124 :load-ind-u8 :reg-reg-imm 1 nil :memory-p t)
(definstruction :load-ind-u8 (vm args)
  (let ((addr (ind-addr vm args)))
    (multiple-value-bind (val fault-addr) (mem-read-u8 (pvm-memory vm) addr)
      (if fault-addr
          (progn (setf (pvm-exit-arg vm) fault-addr) :fault)
          (progn (set-reg vm (arg-ra args) val) :continue)))))

;; 125 = load_ind_i8 (sign-extended)
(register-opcode 125 :load-ind-i8 :reg-reg-imm 1 nil :memory-p t)
(definstruction :load-ind-i8 (vm args)
  (let ((addr (ind-addr vm args)))
    (multiple-value-bind (val fault-addr) (mem-read-u8 (pvm-memory vm) addr)
      (if fault-addr
          (progn (setf (pvm-exit-arg vm) fault-addr) :fault)
          (progn (set-reg vm (arg-ra args) (sign-extend val 1)) :continue)))))

;; 126 = load_ind_u16
(register-opcode 126 :load-ind-u16 :reg-reg-imm 1 nil :memory-p t)
(definstruction :load-ind-u16 (vm args)
  (let ((addr (ind-addr vm args)))
    (multiple-value-bind (val fault-addr) (mem-read-u16 (pvm-memory vm) addr)
      (if fault-addr
          (progn (setf (pvm-exit-arg vm) fault-addr) :fault)
          (progn (set-reg vm (arg-ra args) val) :continue)))))

;; 127 = load_ind_i16 (sign-extended)
(register-opcode 127 :load-ind-i16 :reg-reg-imm 1 nil :memory-p t)
(definstruction :load-ind-i16 (vm args)
  (let ((addr (ind-addr vm args)))
    (multiple-value-bind (val fault-addr) (mem-read-u16 (pvm-memory vm) addr)
      (if fault-addr
          (progn (setf (pvm-exit-arg vm) fault-addr) :fault)
          (progn (set-reg vm (arg-ra args) (sign-extend val 2)) :continue)))))

;; 128 = load_ind_u32
(register-opcode 128 :load-ind-u32 :reg-reg-imm 1 nil :memory-p t)
(definstruction :load-ind-u32 (vm args)
  (let ((addr (ind-addr vm args)))
    (multiple-value-bind (val fault-addr) (mem-read-u32 (pvm-memory vm) addr)
      (if fault-addr
          (progn (setf (pvm-exit-arg vm) fault-addr) :fault)
          (progn (set-reg vm (arg-ra args) val) :continue)))))

;; 129 = load_ind_i32 (sign-extended)
(register-opcode 129 :load-ind-i32 :reg-reg-imm 1 nil :memory-p t)
(definstruction :load-ind-i32 (vm args)
  (let ((addr (ind-addr vm args)))
    (multiple-value-bind (val fault-addr) (mem-read-u32 (pvm-memory vm) addr)
      (if fault-addr
          (progn (setf (pvm-exit-arg vm) fault-addr) :fault)
          (progn (set-reg vm (arg-ra args) (sign-extend val 4)) :continue)))))

;; 130 = load_ind_u64
(register-opcode 130 :load-ind-u64 :reg-reg-imm 1 nil :memory-p t)
(definstruction :load-ind-u64 (vm args)
  (let ((addr (ind-addr vm args)))
    (multiple-value-bind (val fault-addr) (mem-read-u64 (pvm-memory vm) addr)
      (if fault-addr
          (progn (setf (pvm-exit-arg vm) fault-addr) :fault)
          (progn (set-reg vm (arg-ra args) val) :continue)))))
