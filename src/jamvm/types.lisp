;;;; types.lisp — GP A.1 Basic Definition: types and constants
;;;;
;;;; (A.1) Ψ: (𝔹, ℕ_R, ℕ_G, [ℕ_R]₁₃, 𝕄) →
;;;;          ({■, ϡ, ∞} ∪ {∃,ℏ} × ℕ_R) × ℕ_R × ℤ_G × [ℕ_R]₁₃ × 𝕄
;;;;
;;;; This file defines:
;;;;   - Register indices (GP Table A.1)
;;;;   - Exit reason constants
;;;;   - The PVM struct: (p, ι, ϱ, φ, μ) + exit state
;;;;   - Utility: 64-bit wrapping arithmetic, sign extension

(in-package #:jamvm)

(declaim (optimize (speed 3) (safety 1) (debug 1)))

;;; ═══════════════════════════════════════════════════════════════════
;;; Constants
;;; ═══════════════════════════════════════════════════════════════════

(defconstant +page-size+ 4096
  "Z_P — page size in bytes (GP A.1).")

(defconstant +num-regs+ 13
  "Number of general-purpose registers (GP A.1: [ℕ_R]₁₃).")

(defconstant +max-address+ (expt 2 32)
  "2^32 — address space limit.")

(defconstant +u32-max+ (1- (expt 2 32)))
(defconstant +u64-max+ (1- (expt 2 64)))
(defconstant +i64-min+ (- (expt 2 63)))
(defconstant +i64-max+ (1- (expt 2 63)))

(defconstant +z-a+ 2
  "Z_A = 2 — PVM dynamic address alignment factor (GP A.18).")

(defconstant +z-i+ (expt 2 24)
  "Z_I = 2²⁴ — standard PVM initialization input data size (GP A.7).")

(defconstant +z-p+ (expt 2 12)
  "Z_P = 2¹² = 4096 — PVM memory page size (GP eq. 4.24). Same as +page-size+.")

(defconstant +z-z+ (expt 2 16)
  "Z_Z = 2¹⁶ = 65536 — standard PVM program initialization zone size (GP A.7).")

(defconstant +halt-sentinel+ (- (expt 2 32) (expt 2 16))
  "2³² − 2¹⁶ = #xFFFF0000. djump(a) halts when a equals this (GP A.18).")

;;; ═══════════════════════════════════════════════════════════════════
;;; Exit reasons  ε ∈ {■, ϡ, ∞} ∪ {∃, ℏ} × ℕ_R
;;; ═══════════════════════════════════════════════════════════════════

(defconstant +exit-halt+       :halt       "■ — normal halt")
(defconstant +exit-panic+      :panic      "ϡ — panic")
(defconstant +exit-oog+        :oog        "∞ — out of gas")
(defconstant +exit-page-fault+ :page-fault "∃ — page fault (exit-arg = RAM address)")
(defconstant +exit-host-call+  :host-call  "ℏ — host call   (exit-arg = call id)")
(defconstant +exit-step+       :step       "► — single step completed (continue)")

;;; ═══════════════════════════════════════════════════════════════════
;;; Register indices — GP Table A.1
;;;
;;;   0=RA  1=SP  2=T0 3=T1 4=T2  5=S0 6=S1
;;;   7=A0  8=A1  9=A2 10=A3 11=A4 12=A5
;;; ═══════════════════════════════════════════════════════════════════

(defconstant +ra+ 0  "Return address register")
(defconstant +sp+ 1  "Stack pointer register")
(defconstant +t0+ 2  "Temporary register 0")
(defconstant +t1+ 3  "Temporary register 1")
(defconstant +t2+ 4  "Temporary register 2")
(defconstant +s0+ 5  "Saved register 0")
(defconstant +s1+ 6  "Saved register 1")
(defconstant +a0+ 7  "Argument/return register 0")
(defconstant +a1+ 8  "Argument/return register 1")
(defconstant +a2+ 9  "Argument/return register 2")
(defconstant +a3+ 10 "Argument/return register 3")
(defconstant +a4+ 11 "Argument/return register 4")
(defconstant +a5+ 12 "Argument/return register 5")

;;; ═══════════════════════════════════════════════════════════════════
;;; The PVM struct — GP A.1 state vector
;;;
;;;   p = (c, k, j)     program: code, bitmask, jump-table
;;;   ι                  instruction counter (byte offset into c)
;;;   ϱ                  gas counter (signed — can go negative)
;;;   φ = [ℕ_R]₁₃       registers (64-bit unsigned)
;;;   μ                  memory (see memory.lisp)
;;;   ε                  exit reason (nil while running)
;;; ═══════════════════════════════════════════════════════════════════

(defstruct (pvm (:conc-name pvm-))
  "Polkadot Virtual Machine state (GP Appendix A)."
  ;; Program (from deblob)
  (code      #() :type (simple-array (unsigned-byte 8) (*)))  ; c
  (bitmask   #() :type (simple-array (unsigned-byte 8) (*)))  ; k
  (jump-table #() :type (simple-array (unsigned-byte 32) (*))) ; j
  ;; Dynamic state
  (pc        0   :type (unsigned-byte 32))                     ; ι
  (gas       0   :type integer)                                ; ϱ (signed)
  (regs      (make-array +num-regs+
               :element-type '(unsigned-byte 64)
               :initial-element 0)
             :type (simple-array (unsigned-byte 64) (13)))     ; φ
  (memory    nil)                                              ; μ (memory struct)
  ;; Precomputed basic-block starts ω̄ (GP A.5)
  ;; Bit-vector: 1 at indices that are valid basic-block entry points.
  ;; Computed once during init, used by branch/djump for target validation.
  (basic-blocks #*  :type simple-bit-vector)                   ; ω̄
  ;; Precomputed skip-distance table: skip-table[i] = skip(i)
  ;; Avoids bitmask scanning on every step.
  (skip-table   (make-array 0 :element-type '(unsigned-byte 8))
               :type (simple-array (unsigned-byte 8) (*))) ; ℓ
  ;; AOT pre-decoded instructions for fast execution
  (decoded-code #() :type simple-vector)
  ;; Reusable instruction args buffer (zero allocation per step)
  (args-buf  (make-pvm-args) :type pvm-args)
  ;; Pre-allocated register save buffer (zero allocation on fault rollback)
  (saved-regs (make-array +num-regs+
                :element-type '(unsigned-byte 64)
                :initial-element 0)
              :type (simple-array (unsigned-byte 64) (13)))
  ;; Exit state
  (status    nil  :type (or null keyword))                     ; ε
  (exit-arg  0    :type (unsigned-byte 64)))                   ; associated value

;;; ═══════════════════════════════════════════════════════════════════
;;; Pre-allocated instruction arguments buffer
;;;
;;; Replaces plist allocation in decode-arguments with a reusable struct.
;;; Each VM has one args buffer, reused every vm-step (zero allocation).
;;; ═══════════════════════════════════════════════════════════════════

(defstruct (pvm-args (:conc-name arg-))
  "Reusable instruction argument container. Filled by decode-arguments."
  (ra     0 :type fixnum)      ; first register index
  (rb     0 :type fixnum)      ; second register index
  (rc     0 :type fixnum)      ; third register index (reg-reg-reg-imm)
  (rd     0 :type fixnum)      ; third register index (reg-reg-reg)
  (imm    0 :type integer)     ; immediate value
  (imm1   0 :type integer)     ; first immediate (imm-imm, reg-imm-imm, etc.)
  (imm2   0 :type integer)     ; second immediate
  (offset 0 :type integer))    ; PC-relative offset (resolved to absolute)

(defstruct (pvm-instr (:include pvm-args) (:conc-name instr-))
  "AOT decoded instruction."
  (handler nil :type (or null function))
  (skip 0 :type fixnum)
  (gas-cost 0 :type fixnum)
  (memory-p nil :type boolean))

(declaim (inline arg-ra arg-rb arg-rc arg-rd arg-imm arg-imm1 arg-imm2 arg-offset))

;;; ═══════════════════════════════════════════════════════════════════
;;; Register access — (reg vm i), (set-reg vm i val)
;;; ═══════════════════════════════════════════════════════════════════

(declaim (inline reg set-reg))

(defun reg (vm i)
  "Read register φ_i. Returns 0 for out-of-range."
  (declare (type pvm vm) (type (integer 0 12) i))
  (aref (pvm-regs vm) i))

(defun set-reg (vm i val)
  "Write register φ'_i ← val (mod 2^64)."
  (declare (type pvm vm) (type (integer 0 12) i))
  (setf (aref (pvm-regs vm) i) (logand val +u64-max+)))

(defsetf reg set-reg)

;;; ═══════════════════════════════════════════════════════════════════
;;; 64-bit wrapping arithmetic helpers
;;;
;;; CL integers are arbitrary precision. These enforce 64-bit unsigned
;;; semantics matching the GP's ℕ_R = {0, …, 2^64 − 1}.
;;; ═══════════════════════════════════════════════════════════════════

(declaim (inline u64 u32 s64->u64 u64->s64 s32->u64 u64->s32))

(defun u64 (x)
  "Truncate to unsigned 64-bit: x mod 2^64."
  (logand x +u64-max+))

(defun u32 (x)
  "Truncate to unsigned 32-bit: x mod 2^32."
  (logand x +u32-max+))

(defun s64->u64 (x)
  "Convert signed 64-bit integer to unsigned 64-bit (two's complement)."
  (if (minusp x)
      (logand (+ x #.(ash 1 64)) +u64-max+)
      (logand x +u64-max+)))

(defun u64->s64 (x)
  "Convert unsigned 64-bit to signed 64-bit (two's complement)."
  (if (>= x #.(ash 1 63))
      (- x #.(ash 1 64))
      x))

(defun s32->u64 (x)
  "Sign-extend 32-bit signed to 64-bit unsigned."
  (s64->u64 (if (>= x #.(ash 1 31)) (- x #.(ash 1 32)) x)))

(defun u64->s32 (x)
  "Truncate 64-bit to signed 32-bit."
  (let ((v (logand x +u32-max+)))
    (if (>= v #.(ash 1 31)) (- v #.(ash 1 32)) v)))

;;; ═══════════════════════════════════════════════════════════════════
;;; GP A.10–A.16: Signed/unsigned conversions, bytecode decoding
;;;
;;; (A.10) Z_n:  unsigned n-byte → signed        (interpret as two's complement)
;;; (A.11) Z_n⁻¹: signed → unsigned n-byte       (encode as two's complement)
;;; (A.12) B_n:  integer → bit-vector (LE bits)   [implicit in CL integers]
;;; (A.13) B_n⁻¹: bit-vector → integer (LE bits)  [implicit in CL integers]
;;; (A.14) B̄_n:  integer → bit-vector (BE bits)   [implicit in CL integers]
;;; (A.15) B̄_n⁻¹: bit-vector → integer (BE bits)  [implicit in CL integers]
;;; (A.16) X_n:  sign-extend n-byte value to ℕ_R (64-bit unsigned)
;;;
;;; Note: B_n / B̄_n are implicit — CL integers already encode binary.
;;; We provide Z_n, Z_n⁻¹, X_n as explicit functions.
;;; ═══════════════════════════════════════════════════════════════════

(declaim (inline zn zn-inv sign-extend))

(defun zn (n x)
  "Z_n (GP A.10): interpret unsigned n-byte value X as signed.
   Z_n(a) = a              if a < 2^{8n−1}
          = a − 2^{8n}     otherwise"
  (if (zerop n)
      0
      (let ((half (ash 1 (1- (ash n 3)))))   ; 2^{8n−1}
        (if (< x half) x (- x (ash half 1))))))

(defun zn-inv (n x)
  "Z_n⁻¹ (GP A.11): encode signed integer X as unsigned n-byte value.
   Z_n⁻¹(a) = (2^{8n} + a) mod 2^{8n}"
  (if (zerop n)
      0
      (let ((bits (ash n 3)))                 ; 8n
        (logand (+ x (ash 1 bits))            ; + 2^{8n}
                (1- (ash 1 bits))))))

;;; Bytecode decoding from instruction data

(defun decode-le-unsigned (bytes start length)
  "E_n⁻¹ (GP A.13/B_n⁻¹ on octets): decode LENGTH bytes as LE unsigned
   from BYTES at START. Missing bytes beyond end are zero (GP A.4: ζ)."
  (let ((val 0)
        (end (length bytes)))
    (dotimes (i length val)
      (let ((pos (+ start i)))
        (when (< pos end)
          (setf val (logior val (ash (aref bytes pos) (* 8 i)))))))))

(defun decode-le-signed (bytes start length)
  "Z_n(E_n⁻¹(…)): decode LENGTH bytes as LE signed from BYTES at START.
   Combines unsigned decode with Z_n interpretation."
  (zn length (decode-le-unsigned bytes start length)))

(defun sign-extend (value n-bytes)
  "X_n (GP A.16): sign-extend an N-BYTES unsigned value to ℕ_R (64-bit).
   X_n(x) = x + ⌊x/2^{8n−1}⌋·(2^64 − 2^{8n})
   n ∈ {0,1,2,3,4,8}.
   If MSB is set → fill upper bits with 1s; else value is unchanged."
  (if (zerop n-bytes)
      0   ; X_0: 0-byte immediate = 0
      (let* ((bits (ash n-bytes 3))                ; 8n
             (half (ash 1 (1- bits))))             ; 2^{8n−1}
        (if (< value half)
            (u64 value)                             ; MSB=0: unchanged
            ;; MSB=1: x + (2^64 − 2^{8n})
            (u64 (+ value (- #.(ash 1 64)
                             (ash 1 bits))))))))
