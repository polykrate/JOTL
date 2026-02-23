;;;; decoder.lisp — GP A.2 Instructions, Opcodes and Skip-distance
;;;;
;;;; (A.2) deblob: p → (c, k, j) ∪ ∇
;;;;   Parses the code blob to extract instruction data, bitmask, and jump table.
;;;;
;;;; (A.3) Basic Blocks and Termination Instructions:
;;;;   The bitmask k encodes basic block boundaries.
;;;;   k[i] = 1 iff byte i is the first byte of a basic block.
;;;;
;;;; Skip-distance ℓ = skip(ι):
;;;;   The number of bytes AFTER the opcode that belong to this instruction.
;;;;   Total instruction length = 1 + ℓ.
;;;;
;;;; Instruction argument categories (GP A.5):
;;;;   A.5.1  Args: none                    — ℓ determined by opcode
;;;;   A.5.2  Args: one register            — ℓ = 0..1
;;;;   A.5.3  Args: two registers           — ℓ = 0..1
;;;;   A.5.4  Args: two registers + offset  — variable
;;;;   A.5.5  Args: one offset              — variable
;;;;   A.5.6  Args: one register + imm      — variable
;;;;   A.5.7  Args: two registers + imm     — variable
;;;;   A.5.8  Args: two regs + offset       — variable
;;;;   A.5.9  Args: one reg + two imm       — variable
;;;;   A.5.10 Args: three registers         — variable
;;;;   A.5.11 Args: three registers + imm   — variable

(in-package #:jamvm)

(declaim (optimize (speed 3) (safety 1) (debug 1)))

;;; ═══════════════════════════════════════════════════════════════════
;;; Opcode table
;;;
;;; Maps opcode byte (ζ_ι) to:
;;;   - instruction keyword
;;;   - argument format
;;;   - gas cost (ϱ_Δ)
;;;   - skip-distance rule
;;;
;;; We'll populate this incrementally as the user sends GP pages.
;;; For now, define the structure and a few known opcodes.
;;; ═══════════════════════════════════════════════════════════════════

(defstruct (opcode-info (:conc-name opi-))
  "Metadata for a single opcode."
  (name     :unknown :type keyword)       ; instruction name
  (args     :none    :type keyword)       ; argument format
  (gas-cost 1        :type integer)       ; ϱ_Δ
  (skip-fn  nil)                          ; skip-distance function or fixed value
  (memory-p nil      :type boolean))      ; T if instruction accesses memory (needs reg save)

;; The master opcode table: 256 entries (0x00–0xFF)
(defvar *opcode-table*
  (make-array 256 :initial-element nil)
  "Opcode table: index = opcode byte → opcode-info or NIL (= trap).")

(defun register-opcode (byte name args gas-cost &optional skip-fn &key memory-p)
  "Register an opcode in the master table."
  (setf (aref *opcode-table* byte)
        (make-opcode-info :name name :args args
                          :gas-cost gas-cost :skip-fn skip-fn
                          :memory-p memory-p)))

(defun lookup-opcode (byte)
  "Look up opcode metadata. Returns opcode-info or NIL (= trap)."
  (aref *opcode-table* byte))

;;; ═══════════════════════════════════════════════════════════════════
;;; Skip-distance ℓ = skip(ι)
;;;
;;; GP A.3: The skip-distance is encoded in the bitmask k.
;;; Starting from ι+1, count consecutive 0-bits in k until a 1-bit
;;; is found (or end of code). That count = ℓ.
;;;
;;; Alternatively, for each instruction category the skip distance
;;; is computed from the opcode's argument format.
;;; ═══════════════════════════════════════════════════════════════════

(defun skip-distance (vm pc)
  "Compute skip-distance ℓ for instruction at PC using bitmask k.
   GP (A.3): skip(i) = min(24, j ∈ ℕ : (k ~ [1,1,...])_{i+1+j} = 1)
   ℓ = number of bytes after the opcode byte before the next instruction.
   The next instruction starts at PC + 1 + ℓ."
  (let ((k (pvm-bitmask vm))
        (count 0))
    ;; Scan from pc+1 forward: count consecutive 0-bits in k ~ [1,1,...]
    ;; bitmask-bit returns 1 for indices past end of k (the [1,1,...] extension)
    ;; Cap at 24 per GP A.3
    (loop for i from (1+ pc)
          while (and (< count 24) (zerop (bitmask-bit k i)))
          do (incf count))
    count))

(defun bitmask-bit (bitmask byte-index)
  "Read bit at BYTE-INDEX from BITMASK.
   k[i] = 1 iff byte i starts an instruction."
  (if (>= byte-index (* 8 (length bitmask)))
      1  ; past end = boundary
      (let ((byte-pos (ash byte-index -3))
            (bit-pos  (logand byte-index 7)))
        (if (< byte-pos (length bitmask))
            (ldb (byte 1 bit-pos) (aref bitmask byte-pos))
            1))))

;;; ═══════════════════════════════════════════════════════════════════
;;; Instruction decoding
;;;
;;; Returns (values opcode-info skip-distance arguments)
;;; Arguments is a plist depending on the format:
;;;   :none               → nil
;;;   :reg                → (:ra reg-index)
;;;   :reg-reg            → (:ra idx :rb idx)
;;;   :reg-imm            → (:ra idx :imm value)
;;;   :reg-reg-imm        → (:ra idx :rb idx :imm value)
;;;   :offset             → (:offset value)
;;;   :reg-reg-offset     → (:ra idx :rb idx :offset value)
;;;   etc.
;;; ═══════════════════════════════════════════════════════════════════

(defun decode-instruction (vm pc)
  "Decode the instruction at PC in VM's code.
   Uses pvm-opcode (A.19) for effective opcode.
   Returns (values opcode-info skip-dist arg-plist) or NIL for trap.
   GP A.19: when pc >= |c|, effective opcode is 0 (trap, gas cost 1)."
  (let* ((code (pvm-code vm))
         (len  (length code)))
    ;; Out of bounds → trap (opcode 0, gas cost 1)
    (when (>= pc len)
      (let ((trap-info (lookup-opcode 0)))
        (return-from decode-instruction (values trap-info 0 nil))))
    ;; A.19: effective opcode (0 if invalid)
    (let* ((effective (pvm-opcode vm pc))
           (info (lookup-opcode effective)))
      ;; Unknown/invalid opcode → trap (opcode 0, gas cost 1)
      (unless info
        (let ((trap-info (lookup-opcode 0)))
          (return-from decode-instruction (values trap-info 0 nil))))
      ;; A.20: ℓ = skip(ι)
      (let ((skip (skip-distance vm pc)))
        (values info skip
                (decode-arguments info code pc skip))))))

(defun decode-arguments (info code pc skip)
  "Decode instruction arguments based on argument format.
   Returns a plist of decoded arguments."
  (let ((fmt (opi-args info))
        (len (length code)))
    (flet ((byte-at (i) (if (< i len) (aref code i) 0)))
      (case fmt
        ;; ── A.5.1: no arguments ──
        (:none nil)

        ;; ── A.5.2: one immediate (no register) ──
        ;; (A.21) l_X = min(4, ℓ), ν_X = X_{l_X}(E_{l_X}^{-1}(ζ_{ι+1…+l_X}))
        (:imm
         (let* ((l-x (min 4 skip))
                (raw (decode-le-unsigned code (1+ pc) l-x))
                (imm (sign-extend raw l-x)))
           (list :imm imm)))

        ;; ── A.5.3: one register + extended 8-byte immediate ──
        ;; (A.22) r_A = min(12, ζ_{ι+1} mod 16), ν_X = E_8^{-1}(ζ_{ι+2…+8})
        ;; Note: E_8^{-1} is unsigned decode, NO sign extension (full 64-bit)
        (:reg-imm64
         (let* ((r-a (min 12 (mod (byte-at (1+ pc)) 16)))
                (imm (decode-le-unsigned code (+ pc 2) 8)))
           (list :ra r-a :imm imm)))

        ;; ── A.5.4: two immediates ──
        ;; (A.23) l_X = min(4, ζ_{ι+1} mod 8)
        ;;        ν_X = X_{l_X}(E_{l_X}^{-1}(ζ_{ι+2…+l_X}))
        ;;        l_Y = min(4, max(0, ℓ − l_X − 1))
        ;;        ν_Y = X_{l_Y}(E_{l_Y}^{-1}(ζ_{ι+2+l_X…+l_Y}))
        (:imm-imm
         (let* ((l-x (min 4 (mod (byte-at (1+ pc)) 8)))
                (raw-x (decode-le-unsigned code (+ pc 2) l-x))
                (imm-x (sign-extend raw-x l-x))
                (l-y (min 4 (max 0 (- skip l-x 1))))
                (raw-y (decode-le-unsigned code (+ pc 2 l-x) l-y))
                (imm-y (sign-extend raw-y l-y)))
           (list :imm1 imm-x :imm2 imm-y)))

        ;; ── A.5.2 (regs): one register ──
        ;; r_A = min(12, ζ_{ι+1} mod 16)
        (:reg
         (let ((r-a (min 12 (mod (byte-at (1+ pc)) 16))))
           (list :ra r-a)))

        ;; ── A.5.3: two registers ──
        ;; r_A = min(12, ζ_{ι+1} mod 16)
        ;; r_B = min(12, ⌊ζ_{ι+1} / 16⌋)
        (:reg-reg
         (let* ((b (byte-at (1+ pc)))
                (r-a (min 12 (mod b 16)))
                (r-b (min 12 (floor b 16))))
           (list :ra r-a :rb r-b)))

        ;; ── A.5.5: one offset ──
        ;; (A.24) l_X = min(4, ℓ), ν_X = ι + Z_{l_X}^{-1}(ζ_{ι+1…+l_X})
        (:offset
         (let* ((l-x (min 4 skip))
                (signed-offset (decode-le-signed code (1+ pc) l-x)))
           (list :offset (+ pc signed-offset))))

        ;; ── A.5.6: one register + one immediate ──
        ;; (A.25) r_A = min(12, ζ_{ι+1} mod 16)
        ;;        l_X = min(4, max(0, ℓ-1))
        ;;        ν_X = X_{l_X}(E_{l_X}^{-1}(ζ_{ι+2…+l_X}))
        (:reg-imm
         (let* ((r-a (min 12 (mod (byte-at (1+ pc)) 16)))
                (l-x (min 4 (max 0 (1- skip))))
                (raw (decode-le-unsigned code (+ pc 2) l-x))
                (imm (sign-extend raw l-x)))
           (list :ra r-a :imm imm)))

        ;; ── A.5.7: two registers + one immediate ──
        ;; r_A = min(12, ζ_{ι+1} mod 16)
        ;; r_B = min(12, ⌊ζ_{ι+1} / 16⌋)
        ;; l_X = min(4, max(0, ℓ-1))
        ;; ν_X = X_{l_X}(E_{l_X}^{-1}(ζ_{ι+2…+l_X}))
        (:reg-reg-imm
         (let* ((b (byte-at (1+ pc)))
                (r-a (min 12 (mod b 16)))
                (r-b (min 12 (floor b 16)))
                (l-x (min 4 (max 0 (1- skip))))
                (raw (decode-le-unsigned code (+ pc 2) l-x))
                (imm (sign-extend raw l-x)))
           (list :ra r-a :rb r-b :imm imm)))

        ;; ── A.5.4 / A.5.8: two registers + offset ──
        ;; r_A = min(12, ζ_{ι+1} mod 16)
        ;; r_B = min(12, ⌊ζ_{ι+1} / 16⌋)
        ;; l_X = min(4, max(0, ℓ-1))
        ;; ν_X = ι + Z_{l_X}^{-1}(ζ_{ι+2…+l_X})  [signed offset from PC]
        (:reg-reg-offset
         (let* ((b (byte-at (1+ pc)))
                (r-a (min 12 (mod b 16)))
                (r-b (min 12 (floor b 16)))
                (l-x (min 4 (max 0 (1- skip))))
                (signed-off (decode-le-signed code (+ pc 2) l-x)))
           (list :ra r-a :rb r-b :offset (+ pc signed-off))))

        ;; ── A.5.7 (A.26): one register + two immediates ──
        ;; r_A = min(12, ζ_{ι+1} mod 16)
        ;; l_X = min(4, ⌊ζ_{ι+1}/16⌋ mod 8)   ← high nibble encodes l_X
        ;; ν_X = X_{l_X}(E^{-1}_{l_X}(ζ_{ι+2…+l_X}))
        ;; l_Y = min(4, max(0, ℓ − l_X − 1))
        ;; ν_Y = X_{l_Y}(E^{-1}_{l_Y}(ζ_{ι+2+l_X…+l_Y}))
        (:reg-imm-imm
         (let* ((b1 (byte-at (1+ pc)))
                (r-a (min 12 (mod b1 16)))
                (l-x (min 4 (mod (floor b1 16) 8)))
                (l-y (min 4 (max 0 (- skip l-x 1))))
                (raw-x (decode-le-unsigned code (+ pc 2) l-x))
                (imm-x (sign-extend raw-x l-x))
                (raw-y (decode-le-unsigned code (+ pc 2 l-x) l-y))
                (imm-y (sign-extend raw-y l-y)))
           (list :ra r-a :imm1 imm-x :imm2 imm-y)))

        ;; ── A.5.8 (A.27): one register + immediate + offset ──
        ;; Same byte layout as A.26 but ν_Y is PC-relative:
        ;; r_A = min(12, ζ_{ι+1} mod 16)
        ;; l_X = min(4, ⌊ζ_{ι+1}/16⌋ mod 8)
        ;; ν_X = X_{l_X}(E^{-1}_{l_X}(ζ_{ι+2…+l_X}))
        ;; l_Y = min(4, max(0, ℓ − l_X − 1))
        ;; ν_Y = ι + Z_{l_Y}(E^{-1}_{l_Y}(ζ_{ι+2+l_X…+l_Y}))  ← offset!
        (:reg-imm-offset
         (let* ((b1 (byte-at (1+ pc)))
                (r-a (min 12 (mod b1 16)))
                (l-x (min 4 (mod (floor b1 16) 8)))
                (l-y (min 4 (max 0 (- skip l-x 1))))
                (raw-x (decode-le-unsigned code (+ pc 2) l-x))
                (imm-x (sign-extend raw-x l-x))
                (off-y (decode-le-signed code (+ pc 2 l-x) l-y)))
           (list :ra r-a :imm imm-x :offset (+ pc off-y))))

        ;; ── A.5.12 (A.31): two registers + two immediates ──
        ;; r_A = min(12, ζ_{ι+1} mod 16)
        ;; r_B = min(12, ⌊ζ_{ι+1}/16⌋)
        ;; l_X = min(4, ζ_{ι+2} mod 8)
        ;; ν_X = X_{l_X}(E^{-1}_{l_X}(ζ_{ι+3…+l_X}))
        ;; l_Y = min(4, max(0, ℓ − l_X − 2))
        ;; ν_Y = X_{l_Y}(E^{-1}_{l_Y}(ζ_{ι+3+l_X…+l_Y}))
        (:reg-reg-imm-imm
         (let* ((b1 (byte-at (1+ pc)))
                (b2 (byte-at (+ pc 2)))
                (r-a (min 12 (mod b1 16)))
                (r-b (min 12 (floor b1 16)))
                (l-x (min 4 (mod b2 8)))
                (l-y (min 4 (max 0 (- skip l-x 2))))
                (raw-x (decode-le-unsigned code (+ pc 3) l-x))
                (imm-x (sign-extend raw-x l-x))
                (raw-y (decode-le-unsigned code (+ pc 3 l-x) l-y))
                (imm-y (sign-extend raw-y l-y)))
           (list :ra r-a :rb r-b :imm1 imm-x :imm2 imm-y)))

        ;; ── A.5.13 (A.32): three registers ──
        ;; r_A = min(12, ζ_{ι+1} mod 16)
        ;; r_B = min(12, ⌊ζ_{ι+1}/16⌋)
        ;; r_D = min(12, ζ_{ι+2})            ← full byte, not nibble!
        (:reg-reg-reg
         (let* ((b1 (byte-at (1+ pc)))
                (b2 (byte-at (+ pc 2)))
                (r-a (min 12 (mod b1 16)))
                (r-b (min 12 (floor b1 16)))
                (r-d (min 12 b2)))
           (list :ra r-a :rb r-b :rd r-d)))

        ;; ── A.5.11: three registers + immediate ──
        (:reg-reg-reg-imm
         (let* ((b1 (byte-at (1+ pc)))
                (b2 (byte-at (+ pc 2)))
                (r-a (min 12 (mod b1 16)))
                (r-b (min 12 (floor b1 16)))
                (r-c (min 12 (mod b2 16)))
                (l-x (min 4 (max 0 (- skip 2))))
                (raw (decode-le-unsigned code (+ pc 3) l-x))
                (imm (sign-extend raw l-x)))
           (list :ra r-a :rb r-b :rc r-c :imm imm)))

        ;; Default: no args
        (otherwise nil)))))

;;; ═══════════════════════════════════════════════════════════════════
;;; GP (A.4): ζ ≡ c ~ [0, 0, ...]
;;;
;;; Code padded with infinite zeros.  Ensures no out-of-bounds access
;;; and that a trap will occur if the PC passes beyond the actual code.
;;; Our byte-at helper in decode-arguments already does this, but we
;;; provide a standalone accessor for the VM step function.
;;; ═══════════════════════════════════════════════════════════════════

(declaim (inline zeta))
(defun zeta (vm i)
  "ζ_i — read byte i from code, returning 0 if out of bounds (GP A.4)."
  (let ((code (pvm-code vm)))
    (if (< i (length code))
        (aref code i)
        0)))

;;; ═══════════════════════════════════════════════════════════════════
;;; GP A.19: opcode(n) — effective opcode at instruction index n
;;;
;;;   opcode(n) = c_n  if k_n = 1 ∧ c_n ∈ U
;;;             = 0    otherwise
;;;
;;; If the byte at n has its bitmask bit set AND is a valid opcode,
;;; return it. Otherwise treat as 0 (= trap).
;;; ═══════════════════════════════════════════════════════════════════

(defun pvm-opcode (vm n)
  "GP A.19: effective opcode at byte index N.
   Returns the opcode byte if valid, or 0 (trap) otherwise."
  (let ((k (pvm-bitmask vm))
        (cn (zeta vm n)))
    (if (and (= 1 (bitmask-bit k n))      ; k_n = 1
             (valid-opcode-p cn))           ; c_n ∈ U
        cn
        0)))  ; → trap

;;; ═══════════════════════════════════════════════════════════════════
;;; GP A.3: Termination set T and basic-block boundaries ω̄
;;;
;;; T ⊂ U  — opcodes that terminate a basic block.
;;; ω̄ — instruction opcode indices denoting basic-block starts.
;;;
;;; (A.5)  ω̄ = ({0} ∪ {n+1+skip(n) | n ∈ ℕ_{|c|} ∧ k_n = 1 ∧ c_n ∈ T})
;;;             ∩ {n | k_n = 1 ∧ c_n ∈ U}
;;;
;;; We build T and U incrementally as opcodes are registered.
;;; ═══════════════════════════════════════════════════════════════════

(defvar *termination-opcodes* (make-hash-table :test 'eql)
  "Set T: opcode bytes whose instructions are basic-block terminators.
   Populated by register-termination-opcode.")

(defun register-termination-opcode (byte)
  "Mark opcode BYTE as a basic-block termination instruction (member of T)."
  (setf (gethash byte *termination-opcodes*) t))

(defun termination-opcode-p (byte)
  "Is BYTE a block-termination opcode (∈ T)?"
  (gethash byte *termination-opcodes*))

(defun valid-opcode-p (byte)
  "Is BYTE a valid opcode (∈ U)?  True iff registered in *opcode-table*."
  (not (null (aref *opcode-table* byte))))

(defun compute-basic-block-starts (vm)
  "Compute ω̄ — the set of byte offsets that begin a basic block (GP A.5).
   Returns a bit-vector the same length as code, 1 at block starts."
  (let* ((code (pvm-code vm))
         (len  (length code))
         (bitmask (pvm-bitmask vm))
         ;; Candidates: successors of termination instructions
         (successors (make-hash-table :test 'eql)))
    ;; {0} is always a candidate
    (setf (gethash 0 successors) t)
    ;; Add {n+1+skip(n)} for each termination instruction n
    (loop for n from 0 below len
          when (and (= 1 (bitmask-bit bitmask n))         ; k_n = 1
                    (termination-opcode-p (aref code n)))  ; c_n ∈ T
            do (let ((next (+ n 1 (skip-distance vm n))))
                 (setf (gethash next successors) t)))
    ;; Intersect with {n | k_n = 1 ∧ c_n ∈ U}
    (let ((result (make-array len :element-type 'bit :initial-element 0)))
      (loop for n from 0 below len
            when (and (gethash n successors)
                      (= 1 (bitmask-bit bitmask n))       ; k_n = 1
                      (valid-opcode-p (aref code n)))      ; c_n ∈ U
              do (setf (aref result n) 1))
      result)))
