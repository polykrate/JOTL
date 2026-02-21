;;;; instructions.lisp — GP A.5 Instruction Infrastructure
;;;;
;;;; Dispatch table, macros, and shared helpers for all PVM instructions.
;;;; Actual instruction definitions are split by category:
;;;;   inst-control.lisp  — control flow (trap, jump, branches)
;;;;   inst-memory.lisp   — loads & stores (all memory access)
;;;;   inst-reg.lisp      — register ops (move, sbrk, bitops, extend)
;;;;   inst-alu.lisp      — arithmetic & logic (future)

(in-package #:jamvm)

;;; ═══════════════════════════════════════════════════════════════════
;;; Instruction dispatch table
;;;
;;; Maps instruction keyword → handler function.
;;; Handler signature: (handler vm args) → control-flow indicator
;;;
;;; Return values:
;;;   :continue     → PC ← PC + 1 + skip (A.9 default transition)
;;;   (:branch . t) → PC ← t
;;;   :halt         → set status = ■, stop
;;;   :panic        → set status = ϡ, stop
;;;   (:ecalli . n) → set status = ℏ, exit-arg = n, stop
;;;   (:fault . a)  → memory fault, triggers A.8 rollback
;;; ═══════════════════════════════════════════════════════════════════

(defvar *instruction-handlers*
  (make-hash-table :test 'eq)
  "Instruction keyword → handler function.")

(defmacro definstruction (name lambda-list &body body)
  "Define a PVM instruction handler.
   NAME: keyword matching the opcode-info name.
   LAMBDA-LIST: (vm args) — vm is the PVM struct, args is the decoded plist.
   BODY: returns control flow indicator."
  `(setf (gethash ,name *instruction-handlers*)
         (lambda ,lambda-list
           (declare (ignorable ,@lambda-list))
           ,@body)))

(defun dispatch-instruction (name vm args)
  "Execute instruction NAME with decoded ARGS on VM.
   Returns control flow indicator."
  (let ((handler (gethash name *instruction-handlers*)))
    (if handler
        (funcall handler vm args)
        :trap)))  ; unknown instruction → trap

;;; ═══════════════════════════════════════════════════════════════════
;;; Shared helpers
;;; ═══════════════════════════════════════════════════════════════════

;; ── Basic block membership (GP A.3) ──

(declaim (inline basic-block-p))
(defun basic-block-p (vm target)
  "Is TARGET ∈ ω̄ (a valid basic-block entry point)?
   Uses the precomputed bit-vector in pvm-basic-blocks."
  (let ((bb (pvm-basic-blocks vm)))
    (and (< target (length bb))
         (= 1 (aref bb target)))))

;; ── GP A.17: branch(b, C) — static branch ──

(defun do-branch (vm target condition)
  "GP A.17: branch(b, C).
   Returns :continue | (:branch . b) | :panic."
  (cond
    ((not condition) :continue)             ; ¬C → fallthrough
    ((not (basic-block-p vm target)) :panic) ; b ∉ ω̄ → panic
    (t (cons :branch target))))              ; → branch taken

;; ── GP A.18: djump(a) — dynamic jump via jump table j ──

(defvar *djump-debug* nil "When T, log djump panics to *error-output*.")

(defconstant +djump-halt-sentinel+ (- (expt 2 32) (expt 2 16))
  "GP A.18: djump halt sentinel = 2³² − 2¹⁶ = 0xFFFF0000.")

(defun do-djump (vm a)
  "GP A.18: djump(a). Dynamic jump using jump table j.
   Halt sentinel = 2³² − 2¹⁶ (fixed constant per GP A.18).
   Returns :halt | :panic | (:branch . target)."
  (let* ((jt (pvm-jump-table vm))
         (jt-len (length jt)))
    (cond
      ;; ■ Halt: a = 2³² − 2¹⁶
      ((= a +djump-halt-sentinel+)
       (when *djump-debug*
         (format *error-output* "~&[DJUMP] HALT: a=~D (0x~X) pc=~D~%"
                 a a *vm-last-step-pc*))
       :halt)
      ;; ϡ Panic: a = 0
      ((zerop a)
       (when *djump-debug*
         (format *error-output* "~&[DJUMP] PANIC: a=0 pc=~D~%" *vm-last-step-pc*))
       :panic)
      ;; ϡ Panic: a > Z_A · |j|
      ((> a (* jt-len +z-a+))
       (when *djump-debug*
         (format *error-output* "~&[DJUMP] PANIC: a=~D > jt-max=~D pc=~D~%"
                 a (* jt-len +z-a+) *vm-last-step-pc*))
       :panic)
      ;; ϡ Panic: a mod Z_A ≠ 0
      ((/= 0 (mod a +z-a+))
       (when *djump-debug*
         (format *error-output* "~&[DJUMP] PANIC: a=~D not aligned (mod ~D = ~D) pc=~D~%"
                 a +z-a+ (mod a +z-a+) *vm-last-step-pc*))
       :panic)
      ;; branch(j[a/Z_A − 1], ⊤)
      (t (let* ((index (1- (/ a +z-a+)))
                (target (aref jt index)))
           (if (basic-block-p vm target)
               (cons :branch target)
               (progn
                 (when *djump-debug*
                   (format *error-output* "~&[DJUMP] PANIC: target=~D (jt[~D]) not basic-block, a=~D pc=~D~%"
                           target index a *vm-last-step-pc*))
                 :panic)))))))

;; ── Memory access helpers ──

(defun do-store (vm addr data)
  "Write DATA (byte vector) to guest memory at ADDR.
   Returns :continue on success, (:fault . fault-addr) on page fault."
  (multiple-value-bind (ok fault-addr) (mem-write (pvm-memory vm) (u32 addr) data)
    (if ok :continue (cons :fault fault-addr))))

(defun do-load (vm addr n-bytes)
  "Read N-BYTES from guest memory at ADDR (mod 2³²).
   Returns (values raw-u64 NIL) or (values 0 (:fault . fault-addr))."
  (multiple-value-bind (data fault-addr) (mem-read (pvm-memory vm) (u32 addr) n-bytes)
    (if data  ; data is NIL on fault, byte-vector on success
        (let ((val 0))
          (dotimes (i n-bytes)
            (setf val (logior val (ash (aref data i) (* 8 i)))))
          (values val nil))
        (values 0 (cons :fault fault-addr)))))

(defmacro load-reg-or-fault (vm args n-bytes &optional (transform 'identity))
  "Load N-BYTES from memory at :imm, apply TRANSFORM, store in :ra.
   Returns :continue or (:fault . addr)."
  (let ((val (gensym "VAL")) (err (gensym "ERR")))
    `(multiple-value-bind (,val ,err) (do-load ,vm (getf ,args :imm) ,n-bytes)
       (if ,err ,err
           (progn (set-reg ,vm (getf ,args :ra) (,transform ,val))
                  :continue)))))

(declaim (inline ind-addr))
(defun ind-addr (vm args)
  "Compute indirect address: (φ_B + ν_X) mod 2³²."
  (u32 (+ (reg vm (getf args :rb)) (getf args :imm))))

;; ── LE encoding helper ──

(defun encode-le (val n-bytes)
  "Encode VAL as N-BYTES little-endian byte vector."
  (let ((buf (make-array n-bytes :element-type '(unsigned-byte 8))))
    (dotimes (i n-bytes buf)
      (setf (aref buf i) (logand (ash val (* -8 i)) #xFF)))))
