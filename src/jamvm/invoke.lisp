;;;; invoke.lisp — GP A.8 Argument Invocation Definition
;;;;
;;;; Sets up registers and memory for a PVM invocation.
;;;;
;;;; GP A.8: argument-invoke(vm, gas, pc, args)
;;;;   1. Set gas: ϱ = gas
;;;;   2. Set PC: ι = pc
;;;;   3. Allocate args in heap memory
;;;;   4. Set registers: A0 = args_addr, A1 = args_len
;;;;   5. Clear other registers (except SP)
;;;;
;;;; Entry points (GP B.1/B.5/B.9):
;;;;   is_authorized_ext → PC(0)
;;;;   refine_ext        → PC(0)
;;;;   accumulate_ext    → PC(5)
;;;;   on_transfer_ext   → PC(10)

(in-package #:jamvm)

;;; ═══════════════════════════════════════════════════════════════════
;;; Entry point PC values (GP B)
;;; ═══════════════════════════════════════════════════════════════════

(defconstant +pc-is-authorized+ 0)
(defconstant +pc-refine+        0)
(defconstant +pc-accumulate+    5)
(defconstant +pc-on-transfer+   10)

(defun entry-point-pc (name)
  "Map entry point name (string) to initial PC value."
  (cond
    ((string= name "is_authorized_ext") +pc-is-authorized+)
    ((string= name "refine_ext")        +pc-refine+)
    ((string= name "accumulate_ext")    +pc-accumulate+)
    ((string= name "on_transfer_ext")   +pc-on-transfer+)
    (t 0)))  ; default

;;; ═══════════════════════════════════════════════════════════════════
;;; (A.8) argument-invoke
;;;
;;; 1. ϱ ← gas
;;; 2. ι ← pc
;;; 3. Allocate args on heap: sbrk(align8(len))
;;; 4. Write args data to allocated address
;;; 5. φ₇ (A0) ← args_addr, φ₈ (A1) ← args_len
;;; 6. Clear φ₀…₆, φ₉…₁₂ (not SP which was set by init)
;;; ═══════════════════════════════════════════════════════════════════

(defun argument-invoke (vm gas pc args-data)
  "GP A.8: Set up a PVM for invocation.
   VM:        initialized PVM (from make-vm / standard-prog-init)
   GAS:       initial gas budget (ϱ)
   PC:        initial program counter (ι)
   ARGS-DATA: byte vector of encoded arguments, or NIL.

   Returns (values T pages-allocated) on success,
           (values NIL reason) on failure."
  ;; 1. Set gas and PC
  (setf (pvm-gas vm) gas
        (pvm-pc vm) pc
        (pvm-status vm) nil)

  ;; 2. Clear all registers except SP
  (let ((saved-sp (reg vm +sp+)))
    (dotimes (i +num-regs+)
      (set-reg vm i 0))
    (set-reg vm +sp+ saved-sp))

  ;; 3. Allocate and write args
  (let ((args-addr 0)
        (args-len 0)
        (total-pages 0))
    (when (and args-data (plusp (length args-data)))
      (setf args-len (length args-data))
      (let* ((aligned (align-up args-len 8))
             (mem (pvm-memory vm)))
        ;; sbrk: advance heap pointer
        ;; Note: argument-invoke is a HOST-side setup operation.
        ;; The Rust PVM (polkaVM) calls instance.sbrk() which is a host-side API,
        ;; NOT a guest instruction, so no gas is charged for page allocations here.
        ;; Gas is only charged when the guest executes sbrk (opcode 101).
        (multiple-value-bind (old-top new-pages) (mem-sbrk mem aligned)
          (setf args-addr old-top
                total-pages (length new-pages))
          ;; Write args data into allocated memory
          (multiple-value-bind (ok _fault-addr)
              (mem-write mem old-top
                         (coerce args-data '(simple-array (unsigned-byte 8) (*))))
            (declare (ignore _fault-addr))
            (unless ok
              (return-from argument-invoke (values nil :fault)))))))

    ;; 4. Set argument registers
    (set-reg vm +a0+ args-addr)
    (set-reg vm +a1+ args-len)

    ;; 5. Set RA to halt sentinel: Z_A · (|j| + 1)
    ;; When the outermost function returns via jump_ind(RA),
    ;; djump(halt_sentinel) triggers a clean halt (■).
    ;; This matches polkaVM's prepare_call_untyped behavior.
    (let ((halt-sentinel (* +z-a+ (1+ (length (pvm-jump-table vm))))))
      (set-reg vm +ra+ halt-sentinel))

    (values t total-pages)))
