;;;; invoke.lisp — GP A.8 Argument Invocation Definition
;;;;
;;;; Sets up registers and memory for a PVM invocation.
;;;;
;;;; GP A.8: argument-invoke(vm, gas, pc, args)
;;;;   1. Set gas: ϱ = gas
;;;;   2. Set PC: ι = pc
;;;;   3. Map args at ARGS_SEGMENT (0xFEFF0000) as read-only
;;;;   4. Set registers: A0 = ARGS_SEGMENT, A1 = args_len
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
;;; ARGS_SEGMENT — GP A.8
;;;
;;; Arguments are placed at a fixed memory address 0xFEFF0000,
;;; mapped as read-only. This matches the SPI blob convention
;;; and ensures the heap pointer is not affected by argument size.
;;; ═══════════════════════════════════════════════════════════════════

(defconstant +args-segment+ #xFEFF0000
  "Fixed memory address for argument data (GP A.8, SPI convention).")

;;; ═══════════════════════════════════════════════════════════════════
;;; (A.8) argument-invoke
;;;
;;; 1. ϱ ← gas
;;; 2. ι ← pc
;;; 3. Map args at ARGS_SEGMENT (0xFEFF0000) as read-only
;;; 4. Write args data to mapped region
;;; 5. φ₇ (A0) ← ARGS_SEGMENT, φ₈ (A1) ← args_len
;;; 6. Clear φ₀…₆, φ₉…₁₂ (not SP which was set by init)
;;; ═══════════════════════════════════════════════════════════════════

(defun argument-invoke (vm gas pc args-data)
  "GP A.8: Set up a PVM for invocation.
   VM:        initialized PVM (from make-vm / standard-prog-init)
   GAS:       initial gas budget (ϱ)
   PC:        initial program counter (ι)
   ARGS-DATA: byte vector of encoded arguments, or NIL.

   Args are mapped at ARGS_SEGMENT (0xFEFF0000) as read-only memory,
   NOT on the heap. This matches the SPI convention and ensures the
   guest's heap pointer is not affected by argument size.

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

  ;; 3. Map args at ARGS_SEGMENT as read-only
  (let ((args-addr +args-segment+)
        (args-len 0)
        (total-pages 0))
    (when (and args-data (plusp (length args-data)))
      (setf args-len (length args-data))
      ;; Map the ARGS_SEGMENT region as read-only and write args data
      (mem-map-range (pvm-memory vm) +args-segment+ args-len :read-only
                     (coerce args-data '(simple-array (unsigned-byte 8) (*))))
      ;; Count mapped pages
      (setf total-pages (1+ (- (page-index (+ +args-segment+ args-len -1))
                                (page-index +args-segment+)))))

    ;; 4. Set argument registers
    (set-reg vm +a0+ args-addr)
    (set-reg vm +a1+ args-len)

    ;; 5. Set RA to halt sentinel: 2³² − 2¹⁶ (GP A.18)
    ;; When the outermost function returns via jump_ind(RA),
    ;; djump(halt_sentinel) triggers a clean halt (■).
    (set-reg vm +ra+ +djump-halt-sentinel+)

    (values t total-pages)))
