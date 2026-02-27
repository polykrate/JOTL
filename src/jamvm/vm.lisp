;;;; vm.lisp — GP A.4 Single-Step State Transition + Ψ Recursive Execution
;;;;
;;;; (A.1) Ψ: the general PVM function.
;;;; Recursively applies Ψ₁ until a halting condition.
;;;;
;;;;   Ψ(p, ι, ϱ, φ, μ) →
;;;;     Ψ(p, ι', ϱ', φ', μ')    if ε = ►  (continue)
;;;;     (∞, ι, ϱ', φ, μ)         if ϱ' < 0  (out of gas)
;;;;     (ε, 0, ϱ', φ', μ')       if ε ∈ {ϡ, ■}  (panic/halt → PC=0)
;;;;     (ε, ι, ϱ', φ, μ)         otherwise  (host call/page fault)
;;;;
;;;; (A.4) Ψ₁: single-step.
;;;;   Decodes instruction at ι, charges gas, executes mutation.

(in-package #:jamvm)

(declaim (optimize (speed 3) (safety 1) (debug 1)))

;;; ═══════════════════════════════════════════════════════════════════
;;; Gas per page allocation (for sbrk / segfault handling)
;;; ═══════════════════════════════════════════════════════════════════

(defconstant +gas-per-page+ 10
  "Gas cost per page allocation. GP §A: memory pages are charged.")

;;; ═══════════════════════════════════════════════════════════════════
;;; Ψ₁ — Single-step state transition (GP A.4 / A.6–A.9)
;;;
;;; (A.6) (c,k,j,ι,ϱ,φ,μ) ↦ (ε*,ι*,ϱ*,φ*,μ*)
;;;
;;; (A.9) Default posterior values (ε = ►, continue):
;;;   ι' = ι + 1 + skip(ι)    — advance PC
;;;   ϱ' = ϱ − ϱ_Δ            — charge gas
;;;   φ' = φ                   — regs unchanged
;;;   μ' = μ                   — RAM unchanged
;;;   "except as indicated" by each instruction.
;;;
;;; (A.7) Memory-access fault set:
;;;   x = { a | a ∈ r ∧ a mod 2³² ∉ V_μ ∨ a ∈ w ∧ a mod 2³² ∉ V*_μ }
;;;
;;; (A.8) Memory-access exceptional execution state:
;;;   if x = {}                   → (ε, ι', ϱ', φ', μ')   — normal
;;;   if min(x) mod 2³² < 2¹⁶    → (♯, ι, ϱ', φ, μ)      — PANIC
;;;   otherwise                   → (∃×page, ι, ϱ', φ, μ)  — PAGE FAULT
;;;   where page = Z_P⌊min(x) mod 2³² / Z_P⌋
;;;
;;; NOTE: A.1 case 4 uses ϱ' (primed) = gas AFTER charging (ϱ − ϱ_Δ).
;;; Gas is ALWAYS charged per attempt (A.1 blue text), even on fault.
;;; Only (ι, φ, μ) are restored to originals; gas stays deducted.
;;; We achieve this by saving/restoring registers and PC on fault,
;;; but leaving gas untouched. Memory writes are already atomic
;;; (mem-write checks all pages before writing any byte).
;;; ═══════════════════════════════════════════════════════════════════

(defun vm-step (vm)
  "Ψ₁: Execute one instruction. Returns exit reason keyword or NIL for ► (continue).

   Modifies VM in place. The caller (vm-run) checks the return value:
     NIL         → ► keep running
     :halt       → ■ normal halt
     :panic      → ♯ panic (bad instruction, addr < 2¹⁶)
     :oog        → ∞ out of gas
     :host-call  → ℏ ecalli (id in pvm-exit-arg)
     :page-fault → ∃ fault  (page-addr in pvm-exit-arg)"
  (let ((pc (pvm-pc vm)))
    (setf *vm-last-step-pc* pc)

    ;; ── 1. Decode instruction at ι ──
    (multiple-value-bind (info skip args) (decode-instruction vm pc)
      (unless info
        ;; ── Trap diagnostic logging ──
        (when *vm-trap-log*
          (let ((raw-byte (if (< pc (length (pvm-code vm)))
                              (aref (pvm-code vm) pc) 0))
                (bm-bit (bitmask-bit (pvm-bitmask vm) pc)))
            (push (list :pc pc :raw-opcode raw-byte :bitmask-bit bm-bit
                        :effective (pvm-opcode vm pc))
                  *vm-trap-log*)))
        ;; Unknown opcode / out of bounds → ♯ panic
        (setf (pvm-status vm) +exit-panic+)
        (return-from vm-step :panic))

      ;; ── Opcode counting / trace logging (skip when disabled) ──
      (when (or *vm-opcode-counts* *vm-trace-stream*)
        (let ((raw-byte (if (< pc (length (pvm-code vm)))
                            (aref (pvm-code vm) pc) 0)))
          (when *vm-opcode-counts*
            (incf (aref *vm-opcode-counts* raw-byte)))
          (when *vm-trace-stream*
            (incf *vm-step-counter*)
            (format *vm-trace-stream*
                    "~D ~D ~D ~D~{ ~D~}~%"
                    *vm-step-counter* pc raw-byte (pvm-gas vm)
                    (coerce (pvm-regs vm) 'list)))))

      ;; ── 2. Charge gas: ϱ' = ϱ − ϱ_Δ ──
      (let ((cost (opi-gas-cost info)))
        (decf (pvm-gas vm) cost)
        ;; If ϱ' < 0 → ∞ (out of gas).  Gas is always deducted.
        (when (minusp (pvm-gas vm))
          (setf (pvm-status vm) +exit-oog+)
          (return-from vm-step :oog)))

      ;; ── 3. Save registers for fault rollback (A.8) ──
      ;; Only needed for memory instructions that can fault.
      ;; Non-memory instructions (ALU, control) never produce :fault.
      ;; Gas (ϱ) stays deducted per GP: "some gas is always charged
      ;; whenever execution is attempted, even if no instruction is
      ;; effectively executed and machine state is unchanged."
      ;; Uses pre-allocated saved-regs buffer (zero allocation).
      (let ((saved-regs (when (opi-memory-p info)
                          (replace (pvm-saved-regs vm) (pvm-regs vm))
                          (pvm-saved-regs vm))))

        ;; ── 4. Execute instruction ──
        (let ((result (dispatch-instruction info vm args)))
          (case result
            ;; ► Continue → advance PC: ι' = ι + 1 + skip(ι)
            (:continue
             (setf (pvm-pc vm) (u32 (+ pc 1 skip)))
             nil)

            ;; ► Branch → ι' = target (stored in pvm-exit-arg by do-branch/do-djump)
            (:branch
             (setf (pvm-pc vm) (u32 (pvm-exit-arg vm)))
             nil)

            ;; ■ Halt
            (:halt
             (setf (pvm-status vm) +exit-halt+
                   (pvm-pc vm) 0)
             :halt)

            ;; ♯ Trap/Panic
            ((:trap :panic)
             (setf (pvm-status vm) +exit-panic+
                   (pvm-pc vm) 0)
             :panic)

            ;; ℏ Host call → ε = ℏ, exit-arg = id (stored by ecalli handler), PC unchanged
            (:host-call
             (setf (pvm-status vm) +exit-host-call+
                   (pvm-pc vm) pc)          ; PC stays at ecalli
             :host-call)

            ;; ∃ Page fault (A.8) — ROLLBACK (ι, φ), KEEP ϱ' charged
            ;; Fault address already in pvm-exit-arg (set by do-load/do-store)
            (:fault
             (let* ((fault-addr (logand (pvm-exit-arg vm) +u32-max+)))

               ;; Rollback: restore (ι, φ) to pre-instruction values
               ;; Gas (ϱ') stays deducted — GP: gas always charged on attempt
               (replace (pvm-regs vm) saved-regs)
               (setf (pvm-pc  vm) pc)

               (cond
                 ;; (A.8) min(x) mod 2³² < 2¹⁶ → ♯ panic
                 ((< fault-addr #x10000)
                  (setf (pvm-status vm) +exit-panic+)
                  :panic)

                 ;; (A.8) otherwise → ∃ with page-aligned address
                 (t
                  (let ((page-addr (logand fault-addr (lognot #xFFF))))
                    (setf (pvm-status vm) +exit-page-fault+
                          (pvm-exit-arg vm) page-addr)
                    :page-fault)))))

            ;; ∃ Partial fault (memset) — NO ROLLBACK, preserve partial progress
            ;; Fault address already in pvm-exit-arg
            (:partial-fault
             (let* ((fault-addr (logand (pvm-exit-arg vm) +u32-max+)))
               ;; Keep current registers/gas (partial progress)
               ;; Only restore PC to current instruction
               (setf (pvm-pc vm) pc)
               (cond
                 ((< fault-addr #x10000)
                  (setf (pvm-status vm) +exit-panic+)
                  :panic)
                 (t
                  (let ((page-addr (logand fault-addr (lognot #xFFF))))
                    (setf (pvm-status vm) +exit-page-fault+
                          (pvm-exit-arg vm) page-addr)
                    :page-fault)))))

            ;; ∞ OOG from instruction (e.g. sbrk page allocation)
            (:oog
             (setf (pvm-status vm) +exit-oog+)
             :oog)

            ;; ∞ Partial OOG (memset) — NO ROLLBACK, preserve partial progress
            (:partial-oog
             (setf (pvm-pc vm) pc
                   (pvm-status vm) +exit-oog+)
             :oog)

            ;; Unknown → ♯ panic
            (otherwise
             (setf (pvm-status vm) +exit-panic+
                   (pvm-pc vm) 0)
             :panic)))))))


;;; ═══════════════════════════════════════════════════════════════════
;;; Ψ — Full execution (GP A.1)
;;;
;;; Run Ψ₁ repeatedly until halting condition.
;;; Returns: (values status exit-arg)
;;;   status:   :halt | :panic | :oog | :host-call | :page-fault
;;;   exit-arg: associated value (host call id, fault address, etc.)
;;; ═══════════════════════════════════════════════════════════════════

(defvar *host-call-handler* nil
  "Callback for host calls: (funcall handler vm id) → T to continue, NIL to stop.
   If NIL, host calls cause the VM to yield back to the caller.")

(defvar *vm-last-step-pc* nil
  "PC of the last instruction before vm-step executed.
   Useful for diagnosing panics (vm-step sets pc=0 on panic).")

(defvar *max-steps* nil
  "Maximum number of steps before forced yield. NIL = unlimited.")

;;; ═══════════════════════════════════════════════════════════════════
;;; Diagnostic instrumentation
;;; ═══════════════════════════════════════════════════════════════════

(defvar *vm-opcode-counts* nil
  "When non-NIL, a 256-element vector counting executions of each opcode.
   Set to (make-array 256 :initial-element 0) to enable.")

(defvar *vm-trap-log* nil
  "When non-NIL, a list collecting (PC raw-opcode bitmask-bit) for each trap.")

(defvar *vm-trace-stream* nil
  "When non-NIL, a stream to log (step# PC opcode gas R0..R12) per instruction.")

(defvar *vm-step-counter* 0
  "Current step number, incremented by vm-step when tracing is active.")

(defvar *vm-page-fault-count* 0
  "Counter for page faults encountered during vm-run.
   Reset to 0 at the start of each vm-run call.")

(defun vm-run (vm)
  "Ψ: Run VM until halt/trap/oog/ecalli/fault.
   Returns (values status exit-arg).

   If *host-call-handler* is set, ecalli instructions invoke it.
   If the handler returns T, execution continues.
   If it returns NIL, the VM yields with :host-call.

   Page faults (addr ≥ 2¹⁶) are propagated to the caller as
   (values :page-fault page-addr). The caller decides how to handle:
   inner PVMs (HC12) map to +pvm-fault+, outer PVM treats as panic."
  ;; Clear any previous exit state
  (setf (pvm-status vm) nil)
  (setf *vm-page-fault-count* 0)

  (let ((steps 0))
    (loop
      ;; Step limit check
      (when (and *max-steps* (>= steps *max-steps*))
        (setf (pvm-status vm) +exit-step+)
        (return (values :step 0)))

      (let ((result (vm-step vm)))
        (incf steps)
        (case result
          ;; Continue stepping
          ((nil) nil)

          ;; Host call — try handler
          (:host-call
           (if *host-call-handler*
               (let ((continue-p (funcall *host-call-handler*
                                          vm (pvm-exit-arg vm))))
                 (if continue-p
                     ;; Handler dealt with it, advance PC past ecalli
                     (let* ((pc (pvm-pc vm))
                            (skip-tbl (pvm-skip-table vm))
                            (skip (if (< pc (length skip-tbl))
                                      (aref skip-tbl pc)
                                      (skip-distance vm pc))))
                       (setf (pvm-pc vm) (u32 (+ pc 1 skip))
                             (pvm-status vm) nil))
                     ;; Handler says stop
                     (return (values :host-call (pvm-exit-arg vm)))))
               ;; No handler — yield
               (return (values :host-call (pvm-exit-arg vm)))))

          ;; ── Page fault (A.8): propagate to caller ──
          ;; Per GP A.1 case 4: Ψ returns (ε, ι, ϱ', φ, μ) for page faults.
          ;; The CALLER decides what to do:
          ;;   - Inner PVM (HC12): maps to +pvm-fault+ with fault address
          ;;   - Outer PVM: treated as panic (all valid memory pre-mapped)
          ;; Previously this converted to :panic, which was wrong for inner
          ;; PVMs: HC12 returned +pvm-panic+ (1) instead of +pvm-fault+ (2),
          ;; causing guest code to take wrong branches.
          (:page-fault
           (incf *vm-page-fault-count*)
           (return (values :page-fault (pvm-exit-arg vm))))

          ;; Terminal states
          (:halt       (return (values :halt 0)))
          (:panic      (return (values :panic 0)))
          (:oog        (return (values :oog 0)))

          ;; Catch-all
          (t (return (values :panic 0))))))))
