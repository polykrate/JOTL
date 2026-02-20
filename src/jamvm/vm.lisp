;;;; vm.lisp — GP A.4 Single-Step State Transition + Ψ Recursive Execution
;;;;
;;;; (A.1) Ψ: the general PVM function.
;;;; Recursively applies Ψ₁ until a halting condition.
;;;;
;;;;   Ψ(p, ι, ϱ, φ, μ) →
;;;;     Ψ(p, ι', ϱ', φ', μ')    if ε = ►  (continue)
;;;;     (∞, ι, ϱ', φ, μ)         if ϱ' < 0  (out of gas)
;;;;     (ε, 0, ϱ', φ', μ')       if ε ∈ {ϡ, ■}  (panic/halt → PC=0)
;;;;     (ε, ι, ϱ', φ', μ)        otherwise  (host call/page fault)
;;;;
;;;; (A.4) Ψ₁: single-step.
;;;;   Decodes instruction at ι, charges gas, executes mutation.

(in-package #:jamvm)

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
;;;   if min(x) mod 2³² < 2¹⁶    → (♯, ι, ϱ, φ, μ)       — PANIC
;;;   otherwise                   → (∃×page, ι, ϱ, φ, μ)  — PAGE FAULT
;;;   where page = Z_P⌊min(x) mod 2³² / Z_P⌋
;;;
;;; The entire instruction is atomic: on fault, state is UNCHANGED.
;;; We achieve this by saving registers before execution and restoring
;;; them on fault. Memory writes are already atomic (mem-write checks
;;; all pages before writing any byte).
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
    ;; Capture PC for panic diagnosis
    (setf *vm-last-step-pc* pc)

    ;; ── 1. Decode instruction at ι ──
    (multiple-value-bind (info skip args) (decode-instruction vm pc)
      (unless info
        ;; ── Trap diagnostic logging ──
        (let ((raw-byte (if (< pc (length (pvm-code vm)))
                            (aref (pvm-code vm) pc) 0))
              (bm-bit (bitmask-bit (pvm-bitmask vm) pc)))
          (when *vm-trap-log*
            (push (list :pc pc :raw-opcode raw-byte :bitmask-bit bm-bit
                        :effective (pvm-opcode vm pc))
                  *vm-trap-log*)))
        ;; Unknown opcode / out of bounds → ♯ panic
        (setf (pvm-status vm) +exit-panic+)
        (return-from vm-step :panic))

      ;; ── Opcode counting / trace logging ──
      (let ((raw-byte (if (< pc (length (pvm-code vm)))
                          (aref (pvm-code vm) pc) 0)))
        (when *vm-opcode-counts*
          (incf (aref *vm-opcode-counts* raw-byte)))
        (when *vm-trace-stream*
          (incf *vm-step-counter*)
          (format *vm-trace-stream*
                  "~D ~D ~D ~D~{ ~D~}~%"
                  *vm-step-counter* pc raw-byte (pvm-gas vm)
                  (coerce (pvm-regs vm) 'list))))

      ;; ── 2. Charge gas: ϱ' = ϱ − ϱ_Δ ──
      (let ((cost (opi-gas-cost info)))
        (decf (pvm-gas vm) cost)
        ;; If ϱ' < 0 → ∞ (out of gas).  Gas is always deducted.
        (when (minusp (pvm-gas vm))
          (setf (pvm-status vm) +exit-oog+)
          (return-from vm-step :oog)))

      ;; ── 3. Save registers for fault rollback (A.8) ──
      ;; On memory fault, we must return the ORIGINAL (ι,ϱ,φ,μ).
      ;; Gas was already deducted above, so we save ϱ' (post-deduction)
      ;; and restore to the pre-deduction ϱ on fault.
      (let ((saved-regs (copy-seq (pvm-regs vm)))
            (saved-gas  (+ (pvm-gas vm) (opi-gas-cost info))))  ; ϱ before deduction

        ;; ── 4. Execute instruction ──
        (let ((result (dispatch-instruction (opi-name info) vm args)))
          (cond
            ;; ► Continue → advance PC: ι' = ι + 1 + skip(ι)
            ((eq result :continue)
             (setf (pvm-pc vm) (u32 (+ pc 1 skip)))
             nil)

            ;; ► Branch → ι' = target
            ((and (consp result) (eq (car result) :branch))
             (setf (pvm-pc vm) (u32 (cdr result)))
             nil)

            ;; ■ Halt
            ((eq result :halt)
             (setf (pvm-status vm) +exit-halt+
                   (pvm-pc vm) 0)
             :halt)

            ;; ♯ Trap/Panic
            ((or (eq result :trap) (eq result :panic))
             (setf (pvm-status vm) +exit-panic+
                   (pvm-pc vm) 0)
             :panic)

            ;; ℏ Host call → ε = ℏ, exit-arg = id, PC unchanged
            ((and (consp result) (eq (car result) :ecalli))
             (setf (pvm-status vm) +exit-host-call+
                   (pvm-exit-arg vm) (cdr result)
                   (pvm-pc vm) pc)          ; PC stays at ecalli
             :host-call)

            ;; ∃ Page fault (A.8) — ROLLBACK STATE
            ((and (consp result) (eq (car result) :fault))
             (let* ((fault-addr (logand (cdr result) +u32-max+)))

               ;; Rollback: restore (ι, ϱ, φ) to pre-instruction values
               (replace (pvm-regs vm) saved-regs)
               (setf (pvm-gas vm) saved-gas
                     (pvm-pc  vm) pc)

               (cond
                 ;; (A.8) min(x) mod 2³² < 2¹⁶ → ♯ panic
                 ((< fault-addr (expt 2 16))
                  (setf (pvm-status vm) +exit-panic+)
                  :panic)

                 ;; (A.8) otherwise → ∃ with page-aligned address
                 (t
                  (let ((page-addr (* (floor fault-addr +page-size+) +page-size+)))
                    (setf (pvm-status vm) +exit-page-fault+
                          (pvm-exit-arg vm) page-addr)
                    :page-fault)))))

            ;; ∃ Partial fault (memset) — NO ROLLBACK, preserve partial progress
            ((and (consp result) (eq (car result) :partial-fault))
             (let* ((fault-addr (logand (cdr result) +u32-max+)))
               ;; Keep current registers/gas (partial progress)
               ;; Only restore PC to current instruction
               (setf (pvm-pc vm) pc)
               (cond
                 ((< fault-addr (expt 2 16))
                  (setf (pvm-status vm) +exit-panic+)
                  :panic)
                 (t
                  (let ((page-addr (* (floor fault-addr +page-size+) +page-size+)))
                    (setf (pvm-status vm) +exit-page-fault+
                          (pvm-exit-arg vm) page-addr)
                    :page-fault)))))

            ;; ∞ Partial OOG (memset) — NO ROLLBACK, preserve partial progress
            ((eq result :partial-oog)
             (setf (pvm-pc vm) pc
                   (pvm-status vm) +exit-oog+)
             :oog)

            ;; Unknown → ♯ panic
            (t
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

(defun vm-run (vm)
  "Ψ: Run VM until halt/trap/oog/ecalli/fault.
   Returns (values status exit-arg).

   If *host-call-handler* is set, ecalli instructions invoke it.
   If the handler returns T, execution continues.
   If it returns NIL, the VM yields with :host-call."
  ;; Clear any previous exit state
  (setf (pvm-status vm) nil)

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
                            (skip (skip-distance vm pc)))
                       (setf (pvm-pc vm) (u32 (+ pc 1 skip))
                             (pvm-status vm) nil))
                     ;; Handler says stop
                     (return (values :host-call (pvm-exit-arg vm)))))
               ;; No handler — yield
               (return (values :host-call (pvm-exit-arg vm)))))

          ;; Terminal states
          (:halt       (return (values :halt 0)))
          (:panic      (return (values :panic 0)))
          (:oog        (return (values :oog 0)))
          (:page-fault (return (values :page-fault (pvm-exit-arg vm))))

          ;; Catch-all
          (t (return (values :panic 0))))))))
