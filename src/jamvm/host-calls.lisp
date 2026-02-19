;;;; host-calls.lisp — GP A.6 Host Call Definition
;;;;
;;;; (A.35) Ψ_H: Extended PVM execution that handles host calls
;;;; internally via a state-mutator function f, instead of yielding.
;;;;
;;;; (A.36) Ω(X): Host-call context type constructor.
;;;;
;;;; ecalli instructions trigger host call exits in Ψ.
;;;; Ψ_H wraps Ψ and intercepts those exits, dispatching to f.

(in-package #:jamvm)

;;; ═══════════════════════════════════════════════════════════════════
;;; ecalli instruction — GP A.6
;;;
;;; When the VM encounters ecalli(n), it:
;;;   1. Sets ε = ℏ (host call)
;;;   2. Sets exit-arg = n (host call identifier)
;;;   3. Yields control to the caller (Ψ or Ψ_H)
;;;
;;; ecalli is registered here; Ψ_H below handles it in-line.
;;; ═══════════════════════════════════════════════════════════════════

;; 78 = ecalli — host call  (GP A.5.6: one reg + imm format)
;; The immediate value is the host call index.
;; Gas cost: 0 (the host call itself charges gas).
(register-opcode 78 :ecalli :reg-imm 0)
(definstruction :ecalli (vm args)
  (let ((id (getf args :imm)))
    (cons :ecalli (u32 id))))

;;; ═══════════════════════════════════════════════════════════════════
;;; Host call result helpers
;;; ═══════════════════════════════════════════════════════════════════

(defun vm-set-host-result (vm a0 &optional (a1 nil a1-p))
  "Set return registers after a host call.
   A0 goes in register 7, A1 (optional) in register 8."
  (set-reg vm +a0+ a0)
  (when a1-p
    (set-reg vm +a1+ a1)))

(defun vm-advance-past-ecalli (vm)
  "Advance PC past the current ecalli instruction.
   Call this after handling a host call to resume execution."
  (let* ((pc (pvm-pc vm))
         (skip (skip-distance vm pc)))
    (setf (pvm-pc vm) (u32 (+ pc 1 skip))
          (pvm-status vm) nil)))

;;; ═══════════════════════════════════════════════════════════════════
;;; (A.33) smod — signed modulo (used by rem_s_{32,64})
;;;
;;;   smod(a, b) = { a                         if b = 0
;;;                { sgn(a) · (|a| mod |b|)    otherwise
;;;
;;; CL's REM matches this definition exactly.
;;; ═══════════════════════════════════════════════════════════════════

;;; (No code needed — CL:REM is smod. Documented here for GP traceability.)

;;; ═══════════════════════════════════════════════════════════════════
;;; (A.34) rtz — round toward zero
;;;
;;;   rtz(x) = ⌈x⌉   if x < 0
;;;          = ⌊x⌋   otherwise
;;;
;;; CL's TRUNCATE matches this definition exactly.
;;; ═══════════════════════════════════════════════════════════════════

;;; (No code needed — CL:TRUNCATE is rtz. Documented here for GP traceability.)

;;; ═══════════════════════════════════════════════════════════════════
;;; (A.35) Ψ_H — Host-Call VM Execution
;;;
;;; An extended Ψ that handles ecalli instructions in-line,
;;; dispatching them to a state-mutator function f.
;;;
;;; Input:
;;;   (c, ι, ϱ, φ, μ, f, x)
;;;     c   = program (code + bitmask + jump-table) — inside vm struct
;;;     ι   = instruction counter (pc)
;;;     ϱ   = gas
;;;     φ   = registers
;;;     μ   = memory
;;;     f   = host-call handler:
;;;             (funcall f h vm x) → (values status x')
;;;             where status ∈ {:continue, :halt, :panic, :oog}
;;;     x   = opaque host state threaded through calls
;;;
;;; Semantics:
;;;   1. Run Ψ(vm) until exit.
;;;   2. If exit ∈ {■, ♯, ∞, ∃} → return (exit, x).
;;;   3. If exit = ℏ (host call id = h):
;;;      a. Call f(h, vm, x) → (ε'', x'')
;;;         f may mutate vm registers/memory/gas in-place.
;;;      b. If ε'' = :continue (►):
;;;           ι'' = ι' + 1 + skip(ι')   — advance past ecalli
;;;           Loop back to step 1 (tail-recursive).
;;;      c. If ε'' ∈ {:halt, :panic, :oog}:
;;;           Return (ε'', x'').
;;; ═══════════════════════════════════════════════════════════════════

(defun vm-run-host (vm f x)
  "Ψ_H (A.35): Run VM with in-line host-call handling.

   F is called as (funcall f host-call-id vm x) and must return:
     (values status x')
   where STATUS is:
     :continue — host call succeeded, resume execution
     :halt     — host call caused halt (■)
     :panic    — host call caused panic (♯)
     :oog      — host call exhausted gas (∞)

   F may mutate VM's registers, memory, and gas in-place.
   On :continue, PC is advanced past the ecalli automatically.

   Returns (values exit-status exit-arg x')
   where exit-status is :halt, :panic, :oog, or :page-fault."
  (loop
    ;; Step 1: Run Ψ(vm) — execute until next exit
    (multiple-value-bind (status exit-arg) (vm-run vm)
      (case status
        ;; Terminal: pass through with current x
        (:halt       (return (values :halt       exit-arg x)))
        (:panic      (return (values :panic      exit-arg x)))
        (:oog        (return (values :oog        exit-arg x)))
        (:page-fault (return (values :page-fault exit-arg x)))

        ;; Host call: dispatch to f
        (:host-call
         (let ((h exit-arg))
           (multiple-value-bind (f-status x-new) (funcall f h vm x)
             (case f-status
               ;; ► f succeeded — advance PC past ecalli, continue loop
               (:continue
                (vm-advance-past-ecalli vm)
                (setf x x-new))

               ;; f says halt
               (:halt
                (setf (pvm-status vm) +exit-halt+)
                (return (values :halt 0 x-new)))

               ;; f says panic
               (:panic
                (setf (pvm-status vm) +exit-panic+)
                (return (values :panic 0 x-new)))

               ;; f says out of gas
               (:oog
                (setf (pvm-status vm) +exit-oog+)
                (return (values :oog 0 x-new)))

               ;; Unknown f result → panic
               (t
                (setf (pvm-status vm) +exit-panic+)
                (return (values :panic 0 x-new)))))))

        ;; Unexpected vm-run result → panic
        (t (return (values :panic 0 x)))))))

;;; ═══════════════════════════════════════════════════════════════════
;;; (A.36) Ω(X) — Host-call context type
;;;
;;;   Ω(X) ≡ (ℕ, ℕ_G, [ℕ_R]₁₃, M, X)
;;;         → ({►, ■, ♯, ∞}, ℕ_G, [ℕ_R]₁₃, M, X)
;;;
;;; This is the type signature of host-call handler functions.
;;; In our implementation, f : (h, vm, x) → (values status x')
;;; where vm encapsulates (ϱ, φ, μ) mutably.
;;;
;;; Concrete host-call implementations (gas, read, write, info, etc.)
;;; will be defined in the JAM service layer, conforming to this
;;; interface.
;;; ═══════════════════════════════════════════════════════════════════
