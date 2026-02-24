;;;; package.lisp — JamVM package definition
;;;;
;;;; GP Appendix A — Polkadot Virtual Machine
;;;; Pure Common Lisp implementation. No FFI, no polkavm dependency.

(defpackage #:jamvm
  (:use #:cl)
  (:documentation
   "JamVM — Pure Common Lisp PVM interpreter (Gray Paper Appendix A).

    Implements the full PVM instruction set, page-based memory with
    gas-tracked allocation, and the standard program initialization.

    Key entry points:
      MAKE-VM      — Create a VM from a deblob'd program
      VM-RUN       — Ψ: run until halt/trap/oog/ecalli/fault
      VM-STEP      — Ψ₁: execute one instruction
      DEBLOB       — Parse program blob → (code, bitmask, jump-table)
      STANDARD-PROG-INIT — GP A.7: initialize memory layout from blob
      ARGUMENT-INVOKE    — GP A.8: set up registers + memory for invocation")
  (:export
   ;; ── A.1 Exit reasons ──────────────────────────
   #:+exit-halt+              ; ■  normal halt
   #:+exit-panic+             ; ϡ  panic
   #:+exit-oog+               ; ∞  out of gas
   #:+exit-page-fault+        ; ∃  page fault (+ address)
   #:+exit-host-call+         ; ℏ  host call  (+ id)

   ;; ── A.1 Types ─────────────────────────────────
   #:pvm                      ; VM struct
   #:make-pvm                 ; constructor (internal, use make-vm)
   #:pvm-pc                   ; ι  instruction counter
   #:pvm-gas                  ; ϱ  gas remaining
   #:pvm-regs                 ; φ  registers [13]
   #:pvm-memory               ; μ  RAM
   #:pvm-status               ; ε  exit reason
   #:pvm-exit-arg             ; associated value (addr for ∃, id for ℏ)
   #:pvm-code                 ; c  instruction data
   #:pvm-bitmask              ; k  basic-block bitmask
   #:pvm-jump-table           ; j  dynamic jump table
   #:pvm-skip-table           ; precomputed skip-distance LUT

   #:pvm-args-buf             ; pre-allocated instruction args buffer
   ;; ── Instruction args struct (zero-allocation) ──
   #:pvm-args #:make-pvm-args
   #:arg-ra #:arg-rb #:arg-rc #:arg-rd
   #:arg-imm #:arg-imm1 #:arg-imm2 #:arg-offset

   ;; ── Register accessors (GP names) ────────────
   #:reg                      ; (reg vm i) → value
   #:set-reg                  ; (set-reg vm i val)
   ;; Named registers
   #:+ra+ #:+sp+
   #:+t0+ #:+t1+ #:+t2+
   #:+s0+ #:+s1+
   #:+a0+ #:+a1+ #:+a2+ #:+a3+ #:+a4+ #:+a5+

   ;; ── A.2 Decoder ───────────────────────────────
   #:decode-instruction       ; decode one instruction at PC
   #:skip-distance            ; ℓ = skip(ι)

   ;; ── A.4 Execution ─────────────────────────────
   #:vm-step                  ; Ψ₁  single-step state transition
   #:vm-run                   ; Ψ   run to completion/interrupt

   ;; ── A.6 Host calls ────────────────────────────
   #:*host-call-handler*      ; callback: (funcall handler vm id) → continue?
   #:*vm-last-step-pc*        ; PC before last vm-step (for panic diagnosis)
   #:*vm-opcode-counts*       ; 256-vector of opcode execution counts
   #:*vm-trap-log*            ; list of (PC raw-opcode bitmask-bit) for traps
   #:*vm-page-fault-count*    ; counter for page faults caught during vm-run
   #:*vm-trace-stream*        ; stream for instruction trace logging
   #:*vm-step-counter*        ; step counter for tracing
   #:vm-run-host              ; run with host-call callback f

   ;; ── A.7 Program init ──────────────────────────
   #:deblob                   ; p → (c, k, j) or NIL
   #:standard-prog-init       ; set up memory layout from blob
   #:make-vm                  ; high-level: blob → ready VM

   ;; ── A.8 Argument invocation ───────────────────
   #:argument-invoke          ; set up regs + memory for entry
   #:entry-point-pc           ; map name → PC value
   #:+pc-is-authorized+       ; PC = 0
   #:+pc-refine+              ; PC = 0
   #:+pc-accumulate+          ; PC = 5
   #:+pc-on-transfer+         ; PC = 10

   ;; ── Memory ────────────────────────────────────
   #:make-memory              ; constructor
   #:mem-read                 ; read bytes from guest memory
   #:mem-write                ; write bytes to guest memory
   #:mem-read-u8 #:mem-read-u16 #:mem-read-u32 #:mem-read-u64
   #:mem-write-u8 #:mem-write-u16 #:mem-write-u32 #:mem-write-u64
   #:mem-sbrk                 ; sbrk with page-level gas accounting
   #:page-access              ; read page access mode
   #:ensure-page              ; create page if needed
   #:mem-pages                ; pages hash-table accessor
   #:mem-access               ; access hash-table accessor

   ;; ── Arithmetic helpers ────────────────────────
   #:u32                      ; mask to 32-bit unsigned
   #:u64                      ; mask to 64-bit unsigned
   #:u64->s64                 ; interpret as signed 64-bit
   #:u64->s32                 ; interpret as signed 32-bit

   ;; ── Constants ─────────────────────────────────
   #:+page-size+              ; Z_P = 4096
   #:+num-regs+               ; 13 registers
   #:+max-address+            ; 2^32
   #:+gas-per-page+
   #:+z-a+                    ; Z_A = 2 (jump table entry size)
   #:+halt-sentinel+          ; 2³² − 2¹⁶ (static, but see do-djump)
   #:+u32-max+
   #:+u64-max+))          ; 2^32
