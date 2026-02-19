;;;; jamvm.asd — JamVM: Pure Common Lisp PVM (GP Appendix A & B)
;;;;
;;;; A complete implementation of the Polkadot Virtual Machine
;;;; directly from the Gray Paper specification.
;;;;
;;;; Module 1 — jamvm (GP Appendix A: PVM core):
;;;;   types.lisp        — A.1  Basic types: registers, exit reasons, program
;;;;   memory.lisp       — A.1  Page-based RAM (μ) with gas-tracked allocation
;;;;   decoder.lisp      — A.2  Instruction decoding from bytecode (ζ → ops)
;;;;   instructions.lisp — A.5  Instruction infra (macros, dispatch, helpers)
;;;;   inst-control.lisp —      Control flow (trap, jump, branches)
;;;;   inst-memory.lisp  —      Memory access (loads & stores)
;;;;   inst-reg.lisp     —      Register ops (move, sbrk, bitops, extend)
;;;;   inst-alu.lisp     —      Arithmetic & logic (add, sub, mul, ...)
;;;;   vm.lisp           — A.4  Ψ₁ single-step + Ψ recursive execution
;;;;   host-calls.lisp   — A.6  Host call interface (ecalli → Ω)
;;;;   init.lisp         — A.7  Standard program initialization (deblob)
;;;;   invoke.lisp       — A.8  Argument invocation definition
;;;;
;;;; Module 2 — jam-host (GP Appendix B: Host calls):
;;;;   constants.lisp        — B.1   Result codes, FetchKind, protocol constants
;;;;   context.lisp          — B     ServiceAccount, EmpowerState, HostContext
;;;;   helpers.lisp          —       Guest memory I/O, hashing, checkpoint B.13
;;;;   dispatch.lisp         — B.15  Central Ω dispatch + gas/context gating
;;;;   omega-gas.lisp        — ΩG(0)   Gas remaining + ext_log(100)
;;;;   omega-fetch.lisp      — ΩY(1)   Fetch context data
;;;;   omega-preimage.lisp   — ΩL(2) ΩH(6) ΩQ(22) ΩS(23) ΩF(24) Ωyield(25) Ωprovide(26)
;;;;   omega-storage.lisp    — ΩR(3) ΩW(4)
;;;;   omega-info.lisp       — ΩI(5)   Service account info
;;;;   omega-export.lisp     — ΩE(7)   Export segment
;;;;   omega-pvm.lisp        — ΩM(8) ΩP(9) ΩO(10) ΩZ(11) ΩK(12) ΩX(13)
;;;;   omega-privileged.lisp — ΩB(14) ΩA(15) ΩD(16) ΩC(17)
;;;;   omega-service.lisp    — ΩN(18) ΩU(19) ΩT(20) ΩJ(21)

(asdf:defsystem #:jamvm
  :description "JamVM — Pure Common Lisp PVM (Gray Paper Appendix A & B)"
  :author "Polycrate"
  :license "GPL-3.0"
  :version "0.1.0"
  :depends-on (#:ironclad)
  :serial t
  :components ((:module "jamvm"
                :pathname "src/jamvm"
                :serial t
                :components
                ((:file "package")
                 (:file "types")
                 (:file "memory")
                 (:file "decoder")
                 (:file "instructions")
                 (:file "inst-control")
                 (:file "inst-memory")
                 (:file "inst-reg")
                 (:file "inst-alu")
                 (:file "vm")
                 (:file "host-calls")
                 (:file "init")
                 (:file "invoke")))
               (:module "jam-host"
                :pathname "src/jam-host"
                :serial t
                :depends-on ("jamvm")
                :components
                ((:file "package")
                 (:file "constants")
                 (:file "context")
                 (:file "helpers")
                 (:file "dispatch")
                 (:file "omega-gas")
                 (:file "omega-fetch")
                 (:file "omega-preimage")
                 (:file "omega-storage")
                 (:file "omega-info")
                 (:file "omega-export")
                 (:file "omega-pvm")
                 (:file "omega-privileged")
                 (:file "omega-service")))))
