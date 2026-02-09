;;;; jotl.asd — ASDF System Definition for JOTL (clean rebuild)
;;;;
;;;; Architecture:
;;;;   lib/     — Macros (v1+v2), constants, codecs, Merkle, MMR, display
;;;;   state/   — State σ: one file per GP component (define-state-closure)
;;;;   src/     — Υ(σ,B)→σ' orchestrator (upsilon.lisp)
;;;;   archive/ — Previous implementation (reference only, not loaded)

(asdf:defsystem #:jotl
  :description "JAM (Join-Accumulate Machine) implementation in Common Lisp"
  :author "Polycrate"
  :license "MIT"
  :version "5.0.0"
  :serial t
  :depends-on (#:alexandria
               #:jam-crypto)
  :components
  (;; 1. Package
   (:file "package")
   
   ;; 2. Lib — Macros (define-value-object + define-state-closure),
   ;;          constants, codecs, Merkle trie, MMR
   (:module "lib"
    :pathname "src/lib"
    :serial t
    :components
    ((:file "macros")
     (:file "constants")
     (:file "primitives")
     (:file "types")
     (:file "state-keys")
     (:file "merkle-trie")
     (:file "mmr")
     (:file "display")))
   
   ;; 3. State — One file per GP state component (GP I.4.2)
   ;;    Order matters: σ first (defines make-state), then τ (first real closure),
   ;;    then components in dependency order for transitions.
   (:module "state"
    :pathname "src/state"
    :serial t
    :components
    ((:file "sigma")      ;; σ  — overall state (make-state, make-genesis-state)
     (:file "tau")        ;; τ  — timeslot       ✓ define-state-closure
     (:file "eta")        ;; η  — entropy         ◐ define-state-closure
     (:file "kappa")      ;; κ  — current validators ◐
     (:file "lambda")     ;; λ  — archived validators ◐
     (:file "beta")       ;; β  — recent history   ○
     (:file "psi")        ;; ψ  — judgments        ○
     (:file "rho")        ;; ρ  — core assignments ○
     (:file "iota")       ;; ι  — enqueued validators ○
     (:file "gamma")      ;; γ  — safrole         ○
     (:file "alpha")      ;; α  — authorizations  ○
     (:file "phi")        ;; ϕ  — auth queue      ○
     (:file "delta")      ;; δ  — services        ○
     (:file "pi")         ;; π  — statistics      ○
     (:file "chi")        ;; χ  — privileged IDs  ○
     (:file "omega")      ;; ω  — accum queue     ○
     (:file "xi")         ;; ξ  — accum history   ○
     (:file "theta")))    ;; θ  — accum outputs   ○
   
   ;; 4. Υ — Top-level STF orchestrator (GP §4.2.1)
   (:file "upsilon" :pathname "src/upsilon")))
