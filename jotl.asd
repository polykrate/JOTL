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
     (:file "protocol")
     (:file "state-keys")
     (:file "merkle-trie")
     (:file "mmr")
     (:file "display")))
   
   ;; 3. Bloc — Block data structures B=(H,E) + codec + validation
   ;;    Uses define-value-object (v1) — no state transitions, no Merkle keys.
   (:module "bloc"
    :pathname "src/bloc"
    :serial t
    :components
    ((:file "tickets")       ;; ET codec
     (:file "disputes")      ;; ED codec
     (:file "preimages")     ;; EP codec
     (:file "assurances")    ;; EA codec
     (:file "work-report")   ;; WorkReport, WorkResult codec
     (:file "guarantees")    ;; EG codec (depends on work-report)
     (:file "header")        ;; H closure + epoch-marker, tickets-mark codec
     (:file "extrinsic")     ;; E closure + HX computation
     (:file "block")         ;; B ≡ (H, E) closure
     (:file "validation")))  ;; HX, HO, env checks
   
   ;; 4. State — One file per GP state component (GP I.4.2)
   ;;    Uses define-state-closure (v2) — self-transforming, codec, Merkle.
   (:module "state"
    :pathname "src/state"
    :serial t
    :components
    ((:file "tau")        ;; τ  — timeslot         ✓ define-state-closure
     (:file "eta")        ;; η  — entropy          ✓ define-state-closure
     (:file "kappa")      ;; κ  — current validators ✓
     (:file "lambda")     ;; λ  — archived validators ✓
     (:file "beta")       ;; β  — recent history   ✓
     (:file "psi")        ;; ψ  — judgments        ✓
     (:file "rho")        ;; ρ  — core assignments ✓
     (:file "iota")       ;; ι  — enqueued validators ✓
     (:file "gamma")      ;; γ  — safrole          ✓
     (:file "alpha")      ;; α  — authorizations   ○
     (:file "phi")        ;; ϕ  — auth queue       ○
     (:file "delta")      ;; δ  — services         ○
     (:file "pi")         ;; π  — statistics       ○
     (:file "chi")        ;; χ  — privileged IDs   ○
     (:file "omega")      ;; ω  — ready work-reports ○
     (:file "xi")         ;; ξ  — recent accum     ○
     (:file "theta")      ;; θ  — accum queue      ○
     (:file "sigma")))    ;; σ  — overall state (last — needs all components)
   
   ;; 5. Υ — Top-level STF orchestrator (GP §4.2.1)
   (:file "upsilon" :pathname "src/upsilon")))
