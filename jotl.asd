;;;; jotl.asd — ASDF System Definition for JOTL v3
;;;;
;;;; Architecture:
;;;;   lib/    — Macros, constants, codecs, Merkle trie, MMR, display
;;;;   block/  — Block data structures B=(H,E) + encode/decode/hash/validation
;;;;   state/  — State σ: one file per component (Greek letter)
;;;;   src/    — Υ(σ,B)→σ' orchestrator (upsilon.lisp)

(asdf:defsystem #:jotl
  :description "JAM (Join-Accumulate Machine) implementation in Pure Functional Common Lisp"
  :author "Polycrate"
  :license "MIT"
  :version "4.0.0"
  :serial t
  :depends-on (#:alexandria
               #:jam-crypto)
  :components
  (;; 1. Package
   (:file "package")
   
   ;; 2. Lib — Macros, constants, codecs, utils
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
   
   ;; 3. Block — Data structures B=(H,E) + encode/decode + hash + validation
   (:module "block"
    :pathname "src/block"
    :serial t
    :components
    ((:file "header")
     (:file "work-report")
     (:module "extrinsic"
      :pathname "extrinsic"
      :serial t
      :components
      ((:file "tickets")
       (:file "preimages")
       (:file "assurances")
       (:file "disputes")
       (:file "guarantees")
       (:file "extrinsic")))
     (:file "block")
     (:file "validation")))
   
   ;; 4. State — One file per GP state component (GP I.4.2)
   (:module "state"
    :pathname "src/state"
    :serial t
    :components
    ((:file "sigma")      ;; σ  — overall state
     (:file "tau")        ;; τ  — timeslot
     (:file "beta")       ;; β  — recent history
     (:file "eta")        ;; η  — entropy
     (:file "psi")        ;; ψ  — judgments
     (:file "rho")        ;; ρ  — core assignments
     (:file "kappa")      ;; κ  — current validators
     (:file "lambda")     ;; λ  — archived validators
     (:file "iota")       ;; ι  — enqueued validators
     (:file "gamma")      ;; γ  — safrole
     (:file "alpha")      ;; α  — core authorizations
     (:file "phi")        ;; ϕ  — authorization queue
     (:file "delta")      ;; δ  — services
     (:file "pi")         ;; π  — validator statistics
     (:file "chi")        ;; χ  — privileged service IDs
     (:file "omega")      ;; ω  — accumulation queue
     (:file "xi")         ;; ξ  — accumulation history
     (:file "theta")))    ;; θ  — accumulation outputs
   
   ;; 5. Υ — Top-level STF orchestrator
   (:file "upsilon" :pathname "src/upsilon")
   
   ;; 6. v2 — Experimental: self-transforming state closures
   (:module "v2"
    :pathname "src/v2"
    :serial t
    :components
    ((:file "macros")
     (:file "tau")))))

;;;; Tests are run via scripts/ — see tests/README.md
