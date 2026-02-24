;;;; jotl.asd — ASDF System Definition for JOTL (clean rebuild)
;;;;
;;;; Architecture:
;;;;   lib/     — Macros (v1+v2), constants, codecs, Merkle, MMR, display
;;;;   state/   — State σ: one file per GP component (define-state-closure)
;;;;   src/     — Υ(σ,B)→σ' orchestrator (upsilon.lisp)
;;;;   tests/   — Conformance runner (600+ trace blocks)

(asdf:defsystem #:jotl
  :description "JAM (Join-Accumulate Machine) implementation in Common Lisp"
  :author "Polycrate"
  :license "GPL-3.0"
  :version "5.0.0"
  :serial t
  :depends-on (#:alexandria
               #:jam-crypto
               #:jamvm)
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
     (:file "extrinsic")     ;; E standalone functions (encode/decode/HX)
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
     (:file "alpha")      ;; α  — authorizations   ✓ codec-only (via accumulate)
     (:file "phi")        ;; ϕ  — auth queue       ✓ codec-only (via accumulate)
     (:file "delta")      ;; δ  — services         ✓ codec-only (via accumulate)
     (:file "pi")         ;; π  — statistics       ✓ define-state-closure
     (:file "chi")        ;; χ  — privileged IDs   ✓ codec-only (via accumulate)
     (:file "omega")      ;; ω  — ready work-reports ✓ codec-only (via accumulate)
     (:file "xi")         ;; ξ  — accum history    ✓ codec-only (via accumulate)
     (:file "theta")      ;; θ  — accum outputs    ✓ codec-only (via accumulate)
     (:file "sigma")))    ;; σ  — overall state (last — needs all components)
   
   ;; 5. §12 Accumulate orchestrator (GP §12)
   (:file "accumulate" :pathname "src/accumulate")
   
   ;; 6. Υ — Top-level STF orchestrator (GP §4.2.1)
   (:file "upsilon" :pathname "src/upsilon")
   
   ;; 7. Block Importer — M1 API (parse binary, import block, run traces)
   (:file "import" :pathname "src/import")

   ;; 8. Fuzz Target — fuzz-v1 protocol server for conformance testing
   (:file "fuzz-target" :pathname "src/fuzz-target")
   
   ))
