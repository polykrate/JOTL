;;;; jotl.asd — ASDF System Definition for JOTL v3
;;;;
;;;; Architecture:
;;;;   core/   — Macros + protocol constants
;;;;   codec/  — JAM encoding primitives + protocol types (GP Appendix C)
;;;;   utils/  — Merkle trie, MMR
;;;;   block/  — Block data structures B=(H,E) + encode/decode/hash/validation
;;;;   stf/    — State σ + state transition Υ(σ,B)→σ'

(asdf:defsystem #:jotl
  :description "JAM (Join-Accumulate Machine) implementation in Pure Functional Common Lisp"
  :author "Polycrate"
  :license "MIT"
  :version "3.2.0"
  :serial t
  :depends-on (#:alexandria
               #:jam-crypto)
  :components
  (;; 1. Package
   (:file "package")
   
   ;; 2. Core — Macros + Protocol constants (GP §3-4)
   (:module "core"
    :pathname "src/core"
    :serial t
    :components
    ((:file "macros")
     (:file "constants")))
   
   ;; 3. Codec — JAM encoding primitives + protocol types (GP Appendix C)
   (:module "codec"
    :pathname "src/codec"
    :serial t
    :components
    ((:file "primitives")
     (:file "types")
     (:file "state-keys")))
   
   ;; 4. Utils
   (:module "utils"
    :pathname "src/utils"
    :serial t
    :components
    ((:file "merkle-trie")
     (:file "mmr")
     (:file "display")))
   
   ;; 5. Block — Data structures B=(H,E) + encode/decode + hash + validation
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
   
   ;; 6. STF — State + Transitions (GP §4-13)
   (:module "stf"
    :pathname "src/stf"
    :serial t
    :components
    ((:file "sigma")
     (:file "tau")
     (:file "beta")
     (:file "eta")
     (:file "psi")
     (:file "rho")
     (:file "upsilon")))))

;;;; Tests are run via scripts/ — see tests/README.md
