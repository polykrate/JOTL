;;;; jotl.asd — ASDF System Definition for JOTL v3
;;;;
;;;; Architecture:
;;;;   codec/  — JAM encoding primitives + protocol types (GP Appendix C)
;;;;   block/  — Block data structures B=(H,E) + encode/decode/hash/validation
;;;;   stf/    — State σ + state transition Υ(σ,B)→σ'

(asdf:defsystem #:jotl
  :description "JAM (Join-Accumulate Machine) implementation in Pure Functional Common Lisp"
  :author "Polycrate"
  :license "MIT"
  :version "3.1.0"
  :serial t
  :depends-on (#:alexandria
               #:jam-crypto)
  :components
  (;; 1. Package
   (:file "package")
   
   ;; 2. Core — Protocol constants (GP §3-4)
   (:module "core"
    :pathname "src/core"
    :serial t
    :components
    ((:file "constants")))
   
   ;; 3. Codec — JAM encoding primitives + protocol types (GP Appendix C)
   ;;    Two clearly separated domains:
   ;;      primitives = HOW to encode (El, compact, sequence, option, result)
   ;;      types      = WHAT to encode (Hash, Key, Signature, Validator, Index)
   (:module "codec"
    :pathname "src/codec"
    :serial t
    :components
    ((:file "primitives")
     (:file "types")))
   
   ;; 4. Utils
   (:module "utils"
    :pathname "src/utils"
    :serial t
    :components
    ((:file "merkle-trie")
     (:file "mmr")))
   
   ;; 5. Block — Data structures B=(H,E) + encode/decode + hash + validation
   ;;    Pure data — not mutable, not an STF.
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
     (:file "upsilon")))))

;;;; Test System
(asdf:defsystem #:jotl/tests
  :description "Test suite for JOTL"
  :author "Polycrate"
  :license "MIT"
  :depends-on (#:jotl #:fiveam)
  :components
  ((:module "tests"
    :serial t
    :components
    ((:file "package")
     (:file "codec-tests")))))
