;;;; jotl.asd - ASDF System Definition for JOTL v3

(asdf:defsystem #:jotl
  :description "JAM (Join-Accumulate Machine) implementation in Pure Functional Common Lisp"
  :author "Polycrate"
  :license "MIT"
  :version "3.0.0"
  :serial t
  :depends-on (#:alexandria
               #:jam-crypto)
  :components
  (;; 1. Package Definition (MUST be first)
   (:file "package")
   
   ;; 2. Core - Protocol foundations (GP §3-4)
   (:module "core"
    :pathname "src/core"
    :serial t
    :components
    ((:file "constants")))    ; Chainspec (tiny/full)
   
   ;; 3. Codec - JAM Codec (GP Appendix C)
   (:module "codec"
    :pathname "src/codec"
    :serial t
    :components
    ((:file "primitives")     ; encode-u8, encode-compact, etc.
     (:file "structures")))   ; encode-header, etc.
   
   ;; 4. Block - Block structure (GP §4-5)
   (:module "block"
    :pathname "src/block"
    :serial t
    :components
    ((:file "header")         ; H ≡ (HP, HR, HX, ...)
     (:file "extrinsic")      ; E ≡ (ET, ED, EP, ...)
     (:file "block")))        ; B ≡ (H, E)
   
   ;; 5. State - State components (GP §6-7)
   (:module "state"
    :pathname "src/state"
    :serial t
    :components
    ((:file "timeslot")))     ; τ (timeslot), e (epoch), m (phase)
   
   ;; 6. STF - State Transition Functions (GP §8-13) - Future
   ;; (:module "stf"
   ;;  :pathname "src/stf"
   ;;  :serial t
   ;;  :components
   ;;  ((:file "accumulate")   ; Α - Accumulation (GP §8)
   ;;   (:file "refine")))     ; Ρ - Refinement (GP §9)
   ))

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
     (:file "timeslot-tests")
     (:file "codec-tests")
     (:file "header-tests")))))
