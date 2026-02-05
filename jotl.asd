;;;; jotl.asd
;;;; ASDF system definition for JOTL (JAM On The Lisp)

(asdf:defsystem #:jotl
  :description "JAM (Join-Accumulate Machine) implementation in Common Lisp"
  :long-description "Complete implementation of the JAM protocol codec, including
                     block structures, state serialization, and primitives based
                     on the JAM Graypaper specification."
  :author "JOTL Contributors"
  :maintainer "JOTL Contributors"
  :license "MIT"
  :version "0.2.0"
  :homepage "https://github.com/your-org/jotl"
  :bug-tracker "https://github.com/your-org/jotl/issues"
  :source-control (:git "https://github.com/your-org/jotl.git")
  :serial t
  :depends-on ()
  
  :components
  (;; ═══════════════════════════════════════════════════════════
   ;; TOP-LEVEL CONFIGURATION (loaded first)
   ;; ═══════════════════════════════════════════════════════════
   (:module "src"
    :serial t
    :components ((:file "package")
                 (:file "types")
                 (:file "config")))
   
   ;; ═══════════════════════════════════════════════════════════
   ;; CODEC MODULES
   ;; ═══════════════════════════════════════════════════════════
   (:module "codec"
    :serial t
    :components
    (;; Primitives: JAM codec primitives (C.1-C.15)
            (:module "primitives"
             :serial t
             :components ((:file "package")
                          (:file "trivial-encodings")
                          (:file "sequence-encoding")
                          (:file "discriminator-encoding")
                          (:file "bit-sequence-encoding")
                          (:file "dictionary-encoding")
                          (:file "set-encoding")
                          (:file "fixed-length-integer-encoding")
                          (:file "crypto-encoding")
                          (:file "decoder-macros")))
     
     ;; State: State structures and serialization (Appendix D)
     (:module "state"
      :serial t
      :components ((:file "package")
                   (:file "types")
                   
                   ;; Simple components (no sub-structures)
                   (:file "tau")      ; τ - Timeslot (equation 6.1)
                   (:file "eta")      ; η - Entropy pool (equation 6.21)
                   
                   ;; Core & Authorization
                   (:file "alpha")    ; α - Core authorizations (equation 8.1)
                   (:file "phi")      ; ϕ - Authorization queue (equation 8.1)
                   
                   ;; Validators (base dependencies for composites)
                   (:file "kappa")    ; κ - Current validators (equation 6.7)
                   (:file "lambda")   ; λ - Archived validators (equation 6.7)
                   (:file "iota")     ; ι - Validator queue (equation 6.7)
                   (:file "pi")       ; π - Validator statistics (equation 13.1)
                   
                   ;; Services
                   (:file "delta")    ; δ - Service accounts (equation 9.1)
                   
                   ;; Work processing
                   (:file "rho")      ; ρ - Pending reports (equation 11.1)
                   (:file "omega")    ; ω - Accumulation queue (equation 12.3)
                   (:file "xi")       ; ξ - Accumulation history (equation 12.1)
                   (:file "theta")    ; θ - Accumulation outputs (equations 7.4, 12.25)
                   
                   ;; Composite components (depend on base components)
                   (:file "beta")     ; β - Recent blocks: βH + βB (equations 7.1-7.7)
                   (:file "gamma")    ; γ - SAFROLE: γA + γP + γS + γZ (equations 6.3-6.7)
                   (:file "chi")      ; χ - Privileged services: χM + χA + χV + χR + χZ (equations 9.9, 12.27)
                   (:file "psi")))
     
     ;; Bloc: Block structures and encoding (C.16-C.35)
     (:module "bloc"
      :serial t
      :components ((:file "package")
                   (:file "types")
                   (:file "work")
                   (:file "header")
                   (:file "epoch")
                   (:file "tickets")
                   (:file "disputes")
                   (:file "preimages")
                   (:file "availability")
                   (:file "reports")
                   (:file "block")))))
   
   ;; ═══════════════════════════════════════════════════════════
   ;; STATE TRANSITION FUNCTION
   ;; ═══════════════════════════════════════════════════════════
   (:module "STF"
    :serial t
    :components ()))
  
  ;; ═══════════════════════════════════════════════════════════
  ;; TEST CONFIGURATION
  ;; ═══════════════════════════════════════════════════════════
  :in-order-to ((test-op (load-op :jotl)))
  :perform (test-op (o c)
                    (symbol-call :cl-user :load
                                 (merge-pathnames "test/suite.lisp"
                                                  (component-pathname c)))))
