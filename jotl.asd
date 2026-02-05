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
                   (:file "decoder-macros")))
     
     ;; State: State structures and serialization (Appendix D)
     (:module "state"
      :serial t
      :components ())
     
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
