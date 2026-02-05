;;;; jotl.asd
;;;; ASDF system definition for JOTL (JAM On The Lisp)

(asdf:defsystem #:jotl
  :description "JAM (Join-Accumulate Machine) implementation in Common Lisp"
  :author "Your Name"
  :license "MIT"
  :version "0.1.0"
  :serial t
  :depends-on ()
  :components ((:module "codec"
                :serial t
                :components ((:module "primitives"
                              :serial t
                              :components ((:file "package")
                                           (:file "trivial-encodings")
                                           (:file "sequence-encoding")
                                           (:file "discriminator-encoding")
                                           (:file "bit-sequence-encoding")
                                           (:file "dictionary-encoding")
                                           (:file "set-encoding")
                                           (:file "fixed-length-integer-encoding")))
                             (:module "state"
                              :serial t
                              :components ())
                             (:module "bloc"
                              :serial t
                              :components (               (:file "package")
               (:file "types")
               (:file "config")
               (:file "header")
               (:file "epoch")
               (:file "tickets")
               (:file "disputes")
               (:file "preimages")
               (:file "availability")
               (:file "reports")
               (:file "block")))))
               (:module "STF"
                :serial t
                :components ())))
