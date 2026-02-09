;;;; state/gamma.lisp — γ Safrole State (GP §6)
;;;;
;;;; γ = (γA, γP, γS, γZ)
;;;; γA : sealing lottery ticket accumulator
;;;; γP : next epoch validator keys (pending)
;;;; γS : current epoch sealing-key sequence
;;;; γZ : Bandersnatch root for ticket submissions
;;;;
;;;; GP (4.7): γ' < (H, T, ET, γ, ι, η', κ', ψ')
;;;;
;;;; TODO: implement with define-state-closure

(in-package #:jotl)

;;; PLACEHOLDER — will be implemented as state closure
