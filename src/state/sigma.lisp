;;;; state/sigma.lisp — σ Overall State (GP §4.1, §4.4)
;;;;
;;;; σ = (α, β, γ, δ, η, ι, κ, λ, ρ, τ, ϕ, χ, ψ, π, ω, ξ, θ)
;;;;
;;;; σ is a pure data holder — no derived properties, no transition.
;;;; Transition lives in upsilon.lisp: Υ(σ, B) → σ'.

(in-package #:jotl)

(define-value-object state
  ((alpha nil) (beta nil) (gamma nil) (delta nil)
   (eta nil) (iota nil) (kappa nil) (lambda* nil)
   (rho nil) (tau nil) (phi nil) (chi nil)
   (psi nil) (pi* nil) (omega nil) (xi nil) (theta nil)))

(defun make-genesis-state ()
  "σ₀ — Genesis state: all components at defaults."
  (make-state :tau (make-tau-state)))
