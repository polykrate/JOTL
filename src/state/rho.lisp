;;;; state/rho.lisp — ρ Core Assignments (GP §10-12)
;;;;
;;;; ρ[c] = nil | (:report w, :timeout t)
;;;;
;;;; GP (4.12): ρ†  < (ED, ρ)        — post-judgment
;;;; GP (4.13): ρ‡  < (EA, ρ†)       — post-assurances
;;;; GP (4.14): ρ'  < (EG, ρ‡, κ, τ') — post-guarantees
;;;; GP (4.15): R*  < (EA, ρ†)       — available reports
;;;;
;;;; TODO: implement with define-state-closure

(in-package #:jotl)

;;; PLACEHOLDER — will be implemented as state closure
