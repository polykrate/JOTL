;;;; stf/sigma.lisp — JAM State σ (Pure FP)
;;;; Gray Paper §4.2 & §4.4
;;;;
;;;; σ = (α, β, θ, γ, δ, η, ι, κ, λ, ρ, τ, ϕ, χ, ψ, π, ω, ξ)
;;;;
;;;; DATA — immutable state closure.
;;;; Transitions produce σ' (see stf/upsilon.lisp).

(in-package #:jotl)

;;; ===================================================================
;;; GRAY PAPER §4.2: THE STATE
;;; ===================================================================

#|
Gray Paper §4.4:

  σ = (α, β, θ, γ, δ, η, ι, κ, λ, ρ, τ, ϕ, χ, ψ, π, ω, ξ)

Segments:
  α  alpha  - Core authorizations
  β  beta   - Recent block headers
  θ  theta  - Accumulation queue
  γ  gamma  - Safrole state (tickets, entropy, validator selection)
  δ  delta  - Services
  η  eta    - Entropy pool
  ι  iota   - Enqueued validator keys (next epoch)
  κ  kappa  - Current validator keys
  λ  lambda - Archived validator keys (prior epoch)
  ρ  rho    - Core assignments (reports pending availability)
  τ  tau    - Timeslot index
  ϕ  phi    - Authorization queue
  χ  chi    - Privileged service IDs
  ψ  psi    - Judgments
  π  pi     - Validator activity statistics
  ω  omega  - Ready work-reports
  ξ  xi     - Recently accumulated work-packages
|#

;;; ===================================================================
;;; STATE CLOSURE
;;; ===================================================================

(defun make-state (&key
                     (alpha nil)     ; α - Core authorizations
                     (beta nil)      ; β - Recent block headers
                     (theta nil)     ; θ - Accumulation queue
                     (gamma nil)     ; γ - Safrole state
                     (delta nil)     ; δ - Services
                     (eta nil)       ; η - Entropy pool
                     (iota nil)      ; ι - Enqueued validator keys
                     (kappa nil)     ; κ - Current validator keys
                     (lambda* nil)   ; λ - Archived validator keys
                     (rho nil)       ; ρ - Core assignments
                     (tau 0)         ; τ - Timeslot index
                     (phi nil)       ; ϕ - Authorization queue
                     (chi nil)       ; χ - Privileged service IDs
                     (psi nil)       ; ψ - Judgments
                     (pi* nil)       ; π - Validator statistics
                     (omega nil)     ; ω - Ready work-reports
                     (xi nil))       ; ξ - Recently accumulated
  "Creates state closure σ = (α,β,θ,γ,δ,η,ι,κ,λ,ρ,τ,ϕ,χ,ψ,π,ω,ξ)
   
   Gray Paper §4.4
   Immutable. Transitions produce new σ' via make-state."
  
  (lambda (msg &rest args)
    (declare (ignore args))
    (case msg
      (:alpha alpha)
      (:beta beta)
      (:theta theta)
      (:gamma gamma)
      (:delta delta)
      (:eta eta)
      (:iota iota)
      (:kappa kappa)
      (:lambda lambda*)
      (:rho rho)
      (:tau tau)
      (:phi phi)
      (:chi chi)
      (:psi psi)
      (:pi pi*)
      (:omega omega)
      (:xi xi)
      
      ;; Derived
      (:epoch (timeslot-epoch tau))
      (:phase (timeslot-phase tau))
      (:epoch-and-phase (timeslot-to-epoch-and-phase tau))
      (:as-plist
       (list :alpha alpha :beta beta :theta theta :gamma gamma
             :delta delta :eta eta :iota iota :kappa kappa
             :lambda lambda* :rho rho :tau tau :phi phi
             :chi chi :psi psi :pi pi* :omega omega :xi xi))
      (:type :state)
      (otherwise (error "Unknown state message: ~a" msg)))))

;;; ===================================================================
;;; ACCESSORS
;;; ===================================================================

(defun state-tau (sigma) (funcall sigma :tau))
(defun state-kappa (sigma) (funcall sigma :kappa))
(defun state-lambda (sigma) (funcall sigma :lambda))
(defun state-iota (sigma) (funcall sigma :iota))
(defun state-gamma (sigma) (funcall sigma :gamma))
(defun state-eta (sigma) (funcall sigma :eta))
(defun state-beta (sigma) (funcall sigma :beta))
(defun state-delta (sigma) (funcall sigma :delta))
(defun state-rho (sigma) (funcall sigma :rho))
(defun state-alpha (sigma) (funcall sigma :alpha))
(defun state-phi (sigma) (funcall sigma :phi))
(defun state-chi (sigma) (funcall sigma :chi))
(defun state-psi (sigma) (funcall sigma :psi))
(defun state-pi (sigma) (funcall sigma :pi))
(defun state-omega (sigma) (funcall sigma :omega))
(defun state-xi (sigma) (funcall sigma :xi))
(defun state-theta (sigma) (funcall sigma :theta))

;;; ===================================================================
;;; GENESIS STATE σ₀
;;; ===================================================================

(defun make-genesis-state (&key validators)
  "Creates genesis state σ₀.
   
   Gray Paper: We presume consensus over H₀ and σ₀."
  (make-state
   :tau 0
   :kappa validators
   :beta nil
   :eta (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
