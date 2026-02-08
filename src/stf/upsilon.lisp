;;;; stf/upsilon.lisp — Υ(σ, B) → σ'
;;;; Gray Paper §4.1 & §4.2.1
;;;;
;;;; TOP-LEVEL STF — orchestrates all sub-STFs.
;;;; Pure function: (sigma, block) → sigma'.
;;;;
;;;; Call hierarchy:
;;;;   import-block(bytes, env)  ← node layer (future, impure)
;;;;     ├─ decode-block(bytes)  ← codec
;;;;     ├─ validate env checks  ← wall-clock, parent hash
;;;;     └─ apply-block(σ, B)   ← THIS FILE = Υ (pure)
;;;;          ├─ validate-block(B)     HX check (intrinsic)
;;;;          └─ transition-state(σ,B) sub-STFs in wave order

(in-package #:jotl)

;;; ═════════════════════════════════════════════════════════════════
;;; Υ — BLOCK-LEVEL STATE TRANSITION (GP §4.1)
;;; ═════════════════════════════════════════════════════════════════

(defun apply-block (sigma block)
  "Υ(σ, B) → σ' — Block-level state transition.
   
   Pure function: σ and B in, σ' out.
   Environmental checks (wall-clock, parent hash) belong
   to import-block (node layer), not here.
   
   1. Intrinsic validation (HX)
   2. Pure state transition
   
   Args: sigma (closure), block (closure)"
  (multiple-value-bind (valid-p errors)
      (validate-block block)
    (unless valid-p
      (error "Υ: block invalid — ~{~A~^, ~}"
             (mapcar (lambda (e) (format nil "~A: ~A" (first e) (second e)))
                     errors))))
  (transition-state sigma block))

;;; ═════════════════════════════════════════════════════════════════
;;; transition-state — σ → σ' (GP §4.2.1)
;;; ═════════════════════════════════════════════════════════════════
;;;
;;; Pure composition of sub-STFs in dependency-graph order.
;;; All closures — no (if (functionp ...) ...) dispatch.

(defun transition-state (sigma block)
  "Υ-inner: σ → σ' — Pure state transition.
   
   GP §4.2.1 dependency graph (5 waves).
   Block is a closure from decode-block or make-block."
  (let* ((h (funcall block :header))
         (e (funcall block :extrinsic))
         ;; Extrinsic sub-components (from closures)
         (e-t (funcall e :tickets))
         (e-d (funcall e :disputes))
         (e-p (funcall e :preimages))
         (e-a (funcall e :assurances))
         (e-g (funcall e :guarantees))
         ;; Prior state segments
         (tau          (funcall sigma :tau))
         (eta          (funcall sigma :eta))
         (kappa        (funcall sigma :kappa))
         (lambda-prev  (funcall sigma :lambda))
         (gamma-prev   (funcall sigma :gamma))
         (rho          (funcall sigma :rho))
         (psi          (funcall sigma :psi))
         (beta         (funcall sigma :beta))
         (alpha-prev   (funcall sigma :alpha))
         (delta        (funcall sigma :delta))
         ;; θ not extracted: it's only an OUTPUT of (4.16), never an input
         (iota         (funcall sigma :iota))
         (phi          (funcall sigma :phi))
         (chi          (funcall sigma :chi))
         (pi-prev      (funcall sigma :pi))
         (omega        (funcall sigma :omega))
         (xi           (funcall sigma :xi)))
    ;; ═══════════════════════════════════════════════════════════
    ;; WAVE 1 — depends only on prior σ and block B
    ;; (4.5)  τ'  < (H, τ)
    ;; (4.6)  β†  < (H, βH)
    ;; (4.8)  η'  < (H, τ, η)
    ;; (4.9)  κ'  < (H, τ, κ, γ)
    ;; (4.10) λ'  < (H, τ, λ, κ)
    ;; (4.11) ψ'  < (ED, ψ)     [+τ,κ,λ for §10.3]
    ;; (4.12) ρ†  < (ED, ρ)     [via v-list from (10.12)]
    ;; ═══════════════════════════════════════════════════════════
    (let ((tau-prime    (transition-tau tau h))
          (eta-prime    (transition-eta h tau eta))
          (beta-dagger  (transition-beta-dagger h beta))
          (kappa-prime  (transition-kappa h tau kappa gamma-prev))
          (lambda-prime (transition-lambda h tau lambda-prev kappa)))
      ;; ψ' returns (values ψ' v-list) per (10.12)
      (multiple-value-bind (psi-prime v-list)
          (transition-psi e-d psi tau kappa lambda-prev)
        ;; ρ† uses v-list to invalidate bad/wonky assignments (10.15)
        (let* ((rho-dagger (transition-rho-dagger v-list rho))
               ;; ═══════════════════════════════════════════════
               ;; WAVE 2 — depends on Wave 1 results
               ;; (4.7)  γ'  < (H, τ, ET, γ, ι, η', κ', ψ')
               ;; (4.13) ρ‡  < (EA, ρ†)
               ;; (4.15) R*  < (EA, ρ†)
               ;; ═══════════════════════════════════════════════
               (gamma-prime (transition-gamma h tau e-t gamma-prev
                                              iota eta-prime kappa-prime psi-prime))
               (rho-ddagger (transition-rho-ddagger e-a rho-dagger))
               (r-star      (compute-ready-reports e-a rho-dagger))
               ;; ═══════════════════════════════════════════════
               ;; WAVE 3 — depends on Wave 2 results (parallel)
               ;; (4.14) ρ'  < (EG, ρ‡, κ, τ')
               ;; (4.16) accumulate < (R*, ω, ξ, δ, χ, ι, ϕ, τ, τ')
               ;; ═══════════════════════════════════════════════
               (rho-prime   (transition-rho e-g rho-ddagger kappa tau-prime)))
          (multiple-value-bind (omega-prime xi-prime delta-ddagger
                                chi-prime iota-prime phi-prime
                                theta-prime s-reports)
              (transition-accumulate r-star omega xi delta chi
                                    iota phi tau tau-prime)
            ;; ═══════════════════════════════════════════════
            ;; WAVE 4 — merge / join (depends on Wave 3)
            ;; (4.17) β'  < (H, EG, β†, θ')
            ;; (4.18) δ'  < (EP, δ‡, τ')
            ;; (4.19) α'  < (H, EG, ϕ', α)
            ;; (4.20) π'  < (EG, EP, EA, ET, τ, κ', π, H, S)
            ;; ═══════════════════════════════════════════════
            (let* ((beta-prime  (transition-beta h e-g beta-dagger theta-prime))
                   (delta-prime (transition-delta e-p delta-ddagger tau-prime))
                   (alpha-prime (transition-alpha h e-g phi-prime alpha-prev))
                   (pi-prime    (transition-pi e-g e-p e-a e-t tau
                                               kappa-prime pi-prev h s-reports)))
              ;; BUILD σ'
              (make-state
               :alpha   alpha-prime
               :beta    beta-prime
               :theta   theta-prime
               :gamma   gamma-prime
               :delta   delta-prime
               :eta     eta-prime
               :iota    iota-prime
               :kappa   kappa-prime
               :lambda* lambda-prime
               :rho     rho-prime
               :tau     tau-prime
               :phi     phi-prime
               :chi     chi-prime
               :psi     psi-prime
               :pi*     pi-prime
               :omega   omega-prime
               :xi      xi-prime))))))))

;;; ═════════════════════════════════════════════════════════════════
;;; SUB-STF STUBS — GP §4.2.1 equations
;;; ═════════════════════════════════════════════════════════════════
;;; Each returns prior value (identity). Implement one by one.

;; transition-eta → stf/eta.lisp
;; transition-psi → stf/psi.lisp
;; transition-rho-dagger, transition-rho-ddagger, transition-rho → stf/rho.lisp
;; transition-beta-dagger → stf/beta.lisp

(defun transition-kappa (header tau kappa gamma)
  "GP §4.9 — Validator keys at epoch boundary. STUB: §6"
  (declare (ignore header tau gamma)) kappa)

(defun transition-lambda (header tau lambda-prev kappa)
  "GP §4.10 — Archived keys. STUB: §6"
  (declare (ignore header tau kappa)) lambda-prev)

(defun transition-gamma (header tau tickets gamma iota eta-prime kappa-prime psi-prime)
  "GP §4.7 — Safrole. TODO: §6"
  (declare (ignore header tau tickets iota eta-prime kappa-prime psi-prime)) gamma)

(defun transition-accumulate (r-star omega xi delta chi iota phi tau tau-prime)
  "GP §4.16 — Accumulation. TODO: §8 + PVM
   Returns: (values ω' ξ' δ‡ χ' ι' ϕ' θ' S)"
  (declare (ignore r-star tau tau-prime))
  (values omega xi delta chi iota phi nil nil))

;; transition-beta → stf/beta.lisp

(defun transition-delta (preimages delta-ddagger tau-prime)
  "GP §4.18 — Services: fold preimages. TODO: §7"
  (declare (ignore preimages tau-prime)) delta-ddagger)

(defun transition-alpha (header guarantees phi-prime alpha)
  "GP §4.19 — Core authorizations. TODO: §13"
  (declare (ignore header guarantees phi-prime)) alpha)

(defun transition-pi (guarantees preimages assurances tickets
                      tau kappa-prime pi-prev header s-reports)
  "GP §4.20 — Validator statistics. TODO: §15"
  (declare (ignore guarantees preimages assurances tickets
                   tau kappa-prime header s-reports))
  pi-prev)
