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
  (let ((sigma-prime (transition-state sigma block)))
    ;; ── HR: state root must match Merkle root of σ' ──
    (when (funcall (funcall block :header) :state-root)
      (validate-state-root (funcall block :header) sigma-prime))
    sigma-prime))

;;; ═════════════════════════════════════════════════════════════════
;;; transition-state — σ → σ' (GP §4.2.1)
;;; ═════════════════════════════════════════════════════════════════
;;;
;;; Pure composition of sub-STFs in dependency-graph order.
;;; All closures — no (if (functionp ...) ...) dispatch.

(defun transition-state (sigma block)
  "Υ-inner: σ → σ' — Pure state transition.
   
   GP §4.2.1 dependency graph (4 waves).
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
         (tau-cl       (or (funcall sigma :tau) (make-tau-state)))
         (tau          (funcall tau-cl :value))
         (eta          (or (funcall sigma :eta) (make-eta)))
         (kappa        (or (funcall sigma :kappa) (make-kappa)))
         (lambda-prev  (or (funcall sigma :lambda) (make-lambda-state)))
         (gamma-prev   (funcall sigma :gamma))
         (rho          (or (funcall sigma :rho) (make-rho)))
         (psi          (or (funcall sigma :psi)
                           (make-psi)))
         (beta         (funcall sigma :beta))
         (alpha-prev   (funcall sigma :alpha))
         (delta        (funcall sigma :delta))
         ;; θ not extracted: it's only an OUTPUT of (4.16), never an input
         (iota         (or (funcall sigma :iota) (make-iota)))
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
                                             iota eta-prime kappa-prime psi-prime)))
          ;; ── Header safrole checks: HI, HS, HV, HE, HW ──
          (when (funcall h :seal)
            (validate-header-safrole h tau gamma-prev eta eta-prime
                                     gamma-prime kappa-prime))
          ;; ρ‡ returns (values ρ‡ R* [error]) per §11
          (multiple-value-bind (rho-ddagger r-star)
              (transition-rho-ddagger e-a rho-dagger
                                      :tau-prime tau-prime
                                      :parent-hash (funcall h :parent-hash)
                                      :kappa kappa)
            (let* (;; ═══════════════════════════════════════════════
                   ;; WAVE 3 — depends on Wave 2 results (parallel)
                   ;; (4.14) ρ'  ≺ (EG, ρ‡, κ, τ')
                   ;; (4.16) accumulate ≺ (R*, ω, ξ, δ, χ, ι, ϕ, τ, τ')
                   ;; ═══════════════════════════════════════════════
                   (rho-prime (transition-rho e-g rho-ddagger
                                :tau-prime tau-prime
                                :kappa kappa
                                :lambda-prev lambda-prev
                                :eta eta-prime
                                :offenders (when psi-prime
                                             (funcall psi-prime :offenders))
                                :recent-blocks beta
                                :auth-pools alpha-prev
                                :accounts delta)))
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
              ;; ── Header post-transition checks: HO ──
              (validate-header-post-transition h e-d)
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
               :tau     (make-tau-state :value tau-prime)
               :phi     phi-prime
               :chi     chi-prime
               :psi     psi-prime
               :pi*     pi-prime
               :omega   omega-prime
               :xi      xi-prime))))))))))

;;; ═════════════════════════════════════════════════════════════════
;;; SUB-ORCHESTRATOR — transition-accumulate (GP §4.16)
;;; ═════════════════════════════════════════════════════════════════
;;; Produces ω', ξ', δ‡, χ', ι', ϕ', θ', S from R* and prior state.
;;; This is a sub-orchestrator (like Υ itself), not a state component.

(defun transition-accumulate (r-star omega xi delta chi iota phi tau tau-prime)
  "GP §4.16 — Accumulation. STUB: §8 + PVM
   Returns: (values ω' ξ' δ‡ χ' ι' ϕ' θ' S)"
  (declare (ignore r-star tau tau-prime))
  (values omega xi delta chi iota phi nil nil))

;;; ═════════════════════════════════════════════════════════════════
;;; SUB-STF LOCATIONS — one file per state component
;;; ═════════════════════════════════════════════════════════════════
;;; Implemented (tested):
;;;   transition-tau          → state/tau.lisp        (§6.1-6.2)  ✓ 42/42
;;;   transition-eta          → state/eta.lisp        (§6.21-6.23)✓ 42/42
;;;   transition-beta-dagger  → state/beta.lisp       (§7.5)      ✓  8/8
;;;   transition-psi          → state/psi.lisp        (§10)       ✓ 56/56
;;;   transition-rho-dagger   → state/rho.lisp        (§10.15)    ✓ (via ψ)
;;;   transition-kappa        → state/kappa.lisp      (§6.15)     ✓ (via γ)
;;;   transition-lambda       → state/lambda.lisp     (§6.16)     ✓ (via γ)
;;;   transition-gamma        → state/gamma.lisp      (§6)        ✓ 42/42
;;;   transition-rho-ddagger  → state/rho.lisp        (§11)       ✓ 20/20
;;;   transition-rho          → state/rho.lisp        (§11-12)    ✓ 84/84
;;;
;;; Stubs:
;;;   transition-delta        → state/delta.lisp      (§7)        vectors: 16
;;;   transition-alpha        → state/alpha.lisp      (§13)       vectors:  6
;;;   transition-pi           → state/pi.lisp         (§15)       vectors:  6
;;;   transition-beta (final) → state/beta.lisp       (§7.7-7.8)
