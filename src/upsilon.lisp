;;;; upsilon.lisp — Υ(σ, B) → σ'
;;;; Gray Paper §4.1 & §4.2.1
;;;;
;;;; TOP-LEVEL STF ORCHESTRATOR — composes all state transitions.
;;;; Pure function: (sigma, block) → sigma'.
;;;;
;;;; σ is a pure byte store. Components are loaded lazily per wave
;;;; via (funcall sigma :load :kw) — sigma dispatches to the right decoder.
;;;; After transitions, closures are re-encoded back to bytes for σ'.
;;;;
;;;; Dependency graph from GP §4.2.1:
;;;;
;;;;   Wave 0: τ' < (H)
;;;;
;;;;   Wave 1 (independent — parallelizable):
;;;;     β†H < (H, βH)
;;;;     η'  < (H, τ, η)
;;;;     κ'  < (H, τ, κ, γ)
;;;;     λ'  < (H, τ, λ, κ)
;;;;     ψ'  < (ED, ψ)
;;;;     ρ†  < (ED, ρ)
;;;;
;;;;   Wave 2 (depends on Wave 1):
;;;;     γ'  < (H, T, ET, γ, ι, η', κ', ψ')
;;;;     ρ‡  < (EA, ρ†)
;;;;     R*  < (EA, ρ†)
;;;;
;;;;   Wave 3 (depends on Wave 2 — parallelizable):
;;;;     ρ'  < (EG, ρ‡, κ, τ')
;;;;     (ω', ξ', δ†, χ', ι', ϕ', θ', S) < (R*, ω, ξ, δ, χ, ι, ϕ, τ, τ')
;;;;
;;;;   Wave 4 (merge — depends on Wave 3):
;;;;     β'H < (H, EC, β†H, θ')
;;;;     δ'  < (EP, δ†, τ')
;;;;     α'  < (H, EC, ϕ', α)
;;;;     π'  < (EG, EP, EA, ET, τ, κ', π, H, S)

(in-package #:jotl)

;;; ═════════════════════════════════════════════════════════════════
;;; Υ — BLOCK-LEVEL STATE TRANSITION (GP §4.1)
;;; ═════════════════════════════════════════════════════════════════

(defun apply-block (sigma block)
  "Υ(σ, B) → σ' — Block-level state transition.
   Pure function: σ and B in, σ' out.
   Environmental checks (wall-clock, parent hash) belong to import-block."
  ;; TODO: (validate-block block) — HX check
  (transition-state sigma block))

;;; ═════════════════════════════════════════════════════════════════
;;; transition-state — σ → σ' (GP §4.2.1)
;;; ═════════════════════════════════════════════════════════════════

(defun transition-state (sigma block)
  "Υ-inner: σ → σ' — Pure state transition following GP dependency graph.
   σ is a byte store. Components are loaded lazily per wave via
   (funcall sigma :load :kw), then re-encoded back into σ' bytes."
  (let* (;; ── Block is a message, not an actor ──
         ;; H is a closure (sovereignty: hash, EU(H), genesis).
         ;; ET, ED, EA, EG are raw data — consumed directly.
         (h   (funcall block :header))
         (e-t (funcall block :tickets))        ;; ET
         (e-d (funcall block :disputes))       ;; ED
         (e-a (funcall block :assurances))     ;; EA
         (e-g (funcall block :guarantees)))    ;; EG

    ;; ═══════════════════════════════════════════════════════════
    ;; WAVE 0 — τ' < (H)
    ;; Decode: τ
    ;; ═══════════════════════════════════════════════════════════
    (let* ((tau       (funcall sigma :load :tau))
           (tau-prime (funcall tau :transition :header h)))

      ;; ═══════════════════════════════════════════════════════════
      ;; WAVE 1 — independent, all depend on prior σ + B only
      ;; Decode: β, η, κ, λ, γ, ψ, ρ
      ;; ═══════════════════════════════════════════════════════════
      (let* ((beta        (funcall sigma :load :beta))
             (eta         (funcall sigma :load :eta))
             (kappa       (funcall sigma :load :kappa))
             (lambda-prev (funcall sigma :load :lambda))
             (gamma       (funcall sigma :load :gamma))
             (psi         (funcall sigma :load :psi))
             (rho         (funcall sigma :load :rho))
             ;; (4.6)  β†H < (H, βH)
             (beta-dagger  (funcall beta :transition-dagger :header h))
             ;; (4.8)  η'  < (H, τ, η)
             (eta-prime    (funcall eta :transition
                                    :header h :tau tau :tau-prime tau-prime))
             ;; (4.9)  κ'  < (H, τ, κ, γ)
             (kappa-prime  (funcall kappa :transition
                                    :tau tau :tau-prime tau-prime :gamma gamma))
             ;; (4.10) λ'  < (H, τ, λ, κ)
             (lambda-prime (funcall lambda-prev :transition
                                    :tau tau :tau-prime tau-prime :kappa kappa))
             ;; (4.11) ψ'  < (ED, ψ)  [+τ,κ,λ for §10.3 signing]
             ;; v-list accessible via (funcall psi-prime :v-list)
             (psi-prime    (funcall psi :transition
                                    :disputes e-d
                                    :tau tau
                                    :kappa kappa
                                    :lambda-prev lambda-prev))
             ;; (4.12) ρ†  < (ED, ρ)  [via v-list from ψ (10.12)]
             (rho-dagger   (funcall rho :transition-dagger
                                    :v-list (funcall psi-prime :v-list))))

        ;; ═══════════════════════════════════════════════════════════
        ;; WAVE 2 — depends on Wave 1 results
        ;; Decode: ι
        ;; ═══════════════════════════════════════════════════════════
        (let* ((iota (funcall sigma :load :iota))
               ;; (4.7)  γ'  < (H, T, ET, γ, ι, η', κ', ψ')
               (gamma-prime (funcall gamma :transition
                                     :tau tau :tau-prime tau-prime
                                     :tickets e-t :iota iota
                                     :eta-prime eta-prime :kappa-prime kappa-prime
                                     :psi-prime psi-prime))
               ;; (4.13) ρ‡  < (EA, ρ†)
               ;; (4.15) R*  accessible via (funcall rho-ddagger :reported)
               (rho-ddagger (funcall rho-dagger :transition-ddagger
                                     :assurances e-a
                                     :tau-prime tau-prime
                                     :parent-hash (funcall h :parent-hash)
                                     :kappa kappa)))

          ;; ═══════════════════════════════════════════════════════════
          ;; WAVE 3 — depends on Wave 2 (parallelizable)
          ;; ═══════════════════════════════════════════════════════════
          (let* (;; (4.14) ρ'  < (EG, ρ‡, κ, τ')
                 ;; FIXME: wrap in handler-case for guarantee-error
                 (rho-prime (funcall rho-ddagger :transition
                                     :guarantees e-g
                                     :tau-prime tau-prime
                                     :kappa kappa
                                     :lambda-prev lambda-prev
                                     :eta eta-prime
                                     :offenders (when psi-prime
                                                  (funcall psi-prime :offenders))
                                     :recent-blocks beta-dagger
                                     :auth-pools (funcall sigma :segment :alpha)
                                     :accounts (funcall sigma :segment :delta)))

                 ;; (4.16) (ω', ξ', δ†, χ', ι', ϕ', θ', S) < (R*, ω, ξ, δ, χ, ι, ϕ, τ, τ')
                 (r-star (funcall rho-ddagger :reported))
                 (omega-cl (funcall sigma :load :omega))
                 (xi-cl    (funcall sigma :load :xi))
                 (chi-cl   (funcall sigma :load :chi))
                 (phi-cl   (funcall sigma :load :phi))
                 (delta-cl (load-delta-from-extra-kvs (funcall sigma :extra-kvs)))
                 (accum (transition-accumulate
                         r-star omega-cl xi-cl delta-cl chi-cl iota phi-cl
                         tau tau-prime))
                 ;; Extract accumulation results
                 (omega-prime  (getf accum :omega-prime))
                 (xi-prime     (getf accum :xi-prime))
                 (delta-dagger (getf accum :delta-dagger))
                 (chi-prime    (getf accum :chi-prime))
                 (iota-prime   (getf accum :iota-prime))
                 (phi-prime    (getf accum :phi-prime))
                 (theta-prime  (getf accum :theta-prime))
                 ;; S — service statistics for π'
                 ;; (service-stats (getf accum :service-stats))
                 )

            ;; ═══════════════════════════════════════════════════════════
            ;; WAVE 4 — merge / join
            ;; ═══════════════════════════════════════════════════════════
            ;; (4.17) β'H < (H, EC, β†H, θ')
            ;; (4.18) δ'  < (EP, δ†, τ')
            ;; (4.19) α'  < (H, EC, ϕ', α)
            ;; (4.20) π'  < (EG, EP, EA, ET, τ, κ', π, H, S)
            (let* ((alpha-cl (funcall sigma :load :alpha))
                   (pi-cl (funcall sigma :load :pi))

                   ;; (4.19) α' < (H, EC, ϕ', α)
                   (alpha-prime (funcall alpha-cl :transition
                                        :tau tau
                                        :tau-prime tau-prime
                                        :phi-prime phi-prime
                                        :offender-auth-hashes nil)) ;; TODO: derive from EC

                   ;; (4.18) δ' < (EP, δ†, τ')
                   (delta-prime (funcall delta-dagger :transition
                                        :preimages (funcall block :preimages)
                                        :tau-prime tau-prime))

                   ;; (4.20) π' < (EG, EP, EA, ET, τ, κ', π, H, S)
                   (pi-prime (funcall pi-cl :transition
                                      :header h
                                      :tau tau :tau-prime tau-prime
                                      :tickets e-t :preimages (funcall block :preimages)
                                      :assurances e-a :guarantees e-g
                                      :kappa-prime kappa-prime)))

              ;; ── β' (4.17): β'H < (H, EC, β†H, θ') ─────────────
              (let ((beta-prime (funcall beta-dagger :transition
                                        :header h
                                        :guarantees e-g
                                        :theta-prime theta-prime)))

              ;; ── BUILD σ' — re-encode closures back to bytes ──
              (make-sigma-state
               :alpha   (funcall alpha-prime :encoded)     ;; ✓ (4.19) α' < (H, EC, ϕ', α)
               :beta    (funcall beta-prime :encoded)      ;; ✓ (4.17)
               :gamma   (funcall gamma-prime :encoded)     ;; ✓ (4.7)
               :delta   nil                                ;; δ uses extra-kvs, not a segment
               :eta     (funcall eta-prime :encoded)       ;; ✓ (4.8)
               :iota    (funcall iota-prime :encoded)      ;; ✓ (4.16) via accumulate
               :kappa   (funcall kappa-prime :encoded)     ;; ✓ (4.9)
               :lambda* (funcall lambda-prime :encoded)    ;; ✓ (4.10)
               :rho     (funcall rho-prime :encoded)       ;; ✓ (4.12→4.14) ρ† → ρ‡ → ρ'
               :tau     (funcall tau-prime :encoded)       ;; ✓ (4.5)
               :phi     (funcall phi-prime :encoded)       ;; ✓ (4.16) via accumulate
               :chi     (funcall chi-prime :encoded)       ;; ✓ (4.16) via accumulate
               :psi     (funcall psi-prime :encoded)       ;; ✓ (4.11)
               :pi*     (funcall pi-prime :encoded)        ;; ✓ (4.20)
               :omega   (funcall omega-prime :encoded)     ;; ✓ (4.16) via accumulate
               :xi      (funcall xi-prime :encoded)        ;; ✓ (4.16) via accumulate
               :theta   (funcall sigma :segment :theta)    ;; TODO: θ' from accumulate
               ;; Propagate non-segment Merkle entries (service accounts etc.)
               :extra-kvs (funcall delta-prime :extra-kvs))))))))))

;;; ═════════════════════════════════════════════════════════════════
;;; IMPLEMENTATION STATUS
;;; ═════════════════════════════════════════════════════════════════
;;;
;;; ✓ τ  — state/tau.lisp     (define-state-closure, :transition)
;;; ✓ η  — state/eta.lisp     (define-state-closure, :transition)
;;; ✓ κ  — state/kappa.lisp   (define-state-closure, :transition)
;;; ✓ λ  — state/lambda.lisp  (define-state-closure, :transition)
;;; ✓ ι  — state/iota.lisp    (define-state-closure, codec — no transition, via accumulate)
;;; ✓ β  — state/beta.lisp    (define-state-closure, :transition-dagger/:transition)
;;; ✓ ψ  — state/psi.lisp     (define-state-closure, :transition)
;;; ✓ ρ  — state/rho.lisp     (define-state-closure, :transition-dagger/:transition-ddagger/:transition)
;;; ✓ γ  — state/gamma.lisp   (define-state-closure, :transition)
;;; ✓ σ  — state/sigma.lisp   (byte store, :load/:merkle-kvs/:state-root)
;;; ✓ α  — state/alpha.lisp   (codec-only, no :transition — via accumulate)
;;; ✓ ϕ  — state/phi.lisp     (codec-only, no :transition — via accumulate)
;;; ✓ δ  — state/delta.lisp   (codec-only, extra-kvs C(255,s) — via accumulate)
;;; ✓ π  — state/pi.lisp      (define-state-closure, :transition)
;;; ✓ χ  — state/chi.lisp     (codec-only, no :transition — via accumulate)
;;; ✓ ω  — state/omega.lisp   (codec-only, no :transition — via accumulate)
;;; ✓ ξ  — state/xi.lisp      (codec-only, no :transition — via accumulate)
;;; ✓ θ  — state/theta.lisp   (codec-only, no :transition — via accumulate)
;;; ✓ Acc — accumulate.lisp   (orchestrator, GP §12)
