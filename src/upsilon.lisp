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
;;;;     β'  < (H, EC, β†H, θ')
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
         ;; Extrinsics are raw data — consumed directly by closures.
         (h   (funcall block :header))
         (e-t (funcall block :tickets))        ;; ET
         (e-d (funcall block :disputes))       ;; ED
         (e-p (funcall block :preimages))      ;; EP
         (e-a (funcall block :assurances))     ;; EA
         (e-g (funcall block :guarantees)))    ;; EG

    ;; ═══════════════════════════════════════════════════════════
    ;; WAVE 0 — τ' < (H)
    ;; ═══════════════════════════════════════════════════════════
    (let* ((tau       (funcall sigma :load :tau))
           (tau-prime (funcall tau :transition :header h)))

      ;; ═══════════════════════════════════════════════════════════
      ;; WAVE 1 — independent, all depend on prior σ + B only
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
             (psi-prime    (funcall psi :transition
                                    :disputes e-d
                                    :tau tau
                                    :kappa kappa
                                    :lambda-prev lambda-prev))
             ;; (4.12) ρ†  < (ED, ρ)  [via v-list from ψ (10.12)]
             (rho-dagger   (funcall rho :transition-dagger
                                    :v-list (funcall psi-prime :v-list))))

        ;; ═══════════════════════════════════════════════════════════
        ;; WAVE 2 — depends on Wave 1
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
          ;; WAVE 3 — depends on Wave 2
          ;; ═══════════════════════════════════════════════════════════
          (let* (;; Load closures needed by Wave 3
                 (alpha (funcall sigma :load :alpha))
                 (delta (load-delta-from-extra-kvs (funcall sigma :extra-kvs)))

                 ;; (4.14) ρ'  < (EG, ρ‡, κ, τ', ψ', α, δ, β†, λ, η)
                 (rho-prime (funcall rho-ddagger :transition
                                     :guarantees e-g
                                     :tau-prime tau-prime
                                     :kappa kappa
                                     :lambda-prev lambda-prev
                                     :eta eta-prime
                                     :psi-prime psi-prime
                                     :recent-blocks beta-dagger
                                     :alpha alpha
                                     :delta delta))

                 ;; (4.16) (ω', ξ', δ†, χ', ι', ϕ', θ', S) < (R*, ω, ξ, δ, χ, ι, ϕ, τ, τ')
                 (r-star (funcall rho-ddagger :reported))
                 (omega  (funcall sigma :load :omega))
                 (xi     (funcall sigma :load :xi))
                 (chi    (funcall sigma :load :chi))
                 (phi    (funcall sigma :load :phi))
                 (accum  (transition-accumulate
                          r-star omega xi delta chi iota phi
                          tau tau-prime))
                 ;; Destructure accumulation results
                 (omega-prime   (getf accum :omega-prime))
                 (xi-prime      (getf accum :xi-prime))
                 (delta-dagger  (getf accum :delta-dagger))
                 (chi-prime     (getf accum :chi-prime))
                 (iota-prime    (getf accum :iota-prime))
                 (phi-prime     (getf accum :phi-prime))
                 (theta-prime   (getf accum :theta-prime))
                 (service-stats (getf accum :service-stats)))

            ;; ═══════════════════════════════════════════════════════════
            ;; WAVE 4 — merge / join
            ;; ═══════════════════════════════════════════════════════════
            (let* ((pi-stats (funcall sigma :load :pi))

                   ;; (4.19) α' < (H, EC, ϕ', α)
                   (alpha-prime (funcall alpha :transition
                                        :tau tau
                                        :tau-prime tau-prime
                                        :phi-prime phi-prime
                                        :offender-auth-hashes nil)) ;; TODO: derive from EC

                   ;; (4.18) δ' < (EP, δ†, τ')
                   (delta-prime (funcall delta-dagger :transition
                                        :preimages e-p
                                        :tau-prime tau-prime))

                   ;; (4.20) π' < (EG, EP, EA, ET, τ, κ', π, H, S)
                   (pi-prime (funcall pi-stats :transition
                                      :header h
                                      :tau tau :tau-prime tau-prime
                                      :tickets e-t :preimages e-p
                                      :assurances e-a :guarantees e-g
                                      :kappa-prime kappa-prime
                                      :accum-stats service-stats
                                      :r-star r-star))

                   ;; (4.17) β' < (H, EC, β†H, θ')
                   (beta-prime (funcall beta-dagger :transition
                                        :header h
                                        :guarantees e-g
                                        :theta-prime theta-prime)))

              ;; ── BUILD σ' — re-encode closures back to bytes ──
              (make-sigma-state
               :alpha   (funcall alpha-prime :encoded)
               :beta    (funcall beta-prime :encoded)
               :gamma   (funcall gamma-prime :encoded)
               :delta   nil                              ;; δ uses extra-kvs
               :eta     (funcall eta-prime :encoded)
               :iota    (funcall iota-prime :encoded)
               :kappa   (funcall kappa-prime :encoded)
               :lambda* (funcall lambda-prime :encoded)
               :rho     (funcall rho-prime :encoded)
               :tau     (funcall tau-prime :encoded)
               :phi     (funcall phi-prime :encoded)
               :chi     (funcall chi-prime :encoded)
               :psi     (funcall psi-prime :encoded)
               :pi*     (funcall pi-prime :encoded)
               :omega   (funcall omega-prime :encoded)
               :xi      (funcall xi-prime :encoded)
               :theta   (if theta-prime
                            (funcall theta-prime :encoded)
                            (funcall sigma :segment :theta))
               :extra-kvs (funcall delta-prime :extra-kvs)))))))))
