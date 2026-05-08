;;;; upsilon.lisp — Υ(σ, B) → σ'  (implementation of σ :transition)
;;;; Gray Paper §4.1 & §4.2.1
;;;;
;;;; IMPLEMENTATION of σ's :transition message — composes all sub-transitions
;;;; in wave-ordered dependency graph.
;;;;
;;;; σ is the meta-closure (pure byte store). Its :transition message
;;;; delegates here: (funcall sigma :transition :block B) calls
;;;; transition-state(σ, B), which loads components lazily via
;;;; (funcall sigma :decode-segment :kw) and re-encodes them back to bytes for σ'.
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
   σ transforms itself via :transition (like every other closure).
   Environmental checks (wall-clock, parent hash) belong to import-block."
  ;; §5.4-5.6: HX — intrinsic validation (extrinsic hash check)
  (multiple-value-bind (valid-p errors) (validate-block block)
    (unless valid-p
      (error "Block validation failed: ~{~A~^, ~}"
             (mapcar #'second errors))))
  (funcall sigma :transition :block block))

;;; ═════════════════════════════════════════════════════════════════
;;; transition-state — σ → σ' (GP §4.2.1)
;;; ═════════════════════════════════════════════════════════════════

(defun transition-state (sigma block)
  "Υ-inner: σ → σ' — Pure state transition following GP dependency graph.
   σ is a byte store. Components are loaded lazily per wave via
   (funcall sigma :decode-segment :kw), then re-encoded back into σ' bytes."
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
    (let* ((tau       (funcall sigma :decode-segment :tau))
           (tau-prime (funcall tau :transition :header h)))

      ;; ═══════════════════════════════════════════════════════════
      ;; WAVE 1 — independent, all depend on prior σ + B only
      ;; ═══════════════════════════════════════════════════════════
      (let* ((beta        (funcall sigma :decode-segment :beta))
             (eta         (funcall sigma :decode-segment :eta))
             (kappa       (funcall sigma :decode-segment :kappa))
             (lambda-prev (funcall sigma :decode-segment :lambda))
             (gamma       (funcall sigma :decode-segment :gamma))
             (psi         (funcall sigma :decode-segment :psi))
             (rho         (funcall sigma :decode-segment :rho))
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
        (let* ((iota (funcall sigma :decode-segment :iota))
               ;; (4.7)  γ'  < (H, T, ET, γ, ι, η', κ', ψ')
               (gamma-prime (funcall gamma :transition
                                     :tau tau :tau-prime tau-prime
                                     :tickets e-t :iota iota
                                     :eta-prime eta-prime :kappa-prime kappa-prime
                                     :psi-prime psi-prime))
               ;; ── Safrole header validation (GP §5-6) ──
               ;; Validate HI, HS, HV, HE, HW against γ'/η'/κ'
               ;; Must happen after γ' is computed.
               (_ (validate-header-safrole h tau tau-prime gamma eta eta-prime
                                           gamma-prime kappa-prime))
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
                 (alpha (funcall sigma :decode-segment :alpha))
                 (delta (funcall sigma :decode-segment :delta))

                 ;; (4.14) ρ'  < (EG, ρ‡, κ', τ', ψ', α, δ, β†, λ, η')
                 (rho-prime (funcall rho-ddagger :transition
                                     :guarantees e-g
                                     :tau-prime tau-prime
                                     :kappa kappa-prime
                                     :lambda-prev lambda-prev
                                     :eta eta-prime
                                     :psi-prime psi-prime
                                     :recent-blocks beta-dagger
                                     :alpha alpha
                                     :delta delta))

                 ;; (4.16) (ω', ξ', δ†, χ', ι', ϕ', θ', S) < (R*, ω, ξ, δ, χ, ι, ϕ, τ, τ')
                 (r-star (funcall rho-ddagger :reported))
                 (omega  (funcall sigma :decode-segment :omega))
                 (xi     (funcall sigma :decode-segment :xi))
                 (chi    (funcall sigma :decode-segment :chi))
                 (phi    (funcall sigma :decode-segment :phi))
                (accum  (prof :accumulate
                         (transition-accumulate
                          r-star omega xi delta chi iota phi
                          tau tau-prime
                          :eta eta-prime
                          :header h)))
                 ;; Destructure accumulation results
                 (omega-prime   (getf accum :omega-prime))
                 (xi-prime      (getf accum :xi-prime))
                 (delta-dagger  (getf accum :delta-dagger))
                 (chi-prime     (getf accum :chi-prime))
                 (iota-prime    (getf accum :iota-prime))
                 (phi-prime     (getf accum :phi-prime))
                 (theta-prime   (getf accum :theta-prime))
                 (commitments   (getf accum :commitments))
                 (service-stats (getf accum :service-stats)))

            ;; ═══════════════════════════════════════════════════════════
            ;; WAVE 4 — merge / join
            ;; ═══════════════════════════════════════════════════════════
            (let* ((pi-stats (funcall sigma :decode-segment :pi))

                   ;; (4.19) α' < (H, EC, ϕ', α)
                   ;; ρ travels through the transition — ask it directly.
                   (offender-auth-hashes
                    (funcall rho :offender-auth-hashes e-d))

                   (alpha-prime (funcall alpha :transition
                                        :tau tau
                                        :tau-prime tau-prime
                                        :phi-prime phi-prime
                                        :offender-auth-hashes offender-auth-hashes))

                   ;; (4.18) δ' < (EP, δ†, τ')
                   (delta-prime (funcall delta-dagger :transition
                                        :preimages e-p
                                        :tau-prime tau-prime))

                   ;; (4.20) π' < (EG, EP, EA, ET, τ, κ', π, H, S, κ, λ)
                   (pi-prime (funcall pi-stats :transition
                                      :header h
                                      :tau tau :tau-prime tau-prime
                                      :tickets e-t :preimages e-p
                                      :assurances e-a :guarantees e-g
                                      :kappa-prime kappa-prime
                                      :kappa kappa
                                      :lambda-prev lambda-prev
                                      :accum-stats service-stats
                                      :r-star r-star))

                   ;; (4.17) β' < (H, EC, β†H, θ')
                   (beta-prime (funcall beta-dagger :transition
                                        :header h
                                        :guarantees e-g
                                        :theta-prime commitments)))

              ;; ── BUILD σ' — re-encode closures back to bytes ──
              ;; Pass parent's Merkle trie + KV index for incremental state-root.
              ;; On σ' state-root computation, the trie is updated with only
              ;; the changed keys (O(K log N) instead of O(N log N) full recompute).
              (make-sigma-state
               :alpha   (funcall alpha-prime :encode)
               :beta    (funcall beta-prime :encode)
               :gamma   (funcall gamma-prime :encode)
               ;; no :delta segment — δ uses multi-key delta-kvs
               :eta     (funcall eta-prime :encode)
               :iota    (funcall iota-prime :encode)
               :kappa   (funcall kappa-prime :encode)
               :lambda* (funcall lambda-prime :encode)
               :rho     (funcall rho-prime :encode)
               :tau     (funcall tau-prime :encode)
               :phi     (funcall phi-prime :encode)
               :chi     (funcall chi-prime :encode)
               :psi     (funcall psi-prime :encode)
               :pi*     (funcall pi-prime :encode)
               :omega   (funcall omega-prime :encode)
               :xi      (funcall xi-prime :encode)
               :theta   (funcall theta-prime :encode)
               :delta-kvs (prof :delta-save
                            (funcall delta-prime :encode))
               ;; DISABLED incremental Merkle for debugging — force full rebuild
               :parent-trie nil
               :parent-kv-index nil))))))))
