;;;; package.lisp — Single source of truth for JOTL exports
;;;;
;;;; ALL exports are declared here. No (export ...) in source files.
;;;; Clean rebuild: only exports for active code (not archive/).

(defpackage #:jotl
  (:use #:cl #:alexandria)
  (:import-from #:jam.ffi
                #:blake2b-256
                #:keccak-256
                #:hex-string-to-bytes
                #:bytes-to-hex-string
                #:compute-core-assignments)
  (:documentation "JAM On The Lisp — State Transition Machine")
  (:export
   ;; ═══════════════════════════════════════════
   ;; Lib — Macros
   ;; ═══════════════════════════════════════════
   #:define-state-closure
   
   ;; ═══════════════════════════════════════════
   ;; Lib — Constants
   ;; ═══════════════════════════════════════════
   #:*chain*
   #:chain
   #:switch-chain
   #:with-chain
   #:num-validators
   #:num-cores
   #:slot-duration
   #:epoch-duration
   #:max-block-gas
   #:max-refine-gas
   #:preimage-expunge-period
   #:contest-duration
   #:tickets-per-validator
   #:max-tickets-per-extrinsic
   #:rotation-period
   #:num-ec-pieces-per-segment
   ;; Protocol constants (GP I.4.4)
   #:+zero-hash+ #:+mmr-peak-prefix+
   #:+history-size+ #:+availability-timeout+
   #:+max-work-items+ #:+max-dependencies+
   #:+max-lookup-anchor-age+ #:+max-auth-pool+ #:+auth-queue-size+
   #:+min-service-index+ #:+max-work-package-extrinsics+
   #:+accumulation-gas+ #:+is-authorized-gas+
   #:+min-balance+ #:+min-balance-per-item+ #:+min-balance-per-octet+
   #:+audit-tranche-period+ #:+audit-bias-factor+
   #:+max-is-authorized-code+ #:+max-service-code+
   #:+erasure-piece-size+ #:+segment-size+
   #:+max-imports+ #:+max-exports+
   #:+max-unbounded-blob-size+ #:+transfer-memo-size+
   #:+pvm-address-alignment+ #:+pvm-init-data-size+
   #:+pvm-page-size+ #:+pvm-init-zone-size+
   ;; Validator key sizes (GP §6.9-6.12)
   #:+bandersnatch-key-size+ #:+ed25519-key-size+
   #:+bls-key-size+ #:+metadata-size+ #:+validator-key-size+
   ;; Context strings X (GP I.4.5)
   #:+ctx-available+     ;; XA
   #:+ctx-beefy+         ;; XB
   #:+ctx-entropy+       ;; XE
   #:+ctx-fallback-seal+ ;; XF
   #:+ctx-guarantee+     ;; XG
   #:+ctx-announce+      ;; XI
   #:+ctx-ticket-seal+   ;; XT
   #:+ctx-audit+         ;; XU
   #:+ctx-valid+         ;; X⊤
   #:+ctx-invalid+       ;; X⊥
   
   ;; ═══════════════════════════════════════════
   ;; Lib — Codec Primitives (GP Appendix C)
   ;; ═══════════════════════════════════════════
   #:encode-fixed-le #:decode-fixed-le
   #:E1 #:E2 #:E4 #:E8
   #:encode-u8 #:encode-u16 #:encode-u32 #:encode-u64
   #:decode-u8 #:decode-u16 #:decode-u32 #:decode-u64
   #:encode-compact #:decode-compact
   #:encode-sequence #:decode-sequence
   #:encode-option #:decode-option
   #:ensure-bytes
   
   ;; ═══════════════════════════════════════════
   ;; Lib — State Keys (GP Appendix D)
   ;; ═══════════════════════════════════════════
   #:state-key #:service-key #:state-key-for-segment
   #:+C1+ #:+C2+ #:+C3+ #:+C4+ #:+C5+ #:+C6+ #:+C7+ #:+C8+
   #:+C9+ #:+C10+ #:+C11+ #:+C12+ #:+C13+ #:+C14+ #:+C15+ #:+C16+
   #:+state-key-names+
   
   ;; ═══════════════════════════════════════════
   ;; Lib — Codec Types
   ;; ═══════════════════════════════════════════
   #:bytes<
   #:encode-auth-pools
   #:encode-hash-32 #:decode-hash-32
   #:encode-ed25519-key #:decode-ed25519-key
   #:encode-bandersnatch-key #:decode-bandersnatch-key
   #:encode-signature-96 #:decode-signature-96
   #:encode-validator #:decode-validator
   #:encode-validator-sequence #:decode-validator-sequence
   #:encode-full-validator #:decode-full-validator
   #:encode-full-validator-sequence #:decode-full-validator-sequence
   #:encode-service-account-index #:decode-service-account-index
   #:encode-validator-index #:decode-validator-index
   
   ;; ═══════════════════════════════════════════
   ;; Lib — Merkle Trie
   ;; ═══════════════════════════════════════════
   #:trie-bit #:trie-branch #:trie-leaf
   #:merkle-root #:compute-state-root #:pad-key-to-32
   
   ;; ═══════════════════════════════════════════
   ;; Lib — MMR (GP Appendix E)
   ;; ═══════════════════════════════════════════
   #:mmr-merge
   #:mmr-super-peak
   #:mmr-append
   #:mmr-leaf-count
   #:mmr-from-leaves
   #:binary-merkle-root-keccak
   
   ;; ═══════════════════════════════════════════
   ;; Bloc — Header H (GP §5)
   ;; ═══════════════════════════════════════════
   #:make-header
   #:decode-header
   ;; HE sub-closure (GP §6.6)
   #:make-epoch-mark
   ;; HW sub-closure (GP §6.6)
   #:make-tickets-mark
   
   ;; ═══════════════════════════════════════════
   ;; Bloc — Extrinsic codec (GP §4.3)
   ;; ═══════════════════════════════════════════
   ;; No extrinsic closure — raw data consumed by state closures.
   #:encode-extrinsic-data
   #:decode-extrinsic-data
   #:compute-extrinsic-hash
   
   ;; ═══════════════════════════════════════════
   ;; Bloc — B ≡ (H, ET, ED, EP, EA, EG) (GP §4.2)
   ;; ═══════════════════════════════════════════
   #:make-block
   #:decode-block
   
   ;; ═══════════════════════════════════════════
   ;; Bloc — Codec helpers
   ;; ═══════════════════════════════════════════
   #:encode-work-report #:decode-work-report
   #:encode-ticket #:decode-ticket
   #:encode-tickets-extrinsic #:decode-tickets-extrinsic
   #:encode-disputes-extrinsic #:decode-disputes-extrinsic
   #:encode-preimages-extrinsic #:decode-preimages-extrinsic
   #:encode-assurances-extrinsic #:decode-assurances-extrinsic
   #:encode-guarantees-extrinsic #:decode-guarantees-extrinsic
   #:encode-guarantee-signatures #:decode-guarantee-signatures
   
   ;; ═══════════════════════════════════════════
   ;; Bloc — Validation (GP §5)
   ;; ═══════════════════════════════════════════
   #:compute-offenders-mark
   #:validate-extrinsic-hash
   #:validate-block
   #:validate-timeslot-not-future
   #:validate-parent-hash
   #:validate-header-post-transition
   
   ;; ═══════════════════════════════════════════
   ;; State — σ overall (GP §4.4)
   ;; ═══════════════════════════════════════════
   #:make-sigma-state #:load-state-from-keyvals
   #:+sigma-segment-order+
   #:sigma-decode-segment #:segment-key-p
   
   ;; ═══════════════════════════════════════════
   ;; State — τ Timeslot (GP §6.1-6.2)
   ;; ═══════════════════════════════════════════
   #:make-tau-state #:decode-tau-state
   #:tau-state-slot
   
   ;; ═══════════════════════════════════════════
   ;; State — η Entropy (GP §6.21-6.23)
   ;; ═══════════════════════════════════════════
   #:make-eta-state #:decode-eta-state
   
   ;; ═══════════════════════════════════════════
   ;; State — κ Current Validators (GP §6.15)
   ;; ═══════════════════════════════════════════
   #:make-kappa-state #:decode-kappa-state
   
   ;; ═══════════════════════════════════════════
   ;; State — λ Archived Validators (GP §6.16)
   ;; ═══════════════════════════════════════════
   #:make-lambda-state #:decode-lambda-state
   
   ;; ═══════════════════════════════════════════
   ;; State — ι Enqueued Validators (GP §6.7)
   ;; ═══════════════════════════════════════════
   #:make-iota-state #:decode-iota-state
   
   ;; ═══════════════════════════════════════════
   ;; State — β Recent History (GP §7)
   ;; ═══════════════════════════════════════════
   #:make-beta-state #:decode-beta-state
   #:make-history-record
   #:encode-block-info #:decode-block-info
   #:encode-reported-wp #:decode-reported-wp
   
   ;; ═══════════════════════════════════════════
   ;; State — γ Safrole (GP §6)
   ;; ═══════════════════════════════════════════
   #:make-gamma-state #:decode-gamma-state
   #:safrole-error #:safrole-error-code #:safrole-error-detail
   ;; Gamma-specific codec helpers
   #:encode-state-ticket #:decode-state-ticket
   #:encode-gamma-sealing #:decode-gamma-sealing
   ;; Gamma standalone functions
   #:filter-offenders #:outside-in-sequencer
   #:fallback-key-sequence #:closing-offset
   #:compute-epoch-mark #:compute-winning-tickets-mark
   #:validate-header-safrole
   
   ;; ═══════════════════════════════════════════
   ;; State — ψ Judgments (GP §10)
   ;; ═══════════════════════════════════════════
   #:make-psi-state #:decode-psi-state
   #:disputes-error #:disputes-error-code #:disputes-error-detail
   #:super-majority
   
   ;; ═══════════════════════════════════════════
   ;; State — ρ Core Assignments (GP §10-12)
   ;; ═══════════════════════════════════════════
   #:make-rho-state #:decode-rho-state
   #:encode-rho-assignment #:decode-rho-assignment
   #:assurance-error #:assurance-error-code #:assurance-error-detail
   #:guarantee-error #:guarantee-error-code #:guarantee-error-detail
   
   ;; ═══════════════════════════════════════════
   ;; State — π Validator Statistics (GP §13)
   ;; ═══════════════════════════════════════════
   #:make-pi-state #:decode-pi-state
   #:encode-validator-activity #:decode-validator-activity
   #:encode-validators-statistics #:decode-validators-statistics
   
   ;; ═══════════════════════════════════════════
   ;; State — α Authorizations (GP §8.1)
   ;; ═══════════════════════════════════════════
   #:make-alpha-state #:decode-alpha-state
   
   ;; ═══════════════════════════════════════════
   ;; State — ϕ Authorization Queue (GP §8.1-8.2)
   ;; ═══════════════════════════════════════════
   #:make-phi-state #:decode-phi-state
   
   ;; ═══════════════════════════════════════════
   ;; State — δ Service Accounts (GP §9)
   ;; ═══════════════════════════════════════════
   #:make-delta-state #:decode-delta-state
   #:load-delta-from-extra-kvs
   
   ;; ═══════════════════════════════════════════
   ;; State — χ Privileged IDs (GP §9.4)
   ;; ═══════════════════════════════════════════
   #:make-chi-state #:decode-chi-state
   
   ;; ═══════════════════════════════════════════
   ;; State — ω Accumulation Queue (GP §12.3)
   ;; ═══════════════════════════════════════════
   #:make-omega-state #:decode-omega-state
   
   ;; ═══════════════════════════════════════════
   ;; State — ξ Accumulation History (GP §12.1)
   ;; ═══════════════════════════════════════════
   #:make-xi-state #:decode-xi-state
   
   ;; ═══════════════════════════════════════════
   ;; State — θ Accumulation Outputs (GP §12.25)
   ;; ═══════════════════════════════════════════
   #:make-theta-state #:decode-theta-state
   
   ;; ═══════════════════════════════════════════
   ;; §12 Accumulate Orchestrator (GP §12)
   ;; ═══════════════════════════════════════════
   #:transition-accumulate
   #:extract-operand-tuples
   #:group-by-service
   #:deferred-transfers-for-service
   #:accumulate-service
   #:accumulate-report
   #:accumulate-all
   
   ;; ═══════════════════════════════════════════
   ;; Υ — Orchestrator (GP §4.1)
   ;; ═══════════════════════════════════════════
   #:transition-state
   #:apply-block
   
   ;; ═══════════════════════════════════════════
   ;; Import — M1 Block Importer (GP Milestone 1)
   ;; ═══════════════════════════════════════════
   #:decode-raw-state-bin
   #:decode-genesis-bin
   #:decode-trace-step-bin
   #:load-genesis
   #:load-trace-step
   #:import-block
   #:run-trace
   
   ;; ═══════════════════════════════════════════
   ;; Fuser — Unix Socket API
   ;; ═══════════════════════════════════════════
   #:encode-raw-state-bin
   #:fuser-init-state
   #:fuser-add-block
   #:fuser-debug
   #:fuser-set-state
   #:fuser-start
   #:fuser-run-trace
   #:fuser-run-all-traces
   #:*fuser-sigma*
   #:*fuser-block-count*
   
   ;; ═══════════════════════════════════════════
   ;; Crypto (re-exported from jam.ffi)
   ;; ═══════════════════════════════════════════
   #:blake2b-256 #:keccak-256
   #:hex-string-to-bytes #:bytes-to-hex-string
   
   ;; Version
   #:*jotl-version*))
