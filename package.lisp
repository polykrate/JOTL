;;;; package.lisp — Single source of truth for JOTL exports
;;;;
;;;; ALL exports are declared here. No (export ...) in source files.

(defpackage #:jotl
  (:use #:cl #:alexandria)
  (:import-from #:jam.ffi
                #:blake2b-256
                #:keccak-256
                #:hex-string-to-bytes
                #:bytes-to-hex-string
                #:compute-core-assignments)
  (:documentation "JAM On The Lisp — Pure Functional Programming")
  (:export
   ;; ═══════════════════════════════════════════
   ;; Core — Macros
   ;; ═══════════════════════════════════════════
   #:define-value-object
   
   ;; ═══════════════════════════════════════════
   ;; Core — Constants
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
   ;; Context strings X (GP I.4.5) — all 10
   #:+ctx-available+     ;; XA — assurances
   #:+ctx-beefy+         ;; XB — BEEFY commitment
   #:+ctx-entropy+       ;; XE — entropy VRF
   #:+ctx-fallback-seal+ ;; XF — fallback seal
   #:+ctx-guarantee+     ;; XG — guarantees
   #:+ctx-announce+      ;; XI — audit announcement
   #:+ctx-ticket-seal+   ;; XT — ticket seal / regular seal
   #:+ctx-audit+         ;; XU — audit selection entropy
   #:+ctx-valid+         ;; X⊤ — valid judgement
   #:+ctx-invalid+       ;; X⊥ — invalid judgement
   
   ;; ═══════════════════════════════════════════
   ;; Codec — Primitives (GP Appendix C)
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
   ;; Codec — State Keys (GP Appendix D)
   ;; ═══════════════════════════════════════════
   #:state-key #:service-key #:state-key-for-segment
   #:+C1+ #:+C2+ #:+C3+ #:+C4+ #:+C5+ #:+C6+ #:+C7+ #:+C8+
   #:+C9+ #:+C10+ #:+C11+ #:+C12+ #:+C13+ #:+C14+ #:+C15+ #:+C16+
   #:+state-key-names+
   
   ;; ═══════════════════════════════════════════
   ;; Codec — Types
   ;; ═══════════════════════════════════════════
   #:bytes<
   #:encode-hash-32 #:decode-hash-32
   #:encode-ed25519-key #:decode-ed25519-key
   #:encode-bandersnatch-key #:decode-bandersnatch-key
   #:encode-signature-96 #:decode-signature-96
   ;; Block epoch mark validators (64B: bandersnatch + ed25519)
   #:encode-validator #:decode-validator
   #:encode-validator-sequence #:decode-validator-sequence
   ;; Full state validators (336B: ed25519 + bandersnatch + bls + metadata)
   #:encode-full-validator #:decode-full-validator
   #:encode-full-validator-sequence #:decode-full-validator-sequence
   ;; Other types
   #:encode-service-account-index #:decode-service-account-index
   #:encode-validator-index #:decode-validator-index
   
   ;; ═══════════════════════════════════════════
   ;; Utils — Merkle Trie
   ;; ═══════════════════════════════════════════
   #:trie-bit #:trie-branch #:trie-leaf
   #:merkle-root #:compute-state-root #:pad-key-to-32
   
   ;; ═══════════════════════════════════════════
   ;; Utils — MMR (GP Appendix E)
   ;; ═══════════════════════════════════════════
   #:mmr-merge
   #:mmr-super-peak
   #:mmr-append
   #:mmr-leaf-count
   #:mmr-from-leaves
   #:binary-merkle-root-keccak
   
   ;; ═══════════════════════════════════════════
   ;; Block — Header (GP §5)
   ;; ═══════════════════════════════════════════
   #:make-header
   #:encode-header #:encode-header-unsealed #:decode-header
   #:header-parent-hash #:header-state-root #:header-extrinsic-hash
   #:header-slot #:header-epoch-mark #:header-tickets-mark
   #:header-author-index #:header-entropy-source #:header-offenders-mark
   #:header-seal #:header-hash
   
   ;; ═══════════════════════════════════════════
   ;; Block — Extrinsic (GP §4.3)
   ;; ═══════════════════════════════════════════
   #:make-extrinsic
   #:encode-extrinsic #:decode-extrinsic
   #:extrinsic-tickets #:extrinsic-disputes #:extrinsic-preimages
   #:extrinsic-assurances #:extrinsic-guarantees
   #:compute-extrinsic-hash
   
   ;; ═══════════════════════════════════════════
   ;; Block — B ≡ (H, E) (GP §4.2)
   ;; ═══════════════════════════════════════════
   #:make-block
   #:encode-block #:decode-block
   #:block-header #:block-extrinsic
   #:block-tickets #:block-disputes #:block-preimages
   #:block-assurances #:block-guarantees #:block-slot
   
   ;; ═══════════════════════════════════════════
   ;; Block — Validation (GP §5)
   ;; ═══════════════════════════════════════════
   ;; Intrinsic (called by Υ):
   #:validate-extrinsic-hash
   #:validate-block
   ;; Environmental (called by import-block / node layer):
   #:validate-timeslot-not-future
   #:validate-parent-hash
   
   ;; ═══════════════════════════════════════════
   ;; STF — State σ (GP §4.4)
   ;; ═══════════════════════════════════════════
   #:make-state #:make-genesis-state
   #:state-tau #:state-kappa #:state-lambda #:state-iota
   #:state-gamma #:state-eta #:state-beta #:state-delta
   #:state-rho #:state-alpha #:state-phi #:state-chi
   #:state-psi #:state-pi #:state-omega #:state-xi #:state-theta
   
   ;; ═══════════════════════════════════════════
   ;; STF — Timeslot τ (GP §6.1-6.2)
   ;; ═══════════════════════════════════════════
   #:timeslot-to-epoch-and-phase
   #:timeslot-epoch #:timeslot-phase
   #:epoch-phase-to-timeslot
   #:new-epoch-p
   #:timeslot-from-header
   #:transition-tau
   #:encode-state-tau #:decode-state-tau
   
   ;; ═══════════════════════════════════════════
   ;; STF — Recent History β (GP §7)
   ;; ═══════════════════════════════════════════
   #:+history-size+
   #:make-beta
   #:make-history-record
   #:beta-history
   #:beta-mmr-peaks
   #:transition-beta-dagger
   #:transition-beta
   #:transition-beta-with-root
   #:transition-beta-from-inputs
   #:bounded-append
   #:encode-state-beta #:decode-state-beta
   #:encode-block-info #:decode-block-info
   #:encode-reported-wp #:decode-reported-wp
   #:encode-mmr-peak #:decode-mmr-peak
   
   ;; ═══════════════════════════════════════════
   ;; STF — Entropy η (GP §6.21-6.23)
   ;; ═══════════════════════════════════════════
   #:transition-eta
   #:encode-state-eta #:decode-state-eta
   
   ;; ═══════════════════════════════════════════
   ;; STF — Judgments ψ (GP §10)
   ;; ═══════════════════════════════════════════
   #:transition-psi
   #:classify-verdict
   #:compute-offenders-mark
   #:super-majority
   #:disputes-error #:disputes-error-code #:disputes-error-detail
   ;; Helpers (used by psi + rho)
   #:hash< #:sorted-unique-p #:member-hash
   #:judgment-signing-context #:guarantee-signing-context
   #:validator-ed25519-key #:build-valid-key-set
   ;; Codecs
   #:encode-state-psi #:decode-state-psi
   
   ;; ═══════════════════════════════════════════
   ;; STF — Validator Keys κ (GP §6.15)
   ;; ═══════════════════════════════════════════
   #:transition-kappa
   #:encode-state-kappa #:decode-state-kappa
   
   ;; ═══════════════════════════════════════════
   ;; STF — Archived Keys λ (GP §6.16)
   ;; ═══════════════════════════════════════════
   #:transition-lambda
   #:encode-state-lambda #:decode-state-lambda
   
   ;; ═══════════════════════════════════════════
   ;; STF — Enqueued Keys ι (GP §8)
   ;; ═══════════════════════════════════════════
   #:encode-state-iota #:decode-state-iota
   
   ;; ═══════════════════════════════════════════
   ;; STF — Safrole γ (GP §6)
   ;; ═══════════════════════════════════════════
   #:make-gamma
   #:gamma-pending-keys #:gamma-ring-commitment
   #:gamma-sealing #:gamma-accumulator
   #:transition-gamma
   #:filter-offenders #:+null-validator-key+
   #:outside-in-sequencer          ;; Z  (GP 6.25)
   #:fallback-key-sequence         ;; F  (GP 6.26)
   #:closing-offset                ;; Y  (GP §6)
   #:compute-epoch-mark            ;; HE (GP 6.27)
   #:compute-winning-tickets-mark  ;; HW (GP 6.28)
   ;; Ticket processing (GP 6.29-6.35)
   #:process-ticket-extrinsic
   #:validate-ticket-count #:validate-ticket-proof
   #:extract-new-tickets #:ticket-id<
   #:validate-new-tickets-sorted #:validate-new-tickets-no-duplicates
   #:compute-accumulator-prime #:validate-tickets-included
   #:safrole-error #:safrole-error-code #:safrole-error-detail
   #:validate-seal #:validate-seal-tickets #:validate-seal-fallback
   #:validate-entropy-source #:seal-key-index
   #:encode-state-gamma #:decode-state-gamma
   #:encode-gamma-sealing #:decode-gamma-sealing
   #:encode-state-ticket #:decode-state-ticket
   
   ;; ═══════════════════════════════════════════
   ;; STF — Core Assignments ρ (GP §10-12)
   ;; ═══════════════════════════════════════════
   #:make-rho
   #:encode-state-rho #:decode-state-rho
   #:encode-rho-assignment #:decode-rho-assignment
   #:assignment-report-hash
   #:transition-rho-dagger
   ;; Assurances (§11)
   #:transition-rho-ddagger
   #:compute-ready-reports
   #:assurance-error #:assurance-error-code #:assurance-error-detail
   #:assurance-signing-payload
   #:bitfield-core-set-p #:bitfield-flagged-cores #:count-core-votes
   #:validate-assurances-sorted-unique
   #:validate-assurance-anchor #:validate-assurance-validator-index
   #:validate-assurance-cores-engaged #:validate-assurance-signature
   #:report-stale-p
   ;; Guarantees (§11-12)
   #:transition-rho
   #:guarantee-error #:guarantee-error-code #:guarantee-error-detail
   #:guarantee-signing-payload
   #:guarantor-assignments #:guarantor-assignments-star
   #:assignments-for-guarantee
   #:phi-filter
   #:validate-guarantees-sorted-unique
   #:validate-guarantee-core-index
   #:validate-guarantee-results-present
   #:validate-guarantee-slot-age
   #:validate-guarantee-sufficient-signatures
   #:validate-guarantee-signatures-sorted-unique
   #:validate-guarantee-validator-index
   #:validate-guarantee-not-banned
   #:validate-guarantee-core-assignment
   #:validate-guarantee-signature
   #:validate-guarantee-core-not-engaged
   #:validate-guarantee-anchor
   #:validate-guarantee-lookup-anchor
   #:validate-guarantee-service-ids
   #:validate-guarantee-code-hashes
   #:validate-guarantee-authorization
   #:validate-guarantee-gas
   #:validate-guarantee-item-gas
   #:validate-guarantee-dependencies-count
   #:validate-guarantee-output-size
   #:validate-guarantee-not-duplicate
   #:validate-guarantee-dependencies
   #:validate-guarantee-segment-root-lookup
   #:compute-output-packages-and-reporters
   #:update-cores-statistics #:update-services-statistics
   #:compute-core-assignments
   
   ;; ═══════════════════════════════════════════
   ;; STF — Υ(σ,B)→σ' (GP §4.1)
   ;; ═══════════════════════════════════════════
   #:transition-state
   #:apply-block
   
   ;; ═══════════════════════════════════════════
   ;; Crypto (re-exported from jam.ffi)
   ;; ═══════════════════════════════════════════
   #:blake2b-256 #:keccak-256
   #:hex-string-to-bytes #:bytes-to-hex-string
   
   ;; Version
   #:*jotl-version*))
