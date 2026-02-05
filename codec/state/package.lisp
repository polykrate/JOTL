;;;; package.lisp
;;;; Package definition for JOTL state structures and serialization

(defpackage #:jotl-state
  (:use #:cl #:jotl-codec)
  (:import-from #:jotl-config
                ;; Common types from jotl-config (defined in src/types.lisp)
                #:hash
                #:hash32
                #:hash256
                #:blob
                #:natural
                #:natural-limited
                #:length-type
                #:ed25519-public-key
                #:ed25519-signature
                #:bandersnatch-public-key
                #:bandersnatch-signature
                #:bls-public-key
                #:bls-signature
                #:service-id
                #:core-id
                #:timeslot
                #:gas-amount
                #:list-to-blob
                #:blob-to-list
                #:hash-zero
                #:hash32-p)
  (:documentation "JAM state structures and serialization (Appendix D)")
  (:export
   
   ;; ══════════════════════════════════════════════════════════════
   ;; STATE STRUCTURES (σ components)
   ;; ══════════════════════════════════════════════════════════════
   
   ;; δ - Service accounts
   #:service-account
   #:make-service-account
   #:service-account-id
   #:service-account-code-hash
   #:service-account-balance
   #:service-account-gas-limit-accumulate
   #:service-account-gas-limit-refine
   #:service-account-memory-pages
   #:service-account-storage-lookup
   #:service-account-preimage-lookup
   #:service-account-threshold-balance
   
   ;; κ - Current validators
   #:validator-keys
   #:make-validator-keys
   #:validator-keys-bandersnatch
   #:validator-keys-ed25519
   #:validator-keys-bls
   
   ;; λ - Archived validators
   #:archived-validator
   #:make-archived-validator
   #:archived-validator-epoch
   #:archived-validator-validator-index
   #:archived-validator-bandersnatch
   #:archived-validator-ed25519
   
   ;; ι - Validator queue
   #:validator-queue-entry
   #:make-validator-queue-entry
   #:validator-queue-entry-bandersnatch
   #:validator-queue-entry-ed25519
   #:validator-queue-entry-bls
   #:validator-queue-entry-deposit
   
   ;; ϕ - Authorization queue
   #:authorization-queue-entry
   #:make-authorization-queue-entry
   #:authorization-queue-entry-service-id
   #:authorization-queue-entry-code-hash
   #:authorization-queue-entry-auth-pool
   
   ;; γ - SAFROLE state (with sub-components γA, γP, γS, γZ)
   #:safrole-state
   #:make-safrole-state
   #:safrole-state-ticket-accumulator    ; γA
   #:safrole-state-next-validators        ; γP
   #:safrole-state-seal-keys              ; γS
   #:safrole-state-tickets-root           ; γZ
   
   ;; α - Core authorizations
   #:core-authorization
   #:make-core-authorization
   #:core-authorization-core-index
   #:core-authorization-auth-pool
   #:core-authorization-authorized-code
   
   ;; ρ - Pending reports
   #:pending-report
   #:make-pending-report
   #:pending-report-core-index
   #:pending-report-report-hash
   #:pending-report-reported-timeslot
   #:pending-report-availability-votes
   
   ;; β - Recent blocks (with sub-components βH and βB)
   #:recent-blocks-info              ; βH
   #:make-recent-blocks-info
   #:recent-blocks-info-block-headers
   #:recent-blocks-info-timeslots
   
   #:merkle-mountain-belt            ; βB
   #:make-merkle-mountain-belt
   #:merkle-mountain-belt-peaks
   #:merkle-mountain-belt-leaves-count
   
   #:recent-blocks                   ; β (composite)
   #:make-recent-blocks
   #:recent-blocks-info
   #:recent-blocks-merkle-belt
   
   ;; ω - Pending work-reports
   #:pending-accumulation
   #:make-pending-accumulation
   #:pending-accumulation-report-hash
   #:pending-accumulation-service-id
   #:pending-accumulation-results
   
   ;; ξ - Accumulated packages
   #:accumulated-package
   #:make-accumulated-package
   #:accumulated-package-package-hash
   #:accumulated-package-accumulated-timeslot
   
   ;; χ - Privileged services (with sub-components χM, χA, χV, χR, χZ)
   #:privileged-services
   #:make-privileged-services
   #:privileged-services-blessed           ; χM
   #:privileged-services-authorizer-assigners  ; χA
   #:privileged-services-designate         ; χV
   #:privileged-services-registrar         ; χR
   #:privileged-services-always-accumulate ; χZ
   
   ;; ψ - Judgements (with sub-components ψB, ψG, ψW, ψO)
   #:judgements
   #:make-judgements
   #:judgements-incorrect-reports       ; ψB
   #:judgements-correct-reports         ; ψG
   #:judgements-unknowable-reports      ; ψW
   #:judgements-offending-validators    ; ψO
   
   ;; π - Validator statistics
   #:validator-stats
   #:make-validator-stats
   #:validator-stats-validator-index
   #:validator-stats-blocks-produced
   #:validator-stats-votes-cast
   #:validator-stats-slashes
   #:validator-stats-rewards
   
   ;; θ - Accumulation outputs
   #:accumulation-output
   #:make-accumulation-output
   #:accumulation-output-service-id
   #:accumulation-output-output-data
   #:accumulation-output-gas-consumed
   
   ;; σ - Complete state (17 components)
   #:jam-state
   #:make-jam-state
   #:jam-state-core-authorizations
   #:jam-state-recent-blocks
   #:jam-state-safrole
   #:jam-state-service-accounts
   #:jam-state-entropy-pool
   #:jam-state-validator-queue
   #:jam-state-current-validators
   #:jam-state-archived-validators
   #:jam-state-pending-reports
   #:jam-state-timeslot
   #:jam-state-authorization-queue
   #:jam-state-privileged-services
   #:jam-state-judgements
   #:jam-state-validator-statistics
   #:jam-state-pending-work-reports
   #:jam-state-accumulated-packages
   #:jam-state-accumulation-outputs
   
   ;; ══════════════════════════════════════════════════════════════
   ;; CODEC FUNCTIONS (encode/decode for all 17 components)
   ;; ══════════════════════════════════════════════════════════════
   
   ;; τ - Timeslot
   #:encode-timeslot
   #:decode-timeslot
   
   ;; η - Entropy pool
   #:encode-entropy-pool
   #:decode-entropy-pool
   
   ;; α - Core authorizations
   #:encode-core-authorization
   #:encode-core-authorizations
   #:decode-core-authorization
   #:decode-core-authorizations
   
   ;; ϕ - Authorization queue
   #:encode-authorization-queue-entry
   #:encode-authorization-queue
   #:decode-authorization-queue-entry
   #:decode-authorization-queue
   
   ;; κ - Current validators
   #:encode-validator-keys
   #:encode-current-validators
   #:decode-validator-keys
   #:decode-current-validators
   
   ;; λ - Archived validators
   #:encode-archived-validator
   #:encode-archived-validators
   #:decode-archived-validator
   #:decode-archived-validators
   
   ;; ι - Validator queue
   #:encode-validator-queue-entry
   #:encode-validator-queue
   #:decode-validator-queue-entry
   #:decode-validator-queue
   
   ;; π - Validator statistics
   #:encode-validator-stats
   #:encode-validator-statistics
   #:decode-validator-stats
   #:decode-validator-statistics
   
   ;; δ - Service accounts
   #:encode-service-account
   #:encode-service-accounts
   #:decode-service-account
   #:decode-service-accounts
   
   ;; ρ - Pending reports
   #:encode-pending-report
   #:encode-pending-reports
   #:decode-pending-report
   #:decode-pending-reports
   
   ;; ω - Accumulation queue
   #:encode-pending-accumulation
   #:encode-accumulation-queue
   #:decode-pending-accumulation
   #:decode-accumulation-queue
   
   ;; ξ - Accumulation history
   #:encode-accumulated-package
   #:encode-accumulation-history
   #:decode-accumulated-package
   #:decode-accumulation-history
   
   ;; θ - Accumulation outputs
   #:encode-accumulation-output
   #:encode-accumulation-outputs
   #:decode-accumulation-output
   #:decode-accumulation-outputs
   
   ;; β - Recent blocks (composite: βH + βB)
   #:encode-recent-blocks-info
   #:decode-recent-blocks-info
   #:encode-merkle-mountain-belt
   #:decode-merkle-mountain-belt
   #:encode-recent-blocks
   #:decode-recent-blocks
   
   ;; γ - SAFROLE (composite: γA + γP + γS + γZ)
   #:encode-ticket-accumulator
   #:decode-ticket-accumulator
   #:encode-next-validators
   #:decode-next-validators
   #:encode-seal-keys
   #:decode-seal-keys
   #:encode-tickets-root
   #:decode-tickets-root
   #:encode-safrole-state
   #:decode-safrole-state
   
   ;; χ - Privileged services (composite: χM + χA + χV + χR + χZ)
   #:encode-blessed-service
   #:decode-blessed-service
   #:encode-authorizer-assigners
   #:decode-authorizer-assigners
   #:encode-designate-service
   #:decode-designate-service
   #:encode-registrar-service
   #:decode-registrar-service
   #:encode-always-accumulate-entry
   #:encode-always-accumulate
   #:decode-always-accumulate-entry
   #:decode-always-accumulate
   #:encode-privileged-services
   #:decode-privileged-services
   
   ;; ψ - Judgements (composite: ψB + ψG + ψW + ψO)
   #:encode-incorrect-reports
   #:decode-incorrect-reports
   #:encode-correct-reports
   #:decode-correct-reports
   #:encode-unknowable-reports
   #:decode-unknowable-reports
   #:encode-offending-validators
   #:decode-offending-validators
   #:encode-judgements
   #:decode-judgements))
