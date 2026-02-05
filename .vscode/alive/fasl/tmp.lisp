;;;; package.lisp
;;;; Package definition for JOTL state structures and serialization

(defpackage #:jotl-state
  (:use #:cl #:jotl-codec)
  (:import-from #:jotl-config
                ;; Common types
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
   
   ;; γ - SAFROLE state
   #:safrole-state
   #:make-safrole-state
   #:safrole-state-current-epoch
   #:safrole-state-tickets-current
   #:safrole-state-tickets-previous
   #:safrole-state-entropy
   #:safrole-state-tickets-accumulator
   #:safrole-state-seal-keys
   
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
   
   ;; β - Recent blocks
   #:recent-blocks
   #:make-recent-blocks
   #:recent-blocks-hashes
   
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
   
   ;; χ - Privileged services
   #:privileged-service
   #:make-privileged-service
   #:privileged-service-service-id
   #:privileged-service-privilege-type
   
   ;; ψ - Judgements
   #:judgement-entry
   #:make-judgement-entry
   #:judgement-entry-target
   #:judgement-entry-verdict
   #:judgement-entry-judged-timeslot
   
   ;; π - Validator statistics
   #:validator-stats
   #:make-validator-stats
   #:validator-stats-validator-index
   #:validator-stats-blocks-produced
   #:validator-stats-votes-cast
   #:validator-stats-slashes
   #:validator-stats-rewards
   
   ;; σ - Complete state
   #:jam-state
   #:make-jam-state
   #:jam-state-core-authorizations
   #:jam-state-recent-blocks
   #:jam-state-theta
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
   #:jam-state-accumulated-packages))
