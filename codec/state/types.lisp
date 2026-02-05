;;;; types.lisp
;;;; State-specific type definitions for JAM state (σ)
;;;;
;;;; Based on Graypaper Section 3 (State definitions) and Appendix D (Serialization)
;;;; σ ≡ (α, β, θ, γ, δ, η, ι, κ, λ, ρ, τ, ϕ, χ, ψ, π, ω, ξ)

(in-package :jotl-state)

;;; ═══════════════════════════════════════════════════════════════════
;;; δ - SERVICE ACCOUNTS (Service State)
;;; ═══════════════════════════════════════════════════════════════════
;;; Graypaper Section 3.2: δ is analogous to Ethereum smart contract accounts

(defstruct service-account
  "Service account state (δ[s]).
   
   Each service has storage, code hash, balance, and gas limits."
  
  ;; s: Service identifier (u32)
  (id nil :type (or null service-id))
  
  ;; c: Code hash (32 bytes)
  (code-hash nil :type (or null hash32))
  
  ;; b: Balance (gas token amount)
  (balance nil :type (or null gas-amount))
  
  ;; g_a: Gas limit for accumulate
  (gas-limit-accumulate nil :type (or null gas-amount))
  
  ;; g_r: Gas limit for refine (per work-item)
  (gas-limit-refine nil :type (or null gas-amount))
  
  ;; m: Memory pages allocated
  (memory-pages nil :type (or null natural))
  
  ;; l: Lookup anchor (hash for storage lookup)
  (storage-lookup nil :type (or null hash32))
  
  ;; p: Preimage lookup (hash for preimage lookup)
  (preimage-lookup nil :type (or null hash32))
  
  ;; t: Threshold (minimum balance)
  (threshold-balance nil :type (or null gas-amount)))

;;; ═══════════════════════════════════════════════════════════════════
;;; κ - CURRENT VALIDATORS (Validator Keys)
;;; ═══════════════════════════════════════════════════════════════════
;;; Graypaper Section 3.3: Current epoch validator set

(defstruct validator-keys
  "Validator key pair for current epoch (κ[v]).
   
   Each validator has Bandersnatch (block production) and Ed25519 (finality) keys."
  
  ;; k_b: Bandersnatch public key (32 bytes)
  (bandersnatch nil :type (or null bandersnatch-public-key))
  
  ;; k_e: Ed25519 public key (32 bytes)
  (ed25519 nil :type (or null ed25519-public-key))
  
  ;; k_bls: BLS public key (144 bytes, optional for future)
  (bls nil :type (or null bls-public-key)))

;;; ═══════════════════════════════════════════════════════════════════
;;; γ - SAFROLE STATE (Validator Rotation)
;;; ═══════════════════════════════════════════════════════════════════
;;; Graypaper Section 6: SAFROLE consensus mechanism state (equation 6.3)
;;; Sub-components: γA, γP, γS, γZ

(defstruct safrole-state
  "SAFROLE state (γ) for validator rotation (equation 6.3).
   
   Composed of 4 sub-components tracking epoch transitions."
  
  ;; γA: The sealing lottery ticket accumulator (equation 6.5)
  (ticket-accumulator nil :type list)
  
  ;; γP: Keys for validators of next epoch (equation 6.7)
  (next-validators nil :type list)
  
  ;; γS: Sealing-key sequence of current epoch (equation 6.5)
  (seal-keys nil :type list)
  
  ;; γZ: Bandersnatch root for current epoch's ticket submissions (equation 6.4)
  (tickets-root nil :type (or null hash32)))

;;; ═══════════════════════════════════════════════════════════════════
;;; α - CORE AUTHORIZATIONS (Core State)
;;; ═══════════════════════════════════════════════════════════════════
;;; Graypaper Section 11: Core authorization requirements

(defstruct core-authorization
  "Core authorization (α[c]).
   
   Each core has an authorization requirement that work must satisfy."
  
  ;; c: Core index (u16)
  (core-index nil :type (or null core-id))
  
  ;; a: Authorization pool hash
  (auth-pool nil :type (or null hash32))
  
  ;; Authorized code hash
  (authorized-code nil :type (or null hash32)))

;;; ═══════════════════════════════════════════════════════════════════
;;; ρ - PENDING REPORTS (Core Work Reports)
;;; ═══════════════════════════════════════════════════════════════════
;;; Graypaper Section 12: Work-reports pending availability

(defstruct pending-report
  "Pending work-report (ρ[c]).
   
   Work-report on core c waiting for availability assurance."
  
  ;; Core index
  (core-index nil :type (or null core-id))
  
  ;; Work-report hash
  (report-hash nil :type (or null hash32))
  
  ;; Timeslot when reported
  (reported-timeslot nil :type (or null timeslot))
  
  ;; Availability votes (bitfield of validators)
  (availability-votes nil :type (or null list)))

;;; ═══════════════════════════════════════════════════════════════════
;;; β - RECENT BLOCKS (Block History)
;;; ═══════════════════════════════════════════════════════════════════
;;; Graypaper Section 7: Log of recent activity (equation 7.1)
;;; Sub-components: βH (block info), βB (Merkle mountain belt)

(defstruct recent-blocks-info
  "Recent blocks information (βH) - equation 7.2.
   
   Information on the most recent blocks."
  
  ;; List of recent block headers/hashes
  (block-headers nil :type list)
  
  ;; Timeslots of recent blocks
  (timeslots nil :type list))

(defstruct merkle-mountain-belt
  "Merkle mountain belt (βB) - equations 7.3 and 7.7.
   
   Belt for accumulating Accumulation outputs."
  
  ;; Merkle mountain ranges (peaks)
  (peaks nil :type list)
  
  ;; Total number of leaves
  (leaves-count nil :type (or null natural)))

(defstruct recent-blocks
  "Complete recent activity log (β) - equation 7.1.
   
   Composed of block info (βH) and Merkle belt (βB)."
  
  ;; βH: Information on most recent blocks (equation 7.2)
  (info nil :type (or null recent-blocks-info))
  
  ;; βB: Merkle mountain belt (equations 7.3, 7.7)
  (merkle-belt nil :type (or null merkle-mountain-belt)))

;;; ═══════════════════════════════════════════════════════════════════
;;; ω - PENDING WORK-REPORTS (Accumulation Queue)
;;; ═══════════════════════════════════════════════════════════════════
;;; Graypaper Section 13: Work-reports ready to accumulate

(defstruct pending-accumulation
  "Pending work-report ready for accumulation (ω).
   
   Work-reports that have passed availability and are ready for Ψ_A."
  
  ;; Work-report hash
  (report-hash nil :type (or null hash32))
  
  ;; Service affected
  (service-id nil :type (or null service-id))
  
  ;; Work-report results
  (results nil :type list))

;;; ═══════════════════════════════════════════════════════════════════
;;; ξ - ACCUMULATED WORK-PACKAGES (Recently Processed)
;;; ═══════════════════════════════════════════════════════════════════
;;; Graypaper Section 13: Recently accumulated work-packages

(defstruct accumulated-package
  "Recently accumulated work-package (ξ).
   
   Work-packages that were recently accumulated (prevents replay)."
  
  ;; Work-package hash
  (package-hash nil :type (or null hash32))
  
  ;; Timeslot of accumulation
  (accumulated-timeslot nil :type (or null timeslot)))

;;; ═══════════════════════════════════════════════════════════════════
;;; λ - ARCHIVED VALIDATORS (Historical Validator Keys)
;;; ═══════════════════════════════════════════════════════════════════
;;; Graypaper Section 6: Historical validator keys for disputes

(defstruct archived-validator
  "Archived validator keys (λ[e][v]).
   
   Historical validator keys indexed by epoch for dispute resolution."
  
  ;; Epoch index
  (epoch nil :type (or null natural))
  
  ;; Validator index
  (validator-index nil :type (or null natural))
  
  ;; Bandersnatch public key (32 bytes)
  (bandersnatch nil :type (or null bandersnatch-public-key))
  
  ;; Ed25519 public key (32 bytes)
  (ed25519 nil :type (or null ed25519-public-key)))

;;; ═══════════════════════════════════════════════════════════════════
;;; ι - VALIDATOR QUEUE (Enrollment Queue)
;;; ═══════════════════════════════════════════════════════════════════
;;; Graypaper Section 6: Queue of validators waiting to be enrolled

(defstruct validator-queue-entry
  "Validator queue entry (ι).
   
   Validator waiting to be enrolled in next epoch."
  
  ;; Bandersnatch public key (32 bytes)
  (bandersnatch nil :type (or null bandersnatch-public-key))
  
  ;; Ed25519 public key (32 bytes)
  (ed25519 nil :type (or null ed25519-public-key))
  
  ;; BLS public key (144 bytes, optional)
  (bls nil :type (or null bls-public-key))
  
  ;; Deposit/stake amount
  (deposit nil :type (or null gas-amount)))

;;; ═══════════════════════════════════════════════════════════════════
;;; ϕ - AUTHORIZATION QUEUE (Core Authorization Queue)
;;; ═══════════════════════════════════════════════════════════════════
;;; Graypaper Section 11: Queue filling core authorization requirements

(defstruct authorization-queue-entry
  "Authorization queue entry (ϕ).
   
   Authorization requests queued for core assignment."
  
  ;; Service requesting authorization
  (service-id nil :type (or null service-id))
  
  ;; Code hash to authorize
  (code-hash nil :type (or null hash32))
  
  ;; Authorization pool hash
  (auth-pool nil :type (or null hash32)))

;;; ═══════════════════════════════════════════════════════════════════
;;; χ - PRIVILEGED SERVICES (Special Services)
;;; ═══════════════════════════════════════════════════════════════════
;;; Graypaper Section 9.9: Privileged service indices (equation 9.9)
;;; Sub-components: χM, χA, χV, χR, χZ

(defstruct privileged-services
  "Privileged service indices (χ) - equation 9.9.
   
   Tracks all services with special on-chain privileges."
  
  ;; χM: The index of the blessed service (equation 12.27)
  (blessed nil :type (or null service-id))
  
  ;; χA: Indices of services able to assign each core's authorizer queue (equation 12.27)
  (authorizer-assigners nil :type list)
  
  ;; χV: The index of the designate service (equation 12.27)
  (designate nil :type (or null service-id))
  
  ;; χR: The index of the registrar service (equation 12.27)
  (registrar nil :type (or null service-id))
  
  ;; χZ: Always-accumulate service indices and their basic gas allowance (equation 12.27)
  (always-accumulate nil :type list))

;;; ═══════════════════════════════════════════════════════════════════
;;; ψ - JUDGEMENTS (Dispute Judgements)
;;; ═══════════════════════════════════════════════════════════════════
;;; Graypaper Section 10: Past judgments (equation 10.1)
;;; Sub-components: ψB (incorrect), ψG (correct), ψW (unknowable), ψO (offenders)

(defstruct judgements
  "Past judgments on work-reports and validators (ψ) - equation 10.1.
   
   Split into 4 categories based on judgment outcome."
  
  ;; ψB: Work-reports judged to be incorrect (equation 10.17)
  (incorrect-reports nil :type list)
  
  ;; ψG: Work-reports judged to be correct (equation 10.16)
  (correct-reports nil :type list)
  
  ;; ψW: Work-reports whose validity is judged to be unknowable (equation 10.18)
  (unknowable-reports nil :type list)
  
  ;; ψO: Validators who made a judgment found to be incorrect (equation 10.19)
  (offending-validators nil :type list))

;;; ═══════════════════════════════════════════════════════════════════
;;; π - VALIDATOR STATISTICS (Performance Tracking)
;;; ═══════════════════════════════════════════════════════════════════
;;; Graypaper Section 17: Validator performance metrics

(defstruct validator-stats
  "Validator statistics (π[v]).
   
   Tracks validator performance for rewards/slashing."
  
  ;; Validator index
  (validator-index nil :type (or null natural))
  
  ;; Blocks produced
  (blocks-produced nil :type (or null natural))
  
  ;; Votes cast
  (votes-cast nil :type (or null natural))
  
  ;; Slashes received
  (slashes nil :type (or null natural))
  
  ;; Accumulated rewards
  (rewards nil :type (or null gas-amount)))

;;; ═══════════════════════════════════════════════════════════════════
;;; τ - TIMESLOT (Current Timeslot Index)
;;; ═══════════════════════════════════════════════════════════════════
;;; Graypaper Section 4.2: Current timeslot (just a natural number, no struct needed)
;;; NOTE: τ is stored directly as (timeslot) type in jam-state

;;; ═══════════════════════════════════════════════════════════════════
;;; η - ENTROPY POOL (On-chain Entropy)
;;; ═══════════════════════════════════════════════════════════════════
;;; Graypaper Section 4.2: On-chain entropy for randomness (just a hash32, no struct needed)
;;; NOTE: η is stored directly as hash32 in jam-state

;;; ═══════════════════════════════════════════════════════════════════
;;; θ - ACCUMULATION OUTPUTS (Most Recent)
;;; ═══════════════════════════════════════════════════════════════════
;;; Graypaper Section 4.2: θ: The most recent Accumulation outputs. See equations 7.4 and 12.25.

(defstruct accumulation-output
  "Accumulation output (θ).
   
   The most recent Accumulation outputs from work-package processing."
  
  ;; Service affected
  (service-id nil :type (or null service-id))
  
  ;; Output data/blob from accumulation
  (output-data nil :type (or null blob))
  
  ;; Gas consumed
  (gas-consumed nil :type (or null gas-amount)))

;;; ═══════════════════════════════════════════════════════════════════
;;; GLOBAL STATE (σ)
;;; ═══════════════════════════════════════════════════════════════════
;;; Graypaper Section 3: Complete JAM state

(defstruct jam-state
  "Complete JAM state (σ).
   
   σ ≡ (α, β, γ, δ, η, ι, κ, λ, ρ, τ, ϕ, χ, ψ, π, ω, ξ, θ)
   
   17 components of the JAM protocol state (Graypaper Section 4.2)."
  
  ;; α: Core authorizations (list of core-authorization)
  (core-authorizations nil :type list)
  
  ;; β: Recent blocks (recent-blocks struct)
  (recent-blocks nil :type (or null recent-blocks))
  
  ;; γ: SAFROLE state (safrole-state struct)
  (safrole nil :type (or null safrole-state))
  
  ;; δ: Service accounts (list of service-account)
  (service-accounts nil :type list)
  
  ;; η: Entropy pool (32-byte hash for on-chain randomness)
  (entropy-pool nil :type (or null hash32))
  
  ;; ι: Validator queue (list of validator-queue-entry)
  (validator-queue nil :type list)
  
  ;; κ: Current validators (list of validator-keys)
  (current-validators nil :type list)
  
  ;; λ: Archived validators (list of archived-validator)
  (archived-validators nil :type list)
  
  ;; ρ: Pending reports (list of pending-report)
  (pending-reports nil :type list)
  
  ;; τ: Current timeslot (natural number index)
  (timeslot nil :type (or null timeslot))
  
  ;; ϕ: Authorization queue (list of authorization-queue-entry)
  (authorization-queue nil :type list)
  
  ;; χ: Privileged services (single privileged-services struct)
  (privileged-services nil :type (or null privileged-services))
  
  ;; ψ: Judgements (single judgements struct with 4 sub-lists)
  (judgements nil :type (or null judgements))
  
  ;; π: Validator statistics (list of validator-stats)
  (validator-statistics nil :type list)
  
  ;; ω: Pending work-reports (list of pending-accumulation)
  (pending-work-reports nil :type list)
  
  ;; ξ: Accumulated work-packages (list of accumulated-package)
  (accumulated-packages nil :type list)
  
  ;; θ: Most recent accumulation outputs (list of accumulation-output)
  (accumulation-outputs nil :type list))
