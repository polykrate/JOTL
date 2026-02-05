;;;; package.lisp
;;;; Package definition for JOTL block structures
;;;;
;;;; This follows Common Lisp convention: one package.lisp per package,
;;;; with all exports centralized for easy maintenance and visibility.

(defpackage #:jotl-bloc
  (:use #:cl #:jotl-codec)
  (:import-from #:jotl-config
                ;; Configuration symbols
                #:chainspec-p
                #:chainspec-num-validators
                #:chainspec-avail-bitfield-bytes
                #:*chainspec*
                #:*validators-super-majority*
                #:validators-super-majority
                ;; Common JAM types (imported to re-export for convenience)
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
  (:documentation "JAM block structures and serialization")
  (:export
   
   ;; ══════════════════════════════════════════════════════════════
   ;; PRIMITIVE TYPES (from jotl-config, re-exported for convenience)
   ;; ══════════════════════════════════════════════════════════════
   
   ;; Basic types (Graypaper Section 3)
   #:hash                       ; 32-byte hash type
   #:hash32                     ; Alias for hash
   #:hash256                    ; Alias for hash
   #:blob                       ; Variable-length octet sequence
   #:natural                    ; Natural number type
   #:natural-limited            ; Bounded natural number
   #:length-type                ; Length discriminator type
   
   ;; Cryptographic types
   #:ed25519-signature          ; Ed25519 signature (64 bytes)
   #:ed25519-public-key         ; Ed25519 public key (32 bytes)
   #:bandersnatch-signature     ; Bandersnatch signature (96 bytes)
   #:bandersnatch-public-key    ; Bandersnatch public key (32 bytes)
   #:bls-signature              ; BLS signature (96 bytes)
   #:bls-public-key             ; BLS public key (144 bytes)
   
   ;; JAM identifiers
   #:service-id                 ; Service ID (u32)
   #:core-id                    ; Core ID (u16)
   #:timeslot                   ; Timeslot index (u32)
   #:gas-amount                 ; Gas amount (u64)
   
   ;; Helper functions
   #:list-to-blob               ; Convert list to vector
   #:blob-to-list               ; Convert vector to list
   #:hash-zero                  ; Zero hash (32 bytes)
   #:hash32-p                   ; Hash predicate
   
   ;; Constructors & utilities
   #:make-hash
   #:make-blob
   #:hash-zero
   #:list-to-blob
   #:blob-to-list
   
   ;; ══════════════════════════════════════════════════════════════
   ;; NOTE: Chainspec configuration is in jotl-config package
   ;;       Use (jotl-config:set-chainspec :tiny) to configure
   ;; ══════════════════════════════════════════════════════════════
   
   ;; ══════════════════════════════════════════════════════════════
   ;; BLOCK STRUCTURE (4.2 - Top Level)
   ;; ══════════════════════════════════════════════════════════════
   
   #:chain-block
   #:make-chain-block
   #:chain-block-header
   #:chain-block-extrinsic
   
   ;; Block codec (top-level)
   #:encode-chain-block
   #:decode-chain-block
   #:encode-block               ; Alias
   #:decode-block               ; Alias
   
   ;; ══════════════════════════════════════════════════════════════
   ;; EXTRINSIC DATA (4.3 - Block Body)
   ;; ══════════════════════════════════════════════════════════════
   
   #:extrinsic
   #:make-extrinsic
   #:extrinsic-tickets
   #:extrinsic-disputes
   #:extrinsic-preimages
   #:extrinsic-availability
   #:extrinsic-reports
   
   ;; ══════════════════════════════════════════════════════════════
   ;; HEADER (4.4 - Block Metadata)
   ;; ══════════════════════════════════════════════════════════════
   
   #:header
   #:make-header
   #:header-parent-hash
   #:header-prior-state-root
   #:header-extrinsic-hash
   #:header-timeslot
   #:header-epoch-marker
   #:header-winning-tickets
   #:header-offenders
   #:header-author-index
   #:header-vrf-signature
   #:header-seal
   
   ;; Header codec
   #:encode-header
   #:encode-header-unsigned
   #:decode-header
   
   ;; ══════════════════════════════════════════════════════════════
   ;; EPOCH MARKER (Validator Set Transitions)
   ;; ══════════════════════════════════════════════════════════════
   
   #:validator
   #:make-validator
   #:validator-bandersnatch
   #:validator-ed25519
   
   #:epoch-marker
   #:make-epoch-marker
   #:epoch-marker-entropy
   #:epoch-marker-tickets-entropy
   #:epoch-marker-validators
   
   ;; Epoch codec
   #:encode-validator
   #:decode-validator
   #:encode-epoch-marker
   #:decode-epoch-marker
   
   ;; ══════════════════════════════════════════════════════════════
   ;; TICKETS (Consensus Participation)
   ;; ══════════════════════════════════════════════════════════════
   
   #:ticket
   #:make-ticket
   #:ticket-identifier
   #:ticket-entry-index
   
   ;; Tickets codec
   #:encode-tickets
   #:decode-tickets
   
   ;; ══════════════════════════════════════════════════════════════
   ;; PREIMAGES (Service Code/Data)
   ;; ══════════════════════════════════════════════════════════════
   
   #:preimage
   #:make-preimage
   #:preimage-service-id
   #:preimage-data
   
   ;; Preimages codec
   #:encode-preimages
   #:decode-preimages
   
   ;; ══════════════════════════════════════════════════════════════
   ;; GUARANTEES/REPORTS (Work Package Attestations)
   ;; ══════════════════════════════════════════════════════════════
   
   #:report
   #:make-report
   #:report-report-data
   #:report-timeslot
   #:report-assurances
   
   #:guarantee
   #:make-guarantee
   #:guarantee-report
   #:guarantee-slot
   #:guarantee-signatures
   
   ;; Reports/Guarantees codec
   #:encode-reports
   #:decode-reports
   #:encode-guarantee
   #:decode-guarantee
   
   ;; ══════════════════════════════════════════════════════════════
   ;; WORK STRUCTURES (C.24-C.35 - Work Package Components)
   ;; ══════════════════════════════════════════════════════════════
   
   ;; Refine context (C.24)
   #:refine-context
   #:make-refine-context
   #:refine-context-anchor
   #:refine-context-state-root
   #:refine-context-beefy-root
   #:refine-context-lookup-anchor
   #:refine-context-lookup-anchor-slot
   #:refine-context-prerequisites
   #:encode-refine-context
   #:decode-refine-context
   
   ;; Package specification (C.25)
   #:package-spec
   #:make-package-spec
   #:package-spec-hash
   #:package-spec-length
   #:package-spec-erasure-root
   #:package-spec-exports-root
   #:package-spec-exports-count
   #:encode-package-spec
   #:decode-package-spec
   
   ;; Refine load metrics
   #:refine-load
   #:make-refine-load
   #:refine-load-gas-used
   #:refine-load-imports
   #:refine-load-extrinsic-count
   #:refine-load-extrinsic-size
   #:refine-load-exports
   
   ;; Work result (C.29)
   #:work-result
   #:make-work-result
   #:work-result-service-id
   #:work-result-code-hash
   #:work-result-payload-hash
   #:work-result-accumulate-gas
   #:work-result-result
   #:work-result-refine-load
   #:encode-work-result
   #:decode-work-result
   
   ;; Work output (C.34)
   #:encode-work-output
   #:decode-work-output
   
   ;; Work report (complete work package)
   #:work-report
   #:make-work-report
   #:work-report-package-spec
   #:work-report-context
   #:work-report-core-index
   #:work-report-authorizer-hash
   #:work-report-auth-gas-used
   #:work-report-auth-output
   #:work-report-segment-root-lookup
   #:work-report-results
   #:encode-work-report
   #:decode-work-report
   
   ;; ══════════════════════════════════════════════════════════════
   ;; AVAILABILITY (Data Availability Attestations)
   ;; ══════════════════════════════════════════════════════════════
   
   #:availability-assurance
   #:make-availability-assurance
   #:availability-assurance-assurance-a
   #:availability-assurance-component-f
   #:availability-assurance-validator-index
   #:availability-assurance-signature
   
   ;; Availability codec
   #:encode-availability
   #:decode-availability
   
   ;; ══════════════════════════════════════════════════════════════
   ;; DISPUTES (Misbehavior & Judgements)
   ;; ══════════════════════════════════════════════════════════════
   
   #:disputes
   #:make-disputes
   #:disputes-verdicts
   #:disputes-culprits
   #:disputes-faults
   
   ;; Culprits (misbehaving validators)
   #:culprit
   #:make-culprit
   #:culprit-target
   #:culprit-key
   #:culprit-signature
   #:encode-culprit
   #:decode-culprit
   
   ;; Faults (invalid votes)
   #:fault
   #:make-fault
   #:fault-target
   #:fault-vote
   #:fault-key
   #:fault-signature
   #:encode-fault
   #:decode-fault
   
   ;; Verdicts (judgements)
   #:verdict-entry
   #:make-verdict-entry
   #:verdict-entry-target
   #:verdict-entry-age
   #:verdict-entry-judgement
   
   ;; Disputes codec
   #:encode-disputes
   #:decode-disputes))
