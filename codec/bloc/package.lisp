;;;; package.lisp
;;;; Package definition for JOTL block structures
;;;;
;;;; This follows Common Lisp convention: one package.lisp per package,
;;;; with all exports centralized for easy maintenance and visibility.

(defpackage #:jotl-bloc
  (:use #:cl #:jotl-codec)
  (:documentation "JAM block structures and serialization")
  (:export
   
   ;; ══════════════════════════════════════════════════════════════
   ;; PRIMITIVE TYPES (Hashes, Blobs, Signatures)
   ;; ══════════════════════════════════════════════════════════════
   
   #:hash                       ; 32-byte hash type
   #:blob                       ; Variable-length octet sequence
   #:blob-n                     ; Fixed-length octet sequence
   #:natural                    ; Natural number type
   #:natural-limited            ; Bounded natural number
   #:length-type                ; Length discriminator type
   
   ;; Cryptographic primitives
   #:ed25519-signature          ; Ed25519 signature (64 bytes)
   #:ed25519-public-key         ; Ed25519 public key (32 bytes)
   #:bandersnatch-signature     ; Bandersnatch signature
   #:bandersnatch-public-key    ; Bandersnatch public key
   #:bandersnatch-vrf-signature ; Bandersnatch VRF signature
   #:bls-signature              ; BLS signature
   #:bls-public-key             ; BLS public key
   
   ;; Constructors & utilities
   #:make-hash
   #:make-blob
   #:hash-zero
   #:list-to-blob
   #:blob-to-list
   
   ;; ══════════════════════════════════════════════════════════════
   ;; CHAINSPEC CONFIGURATION (Network Parameters)
   ;; ══════════════════════════════════════════════════════════════
   
   #:chainspec
   #:make-chainspec
   #:chainspec-name
   #:chainspec-num-validators
   #:chainspec-num-cores
   #:chainspec-avail-bitfield-bytes
   
   ;; Predefined chainspecs
   #:*tiny-chainspec*           ; Tiny test network (6 validators)
   #:*full-chainspec*           ; Full network (1023 validators)
   #:*chainspec*                ; Currently active chainspec
   #:set-chainspec              ; Switch active chainspec
   
   ;; Dynamic configuration (locally rebound in decode/encode)
   #:*validators-super-majority*  ; Dynamic var: current super-majority threshold
   #:validators-super-majority    ; Function: ceil(num-validators * 2/3 + 1)
   #:num-validators
   
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
