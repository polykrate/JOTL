;;;; package.lisp
;;;; Package definition for JOTL block structures

(defpackage #:jotl-bloc
  (:use #:cl #:jotl-codec)
  (:documentation "JAM block structures and serialization")
  (:export
   ;; Types
   #:hash
   #:blob
   #:blob-n
   #:natural
   #:natural-limited
   #:length-type
   #:ed25519-signature
   #:ed25519-public-key
   #:bandersnatch-signature
   #:bandersnatch-public-key
   #:bandersnatch-vrf-signature
   #:bls-signature
   #:bls-public-key
   #:make-hash
   #:make-blob
   #:hash-zero
   #:list-to-blob
   #:blob-to-list
   
   ;; Configuration
   #:chainspec
   #:make-chainspec
   #:chainspec-name
   #:chainspec-num-validators
   #:chainspec-num-cores
   #:*tiny-chainspec*
   #:*full-chainspec*
   #:*chainspec*
   #:set-chainspec
   #:num-validators
   
   ;; Block structure (4.2)
   #:chain-block
   #:make-chain-block
   #:chain-block-header
   #:chain-block-extrinsic
   
   ;; Extrinsic data (4.3)
   #:extrinsic
   #:make-extrinsic
   #:extrinsic-tickets
   #:extrinsic-disputes
   #:extrinsic-preimages
   #:extrinsic-availability
   #:extrinsic-reports
   
   ;; Header
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
   #:encode-header
   #:encode-header-unsigned
   #:decode-header
   
   ;; Epoch Marker
   #:validator
   #:make-validator
   #:validator-bandersnatch
   #:validator-ed25519
   #:epoch-marker
   #:make-epoch-marker
   #:epoch-marker-entropy
   #:epoch-marker-tickets-entropy
   #:epoch-marker-validators
   #:encode-validator
   #:decode-validator
   #:encode-epoch-marker
   #:decode-epoch-marker
   
   ;; Tickets
   #:ticket
   #:make-ticket
   #:ticket-identifier
   #:ticket-entry-index
   #:encode-tickets
   #:decode-tickets
   
   ;; Preimages
   #:preimage
   #:make-preimage
   #:preimage-service-id
   #:preimage-data
   #:encode-preimages
   #:decode-preimages
   
   ;; Reports
   #:report
   #:make-report
   #:report-report-data
   #:report-timeslot
   #:report-assurances
   #:encode-reports
   #:decode-reports
   
   ;; Availability
   #:availability-assurance
   #:make-availability-assurance
   #:availability-assurance-assurance-a
   #:availability-assurance-component-f
   #:availability-assurance-validator-index
   #:availability-assurance-signature
   #:encode-availability
   #:decode-availability
   
   ;; Disputes
   #:disputes
   #:make-disputes
   #:disputes-verdicts
   #:disputes-culprits
   #:disputes-faults
   #:verdict-entry
   #:make-verdict-entry
   #:verdict-entry-report-data
   #:verdict-entry-component-a
   #:verdict-entry-judgments
   #:encode-disputes
   #:decode-disputes
   
   ;; Work structures (C.24, C.25, C.29, C.34)
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
   
   #:package-spec
   #:make-package-spec
   #:package-spec-hash
   #:package-spec-length
   #:package-spec-erasure-root
   #:package-spec-exports-root
   #:package-spec-exports-count
   #:encode-package-spec
   #:decode-package-spec
   
   #:refine-load
   #:make-refine-load
   #:refine-load-gas-used
   #:refine-load-imports
   #:refine-load-extrinsic-count
   #:refine-load-extrinsic-size
   #:refine-load-exports
   
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
   #:encode-work-output
   #:decode-work-output
   
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
   
   #:guarantee
   #:make-guarantee
   #:guarantee-report
   #:guarantee-slot
   #:guarantee-signatures
   #:encode-guarantee
   #:decode-guarantee
   
   ;; Encoding/Decoding
   #:encode-chain-block
   #:decode-chain-block))
