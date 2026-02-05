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
   
   ;; Encoding/Decoding
   #:encode-chain-block
   #:decode-chain-block))
