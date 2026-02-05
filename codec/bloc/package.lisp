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
   
   ;; Block structure (4.2)
   #:jam-block
   #:make-jam-block
   #:jam-block-header
   #:jam-block-extrinsic
   
   ;; Extrinsic data (4.3)
   #:jam-extrinsic
   #:make-jam-extrinsic
   #:jam-extrinsic-tickets
   #:jam-extrinsic-disputes
   #:jam-extrinsic-preimages
   #:jam-extrinsic-availability
   #:jam-extrinsic-reports
   
   ;; Header
   #:jam-header
   #:make-jam-header
   #:jam-header-parent-hash
   #:jam-header-prior-state-root
   #:jam-header-extrinsic-hash
   #:jam-header-timeslot
   #:jam-header-epoch-marker
   #:jam-header-winning-tickets
   #:jam-header-offenders
   #:jam-header-author-index
   #:jam-header-vrf-signature
   #:jam-header-seal
   #:encode-jam-header
   #:encode-jam-header-unsigned
   #:decode-jam-header
   
   ;; Tickets
   #:jam-ticket
   #:make-jam-ticket
   #:jam-ticket-id
   #:jam-ticket-entry-index
   #:encode-tickets
   #:decode-tickets
   
   ;; Preimages
   #:jam-preimage
   #:make-jam-preimage
   #:jam-preimage-service-id
   #:jam-preimage-data
   #:encode-preimages
   #:decode-preimages
   
   ;; Reports
   #:jam-report
   #:make-jam-report
   #:jam-report-report-data
   #:jam-report-timeslot
   #:jam-report-assurances
   #:encode-reports
   #:decode-reports
   
   ;; Availability
   #:jam-availability-assurance
   #:make-jam-availability-assurance
   #:jam-availability-assurance-assurance-a
   #:jam-availability-assurance-component-f
   #:jam-availability-assurance-validator-index
   #:jam-availability-assurance-signature
   #:encode-availability
   #:decode-availability
   
   ;; Disputes
   #:jam-disputes
   #:make-jam-disputes
   #:jam-disputes-verdicts
   #:jam-disputes-culprits
   #:jam-disputes-faults
   #:jam-verdict-entry
   #:make-jam-verdict-entry
   #:jam-verdict-entry-report-data
   #:jam-verdict-entry-component-a
   #:jam-verdict-entry-judgments
   #:encode-disputes
   #:decode-disputes
   
   ;; Encoding/Decoding
   #:encode-jam-block
   #:decode-jam-block))
