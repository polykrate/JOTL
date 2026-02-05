;;;; types.lisp
;;;; Common type definitions for JAM blocks
;;;; REFACTORED: All byte sequences as LISTS (idiomatique Lisp, rapide)

(in-package :jotl-bloc)

;;; Common JAM types from graypaper section 3

;;; 3.8.1. Hashing - all as LISTS
(deftype hash ()
  "H = B32 : 256-bit hash (32 octets) - as list"
  'list)

(deftype blob ()
  "B : octet sequence of arbitrary length - as list"
  'list)

;;; 3.4. Numbers
(deftype natural ()
  "N : natural numbers including zero"
  '(integer 0 *))

(deftype natural-limited (n)
  "Nn : naturals less than n"
  `(integer 0 (,n)))

(deftype length-type ()
  "NL = N_{2^32} : lengths of octet sequences"
  '(integer 0 #.(1- (expt 2 32))))

;;; Helper functions for I/O boundaries (convert to/from vectors when needed)

(defun list-to-blob (list)
  "Convert list of octets to vector blob (for I/O only)"
  (make-array (length list) :element-type '(unsigned-byte 8)
              :initial-contents list))

(defun blob-to-list (blob)
  "Convert vector blob to list of octets (for I/O only)"
  (coerce blob 'list))

(defun hash-zero ()
  "H0 = [0]32 - as list"
  (make-list 32 :initial-element 0))

;;; Extrinsic structure (E)
;;;
;;; Graypaper Equation 4.3: E ≡ (ET, ED, EP, EA, EG)

(defstruct extrinsic
  "Extrinsic data (E).
   
   Contains all external data submitted to the block."
  (tickets nil :type list)           ; List of ticket structures
  (preimages nil :type list)         ; List of preimage structures
  (reports nil :type list)           ; List of report structures
  (availability nil :type list)      ; List of availability-assurance structures
  (disputes nil :type (or null disputes)))  ; Disputes structure

;;; Block structure (B)
;;;
;;; Graypaper Equation 4.2: B ≡ (H, E)

(defstruct chain-block
  "JAM Block (B).
   
   A complete block consists of header and extrinsic data."
  (header nil :type (or null header))
  (extrinsic nil :type (or null extrinsic)))

;;; Validator structures
;;;
;;; Graypaper Section 5.10, 6.1: Validator keys

(defstruct validator
  "Validator key pair.
   
   Each validator has two keys:
   - bandersnatch: For block production and VRF (32 bytes as list)
   - ed25519: For finalizing and disputes (32 bytes as list)"
  (bandersnatch nil :type (or null list))  ; 32 bytes as list
  (ed25519 nil :type (or null list)))      ; 32 bytes as list

;;; Epoch Marker structure
;;;
;;; Graypaper Section 5.10: Epoch marker (HE)

(defstruct epoch-marker
  "Epoch marker (HE).
   
   Marks the beginning of a new epoch with new validator set.
   - entropy: Randomness for the new epoch (32 bytes as list)
   - tickets-entropy: Ticket-specific randomness (32 bytes as list)
   - validators: List of validators for the epoch"
  (entropy nil :type (or null list))           ; 32 bytes as list
  (tickets-entropy nil :type (or null list))   ; 32 bytes as list
  (validators nil :type list))                 ; list of validator

;;; Block Header structure
;;;
;;; Graypaper Section 4.2, 5: Block header (H)

(defstruct header
  ;; HP ∈ H : parent block hash (Equation 4.2) - 32 bytes as list
  (parent-hash nil :type (or null list))
  
  ;; HR ∈ H : state root after block application (Equation 5.2) - 32 bytes as list
  (prior-state-root nil :type (or null list))
  
  ;; HX ∈ H : Extrinsic hash (Eq. 5.4) - 32 bytes as list
  (extrinsic-hash nil :type (or null list))
  
  ;; HT ∈ NT : Time-slot index (Eq. 5.7)
  (timeslot nil :type (or null integer))
  
  ;; HE : Epoch marker (Eq. 5.10) - can be +empty+ (symbol) or epoch-marker
  (epoch-marker nil :type (or null epoch-marker symbol))
  
  ;; HW : Winning tickets - can be +empty+ (symbol) or list of tickets
  (winning-tickets nil :type (or null list symbol))
  
  ;; HO ∈ ⟦¯H⟧ : offenders marker (Equation 5.10)
  ;; Ed25519 public keys of newly misbehaving validators (list of 32-byte lists)
  (offenders nil :type list)
  
  ;; HI ∈ NV : block author index (Equation 5.9)
  (author-index nil :type (or null integer))
  
  ;; HV ∈ SB : Bandersnatch VRF signature (entropy-yielding) - 96 bytes as list
  (vrf-signature nil :type (or null list))
  
  ;; HS ∈ SB : Bandersnatch block seal - 96 bytes as list
  (seal nil :type (or null list)))

;;; Ticket structure
;;;
;;; Graypaper Section 6.6: Tickets (T)

(defstruct ticket
  ;; Ticket identifier/ID - list of octets
  (identifier nil :type (or null list))
  
  ;; Attempt index or additional data
  (attempt nil :type t))

;;; Preimage structure
;;;
;;; Graypaper Section 6.6: Preimages (P)

(defstruct preimage
  ;; Service ID (4 bytes, little-endian natural)
  (service-id nil :type (or null integer))
  
  ;; Data blob (variable length) - list of octets
  (data nil :type (or null list)))

;;; Report structure
;;;
;;; Graypaper Section 6.6: Reports (R)

(defstruct report
  ;; Report data/package hash - list of octets
  (report-data nil :type (or null list))
  
  ;; Time slot
  (timeslot nil :type (or null integer))
  
  ;; Authorizer-guarantor data (sequence of pairs)
  (authorizer-guarantor nil :type list))

;;; Availability Assurance structure
;;;
;;; Graypaper Section 6.6: Availability (A)

(defstruct availability-assurance
  ;; Assurance anchor/hash - list of octets
  (assurance-a nil :type (or null list))
  
  ;; Flags - FIXED 1 byte integer
  (flags nil :type (or null integer))
  
  ;; Validator index
  (validator-index nil :type (or null integer))
  
  ;; Signature - list of octets
  (signature nil :type (or null list)))

;;; Disputes structures
;;;
;;; Graypaper Section 6.6: Disputes (D)

(defstruct verdict-entry
  ;; Target hash - FIXED 32 bytes
  (target nil :type (or null list))
  
  ;; Age (E4)
  (age nil :type (or null integer))
  
  ;; Judgement data (sequence of validator, index, signature)
  (judgement nil :type list))

;; Culprit structure (for disputes)
(defstruct culprit
  "Culprit in disputes."
  (target nil :type (or null list))       ; 32-byte hash
  (key nil :type (or null list))          ; 32-byte hash  
  (signature nil :type (or null list)))   ; 64-byte signature

;; Fault structure (for disputes)
(defstruct fault
  "Fault in disputes."
  (target nil :type (or null list))       ; 32-byte hash
  (vote nil :type (or null boolean))      ; boolean vote
  (key nil :type (or null list))          ; 32-byte hash
  (signature nil :type (or null list)))   ; 64-byte signature

(defstruct disputes
  ;; Verdicts - list of verdict-entry
  (verdicts nil :type list)
  
  ;; Culprits - list of culprit structures
  (culprits nil :type list)
  
  ;; Faults - list of fault structures
  (faults nil :type list))
