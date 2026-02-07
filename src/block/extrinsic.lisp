;;;; extrinsic.lisp - JAM Block Extrinsic Data (Pure FP)
;;;; Gray Paper Section 4.3

(in-package #:jotl)

;;; ═══════════════════════════════════════════════════════════════
;;; GRAY PAPER SECTION 4.3: EXTRINSIC DATA
;;; ═══════════════════════════════════════════════════════════════

#|
Gray Paper §4.3:

The extrinsic data E is split into several portions:

  E ≡ (ET, ED, EP, EA, EG)                                 (4.3)

Where:

ET = Tickets
     Used for the mechanism which manages the selection of
     validators for the permissioning of block authoring.

ED = Disputes
     Information relating to disputes between validators over
     the validity of reports.

EP = Preimages
     Static data which is presently being requested to be
     available for workloads to be able to fetch on demand.

EA = Availability assurances
     Assurances by each validator concerning which of the input
     data of workloads they have correctly received and are
     storing locally.

EG = Guarantees/Reports
     Reports of newly completed workloads whose accuracy is
     guaranteed by specific validators.

All extrinsic data is external to the system (provided by users,
validators, or other external actors).
|#

;;; ═══════════════════════════════════════════════════════════════
;;; EXTRINSIC CONSTRUCTION (Pure FP with Closures)
;;; ═══════════════════════════════════════════════════════════════

(defun make-extrinsic (&key tickets disputes preimages assurances guarantees)
  "Creates an extrinsic closure E ≡ (ET, ED, EP, EA, EG)
   
   Gray Paper §4.3
   
   Args:
     tickets     - ET : Tickets for validator selection
     disputes    - ED : Disputes between validators
     preimages   - EP : Static data for workloads
     assurances  - EA : Availability assurances
     guarantees  - EG : Work-reports (guarantees)
   
   Returns: Extrinsic closure E"
  
  (lambda (msg &rest args)
    (case msg
      (:tickets tickets)
      (:disputes disputes)
      (:preimages preimages)
      (:assurances assurances)
      (:guarantees guarantees)
      
      ;; Aliases
      (:reports guarantees)  ; EG is also called "reports"
      
      ;; Component counts
      (:num-tickets (length tickets))
      (:num-disputes (length disputes))
      (:num-preimages (length preimages))
      (:num-assurances (length assurances))
      (:num-guarantees (length guarantees))
      
      ;; Metadata
      (:type :extrinsic)
      
      (otherwise (error "Unknown extrinsic message: ~a" msg)))))

;;; ═══════════════════════════════════════════════════════════════
;;; EXTRINSIC ACCESSORS
;;; ═══════════════════════════════════════════════════════════════

(defun extrinsic-tickets (extrinsic)
  "ET - Tickets"
  (funcall extrinsic :tickets))

(defun extrinsic-disputes (extrinsic)
  "ED - Disputes"
  (funcall extrinsic :disputes))

(defun extrinsic-preimages (extrinsic)
  "EP - Preimages"
  (funcall extrinsic :preimages))

(defun extrinsic-assurances (extrinsic)
  "EA - Availability assurances"
  (funcall extrinsic :assurances))

(defun extrinsic-guarantees (extrinsic)
  "EG - Guarantees/Reports"
  (funcall extrinsic :guarantees))

;;; ═══════════════════════════════════════════════════════════════
;;; TICKETS (ET) - Gray Paper Section 6
;;; ═══════════════════════════════════════════════════════════════

#|
Gray Paper §6:

Tickets ET are used for the validator selection mechanism.

TODO: Fill in from Gray Paper §6 (Tickets)
- Ticket structure
- Ticket validation
- Validator selection algorithm
|#

;;; ═══════════════════════════════════════════════════════════════
;;; DISPUTES (ED) - Gray Paper Section 16
;;; ═══════════════════════════════════════════════════════════════

#|
Gray Paper §16:

Disputes ED contain information about disputes between validators
over the validity of work-reports.

TODO: Fill in from Gray Paper §16 (Disputes)
- Dispute structure
- Dispute resolution
- Slashing conditions
|#

;;; ═══════════════════════════════════════════════════════════════
;;; PREIMAGES (EP) - Gray Paper Section 10
;;; ═══════════════════════════════════════════════════════════════

#|
Gray Paper §10:

Preimages EP are static data being requested to be available
for workloads to fetch on demand.

TODO: Fill in from Gray Paper §10 (Preimages)
- Preimage structure
- Preimage availability
- Preimage expungement
|#

;;; ═══════════════════════════════════════════════════════════════
;;; AVAILABILITY ASSURANCES (EA) - Gray Paper Section 11
;;; ═══════════════════════════════════════════════════════════════

#|
Gray Paper §11:

Availability assurances EA are confirmations by validators that
they have correctly received and stored input data of workloads.

TODO: Fill in from Gray Paper §11 (Availability)
- Assurance structure
- Validator signatures
- Availability verification
|#

;;; ═══════════════════════════════════════════════════════════════
;;; GUARANTEES/REPORTS (EG) - Gray Paper Section 12
;;; ═══════════════════════════════════════════════════════════════

#|
Gray Paper §12:

Guarantees/Reports EG are reports of newly completed workloads
whose accuracy is guaranteed by specific validators.

TODO: Fill in from Gray Paper §12 (Guarantees)
- Work-report structure
- Guarantor signatures
- Report validation
|#

;;; ═══════════════════════════════════════════════════════════════
;;; EXTRINSIC HASH (Gray Paper §5.4-5.6)
;;; ═══════════════════════════════════════════════════════════════

#|
Gray Paper §5.4-5.6:

The extrinsic hash HX is a Merkle commitment to the block's
extrinsic data:

  HX ≡ HEH#(a)                                         (5.4)

where:
  a = [ET(ET), EP(EP), g, EA(EA), ED(ED)]              (5.5)

and:
  g = E(↕[(H(r), E4(t), ↕a) | (r,t,a) ← EG])          (5.6)

Translation:
- Encode each component with SCALE
- For reports (EG), create Merkle proofs: (hash, type, auth)
- Compute binary Merkle tree root
|#

(defun compute-extrinsic-hash (extrinsic)
  "Computes HX ≡ HEH#(a) - Merkle hash of extrinsic
   
   Gray Paper §5.4-5.6
   
   TODO: Implement SCALE encoding and Merkle tree"
  
  ;; Placeholder
  (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))

;;; ═══════════════════════════════════════════════════════════════
;;; EXAMPLES
;;; ═══════════════════════════════════════════════════════════════

#|
Usage:

;; Create empty extrinsic
(let ((extrinsic (make-extrinsic :tickets '()
                                 :disputes '()
                                 :preimages '()
                                 :assurances '()
                                 :guarantees '())))
  
  (extrinsic-tickets extrinsic)     ; => '()
  (funcall extrinsic :num-tickets)) ; => 0

;; Create extrinsic with data
(let ((extrinsic (make-extrinsic :tickets (list ticket1 ticket2)
                                 :guarantees (list report1))))
  
  (funcall extrinsic :num-tickets)    ; => 2
  (funcall extrinsic :num-guarantees)) ; => 1

Code is Law - Pure FP Extrinsics ! 🚀
|#
