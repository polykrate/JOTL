;;;; block.lisp - JAM Block (Pure FP)
;;;; Gray Paper Section 4.1 & 4.2

(in-package #:jotl)

;;; ═══════════════════════════════════════════════════════════════
;;; GRAY PAPER SECTION 4.1: THE BLOCK
;;; ═══════════════════════════════════════════════════════════════

#|
Gray Paper §4.1-4.2:

The block B is restated as the header H and some input data
external to the system (extrinsic), E:

  B ≡ (H, E)                                               (4.2)

Where:
  B = Block
  H = Header (metadata, cryptographic references)
  E = Extrinsic data (external input)

The extrinsic data is split into several portions:

  E ≡ (ET, ED, EP, EA, EG)                                 (4.3)

Where:
  ET = Tickets (validator selection mechanism)
  ED = Disputes (disputes between validators)
  EP = Preimages (static data for workloads)
  EA = Availability assurances (validators' storage confirmations)
  EG = Guarantees/Reports (newly completed workloads)

The header H is immutable and known a priori, assumed to be
available throughout the functional components of block transition.
|#

;;; ═══════════════════════════════════════════════════════════════
;;; BLOCK CONSTRUCTION (Pure FP with Closures)
;;; ═══════════════════════════════════════════════════════════════

(defun make-block (header extrinsic)
  "Creates a block closure B ≡ (H, E)
   
   Gray Paper §4.2
   
   Args:
     header     - Header closure H
     extrinsic  - Extrinsic closure E
   
   Returns: Block closure B"
  
  (lambda (msg &rest args)
    (case msg
      (:header header)
      (:extrinsic extrinsic)
      
      ;; Derived accessors
      (:tickets (funcall extrinsic :tickets))
      (:disputes (funcall extrinsic :disputes))
      (:preimages (funcall extrinsic :preimages))
      (:assurances (funcall extrinsic :assurances))
      (:guarantees (funcall extrinsic :guarantees))
      
      ;; Header passthrough
      (:slot (funcall header :slot))
      (:parent-hash (funcall header :parent-hash))
      (:state-root (funcall header :state-root))
      
      ;; Metadata
      (:type :block)
      
      (otherwise (error "Unknown block message: ~a" msg)))))

;;; ═══════════════════════════════════════════════════════════════
;;; BLOCK ACCESSORS
;;; ═══════════════════════════════════════════════════════════════

(defun block-header (block)
  "Returns header H from block B"
  (funcall block :header))

(defun block-extrinsic (block)
  "Returns extrinsic E from block B"
  (funcall block :extrinsic))

(defun block-tickets (block)
  "Returns tickets ET from block B"
  (funcall block :tickets))

(defun block-disputes (block)
  "Returns disputes ED from block B"
  (funcall block :disputes))

(defun block-preimages (block)
  "Returns preimages EP from block B"
  (funcall block :preimages))

(defun block-assurances (block)
  "Returns assurances EA from block B"
  (funcall block :assurances))

(defun block-guarantees (block)
  "Returns guarantees/reports EG from block B"
  (funcall block :guarantees))

(defun block-slot (block)
  "Returns slot from block header"
  (funcall block :slot))

;;; ═══════════════════════════════════════════════════════════════
;;; BLOCK-CONTEXT TERMS (Gray Paper §I.4.1)
;;; ═══════════════════════════════════════════════════════════════

#|
Gray Paper §I.4.1:

These terms are all contextualized to a single block. They may be
superscripted with some other term to alter the context and reference
some other block.

Key terms:

A:  Ancestor set of the block (see §5.3)
B:  The block (see §4.2)
E:  Block extrinsic (see §4.3)
Fv: Beefy signed commitment of validator v (see §18.1)
G:  Set of Ed25519 guarantor keys who made a work-report (see §11.26)
H:  Block header (see §5.1)
S:  Sequence of work-reports accumulated in this block (see §12.28, §12.29)
M:  Mapping from cores to guarantor keys (see §11.3)
M*: Mapping from cores to guarantor keys for previous rotation (see §11.3)
R:  Sequence of work-reports now available and ready for accumulation (see §11.16)
T:  Ticketed condition (true if sealed with ticket signature, not fallback) (see §6.15, §6.16)
U:  Audit condition (⊺ once block is audited) (see §17)

Superscripts:
  B♮: Latest finalized block (see §19)
  B♭: Block at head of best chain (see §19)
|#

;;; TODO: Implement block-context terms as needed

;;; ═══════════════════════════════════════════════════════════════
;;; EXAMPLES
;;; ═══════════════════════════════════════════════════════════════

#|
Usage:

;; Create a block
(let* ((header (make-header ...))
       (extrinsic (make-extrinsic ...))
       (block (make-block header extrinsic)))
  
  ;; Access components
  (block-header block)      ; => H
  (block-extrinsic block)   ; => E
  (block-tickets block)     ; => ET
  (block-slot block))       ; => τ'

Code is Law - Pure FP Blocks ! 🚀
|#
