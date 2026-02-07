;;;; header.lisp - JAM Header Encoding/Decoding
;;;; Gray Paper §5 - Complete header encoding with Blake2b

(in-package :jotl)

;;; ==========================================================================
;;; Header Component Encoding (Gray Paper §5.1)
;;; ==========================================================================
;;;
;;; H ≡ (HP, HR, HX, HT, HE, HW, HO, HI, HV, HS)
;;;
;;; Component Types:
;;;   HP : H (32 bytes) - Parent hash
;;;   HR : H (32 bytes) - State root
;;;   HX : H (32 bytes) - Extrinsic hash
;;;   HT : u32 - Timeslot
;;;   HE : Option<EpochMarker> - Epoch marker
;;;   HW : Option<TicketsMark> - Tickets marker
;;;   HO : Vec<Ed25519PublicKey> - Offenders (32 bytes each)
;;;   HI : u16 - Author index
;;;   HV : 96 bytes - VRF signature (Bandersnatch)
;;;   HS : 96 bytes - Seal (Bandersnatch signature)
;;;
;;; Encoding Order (Gray Paper §5.8):
;;;   E(H) = E(HP, HR, HX, E4(HT), ¿HE, ¿HW, E2(HI), HV, ↕HO)
;;;   Note: Seal HS is NOT in this order (added after for sealed headers)

;;; ==========================================================================
;;; Epoch Marker Encoding (HE)
;;; ==========================================================================

(defun encode-epoch-marker (epoch-mark)
  "Encode Option<EpochMarker> (HE).
   
   Format:
     None: [0x00]
     Some: [0x01] [entropy:32] [tickets_entropy:32] [validators:NV*64]
   
   EpochMarker (Gray Paper §6.6):
     entropy: H (32 bytes) - η
     tickets_entropy: H (32 bytes) - κ
     validators: Fixed-size sequence of NV validators (no compact length!)
   
   Args:
     epoch-mark: plist with :entropy, :tickets-entropy, :validators or nil
   
   Returns:
     byte array"
  (if epoch-mark
      (let* ((entropy (encode-hash-32 (getf epoch-mark :entropy)))
             (tickets-entropy (encode-hash-32 (getf epoch-mark :tickets-entropy)))
             (validators (getf epoch-mark :validators))
             ;; Encode validators (FIXED SIZE, no compact length)
             (validators-encoded (encode-validator-sequence validators)))
        (concatenate '(vector (unsigned-byte 8))
                     #(1)  ; Some
                     entropy
                     tickets-entropy
                     validators-encoded))
      #(0)))  ; None

(defun decode-epoch-marker (bytes offset num-validators)
  "Decode Option<EpochMarker> (HE).
   
   Args:
     bytes: byte array
     offset: starting position
     num-validators: number of validators (from chainspec NV)
   
   Returns: (values epoch-mark-or-nil bytes-consumed)"
  (let ((tag (aref bytes offset)))
    (cond
      ((= tag 0)  ; None
       (values nil 1))
      ((= tag 1)  ; Some
       (let* ((entropy (subseq bytes (1+ offset) (+ offset 33)))
              (tickets-entropy (subseq bytes (+ offset 33) (+ offset 65)))
              (validators-offset (+ offset 65)))
         (multiple-value-bind (validators validators-size)
             (decode-validator-sequence bytes validators-offset num-validators)
           (values
            (list :entropy entropy
                  :tickets-entropy tickets-entropy
                  :validators validators)
            (+ 1 32 32 validators-size)))))
      (t
       (error "Invalid option tag for epoch marker: ~A" tag)))))

;;; ==========================================================================
;;; Tickets Mark Encoding (HW)
;;; ==========================================================================

(defun encode-tickets-mark (tickets-mark)
  "Encode Option<TicketsMark> (HW).
   
   Format:
     None: [0x00]
     Some: [0x01] [data...]
   
   TODO: Implement full TicketsMark structure when needed
   
   Args:
     tickets-mark: data or nil
   
   Returns:
     byte array"
  (if tickets-mark
      ;; TODO: Implement TicketsMark encoding structure
      (concatenate '(vector (unsigned-byte 8)) #(1) tickets-mark)
      #(0)))  ; None

(defun decode-tickets-mark (bytes offset)
  "Decode Option<TicketsMark> (HW).
   
   TODO: Implement full decoding when structure is defined
   
   Returns: (values tickets-mark-or-nil bytes-consumed)"
  (let ((tag (aref bytes offset)))
    (cond
      ((= tag 0)  ; None
       (values nil 1))
      ((= tag 1)  ; Some
       ;; TODO: Decode full structure
       (error "TicketsMark decoding not yet implemented"))
      (t
       (error "Invalid option tag for tickets mark: ~A" tag)))))

;;; ==========================================================================
;;; Offenders Encoding (HO)
;;; ==========================================================================

(defun encode-offenders (offenders)
  "Encode Vec<Ed25519PublicKey> (HO).
   
   Format: [compact-length] [key1:32] [key2:32] ...
   
   Gray Paper §10: Offenders are Ed25519 keys of misbehaving validators
   
   Args:
     offenders: list of Ed25519 keys (byte arrays or hex strings)
   
   Returns:
     byte array"
  (encode-sequence (or offenders '()) #'encode-ed25519-key))

(defun decode-offenders (bytes offset)
  "Decode Vec<Ed25519PublicKey> (HO).
   
   Returns: (values list-of-keys bytes-consumed)"
  (decode-sequence bytes #'decode-ed25519-key offset))

;;; ==========================================================================
;;; Complete Header Encoding
;;; ==========================================================================

(defun encode-header-unsealed (parent-hash state-root extrinsic-hash 
                                slot epoch-mark tickets-mark 
                                offenders-mark author-index entropy-source)
  "Encode header WITHOUT seal (EU(H) in Gray Paper §5.1).
   
   Used for computing the seal signature.
   
   Gray Paper §5.8:
   EU(H) = E(HP, HR, HX, E4(HT), ¿HE, ¿HW, E2(HI), HV, ↕HO)
   
   Note the ORDER: HO comes AFTER HV in the encoding!
   
   Args:
     parent-hash: 32-byte hash (H)
     state-root: 32-byte hash (H)
     extrinsic-hash: 32-byte hash (H)
     slot: u32 (NT)
     epoch-mark: Option<EpochMarker> or nil
     tickets-mark: Option<TicketsMark> or nil
     offenders-mark: Vec<Ed25519> or nil
     author-index: u16 (NV)
     entropy-source: 96-byte signature (Y)
   
   Returns:
     byte array"
  (concatenate '(vector (unsigned-byte 8))
               (encode-hash-32 parent-hash)        ; HP (32)
               (encode-hash-32 state-root)         ; HR (32)
               (encode-hash-32 extrinsic-hash)     ; HX (32)
               (E4 slot)                           ; HT (4)
               (encode-epoch-marker epoch-mark)    ; HE (variable)
               (encode-tickets-mark tickets-mark)  ; HW (1+ or variable)
               (E2 author-index)                   ; HI (2)
               (encode-signature-96 entropy-source) ; HV (96)
               (encode-offenders offenders-mark))) ; HO (variable)

(defun encode-header (parent-hash state-root extrinsic-hash 
                      slot epoch-mark tickets-mark 
                      offenders-mark author-index entropy-source seal)
  "Encode complete header WITH seal (E(H) in Gray Paper §5.1).
   
   Format: EU(H) || HS
   
   Args:
     (same as encode-header-unsealed)
     seal: 96-byte signature (Y)
   
   Returns:
     byte array"
  (concatenate '(vector (unsigned-byte 8))
               (encode-header-unsealed parent-hash state-root extrinsic-hash
                                      slot epoch-mark tickets-mark
                                      offenders-mark author-index entropy-source)
               (encode-signature-96 seal)))  ; HS (96)

;;; ==========================================================================
;;; Header Hashing (Gray Paper §5.2)
;;; ==========================================================================
;;;
;;; HP ≡ H(E(P(H)))
;;;
;;; The parent hash is the Blake2b-256 hash of the encoded parent header

(defun compute-header-hash (parent-hash state-root extrinsic-hash 
                             slot epoch-mark tickets-mark 
                             offenders-mark author-index entropy-source seal)
  "Compute H(E(H)) - Blake2b-256 hash of encoded header.
   
   Gray Paper §5.2: HP ≡ H(E(P(H)))
   
   Returns: 32-byte hash"
  (let ((encoded (encode-header parent-hash state-root extrinsic-hash
                                slot epoch-mark tickets-mark
                                offenders-mark author-index entropy-source seal)))
    (jam.ffi:blake2b-256 encoded)))

;;; ==========================================================================
;;; Header Closure Integration
;;; ==========================================================================

(defun make-header-encoded (&key parent-hash state-root extrinsic-hash 
                                  slot epoch-mark tickets-mark 
                                  offenders-mark author-index entropy-source seal)
  "Create a header closure with encoding and real hash support.
   
   This integrates encoding into the header closure from src/block/header.lisp
   
   Returns: closure with header interface"
  (lambda (msg &rest args)
    (case msg
      ;; Core fields
      (:parent-hash parent-hash)
      (:state-root state-root)
      (:extrinsic-hash extrinsic-hash)
      (:slot slot)
      (:epoch-mark epoch-mark)
      (:tickets-mark tickets-mark)
      (:author-index author-index)
      (:entropy-source entropy-source)
      (:offenders-mark offenders-mark)
      (:seal seal)
      
      ;; Encoding & Hash (computed on demand - lazy evaluation)
      (:encoded 
       (encode-header parent-hash state-root extrinsic-hash
                     slot epoch-mark tickets-mark
                     offenders-mark author-index entropy-source seal))
      (:hash 
       (jam.ffi:blake2b-256 
        (encode-header parent-hash state-root extrinsic-hash
                      slot epoch-mark tickets-mark
                      offenders-mark author-index entropy-source seal)))
      (:encoded-unsealed 
       (encode-header-unsealed parent-hash state-root extrinsic-hash
                              slot epoch-mark tickets-mark
                              offenders-mark author-index entropy-source))
      
      ;; Derived
      (:timeslot slot)
      (:is-genesis (null parent-hash))
      (:type :header)
      
      (otherwise (error "Unknown header message: ~a" msg)))))

;;; ==========================================================================
;;; Exports
;;; ==========================================================================

(export '(encode-header
          encode-header-unsealed
          compute-header-hash
          make-header-encoded
          encode-epoch-marker
          decode-epoch-marker
          encode-tickets-mark
          decode-tickets-mark
          encode-offenders
          decode-offenders))
