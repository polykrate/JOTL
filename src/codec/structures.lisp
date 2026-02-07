;;;; header-encoding.lisp - JAM Header Encoding
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

(defun encode-hash-32 (hash)
  "Encode a 32-byte hash (no length prefix, just the bytes)"
  (if hash
      (etypecase hash
        ((simple-array (unsigned-byte 8) (32)) hash)
        (string (jam.ffi:hex-string-to-bytes hash))
        (vector (coerce hash '(simple-array (unsigned-byte 8) (*)))))
      (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))

(defun encode-epoch-marker (epoch-mark)
  "Encode Option<EpochMarker>
   
   Format:
     None: [0x00]
     Some: [0x01] [entropy 32] [tickets_entropy 32] [validators...]
   
   EpochMarker:
     entropy: 32 bytes
     tickets_entropy: 32 bytes
     validators: Vec<(Bandersnatch 32, Ed25519 32)>"
  (if epoch-mark
      (let* ((entropy (encode-hash-32 (getf epoch-mark :entropy)))
             (tickets-entropy (encode-hash-32 (getf epoch-mark :tickets-entropy)))
             (validators (getf epoch-mark :validators))
             ;; Encode validators as sequence
             (validators-encoded 
              (encode-sequence validators
                               (lambda (v)
                                 (concatenate '(vector (unsigned-byte 8))
                                            (encode-hash-32 (getf v :bandersnatch))
                                            (encode-hash-32 (getf v :ed25519)))))))
        (concatenate '(vector (unsigned-byte 8))
                     #(1)  ; Some
                     entropy
                     tickets-entropy
                     validators-encoded))
      #(0)))  ; None

(defun encode-tickets-mark (tickets-mark)
  "Encode Option<TicketsMark>
   
   Format:
     None: [0x00]
     Some: [0x01] [data...]"
  (if tickets-mark
      ;; TODO: Implement TicketsMark encoding when needed
      (concatenate '(vector (unsigned-byte 8)) #(1) tickets-mark)
      #(0)))  ; None

(defun encode-offenders (offenders)
  "Encode Vec<Ed25519PublicKey>
   
   Format: [compact-length] [key1 32 bytes] [key2 32 bytes] ..."
  (encode-sequence (or offenders '())
                   #'encode-hash-32))

(defun encode-signature-96 (signature)
  "Encode a 96-byte Bandersnatch signature"
  (if signature
      (etypecase signature
        ((simple-array (unsigned-byte 8) (96)) signature)
        (string (let ((bytes (jam.ffi:hex-string-to-bytes signature)))
                 (assert (= (length bytes) 96) () "Signature must be 96 bytes")
                 bytes))
        (vector (let ((bytes (coerce signature '(simple-array (unsigned-byte 8) (*)))))
                 (assert (= (length bytes) 96) () "Signature must be 96 bytes")
                 bytes)))
      (make-array 96 :element-type '(unsigned-byte 8) :initial-element 0)))

;;; ==========================================================================
;;; Complete Header Encoding
;;; ==========================================================================

(defun encode-header-unsealed (parent-hash state-root extrinsic-hash 
                                slot epoch-mark tickets-mark 
                                offenders-mark author-index entropy-source)
  "Encode header WITHOUT seal (EU in Gray Paper §5.1)
   
   Used for computing the seal signature.
   
   Format: HP || HR || HX || HT || HE || HW || HO || HI || HV"
  (concatenate '(vector (unsigned-byte 8))
               (encode-hash-32 parent-hash)        ; HP (32)
               (encode-hash-32 state-root)         ; HR (32)
               (encode-hash-32 extrinsic-hash)     ; HX (32)
               (E4 slot)                           ; HT (4)
               (encode-epoch-marker epoch-mark)    ; HE (variable)
               (encode-tickets-mark tickets-mark)  ; HW (1+ or variable)
               (encode-offenders offenders-mark)   ; HO (variable)
               (E2 author-index)                   ; HI (2)
               (encode-signature-96 entropy-source))) ; HV (96)

(defun encode-header (parent-hash state-root extrinsic-hash 
                      slot epoch-mark tickets-mark 
                      offenders-mark author-index entropy-source seal)
  "Encode complete header WITH seal (E in Gray Paper §5.1)
   
   Format: EU(H) || HS
         = HP || HR || HX || HT || HE || HW || HO || HI || HV || HS"
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

(defun compute-header-hash-real (parent-hash state-root extrinsic-hash 
                                  slot epoch-mark tickets-mark 
                                  offenders-mark author-index entropy-source seal)
  "Compute H(E(H)) - Blake2b-256 hash of encoded header
   
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
  "Create a header closure with encoding and real hash support
   
   This is the updated version of make-header with encoding"
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
      
      ;; Encoding & Hash (computed on demand)
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
          compute-header-hash-real
          make-header-encoded
          encode-hash-32
          encode-epoch-marker
          encode-offenders
          encode-signature-96))
