;;;; kappa.lisp
;;;; κ - Current Validators (Graypaper equation 6.7)
;;;;
;;;; Current epoch validator keys and metadata.

(in-package :jotl-state)

;;; ═══════════════════════════════════════════════════════════════════
;;; GRAYPAPER REFERENCE
;;; ═══════════════════════════════════════════════════════════════════
;;; 
;;; Equation 6.7: κ ∈ ⟦K⟧V
;;; 
;;; κ is the sequence of validator keys currently active in this epoch.
;;;
;;; K = (b: Ed, e: Bandersnatch, [g: BLS]) where:
;;;   b: Bandersnatch public key (32 bytes) - for block production
;;;   e: Ed25519 public key (32 bytes) - for finality voting
;;;   g: BLS public key (144 bytes, optional) - for aggregate signatures

;;; ═══════════════════════════════════════════════════════════════════
;;; ENCODING (Appendix D)
;;; ═══════════════════════════════════════════════════════════════════

(defun encode-validator-keys (keys)
  "Encode validator key pair κ[v].
   
   Graypaper equation 6.7: κ ∈ ⟦K⟧V
   
   Args:
     keys: validator-keys struct
   
   Returns:
     Encoded octet list"
  (concat-octets
   (encode-hash (validator-keys-bandersnatch keys))  ; b: Bandersnatch (32 bytes)
   (encode-hash (validator-keys-ed25519 keys))       ; e: Ed25519 (32 bytes)
   (encode-optional (validator-keys-bls keys) #'encode-hash))) ; g: BLS (optional 144 bytes)

(defun encode-current-validators (validators-list)
  "Encode the full current validators set κ.
   
   Graypaper equation 6.7: κ ∈ ⟦K⟧V
   
   Args:
     validators-list: list of validator-keys structs
   
   Returns:
     Encoded octet list (length-prefixed sequence)"
  (encode-pre-encoded-sequence
   (mapcar #'encode-validator-keys validators-list)))

;;; ═══════════════════════════════════════════════════════════════════
;;; DECODING (Appendix D)
;;; ═══════════════════════════════════════════════════════════════════

(defun decode-validator-keys (octets position)
  "Decode validator key pair κ[v].
   
   Graypaper equation 6.7: κ ∈ ⟦K⟧V
   
   Args:
     octets: octet list
     position: starting position
   
   Returns:
     (values validator-keys new-position)"
  (let ((pos position))
    (decode>> (octets pos)
      (bandersnatch (decode-hash octets pos))
      (ed25519      (decode-hash octets pos))
      (bls          (decode-optional octets pos #'decode-hash))
      (values
       (make-validator-keys
        :bandersnatch bandersnatch
        :ed25519 ed25519
        :bls bls)
       pos))))

(defun decode-current-validators (octets position)
  "Decode the full current validators set κ.
   
   Graypaper equation 6.7: κ ∈ ⟦K⟧V
   
   Args:
     octets: octet list
     position: starting position
   
   Returns:
     (values validators-list new-position)"
  (decode-length-prefixed-sequence
   octets position #'decode-validator-keys))
