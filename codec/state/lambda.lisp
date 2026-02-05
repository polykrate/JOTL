;;;; lambda.lisp
;;;; λ - Archived Validators (Graypaper equation 6.7)
;;;;
;;;; Historical validator keys indexed by epoch for dispute resolution.

(in-package :jotl-state)

;;; ═══════════════════════════════════════════════════════════════════
;;; GRAYPAPER REFERENCE
;;; ═══════════════════════════════════════════════════════════════════
;;; 
;;; Equation 6.7: λ ∈ (ℕE → ⟦K⟧V)
;;; 
;;; λ maps epoch indices to validator key sets from previous epochs.
;;; Used for verifying signatures in disputes about historical blocks.
;;;
;;; K = (b: Bandersnatch, e: Ed25519) where:
;;;   b: Bandersnatch public key (32 bytes)
;;;   e: Ed25519 public key (32 bytes)

;;; ═══════════════════════════════════════════════════════════════════
;;; ENCODING (Appendix D)
;;; ═══════════════════════════════════════════════════════════════════

(defun encode-archived-validator (validator)
  "Encode archived validator λ[e][v].
   
   Graypaper equation 6.7: λ ∈ (ℕE → ⟦K⟧V)
   
   Args:
     validator: archived-validator struct
   
   Returns:
     Encoded octet list"
  (concat-octets
   (encode-natural (archived-validator-epoch validator))  ; e: Epoch index
   (encode-natural (archived-validator-validator-index validator))  ; v: Validator index
   (encode-hash (archived-validator-bandersnatch validator))  ; b: Bandersnatch (32 bytes)
   (encode-hash (archived-validator-ed25519 validator))))  ; e: Ed25519 (32 bytes)

(defun encode-archived-validators (validators-list)
  "Encode the full archived validators set λ.
   
   Graypaper equation 6.7: λ ∈ (ℕE → ⟦K⟧V)
   
   Args:
     validators-list: list of archived-validator structs
   
   Returns:
     Encoded octet list (length-prefixed sequence)"
  (encode-pre-encoded-sequence
   (mapcar #'encode-archived-validator validators-list)))

;;; ═══════════════════════════════════════════════════════════════════
;;; DECODING (Appendix D)
;;; ═══════════════════════════════════════════════════════════════════

(defun decode-archived-validator (octets position)
  "Decode archived validator λ[e][v].
   
   Graypaper equation 6.7: λ ∈ (ℕE → ⟦K⟧V)
   
   Args:
     octets: octet list
     position: starting position
   
   Returns:
     (values archived-validator new-position)"
  (let ((pos position))
    (decode>> (octets pos)
      (epoch            (decode-natural octets pos))
      (validator-index  (decode-natural octets pos))
      (bandersnatch     (decode-hash octets pos))
      (ed25519          (decode-hash octets pos))
      (values
       (make-archived-validator
        :epoch epoch
        :validator-index validator-index
        :bandersnatch bandersnatch
        :ed25519 ed25519)
       pos))))

(defun decode-archived-validators (octets position)
  "Decode the full archived validators set λ.
   
   Graypaper equation 6.7: λ ∈ (ℕE → ⟦K⟧V)
   
   Args:
     octets: octet list
     position: starting position
   
   Returns:
     (values validators-list new-position)"
  (decode-length-prefixed-sequence
   octets position #'decode-archived-validator))
