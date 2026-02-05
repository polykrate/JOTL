;;;; iota.lisp
;;;; ι - Validator Queue (Graypaper equation 6.7)
;;;;
;;;; Validator keys and metadata to be drawn from next.

(in-package :jotl-state)

;;; ═══════════════════════════════════════════════════════════════════
;;; GRAYPAPER REFERENCE
;;; ═══════════════════════════════════════════════════════════════════
;;; 
;;; Equation 6.7: ι ∈ ⟦K × M⟧
;;; 
;;; ι is the queue of validators waiting to be enrolled in the next epoch.
;;;
;;; K = (b: Bandersnatch, e: Ed25519, [g: BLS]) where:
;;;   b: Bandersnatch public key (32 bytes)
;;;   e: Ed25519 public key (32 bytes)
;;;   g: BLS public key (144 bytes, optional)
;;;
;;; M = metadata (e.g., deposit amount, registration details)

;;; ═══════════════════════════════════════════════════════════════════
;;; ENCODING (Appendix D)
;;; ═══════════════════════════════════════════════════════════════════

(defun encode-validator-queue-entry (entry)
  "Encode validator queue entry ι[i].
   
   Graypaper equation 6.7: ι ∈ ⟦K × M⟧
   
   Args:
     entry: validator-queue-entry struct
   
   Returns:
     Encoded octet list"
  (concat-octets
   (encode-hash (validator-queue-entry-bandersnatch entry))  ; b: Bandersnatch (32 bytes)
   (encode-hash (validator-queue-entry-ed25519 entry))       ; e: Ed25519 (32 bytes)
   (encode-optional (validator-queue-entry-bls entry) #'encode-hash)  ; g: BLS (optional)
   (encode-e8 (validator-queue-entry-deposit entry))))  ; Deposit (u64)

(defun encode-validator-queue (queue-list)
  "Encode the full validator queue ι.
   
   Graypaper equation 6.7: ι ∈ ⟦K × M⟧
   
   Args:
     queue-list: list of validator-queue-entry structs
   
   Returns:
     Encoded octet list (length-prefixed sequence)"
  (encode-pre-encoded-sequence
   (mapcar #'encode-validator-queue-entry queue-list)))

;;; ═══════════════════════════════════════════════════════════════════
;;; DECODING (Appendix D)
;;; ═══════════════════════════════════════════════════════════════════

(defun decode-validator-queue-entry (octets position)
  "Decode validator queue entry ι[i].
   
   Graypaper equation 6.7: ι ∈ ⟦K × M⟧
   
   Args:
     octets: octet list
     position: starting position
   
   Returns:
     (values validator-queue-entry new-position)"
  (decode>> (octets position)
    (bandersnatch <- decode-hash)
    (ed25519      <- decode-hash)
    (bls          <- decode-optional #'decode-hash)
    (deposit      <- decode-e8)
    :result (make-validator-queue-entry
             :bandersnatch bandersnatch
             :ed25519 ed25519
             :bls bls
             :deposit deposit)))

(defun decode-validator-queue (octets position)
  "Decode the full validator queue ι.
   
   Graypaper equation 6.7: ι ∈ ⟦K × M⟧
   
   Args:
     octets: octet list
     position: starting position
   
   Returns:
     (values queue-list new-position)"
  (decode-length-prefixed-sequence
   octets position #'decode-validator-queue-entry))
