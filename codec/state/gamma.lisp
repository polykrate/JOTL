;;;; gamma.lisp
;;;; γ - SAFROLE State (Graypaper equation 6.3)
;;;;
;;;; Validator rotation state: γA (tickets), γP (next validators), γS (seal keys), γZ (tickets root).

(in-package :jotl-state)

;;; ═══════════════════════════════════════════════════════════════════
;;; GRAYPAPER REFERENCE
;;; ═══════════════════════════════════════════════════════════════════
;;; 
;;; Equation 6.3: γ ∈ (γA, γP, γS, γZ)
;;; Equation 6.4: γZ - Bandersnatch root for current epoch's ticket submissions
;;; Equation 6.5: γA - Sealing lottery ticket accumulator, γS - Sealing-key sequence
;;; Equation 6.7: γP - Keys for validators of next epoch
;;; 
;;; γ is the SAFROLE consensus state managing validator rotation:
;;;   γA: Ticket accumulator (list of tickets for next epoch)
;;;   γP: Next epoch validator keys (waiting to become κ)
;;;   γS: Current epoch sealing keys (for block production)
;;;   γZ: Bandersnatch Merkle root for ticket verification

;;; ═══════════════════════════════════════════════════════════════════
;;; γA - TICKET ACCUMULATOR (equation 6.5)
;;; ═══════════════════════════════════════════════════════════════════

(defun encode-ticket-accumulator (tickets-list)
  "Encode ticket accumulator γA.
   
   Graypaper equation 6.5: γA - lottery tickets
   
   Args:
     tickets-list: list of ticket structs (TODO: Define ticket structure)
   
   Returns:
     Encoded octet list (length-prefixed sequence)"
  (encode-length-prefixed-sequence tickets-list))  ; TODO: Implement ticket encoding

(defun decode-ticket-accumulator (octets position)
  "Decode ticket accumulator γA.
   
   Graypaper equation 6.5: γA - lottery tickets
   
   Args:
     octets: octet list
     position: starting position
   
   Returns:
     (values tickets-list new-position)"
  (decode-length-prefixed-sequence octets position nil))  ; TODO: Implement ticket decoding

;;; ═══════════════════════════════════════════════════════════════════
;;; γP - NEXT VALIDATORS (equation 6.7)
;;; ═══════════════════════════════════════════════════════════════════

(defun encode-next-validators (validators-list)
  "Encode next epoch validators γP.
   
   Graypaper equation 6.7: γP - next epoch validator keys
   
   Args:
     validators-list: list of validator-keys structs
   
   Returns:
     Encoded octet list (length-prefixed sequence)"
  (encode-pre-encoded-sequence
   (mapcar #'encode-validator-keys validators-list)))

(defun decode-next-validators (octets position)
  "Decode next epoch validators γP.
   
   Graypaper equation 6.7: γP - next epoch validator keys
   
   Args:
     octets: octet list
     position: starting position
   
   Returns:
     (values validators-list new-position)"
  (decode-length-prefixed-sequence
   octets position #'decode-validator-keys))

;;; ═══════════════════════════════════════════════════════════════════
;;; γS - SEAL KEYS (equation 6.5)
;;; ═══════════════════════════════════════════════════════════════════

(defun encode-seal-keys (seal-keys-list)
  "Encode sealing keys γS.
   
   Graypaper equation 6.5: γS - current epoch sealing keys
   
   Args:
     seal-keys-list: list of Bandersnatch public keys (hashes)
   
   Returns:
     Encoded octet list (length-prefixed sequence)"
  (encode-pre-encoded-sequence
   (mapcar #'encode-hash seal-keys-list)))

(defun decode-seal-keys (octets position)
  "Decode sealing keys γS.
   
   Graypaper equation 6.5: γS - current epoch sealing keys
   
   Args:
     octets: octet list
     position: starting position
   
   Returns:
     (values seal-keys-list new-position)"
  (decode-length-prefixed-sequence
   octets position #'decode-hash))

;;; ═══════════════════════════════════════════════════════════════════
;;; γZ - TICKETS ROOT (equation 6.4)
;;; ═══════════════════════════════════════════════════════════════════

(defun encode-tickets-root (root-hash)
  "Encode tickets root γZ.
   
   Graypaper equation 6.4: γZ - Bandersnatch root
   
   Args:
     root-hash: 32-byte hash
   
   Returns:
     Encoded octet list (fixed 32 bytes)"
  (encode-hash root-hash))

(defun decode-tickets-root (octets position)
  "Decode tickets root γZ.
   
   Graypaper equation 6.4: γZ - Bandersnatch root
   
   Args:
     octets: octet list
     position: starting position
   
   Returns:
     (values root-hash new-position)"
  (decode-hash octets position))

;;; ═══════════════════════════════════════════════════════════════════
;;; γ - COMPOSITE SAFROLE STATE (equation 6.3)
;;; ═══════════════════════════════════════════════════════════════════

(defun encode-safrole-state (state)
  "Encode the full SAFROLE state γ.
   
   Graypaper equation 6.3: γ ∈ (γA, γP, γS, γZ)
   
   Args:
     state: safrole-state struct (composite of γA, γP, γS, γZ)
   
   Returns:
     Encoded octet list"
  (concat-octets
   (encode-ticket-accumulator (safrole-state-ticket-accumulator state))  ; γA
   (encode-next-validators (safrole-state-next-validators state))        ; γP
   (encode-seal-keys (safrole-state-seal-keys state))                    ; γS
   (encode-tickets-root (safrole-state-tickets-root state))))            ; γZ

(defun decode-safrole-state (octets position)
  "Decode the full SAFROLE state γ.
   
   Graypaper equation 6.3: γ ∈ (γA, γP, γS, γZ)
   
   Args:
     octets: octet list
     position: starting position
   
   Returns:
     (values safrole-state new-position)"
  (decode>> (octets position)
    (ticket-accumulator <- decode-ticket-accumulator)
    (next-validators    <- decode-next-validators)
    (seal-keys          <- decode-seal-keys)
    (tickets-root       <- decode-tickets-root)
    :result (make-safrole-state
             :ticket-accumulator ticket-accumulator
             :next-validators next-validators
             :seal-keys seal-keys
             :tickets-root tickets-root)))
