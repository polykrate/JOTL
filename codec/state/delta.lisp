;;;; delta.lisp
;;;; δ - Service Accounts (Graypaper equation 9.1)
;;;;
;;;; Service accounts state (analogous to Ethereum smart contract accounts).

(in-package :jotl-state)

;;; ═══════════════════════════════════════════════════════════════════
;;; GRAYPAPER REFERENCE
;;; ═══════════════════════════════════════════════════════════════════
;;; 
;;; Equation 9.1: δ ∈ (S → ServiceAccount)
;;; 
;;; δ maps service IDs to their account state.
;;;
;;; ServiceAccount = (c: H, b: ℕG, ga: ℕG, gr: ℕG, m: ℕ, l: H, p: H, t: ℕG) where:
;;;   c: Code hash (32 bytes)
;;;   b: Balance (gas tokens)
;;;   ga: Gas limit for accumulate
;;;   gr: Gas limit for refine (per work-item)
;;;   m: Memory pages allocated
;;;   l: Lookup anchor (storage root hash)
;;;   p: Preimage lookup (preimage root hash)
;;;   t: Threshold balance (minimum balance)
;;;
;;; Also see equation 12.27 for post-accumulation state δ†.

;;; ═══════════════════════════════════════════════════════════════════
;;; ENCODING (Appendix D)
;;; ═══════════════════════════════════════════════════════════════════

(defun encode-service-account (account)
  "Encode service account δ[s].
   
   Graypaper equation 9.1: δ ∈ (S → ServiceAccount)
   
   Args:
     account: service-account struct
   
   Returns:
     Encoded octet list"
  (concat-octets
   (encode-e4 (service-account-id account))  ; s: Service ID (u32)
   (encode-hash (service-account-code-hash account))  ; c: Code hash (32 bytes)
   (encode-e8 (service-account-balance account))  ; b: Balance (u64)
   (encode-e8 (service-account-gas-limit-accumulate account))  ; ga: Gas limit accumulate (u64)
   (encode-e8 (service-account-gas-limit-refine account))  ; gr: Gas limit refine (u64)
   (encode-natural (service-account-memory-pages account))  ; m: Memory pages
   (encode-hash (service-account-storage-lookup account))  ; l: Storage lookup hash
   (encode-hash (service-account-preimage-lookup account))  ; p: Preimage lookup hash
   (encode-e8 (service-account-threshold-balance account))))  ; t: Threshold (u64)

(defun encode-service-accounts (accounts-list)
  "Encode the full service accounts state δ.
   
   Graypaper equation 9.1: δ ∈ (S → ServiceAccount)
   
   Args:
     accounts-list: list of service-account structs
   
   Returns:
     Encoded octet list (length-prefixed sequence)"
  (encode-pre-encoded-sequence
   (mapcar #'encode-service-account accounts-list)))

;;; ═══════════════════════════════════════════════════════════════════
;;; DECODING (Appendix D)
;;; ═══════════════════════════════════════════════════════════════════

(defun decode-service-account (octets position)
  "Decode service account δ[s].
   
   Graypaper equation 9.1: δ ∈ (S → ServiceAccount)
   
   Args:
     octets: octet list
     position: starting position
   
   Returns:
     (values service-account new-position)"
  (let ((pos position))
    (decode>> (octets pos)
      (id                  (decode-e4 octets pos))
      (code-hash           (decode-hash octets pos))
      (balance             (decode-e8 octets pos))
      (gas-limit-accumulate (decode-e8 octets pos))
      (gas-limit-refine    (decode-e8 octets pos))
      (memory-pages        (decode-natural octets pos))
      (storage-lookup      (decode-hash octets pos))
      (preimage-lookup     (decode-hash octets pos))
      (threshold-balance   (decode-e8 octets pos))
      (values
       (make-service-account
        :id id
        :code-hash code-hash
        :balance balance
        :gas-limit-accumulate gas-limit-accumulate
        :gas-limit-refine gas-limit-refine
        :memory-pages memory-pages
        :storage-lookup storage-lookup
        :preimage-lookup preimage-lookup
        :threshold-balance threshold-balance)
       pos))))

(defun decode-service-accounts (octets position)
  "Decode the full service accounts state δ.
   
   Graypaper equation 9.1: δ ∈ (S → ServiceAccount)
   
   Args:
     octets: octet list
     position: starting position
   
   Returns:
     (values accounts-list new-position)"
  (decode-length-prefixed-sequence
   octets position #'decode-service-account))
