;;;; alpha.lisp
;;;; α - Core Authorizations Pool (Graypaper equation 8.1)
;;;;
;;;; Authorization requirements for each core.

(in-package :jotl-state)

;;; ═══════════════════════════════════════════════════════════════════
;;; GRAYPAPER REFERENCE
;;; ═══════════════════════════════════════════════════════════════════
;;; 
;;; Equation 8.1: α ∈ (ℕC → A)
;;; 
;;; α maps core indices to authorization requirements.
;;; Each core has specific authorization that work-packages must satisfy.
;;;
;;; A = (s: S, h: H) where:
;;;   s: Service ID (authorizer)
;;;   h: Hash of authorization data

;;; ═══════════════════════════════════════════════════════════════════
;;; ENCODING (Appendix D)
;;; ═══════════════════════════════════════════════════════════════════

(defun encode-core-authorization (auth)
  "Encode a single core authorization α[c].
   
   Graypaper equation 8.1: α: ℕC → (s: S, h: H)
   
   Args:
     auth: core-authorization struct
   
   Returns:
     Encoded octet list"
  (concat-octets
   (encode-e2 (core-authorization-core-index auth))   ; c: Core index (u16)
   (encode-hash (core-authorization-auth-pool auth))  ; a: Authorization pool hash (32 bytes)
   (encode-hash (core-authorization-authorized-code auth)))) ; h: Authorized code hash (32 bytes)

(defun encode-core-authorizations (auth-list)
  "Encode the full core authorizations pool α.
   
   Graypaper equation 8.1: α ∈ (ℕC → A)
   
   Args:
     auth-list: list of core-authorization structs
   
   Returns:
     Encoded octet list (length-prefixed sequence)"
  (encode-pre-encoded-sequence
   (mapcar #'encode-core-authorization auth-list)))

;;; ═══════════════════════════════════════════════════════════════════
;;; DECODING (Appendix D)
;;; ═══════════════════════════════════════════════════════════════════

(defun decode-core-authorization (octets position)
  "Decode a single core authorization α[c].
   
   Graypaper equation 8.1: α: ℕC → (s: S, h: H)
   
   Args:
     octets: octet list
     position: starting position
   
   Returns:
     (values core-authorization new-position)"
  (let ((pos position))
    (decode>> (octets pos)
      (core-index      (decode-e2 octets pos))
      (auth-pool       (decode-hash octets pos))  ; Authorization pool hash (32 bytes)
      (authorized-code (decode-hash octets pos))  ; Authorized code hash (32 bytes)
      (values
       (make-core-authorization
        :core-index core-index
        :auth-pool auth-pool
        :authorized-code authorized-code)
       pos))))

(defun decode-core-authorizations (octets position)
  "Decode the full core authorizations pool α.
   
   Graypaper equation 8.1: α ∈ (ℕC → A)
   
   Args:
     octets: octet list
     position: starting position
   
   Returns:
     (values auth-list new-position)"
  (decode-length-prefixed-sequence
   octets position #'decode-core-authorization))
