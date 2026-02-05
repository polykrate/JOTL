;;;; phi.lisp
;;;; ϕ - Authorization Queue (Graypaper equation 8.1)
;;;;
;;;; Queue filling core authorization requirements.

(in-package :jotl-state)

;;; ═══════════════════════════════════════════════════════════════════
;;; GRAYPAPER REFERENCE
;;; ═══════════════════════════════════════════════════════════════════
;;; 
;;; Equation 8.1: ϕ ∈ ⟦A⟧
;;; 
;;; ϕ is the authorization queue, a sequence of authorization requests.
;;; Authorizations are dequeued and assigned to cores as they become available.
;;;
;;; A = (s: S, c: H, a: H) where:
;;;   s: Service ID requesting authorization
;;;   c: Code hash to authorize
;;;   a: Authorization pool hash

;;; ═══════════════════════════════════════════════════════════════════
;;; ENCODING (Appendix D)
;;; ═══════════════════════════════════════════════════════════════════

(defun encode-authorization-queue-entry (entry)
  "Encode a single authorization queue entry ϕ[i].
   
   Graypaper equation 8.1: ϕ ∈ ⟦A⟧
   
   Args:
     entry: authorization-queue-entry struct
   
   Returns:
     Encoded octet list"
  (concat-octets
   (encode-e4 (authorization-queue-entry-service-id entry))  ; s: Service ID (u32)
   (encode-hash (authorization-queue-entry-code-hash entry))  ; c: Code hash
   (encode-hash (authorization-queue-entry-auth-pool entry)))) ; a: Auth pool hash

(defun encode-authorization-queue (queue-list)
  "Encode the full authorization queue ϕ.
   
   Graypaper equation 8.1: ϕ ∈ ⟦A⟧
   
   Args:
     queue-list: list of authorization-queue-entry structs
   
   Returns:
     Encoded octet list (length-prefixed sequence)"
  (encode-pre-encoded-sequence
   (mapcar #'encode-authorization-queue-entry queue-list)))

;;; ═══════════════════════════════════════════════════════════════════
;;; DECODING (Appendix D)
;;; ═══════════════════════════════════════════════════════════════════

(defun decode-authorization-queue-entry (octets position)
  "Decode a single authorization queue entry ϕ[i].
   
   Graypaper equation 8.1: ϕ ∈ ⟦A⟧
   
   Args:
     octets: octet list
     position: starting position
   
   Returns:
     (values authorization-queue-entry new-position)"
  (let ((pos position))
    (decode>> (octets pos)
      (service-id (decode-e4 octets pos))
      (code-hash  (decode-hash octets pos))
      (auth-pool  (decode-hash octets pos))
      (values
       (make-authorization-queue-entry
        :service-id service-id
        :code-hash code-hash
        :auth-pool auth-pool)
       pos))))

(defun decode-authorization-queue (octets position)
  "Decode the full authorization queue ϕ.
   
   Graypaper equation 8.1: ϕ ∈ ⟦A⟧
   
   Args:
     octets: octet list
     position: starting position
   
   Returns:
     (values queue-list new-position)"
  (decode-length-prefixed-sequence
   octets position #'decode-authorization-queue-entry))
