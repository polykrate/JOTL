;;;; chi.lisp
;;;; χ - Privileged Services (Graypaper equation 9.9)
;;;;
;;;; Service indices with special on-chain privileges: χM, χA, χV, χR, χZ.

(in-package :jotl-state)

;;; ═══════════════════════════════════════════════════════════════════
;;; GRAYPAPER REFERENCE
;;; ═══════════════════════════════════════════════════════════════════
;;; 
;;; Equation 9.9: χ ∈ (χM, χA, χV, χR, χZ)
;;; Equation 12.27: Detailed definitions of privileged services
;;; 
;;; χ is the set of privileged service indices:
;;;   χM: Blessed service (manager service)
;;;   χA: Services able to assign each core's authorizer queue
;;;   χV: Designate service (validator management)
;;;   χR: Registrar service (service registration)
;;;   χZ: Always-accumulate services (with basic gas allowance)

;;; ═══════════════════════════════════════════════════════════════════
;;; χM - BLESSED SERVICE (equation 12.27)
;;; ═══════════════════════════════════════════════════════════════════

(defun encode-blessed-service (service-id)
  "Encode blessed service χM.
   
   Graypaper equation 12.27: χM - blessed/manager service
   
   Args:
     service-id: Service ID (u32) or +empty+ if none
   
   Returns:
     Encoded octet list"
  (encode-optional service-id #'encode-e4))

(defun decode-blessed-service (octets position)
  "Decode blessed service χM.
   
   Graypaper equation 12.27: χM - blessed/manager service
   
   Args:
     octets: octet list
     position: starting position
   
   Returns:
     (values service-id new-position)"
  (decode-optional octets position #'decode-e4))

;;; ═══════════════════════════════════════════════════════════════════
;;; χA - AUTHORIZER ASSIGNERS (equation 12.27)
;;; ═══════════════════════════════════════════════════════════════════

(defun encode-authorizer-assigners (assigners-list)
  "Encode authorizer assigners χA.
   
   Graypaper equation 12.27: χA - core authorizer assigners
   
   Args:
     assigners-list: list of service IDs (u32)
   
   Returns:
     Encoded octet list (length-prefixed sequence)"
  (encode-pre-encoded-sequence
   (mapcar #'encode-e4 assigners-list)))

(defun decode-authorizer-assigners (octets position)
  "Decode authorizer assigners χA.
   
   Graypaper equation 12.27: χA - core authorizer assigners
   
   Args:
     octets: octet list
     position: starting position
   
   Returns:
     (values assigners-list new-position)"
  (decode-length-prefixed-sequence
   octets position #'decode-e4))

;;; ═══════════════════════════════════════════════════════════════════
;;; χV - DESIGNATE SERVICE (equation 12.27)
;;; ═══════════════════════════════════════════════════════════════════

(defun encode-designate-service (service-id)
  "Encode designate service χV.
   
   Graypaper equation 12.27: χV - validator designate service
   
   Args:
     service-id: Service ID (u32) or +empty+ if none
   
   Returns:
     Encoded octet list"
  (encode-optional service-id #'encode-e4))

(defun decode-designate-service (octets position)
  "Decode designate service χV.
   
   Graypaper equation 12.27: χV - validator designate service
   
   Args:
     octets: octet list
     position: starting position
   
   Returns:
     (values service-id new-position)"
  (decode-optional octets position #'decode-e4))

;;; ═══════════════════════════════════════════════════════════════════
;;; χR - REGISTRAR SERVICE (equation 12.27)
;;; ═══════════════════════════════════════════════════════════════════

(defun encode-registrar-service (service-id)
  "Encode registrar service χR.
   
   Graypaper equation 12.27: χR - service registrar
   
   Args:
     service-id: Service ID (u32) or +empty+ if none
   
   Returns:
     Encoded octet list"
  (encode-optional service-id #'encode-e4))

(defun decode-registrar-service (octets position)
  "Decode registrar service χR.
   
   Graypaper equation 12.27: χR - service registrar
   
   Args:
     octets: octet list
     position: starting position
   
   Returns:
     (values service-id new-position)"
  (decode-optional octets position #'decode-e4))

;;; ═══════════════════════════════════════════════════════════════════
;;; χZ - ALWAYS-ACCUMULATE SERVICES (equation 12.27)
;;; ═══════════════════════════════════════════════════════════════════

(defun encode-always-accumulate-entry (entry)
  "Encode always-accumulate entry (s: S, g: ℕG).
   
   Graypaper equation 12.27: χZ - always-accumulate services
   
   Args:
     entry: (service-id . gas-allowance) pair
   
   Returns:
     Encoded octet list"
  (concat-octets
   (encode-e4 (car entry))   ; s: Service ID (u32)
   (encode-e8 (cdr entry)))) ; g: Gas allowance (u64)

(defun encode-always-accumulate (entries-list)
  "Encode always-accumulate services χZ.
   
   Graypaper equation 12.27: χZ - always-accumulate services + gas
   
   Args:
     entries-list: list of (service-id . gas-allowance) pairs
   
   Returns:
     Encoded octet list (length-prefixed sequence)"
  (encode-pre-encoded-sequence
   (mapcar #'encode-always-accumulate-entry entries-list)))

(defun decode-always-accumulate-entry (octets position)
  "Decode always-accumulate entry (s: S, g: ℕG).
   
   Graypaper equation 12.27: χZ - always-accumulate services
   
   Args:
     octets: octet list
     position: starting position
   
   Returns:
     (values (service-id . gas-allowance) new-position)"
  (let ((pos position))
    (decode>> (octets pos)
      (service-id     (decode-e4 octets pos))
      (gas-allowance  (decode-e8 octets pos))
      (values
       (cons service-id gas-allowance)
       pos))))

(defun decode-always-accumulate (octets position)
  "Decode always-accumulate services χZ.
   
   Graypaper equation 12.27: χZ - always-accumulate services + gas
   
   Args:
     octets: octet list
     position: starting position
   
   Returns:
     (values entries-list new-position)"
  (decode-length-prefixed-sequence
   octets position #'decode-always-accumulate-entry))

;;; ═══════════════════════════════════════════════════════════════════
;;; χ - COMPOSITE PRIVILEGED SERVICES (equation 9.9)
;;; ═══════════════════════════════════════════════════════════════════

(defun encode-privileged-services (services)
  "Encode the full privileged services χ.
   
   Graypaper equations 9.9, 12.27: χ ∈ (χM, χA, χV, χR, χZ)
   
   Args:
     services: privileged-services struct (composite of χM, χA, χV, χR, χZ)
   
   Returns:
     Encoded octet list"
  (concat-octets
   (encode-blessed-service (privileged-services-blessed services))         ; χM
   (encode-authorizer-assigners (privileged-services-authorizer-assigners services))  ; χA
   (encode-designate-service (privileged-services-designate services))     ; χV
   (encode-registrar-service (privileged-services-registrar services))     ; χR
   (encode-always-accumulate (privileged-services-always-accumulate services))))  ; χZ

(defun decode-privileged-services (octets position)
  "Decode the full privileged services χ.
   
   Graypaper equations 9.9, 12.27: χ ∈ (χM, χA, χV, χR, χZ)
   
   Args:
     octets: octet list
     position: starting position
   
   Returns:
     (values privileged-services new-position)"
  (let ((pos position))
    (decode>> (octets pos)
      (blessed              (decode-blessed-service octets pos))
      (authorizer-assigners (decode-authorizer-assigners octets pos))
      (designate            (decode-designate-service octets pos))
      (registrar            (decode-registrar-service octets pos))
      (always-accumulate    (decode-always-accumulate octets pos))
      (values
       (make-privileged-services
        :blessed blessed
        :authorizer-assigners authorizer-assigners
        :designate designate
        :registrar registrar
        :always-accumulate always-accumulate)
       pos))))
