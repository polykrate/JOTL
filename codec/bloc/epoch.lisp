;;;; epoch.lisp
;;;; JAM Epoch Marker (HE)
;;;; Graypaper references: Section 5, Appendix C.23

(in-package :jotl-bloc)

;;; Epoch Marker HE
;;;
;;; Graypaper Section 5:
;;; The epoch marker HE appears in the header when a new epoch begins.
;;; It contains:
;;; - entropy: randomness for the epoch (H, 32-byte hash)
;;; - tickets-entropy: entropy for ticket selection (H, 32-byte hash)
;;; - validators: sequence of validator public keys for the new epoch
;;;
;;; Each validator contains:
;;; - bandersnatch: Bandersnatch public key (32 bytes)
;;; - ed25519: Ed25519 public key (32 bytes)
;;;
;;; The epoch marker is encoded as:
;;; E(HE) = entropy ⌢ tickets-entropy ⌢ E([validator1, validator2, ...])
;;; where each validator is: bandersnatch ⌢ ed25519 (64 bytes total)

(defun encode-epoch-marker (epoch-marker)
  "Encode an epoch marker.
   
   Args:
     epoch-marker: An epoch-marker structure
   
   Returns:
     Encoded octet sequence"
  (concat-octets
   (epoch-marker-entropy epoch-marker)
   (epoch-marker-tickets-entropy epoch-marker)
   (apply #'concat-octets
          (mapcar #'encode-validator (epoch-marker-validators epoch-marker)))))

(defun encode-validator (validator)
  "Encode a validator (bandersnatch ⌢ ed25519).
   
   Args:
     validator: A validator structure
   
   Returns:
     64-byte octet sequence"
  (concat-octets
   (validator-bandersnatch validator)
   (validator-ed25519 validator)))

(defun decode-epoch-marker (octets start num-validators)
  "Decode an epoch marker.
   
   Args:
     octets: Encoded data
     start: Starting position
     num-validators: Number of validators to decode
   
   Returns:
     values: (epoch-marker bytes-consumed)"
  (let ((pos start))
    (decode>> (octets pos)
      (entropy (decode-hash octets pos))
      (tickets-entropy (decode-hash octets pos))
      (validators (decode-validators octets pos num-validators))
      
      (values
       (make-epoch-marker
        :entropy entropy
        :tickets-entropy tickets-entropy
        :validators validators)
       (- pos start)))))

(defun decode-validators (octets start count)
  "Decode a fixed-length sequence of validators.
   
   Args:
     octets: Encoded data
     start: Starting position
     count: Number of validators
   
   Returns:
     values: (list-of-validators bytes-consumed)"
  (let ((validators '())
        (pos start))
    (dotimes (i count)
      (multiple-value-bind (validator consumed)
          (decode-validator octets pos)
        (push validator validators)
        (incf pos consumed)))
    (values (nreverse validators) (- pos start))))

(defun decode-validator (octets start)
  "Decode a validator (64 bytes: bandersnatch + ed25519).
   
   Args:
     octets: Encoded data
     start: Starting position
   
   Returns:
     values: (validator 64)"
  (let ((pos start))
    (decode>> (octets pos)
      (bandersnatch (decode-hash octets pos))
      (ed25519 (decode-hash octets pos))
      
      (values
       (make-validator
        :bandersnatch bandersnatch
        :ed25519 ed25519)
       (- pos start)))))
