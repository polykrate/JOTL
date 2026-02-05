;;;; epoch.lisp
;;;; JAM Epoch Marker (HE) - New epoch validator set
;;;; Graypaper references: Section 5.10, 6.1
;;;; REFACTORED: All in lists (no blob conversions)

(in-package :jotl-bloc)

;;; Epoch Marker HE
;;;
;;; Graypaper Section 5.10: Epoch marker
;;; Marks the beginning of a new epoch with updated validator set

;;; Validator encoding/decoding

(defun encode-validator (validator)
  "Encode a validator (bandersnatch + ed25519 keys).
   
   Keys are already lists, just concatenate them.
   
   Args:
     validator: A validator structure
   
   Returns:
     Concatenated 64 bytes (32 + 32) as list"
  (concat-octets (validator-bandersnatch validator)
                 (validator-ed25519 validator)))

(defun decode-validator (octets start)
  "Decode a validator from octets.
   
   Args:
     octets: Encoded validator data (list)
     start: Starting position
   
   Returns:
     values: (validator bytes-consumed=64)"
  (let* ((bandersnatch (subseq octets start (+ start 32)))
         (ed25519 (subseq octets (+ start 32) (+ start 64))))
    (values (make-validator :bandersnatch bandersnatch
                            :ed25519 ed25519)
            64)))

;;; Epoch Marker encoding/decoding

(defun encode-epoch-marker (epoch-marker)
  "Encode epoch marker (HE).
   
   Structure:
     - entropy: 32 bytes
     - tickets-entropy: 32 bytes
     - validators: N × 64 bytes (N determined by chainspec)
   
   All fields already lists, just concatenate.
   
   Args:
     epoch-marker: An epoch-marker structure
   
   Returns:
     Encoded octet sequence (list)"
  (let ((encoded-validators
         (mapcar #'encode-validator (epoch-marker-validators epoch-marker))))
    (concat-octets
     (epoch-marker-entropy epoch-marker)
     (epoch-marker-tickets-entropy epoch-marker)
     (apply #'concat-octets encoded-validators))))

(defun decode-epoch-marker (octets start num-validators)
  "Decode epoch marker from octets.
   
   Args:
     octets: Encoded epoch marker data (list)
     start: Starting position
     num-validators: Number of validators to decode (from chainspec: 6 for tiny, 1023 for full)
   
   Returns:
     values: (epoch-marker bytes-consumed)"
  (let ((pos start))
    ;; entropy: 32 bytes
    (let ((entropy (subseq octets pos (+ pos 32))))
      (incf pos 32)
      
      ;; tickets-entropy: 32 bytes
      (let ((tickets-entropy (subseq octets pos (+ pos 32))))
        (incf pos 32)
        
        ;; validators: num-validators × 64 bytes
        (let ((validators '()))
          (dotimes (i num-validators)
            (multiple-value-bind (validator consumed)
                (decode-validator octets pos)
              (push validator validators)
              (incf pos consumed)))
          
          (values (make-epoch-marker
                   :entropy entropy
                   :tickets-entropy tickets-entropy
                   :validators (nreverse validators))
                  (- pos start)))))))
