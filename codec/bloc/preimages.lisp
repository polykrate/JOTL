;;;; preimages.lisp
;;;; JAM Preimages (EP)
;;;; Graypaper references: Appendix C.18

(in-package :jotl-bloc)

;;; Preimage
;;;
;;; Graypaper Appendix C.18:
;;; EP(EP) = E(↕[(E4(s), ↕d) | (s, d) ← EP])
;;;
;;; Each preimage is a tuple (s, d) where:
;;; - s: service ID (4 bytes, E4)
;;; - d: data blob (variable length, ↕d means length-discriminated)
;;;
;;; The preimages are encoded as a length-prefixed sequence of (service-id, data) pairs.

(defun encode-preimages (preimages)
  "Encode preimages (EP).
   
   Graypaper Appendix C.18: EP(EP) = E(↕[(E4(s), ↕d) | (s, d) ← EP])
   
   Args:
     preimages: List of preimage structures
   
   Returns:
     Encoded octet sequence"
  (let ((encoded-preimages
         (mapcar (lambda (preimage)
                   (concat-octets
                    ;; E4(s) : service-id (4 bytes)
                    (e4 (preimage-service-id preimage))
                    ;; ↕d : length-prefixed data
                    (encode-with-length (preimage-data preimage))))
                 preimages)))
    ;; ↕[...] : length-prefixed sequence of pre-encoded elements
    (encode-length-prefixed-sequence encoded-preimages :pre-encoded t)))

(defun decode-preimages (octets &optional (start 0))
  "Decode preimages from octets.
   
   Inverse of encode-preimages (Appendix C.18).
   
   Args:
     octets: Encoded preimages data
     start: Starting position
   
   Returns:
     values: (list-of-preimage bytes-consumed)"
  (decode-length-prefixed-sequence 
   octets
   (lambda (o s)
     (let ((pos s))
       (decode>> (o pos)
         ;; E4(s) : service-id (4 bytes)
         (service-id (decode-e4 o pos))
         ;; ↕d : length-prefixed data
         (data (decode-with-length o pos))
         
         (values
          (make-preimage
           :service-id service-id
           :data data)
          (- pos s)))))
   start))
