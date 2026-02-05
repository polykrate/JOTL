;;;; availability.lisp
;;;; JAM Availability Assurances (EA)
;;;; Graypaper references: Appendix C.20

(in-package :jotl-bloc)

;;; Availability Assurance
;;;
;;; Graypaper Appendix C.20:
;;; EA(EA) = E(↕[(a, f, E2(v), s) | (a,f,v,s) ← EA])
;;;
;;; Each assurance is a tuple (a, f, v, s) where:
;;; - a: assurance anchor/hash (blob)
;;; - f: flags (blob)
;;; - v: validator index (2 bytes, E2)
;;; - s: signature (blob)
;;;
;;; Availability assurances are encoded as a length-prefixed sequence.

(defun encode-availability (assurances)
  "Encode availability assurances (EA).
   
   Graypaper Appendix C.20: EA(EA) = E(↕[(a, f, E2(v), s) | (a,f,v,s) ← EA])
   
   Args:
     assurances: List of availability-assurance structures
   
   Returns:
     Encoded octet sequence"
  (let ((encoded-assurances
         (mapcar (lambda (assurance)
                   (concat-octets
                    ;; a : assurance anchor (FIXED 32 bytes hash!)
                    (availability-assurance-assurance-a assurance)
                    ;; f : flags/bitfield (FIXED size from chainspec!)
                    (availability-assurance-flags assurance)
                    ;; E2(v) : validator index (2 bytes)
                    (e2 (availability-assurance-validator-index assurance))
                    ;; s : signature (FIXED 64 bytes!)
                    (availability-assurance-signature assurance)))
                 assurances)))
    ;; ↕[...] : length-prefixed sequence of pre-encoded elements
    (encode-length-prefixed-sequence encoded-assurances :pre-encoded t)))

(defun decode-availability (octets &optional (start 0))
  "Decode availability assurances from octets.
   
   Inverse of encode-availability (Appendix C.20).
   
   Args:
     octets: Encoded availability data
     start: Starting position
   
   Returns:
     values: (list-of-availability-assurance bytes-consumed)"
  (decode-length-prefixed-sequence
   octets
   (lambda (o s)
     (let ((pos s))
      (decode>> (o pos)
        ;; a : assurance anchor (FIXED 32 bytes hash!)
        (assurance-a (decode-hash o pos))
        ;; f : flags/bitfield (FIXED size from chainspec!)
        (flags (decode-fixed-bytes o pos (chainspec-avail-bitfield-bytes *chainspec*)))
        ;; E2(v) : validator index (2 bytes)
        (validator-index (decode-e2 o pos))
        ;; s : signature (FIXED 64 bytes!)
        (signature (decode-fixed-bytes o pos 64))
         
         (values
          (make-availability-assurance
           :assurance-a assurance-a
           :flags flags
           :validator-index validator-index
           :signature signature)
          (- pos s)))))
   start))
