;;;; xi.lisp
;;;; ξ - Accumulation History (Graypaper equation 12.1)
;;;;
;;;; Recently accumulated work-packages (prevents replay).

(in-package :jotl-state)

;;; ═══════════════════════════════════════════════════════════════════
;;; GRAYPAPER REFERENCE
;;; ═══════════════════════════════════════════════════════════════════
;;; 
;;; Equation 12.1: ξ ∈ ⟦(H, ℕT)⟧
;;; 
;;; ξ is the history of recently accumulated work-packages.
;;; Used to prevent replay attacks (same work-package accumulated twice).
;;;
;;; Entry = (h: H, t: ℕT) where:
;;;   h: Work-package hash (32 bytes)
;;;   t: Timeslot of accumulation

;;; ═══════════════════════════════════════════════════════════════════
;;; ENCODING (Appendix D)
;;; ═══════════════════════════════════════════════════════════════════

(defun encode-accumulated-package (package)
  "Encode accumulated package ξ[i].
   
   Graypaper equation 12.1: ξ ∈ ⟦(H, ℕT)⟧
   
   Args:
     package: accumulated-package struct
   
   Returns:
     Encoded octet list"
  (concat-octets
   (encode-hash (accumulated-package-package-hash package))  ; h: Package hash (32 bytes)
   (encode-e4 (accumulated-package-accumulated-timeslot package))))  ; t: Timeslot (u32)

(defun encode-accumulation-history (packages-list)
  "Encode the full accumulation history ξ.
   
   Graypaper equation 12.1: ξ ∈ ⟦(H, ℕT)⟧
   
   Args:
     packages-list: list of accumulated-package structs
   
   Returns:
     Encoded octet list (length-prefixed sequence)"
  (encode-pre-encoded-sequence
   (mapcar #'encode-accumulated-package packages-list)))

;;; ═══════════════════════════════════════════════════════════════════
;;; DECODING (Appendix D)
;;; ═══════════════════════════════════════════════════════════════════

(defun decode-accumulated-package (octets position)
  "Decode accumulated package ξ[i].
   
   Graypaper equation 12.1: ξ ∈ ⟦(H, ℕT)⟧
   
   Args:
     octets: octet list
     position: starting position
   
   Returns:
     (values accumulated-package new-position)"
  (decode>> (octets position)
    (package-hash         <- decode-hash)
    (accumulated-timeslot <- decode-e4)
    :result (make-accumulated-package
             :package-hash package-hash
             :accumulated-timeslot accumulated-timeslot)))

(defun decode-accumulation-history (octets position)
  "Decode the full accumulation history ξ.
   
   Graypaper equation 12.1: ξ ∈ ⟦(H, ℕT)⟧
   
   Args:
     octets: octet list
     position: starting position
   
   Returns:
     (values packages-list new-position)"
  (decode-length-prefixed-sequence
   octets position #'decode-accumulated-package))
