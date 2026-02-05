;;;; eta.lisp
;;;; η - Entropy Pool (Graypaper equation 6.21)
;;;;
;;;; On-chain entropy accumulator for randomness (32-byte hash).

(in-package :jotl-state)

;;; ═══════════════════════════════════════════════════════════════════
;;; GRAYPAPER REFERENCE
;;; ═══════════════════════════════════════════════════════════════════
;;; 
;;; Equation 6.21: η ∈ H (32-byte hash)
;;; 
;;; η is the on-chain entropy accumulator, used for epochal randomness.
;;; Updated each block with new entropy from tickets and block seals.

;;; ═══════════════════════════════════════════════════════════════════
;;; ENCODING (Appendix D)
;;; ═══════════════════════════════════════════════════════════════════

(defun encode-entropy-pool (entropy-hash)
  "Encode entropy pool η as a 32-byte hash.
   
   Graypaper equation 6.21: η ∈ H
   
   Args:
     entropy-hash: 32-byte hash (list of 32 octets)
   
   Returns:
     Encoded octet list (fixed 32 bytes)"
  (encode-hash entropy-hash))

;;; ═══════════════════════════════════════════════════════════════════
;;; DECODING (Appendix D)
;;; ═══════════════════════════════════════════════════════════════════

(defun decode-entropy-pool (octets position)
  "Decode entropy pool η from octets.
   
   Graypaper equation 6.21: η ∈ H
   
   Args:
     octets: octet list
     position: starting position
   
   Returns:
     (values entropy-hash new-position)"
  (decode-hash octets position))
