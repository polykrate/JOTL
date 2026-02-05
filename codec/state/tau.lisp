;;;; tau.lisp
;;;; τ - Current Timeslot (Graypaper equation 6.1)
;;;;
;;;; Simple natural number representing the most recent block's timeslot.

(in-package :jotl-state)

;;; ═══════════════════════════════════════════════════════════════════
;;; GRAYPAPER REFERENCE
;;; ═══════════════════════════════════════════════════════════════════
;;; 
;;; Equation 6.1: τ ∈ ℕT (Timeslot index)
;;; 
;;; τ is the timeslot index of the most recent block.
;;; No complex structure - just a natural number.

;;; ═══════════════════════════════════════════════════════════════════
;;; ENCODING (Appendix D)
;;; ═══════════════════════════════════════════════════════════════════

(defun encode-timeslot (timeslot-value)
  "Encode timeslot τ as a natural number.
   
   Graypaper equation 6.1: τ ∈ ℕT
   
   Args:
     timeslot-value: natural number (timeslot type)
   
   Returns:
     Encoded octet list (variable-length natural encoding)"
  (encode-natural timeslot-value))

;;; ═══════════════════════════════════════════════════════════════════
;;; DECODING (Appendix D)
;;; ═══════════════════════════════════════════════════════════════════

(defun decode-timeslot (octets position)
  "Decode timeslot τ from octets.
   
   Graypaper equation 6.1: τ ∈ ℕT
   
   Args:
     octets: octet list
     position: starting position
   
   Returns:
     (values timeslot new-position)"
  (decode-natural octets position))
