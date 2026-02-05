;;;; psi.lisp
;;;; ψ - Judgements (Graypaper equation 10.1)
;;;;
;;;; Past judgments on work-reports and validators: ψB, ψG, ψW, ψO.

(in-package :jotl-state)

;;; ═══════════════════════════════════════════════════════════════════
;;; GRAYPAPER REFERENCE
;;; ═══════════════════════════════════════════════════════════════════
;;; 
;;; Equation 10.1: ψ ∈ (ψB, ψG, ψW, ψO)
;;; Equation 10.16: ψG - Work-reports judged to be correct
;;; Equation 10.17: ψB - Work-reports judged to be incorrect
;;; Equation 10.18: ψW - Work-reports whose validity is judged to be unknowable
;;; Equation 10.19: ψO - Validators who made a judgment found to be incorrect
;;; 
;;; ψ is the set of past judgments from dispute resolution:
;;;   ψB: Incorrect reports (bad work-reports)
;;;   ψG: Correct reports (good work-reports)
;;;   ψW: Unknowable reports (validity cannot be determined)
;;;   ψO: Offending validators (made incorrect judgments)

;;; ═══════════════════════════════════════════════════════════════════
;;; ψB - INCORRECT REPORTS (equation 10.17)
;;; ═══════════════════════════════════════════════════════════════════

(defun encode-incorrect-reports (reports-list)
  "Encode incorrect work-reports ψB.
   
   Graypaper equation 10.17: ψB - bad reports
   
   Args:
     reports-list: list of work-report hashes (32 bytes each)
   
   Returns:
     Encoded octet list (length-prefixed sequence)"
  (encode-pre-encoded-sequence
   (mapcar #'encode-hash reports-list)))

(defun decode-incorrect-reports (octets position)
  "Decode incorrect work-reports ψB.
   
   Graypaper equation 10.17: ψB - bad reports
   
   Args:
     octets: octet list
     position: starting position
   
   Returns:
     (values reports-list new-position)"
  (decode-length-prefixed-sequence
   octets position #'decode-hash))

;;; ═══════════════════════════════════════════════════════════════════
;;; ψG - CORRECT REPORTS (equation 10.16)
;;; ═══════════════════════════════════════════════════════════════════

(defun encode-correct-reports (reports-list)
  "Encode correct work-reports ψG.
   
   Graypaper equation 10.16: ψG - good reports
   
   Args:
     reports-list: list of work-report hashes (32 bytes each)
   
   Returns:
     Encoded octet list (length-prefixed sequence)"
  (encode-pre-encoded-sequence
   (mapcar #'encode-hash reports-list)))

(defun decode-correct-reports (octets position)
  "Decode correct work-reports ψG.
   
   Graypaper equation 10.16: ψG - good reports
   
   Args:
     octets: octet list
     position: starting position
   
   Returns:
     (values reports-list new-position)"
  (decode-length-prefixed-sequence
   octets position #'decode-hash))

;;; ═══════════════════════════════════════════════════════════════════
;;; ψW - UNKNOWABLE REPORTS (equation 10.18)
;;; ═══════════════════════════════════════════════════════════════════

(defun encode-unknowable-reports (reports-list)
  "Encode unknowable work-reports ψW.
   
   Graypaper equation 10.18: ψW - unknowable validity
   
   Args:
     reports-list: list of work-report hashes (32 bytes each)
   
   Returns:
     Encoded octet list (length-prefixed sequence)"
  (encode-pre-encoded-sequence
   (mapcar #'encode-hash reports-list)))

(defun decode-unknowable-reports (octets position)
  "Decode unknowable work-reports ψW.
   
   Graypaper equation 10.18: ψW - unknowable validity
   
   Args:
     octets: octet list
     position: starting position
   
   Returns:
     (values reports-list new-position)"
  (decode-length-prefixed-sequence
   octets position #'decode-hash))

;;; ═══════════════════════════════════════════════════════════════════
;;; ψO - OFFENDING VALIDATORS (equation 10.19)
;;; ═══════════════════════════════════════════════════════════════════

(defun encode-offending-validators (validators-list)
  "Encode offending validators ψO.
   
   Graypaper equation 10.19: ψO - incorrect judgments
   
   Args:
     validators-list: list of validator indices (natural numbers)
   
   Returns:
     Encoded octet list (length-prefixed sequence)"
  (encode-pre-encoded-sequence
   (mapcar #'encode-natural validators-list)))

(defun decode-offending-validators (octets position)
  "Decode offending validators ψO.
   
   Graypaper equation 10.19: ψO - incorrect judgments
   
   Args:
     octets: octet list
     position: starting position
   
   Returns:
     (values validators-list new-position)"
  (decode-length-prefixed-sequence
   octets position #'decode-natural))

;;; ═══════════════════════════════════════════════════════════════════
;;; ψ - COMPOSITE JUDGEMENTS (equation 10.1)
;;; ═══════════════════════════════════════════════════════════════════

(defun encode-judgements (judgements)
  "Encode the full judgements state ψ.
   
   Graypaper equation 10.1: ψ ∈ (ψB, ψG, ψW, ψO)
   
   Args:
     judgements: judgements struct (composite of ψB, ψG, ψW, ψO)
   
   Returns:
     Encoded octet list"
  (concat-octets
   (encode-incorrect-reports (judgements-incorrect-reports judgements))      ; ψB
   (encode-correct-reports (judgements-correct-reports judgements))          ; ψG
   (encode-unknowable-reports (judgements-unknowable-reports judgements))    ; ψW
   (encode-offending-validators (judgements-offending-validators judgements)))) ; ψO

(defun decode-judgements (octets position)
  "Decode the full judgements state ψ.
   
   Graypaper equation 10.1: ψ ∈ (ψB, ψG, ψW, ψO)
   
   Args:
     octets: octet list
     position: starting position
   
   Returns:
     (values judgements new-position)"
  (let ((pos position))
    (decode>> (octets pos)
      (incorrect-reports     (decode-incorrect-reports octets pos))
      (correct-reports       (decode-correct-reports octets pos))
      (unknowable-reports    (decode-unknowable-reports octets pos))
      (offending-validators  (decode-offending-validators octets pos))
      (values
       (make-judgements
        :incorrect-reports incorrect-reports
        :correct-reports correct-reports
        :unknowable-reports unknowable-reports
        :offending-validators offending-validators)
       pos))))
