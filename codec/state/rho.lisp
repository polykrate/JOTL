;;;; rho.lisp
;;;; ρ - Pending Reports (Graypaper equation 11.1)
;;;;
;;;; Work-reports pending availability assurance (per core).

(in-package :jotl-state)

;;; ═══════════════════════════════════════════════════════════════════
;;; GRAYPAPER REFERENCE
;;; ═══════════════════════════════════════════════════════════════════
;;; 
;;; Equation 11.1: ρ ∈ (ℕC → PendingReport)
;;; 
;;; ρ maps core indices to their pending work-report.
;;; Each core can have at most one report awaiting availability assurance.
;;;
;;; PendingReport = (h: H, t: ℕT, v: 𝔹V) where:
;;;   h: Work-report hash (32 bytes)
;;;   t: Timeslot when reported
;;;   v: Availability votes (bitfield of validators)
;;;
;;; Intermediate states:
;;;   ρ†: Post-judgment, pre-guarantees-extrinsic (equation 10.15)
;;;   ρ‡: Post-guarantees, pre-assurances (equation 11.17)

;;; ═══════════════════════════════════════════════════════════════════
;;; ENCODING (Appendix D)
;;; ═══════════════════════════════════════════════════════════════════

(defun encode-pending-report (report)
  "Encode pending report ρ[c].
   
   Graypaper equation 11.1: ρ ∈ (ℕC → PendingReport)
   
   Args:
     report: pending-report struct
   
   Returns:
     Encoded octet list"
  (concat-octets
   (encode-e2 (pending-report-core-index report))  ; c: Core index (u16)
   (encode-hash (pending-report-report-hash report))  ; h: Report hash (32 bytes)
   (encode-e4 (pending-report-reported-timeslot report))  ; t: Timeslot (u32)
   (encode-length-prefixed-sequence  ; v: Availability votes (bitfield)
    (pending-report-availability-votes report))))

(defun encode-pending-reports (reports-list)
  "Encode the full pending reports state ρ.
   
   Graypaper equation 11.1: ρ ∈ (ℕC → PendingReport)
   
   Args:
     reports-list: list of pending-report structs
   
   Returns:
     Encoded octet list (length-prefixed sequence)"
  (encode-pre-encoded-sequence
   (mapcar #'encode-pending-report reports-list)))

;;; ═══════════════════════════════════════════════════════════════════
;;; DECODING (Appendix D)
;;; ═══════════════════════════════════════════════════════════════════

(defun decode-pending-report (octets position)
  "Decode pending report ρ[c].
   
   Graypaper equation 11.1: ρ ∈ (ℕC → PendingReport)
   
   Args:
     octets: octet list
     position: starting position
   
   Returns:
     (values pending-report new-position)"
  (let ((pos position))
    (decode>> (octets pos)
      (core-index        (decode-e2 octets pos))
      (report-hash       (decode-hash octets pos))
      (reported-timeslot (decode-e4 octets pos))
      (availability-votes (decode-length-prefixed-sequence octets nil pos))  ; Bitfield
      (values
       (make-pending-report
        :core-index core-index
        :report-hash report-hash
        :reported-timeslot reported-timeslot
        :availability-votes availability-votes)
       pos))))

(defun decode-pending-reports (octets position)
  "Decode the full pending reports state ρ.
   
   Graypaper equation 11.1: ρ ∈ (ℕC → PendingReport)
   
   Args:
     octets: octet list
     position: starting position
   
   Returns:
     (values reports-list new-position)"
  (decode-length-prefixed-sequence
   octets position #'decode-pending-report))
