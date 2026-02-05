;;;; omega.lisp
;;;; ω - Accumulation Queue (Graypaper equation 12.3)
;;;;
;;;; Work-reports ready to accumulate (passed availability).

(in-package :jotl-state)

;;; ═══════════════════════════════════════════════════════════════════
;;; GRAYPAPER REFERENCE
;;; ═══════════════════════════════════════════════════════════════════
;;; 
;;; Equation 12.3: ω ∈ ⟦WorkReport⟧
;;; 
;;; ω is the queue of work-reports that have passed availability assurance
;;; and are ready to be accumulated (executed).
;;;
;;; WorkReport = (h: H, s: S, results: ⟦WorkResult⟧) where:
;;;   h: Work-report hash (32 bytes)
;;;   s: Service ID affected
;;;   results: Sequence of work results from work-package execution

;;; ═══════════════════════════════════════════════════════════════════
;;; ENCODING (Appendix D)
;;; ═══════════════════════════════════════════════════════════════════

(defun encode-pending-accumulation (pending)
  "Encode pending accumulation ω[i].
   
   Graypaper equation 12.3: ω ∈ ⟦WorkReport⟧
   
   Args:
     pending: pending-accumulation struct
   
   Returns:
     Encoded octet list"
  (concat-octets
   (encode-hash (pending-accumulation-report-hash pending))  ; h: Report hash (32 bytes)
   (encode-e4 (pending-accumulation-service-id pending))  ; s: Service ID (u32)
   (encode-length-prefixed-sequence  ; results: Work results sequence
    (pending-accumulation-results pending))))

(defun encode-accumulation-queue (queue-list)
  "Encode the full accumulation queue ω.
   
   Graypaper equation 12.3: ω ∈ ⟦WorkReport⟧
   
   Args:
     queue-list: list of pending-accumulation structs
   
   Returns:
     Encoded octet list (length-prefixed sequence)"
  (encode-pre-encoded-sequence
   (mapcar #'encode-pending-accumulation queue-list)))

;;; ═══════════════════════════════════════════════════════════════════
;;; DECODING (Appendix D)
;;; ═══════════════════════════════════════════════════════════════════

(defun decode-pending-accumulation (octets position)
  "Decode pending accumulation ω[i].
   
   Graypaper equation 12.3: ω ∈ ⟦WorkReport⟧
   
   Args:
     octets: octet list
     position: starting position
   
   Returns:
     (values pending-accumulation new-position)"
  (decode>> (octets position)
    (report-hash <- decode-hash)
    (service-id  <- decode-e4)
    (results     <- decode-length-prefixed-sequence nil)  ; TODO: Decode work-results
    :result (make-pending-accumulation
             :report-hash report-hash
             :service-id service-id
             :results results)))

(defun decode-accumulation-queue (octets position)
  "Decode the full accumulation queue ω.
   
   Graypaper equation 12.3: ω ∈ ⟦WorkReport⟧
   
   Args:
     octets: octet list
     position: starting position
   
   Returns:
     (values queue-list new-position)"
  (decode-length-prefixed-sequence
   octets position #'decode-pending-accumulation))
