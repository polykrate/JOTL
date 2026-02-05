;;;; theta.lisp
;;;; θ - Accumulation Outputs (Graypaper equations 7.4, 12.25)
;;;;
;;;; Most recent Accumulation outputs from work-package processing.

(in-package :jotl-state)

;;; ═══════════════════════════════════════════════════════════════════
;;; GRAYPAPER REFERENCE
;;; ═══════════════════════════════════════════════════════════════════
;;; 
;;; Equation 7.4: θ ∈ ⟦(S, B, ℕG)⟧
;;; Equation 12.25: Accumulation output generation
;;; 
;;; θ is the sequence of most recent Accumulation outputs.
;;; These are added to the Merkle mountain belt (βB) for commitments.
;;;
;;; Output = (s: S, o: B, g: ℕG) where:
;;;   s: Service ID that produced the output
;;;   o: Output data/blob from accumulation
;;;   g: Gas consumed during accumulation

;;; ═══════════════════════════════════════════════════════════════════
;;; ENCODING (Appendix D)
;;; ═══════════════════════════════════════════════════════════════════

(defun encode-accumulation-output (output)
  "Encode accumulation output θ[i].
   
   Graypaper equations 7.4, 12.25: θ ∈ ⟦(S, B, ℕG)⟧
   
   Args:
     output: accumulation-output struct
   
   Returns:
     Encoded octet list"
  (concat-octets
   (encode-e4 (accumulation-output-service-id output))  ; s: Service ID (u32)
   (encode-length-prefixed-sequence  ; o: Output data (blob)
    (accumulation-output-output-data output))
   (encode-e8 (accumulation-output-gas-consumed output))))  ; g: Gas consumed (u64)

(defun encode-accumulation-outputs (outputs-list)
  "Encode the full accumulation outputs θ.
   
   Graypaper equations 7.4, 12.25: θ ∈ ⟦(S, B, ℕG)⟧
   
   Args:
     outputs-list: list of accumulation-output structs
   
   Returns:
     Encoded octet list (length-prefixed sequence)"
  (encode-pre-encoded-sequence
   (mapcar #'encode-accumulation-output outputs-list)))

;;; ═══════════════════════════════════════════════════════════════════
;;; DECODING (Appendix D)
;;; ═══════════════════════════════════════════════════════════════════

(defun decode-accumulation-output (octets position)
  "Decode accumulation output θ[i].
   
   Graypaper equations 7.4, 12.25: θ ∈ ⟦(S, B, ℕG)⟧
   
   Args:
     octets: octet list
     position: starting position
   
   Returns:
     (values accumulation-output new-position)"
  (decode>> (octets position)
    (service-id    <- decode-e4)
    (output-data   <- decode-length-prefixed-sequence nil)  ; Blob
    (gas-consumed  <- decode-e8)
    :result (make-accumulation-output
             :service-id service-id
             :output-data output-data
             :gas-consumed gas-consumed)))

(defun decode-accumulation-outputs (octets position)
  "Decode the full accumulation outputs θ.
   
   Graypaper equations 7.4, 12.25: θ ∈ ⟦(S, B, ℕG)⟧
   
   Args:
     octets: octet list
     position: starting position
   
   Returns:
     (values outputs-list new-position)"
  (decode-length-prefixed-sequence
   octets position #'decode-accumulation-output))
