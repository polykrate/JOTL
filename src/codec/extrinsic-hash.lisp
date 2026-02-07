;;;; extrinsic-hash.lisp - Extrinsic Hash (HX) Computation
;;;; Gray Paper §5.4-5.6

(in-package :jotl)

;;; ==========================================================================
;;; Extrinsic Hash Computation (Gray Paper §5.4-5.6)
;;; ==========================================================================
;;;
;;; HX ≡ H_MMR(a)                                           (5.4)
;;;
;;; où a = [E(ET), E(EP), g, E(EA), E(ED)]                 (5.5)
;;;
;;; et g = E(↕[(H(r), E4(t), ↕a) | (r, t, a) ← EG])       (5.6)
;;;
;;; The extrinsic hash is a Merkle commitment to the block's extrinsic data,
;;; allowing for individual reports to have their inclusion proven.

(defun encode-guarantee-summary (guarantee)
  "Encode a guarantee summary for Merkle tree: (H(r), E4(t), ↕a).
   
   Gray Paper §5.6:
   g = E(↕[(H(r), E4(t), ↕a) | (r, t, a) ← EG])
   
   where:
     H(r) : Hash of the work report (32 bytes)
     E4(t) : Time slot encoded as u32 (4 bytes)
     ↕a   : Encoded sequence of something (TODO: clarify from Gray Paper)
   
   ⏳ STUB: Not yet implemented (EG is stub)
   
   Args:
     guarantee: A guarantee/work report structure
   
   Returns:
     Encoded summary bytes"
  (declare (ignore guarantee))
  (error "Guarantee summary encoding not yet implemented (EG is stub)"))

(defun compute-guarantee-summaries (guarantees)
  "Compute g = E(↕[(H(r), E4(t), ↕a) | (r, t, a) ← EG]).
   
   Gray Paper §5.6
   
   ⏳ STUB: Returns empty sequence for now (EG is stub)
   
   Args:
     guarantees: List of guarantee structures
   
   Returns:
     Encoded byte array"
  (if (null guarantees)
      ;; Empty sequence = compact(0)
      (encode-compact 0)
      ;; TODO: Implement when EG is fully implemented
      (error "Guarantee summaries computation not yet implemented. Got ~a guarantees."
             (length guarantees))))

(defun compute-extrinsic-hash (extrinsic-data)
  "Compute the extrinsic hash HX from extrinsic data.
   
   Gray Paper §5.4-5.6:
   HX ≡ H_MMR(a)
   where a = [E(ET), E(EP), g, E(EA), E(ED)]
   
   Args:
     extrinsic-data: Plist with :tickets :preimages :assurances :disputes :guarantees
                     OR a closure (extrinsic object)
   
   Returns:
     32-byte hash (Blake2b-256 of Merkle root)"
  ;; Extract components from either plist or closure
  (let* ((tickets (if (functionp extrinsic-data)
                      (funcall extrinsic-data :tickets)
                      (getf extrinsic-data :tickets)))
         (preimages (if (functionp extrinsic-data)
                        (funcall extrinsic-data :preimages)
                        (getf extrinsic-data :preimages)))
         (assurances (if (functionp extrinsic-data)
                         (funcall extrinsic-data :assurances)
                         (getf extrinsic-data :assurances)))
         (disputes (if (functionp extrinsic-data)
                       (funcall extrinsic-data :disputes)
                       (getf extrinsic-data :disputes)))
         (guarantees (if (functionp extrinsic-data)
                         (funcall extrinsic-data :guarantees)
                         (getf extrinsic-data :guarantees)))
         
         ;; Encode each component
         (encoded-tickets (encode-tickets-extrinsic tickets))
         (encoded-preimages (encode-preimages-extrinsic preimages))
         (encoded-assurances (if assurances
                                 (encode-assurances-extrinsic assurances)
                                 (encode-compact 0)))
         (encoded-disputes (if disputes
                               (encode-disputes-extrinsic disputes)
                               (concatenate '(vector (unsigned-byte 8))
                                            (encode-compact 0)  ; verdicts
                                            (encode-compact 0)  ; culprits
                                            (encode-compact 0)))) ; faults
         
         ;; Compute g (guarantee summaries)
         (g (compute-guarantee-summaries guarantees))
         
         ;; Build the array a = [E(ET), E(EP), g, E(EA), E(ED)]
         ;; Gray Paper §5.4: HX ≡ H_MMR(a)
         ;; 
         ;; For now, we interpret this as Blake2b-256 hash of:
         ;; - Each component hashed individually (32 bytes each)
         ;; - Then concatenated and hashed again
         ;;
         ;; This creates a Merkle-like commitment where each component
         ;; can be proven individually.
         (component-hashes (mapcar #'jam.ffi:blake2b-256
                                   (list encoded-tickets
                                         encoded-preimages
                                         g
                                         encoded-assurances
                                         encoded-disputes))))
    
    ;; Hash the concatenation of all component hashes
    ;; This gives us a 32-byte commitment to all extrinsic data
    (jam.ffi:blake2b-256
     (apply #'concatenate '(vector (unsigned-byte 8)) component-hashes))))

(defun compute-extrinsic-hash-from-encoded (encoded-extrinsic)
  "Compute HX from an already-encoded extrinsic byte array.
   
   This is useful when you have the encoded form but want to compute the hash
   without re-encoding.
   
   Args:
     encoded-extrinsic: Byte array of encoded extrinsic
   
   Returns:
     32-byte hash"
  ;; Decode the extrinsic to get components
  (multiple-value-bind (extrinsic-data bytes-consumed)
      (decode-extrinsic encoded-extrinsic 0)
    (declare (ignore bytes-consumed))
    (compute-extrinsic-hash extrinsic-data)))

;;; ==========================================================================
;;; Integration with Header
;;; ==========================================================================

(defun make-extrinsic-hash (extrinsic-data)
  "Convenience function to compute HX for use in header.
   
   Args:
     extrinsic-data: Extrinsic plist or closure
   
   Returns:
     32-byte hash suitable for HX field in header"
  (compute-extrinsic-hash extrinsic-data))

;;; ==========================================================================
;;; Exports
;;; ==========================================================================

(export '(encode-guarantee-summary
          compute-guarantee-summaries
          compute-extrinsic-hash
          compute-extrinsic-hash-from-encoded
          make-extrinsic-hash))
