;;;; guarantees.lisp - EG (Guarantees Extrinsic) Encoding/Decoding
;;;; Gray Paper §11-12 & Appendix C.18

(in-package :jotl)

;;; ==========================================================================
;;; Gray Paper Formula (Appendix C.18)
;;; ==========================================================================
;;; 
;;; EG(EG) = E(↕[(r, E4(t), ↕[(E2(v), s) | (v, s) ← a]) | (r, t, a) ← EG])
;;;
;;; Where:
;;;   EG = sequence of guarantees
;;;   Each guarantee (r, t, a):
;;;     r : WorkReport (complex structure)
;;;     t : slot (u32)
;;;     a : signatures = sequence of (v, s):
;;;       v : validator_index (u16)
;;;       s : signature (64 bytes)

;;; ==========================================================================
;;; Signatures Encoding/Decoding
;;; ==========================================================================

(defun encode-guarantee-signature (sig)
  "Encode a single guarantee signature: (validator_index:u16, signature:64bytes).
   
   Args:
     sig: plist with :validator-index and :signature
   
   Returns:
     byte array (66 bytes: 2 + 64)"
  (let ((validator-index (getf sig :validator-index))
        (signature (getf sig :signature)))
    (let ((sig-bytes (etypecase signature
                       ((simple-array (unsigned-byte 8) (*)) signature)
                       (string (jam.ffi:hex-string-to-bytes signature))
                       (vector (coerce signature '(simple-array (unsigned-byte 8) (*)))))))
      (assert (= (length sig-bytes) 64) ()
              "Guarantee signature must be 64 bytes, got: ~a" (length sig-bytes))
      (concatenate '(vector (unsigned-byte 8))
                   (encode-u16 validator-index)
                   sig-bytes))))

(defun decode-guarantee-signature (bytes offset)
  "Decode a single guarantee signature.
   
   Returns: (values sig-plist bytes-consumed)"
  (let ((validator-index (decode-u16 bytes offset)))
    (values (list :validator-index validator-index
                  :signature (subseq bytes (+ offset 2) (+ offset 66)))
            66))) ; 2 + 64

(defun encode-guarantee-signatures (signatures)
  "Encode sequence of guarantee signatures.
   
   Format: ↕[(E2(v), s) | (v, s) ← a]
   
   Returns:
     byte array"
  (encode-sequence signatures #'encode-guarantee-signature))

(defun decode-guarantee-signatures (bytes offset)
  "Decode sequence of guarantee signatures.
   
   Returns: (values signatures bytes-consumed)"
  (decode-sequence bytes #'decode-guarantee-signature offset))

;;; ==========================================================================
;;; WorkReport Encoding/Decoding - COMPLEX STRUCTURE
;;; ==========================================================================

(defun encode-work-report (report)
  "Encode a work report (r).
   
   ⚠️  STUB: Work report is a VERY complex structure with many nested components:
     - package_spec (hash, length, erasure_root, exports_root, exports_count)
     - context (anchor, state_root, beefy_root, lookup_anchor, lookup_anchor_slot, prerequisites)
     - core_index
     - authorizer_hash
     - auth_gas_used
     - auth_output
     - segment_root_lookup
     - results (array of work results - very complex!)
   
   For now, we encode as raw bytes (for testing with test vectors).
   TODO: Implement full structure encoding from Gray Paper §11-12.
   
   Args:
     report: work report structure or raw bytes
   
   Returns:
     byte array"
  (etypecase report
    ((simple-array (unsigned-byte 8) (*)) report)
    (string (jam.ffi:hex-string-to-bytes report))
    (list
     ;; TODO: Implement full structure encoding
     ;; For now, this is a STUB that will need proper implementation
     (error "WorkReport encoding from structure not yet implemented. Provide raw bytes."))))

(defun decode-work-report (bytes offset size)
  "Decode a work report (r).
   
   ⚠️  STUB: Work report is a VERY complex structure.
   For now, we just read the raw bytes.
   TODO: Implement full structure decoding from Gray Paper §11-12.
   
   Args:
     bytes: byte array
     offset: starting position
     size: number of bytes to read (from outer length prefix)
   
   Returns: (values work-report-raw-bytes bytes-consumed)"
  (values (subseq bytes offset (+ offset size))
          size))

;;; ==========================================================================
;;; Complete Guarantee Encoding/Decoding
;;; ==========================================================================

(defun encode-guarantee (guarantee)
  "Encode a single guarantee: (r, E4(t), ↕[(E2(v), s) | ...]).
   
   Args:
     guarantee: plist with :report :slot :signatures
   
   Returns:
     byte array"
  (let ((report (getf guarantee :report))
        (slot (getf guarantee :slot))
        (signatures (getf guarantee :signatures)))
    (let ((encoded-report (encode-work-report report))
          (encoded-slot (encode-u32 slot))
          (encoded-signatures (encode-guarantee-signatures signatures)))
      ;; The complete guarantee is: (report, slot, signatures)
      ;; But we need to length-prefix the report for decoding
      (concatenate '(vector (unsigned-byte 8))
                   (encode-compact (length encoded-report))
                   encoded-report
                   encoded-slot
                   encoded-signatures))))

(defun decode-guarantee (bytes offset)
  "Decode a single guarantee: (r, t, a).
   
   Returns: (values guarantee-plist bytes-consumed)"
  (let ((pos offset))
    ;; Decode report (length-prefixed)
    (multiple-value-bind (report-size report-len-bytes)
        (decode-compact bytes pos)
      (incf pos report-len-bytes)
      (multiple-value-bind (report report-bytes)
          (decode-work-report bytes pos report-size)
        (incf pos report-bytes)
        
        ;; Decode slot (u32)
        (multiple-value-bind (slot slot-bytes)
            (decode-u32 bytes pos)
          (incf pos slot-bytes)
          
          ;; Decode signatures (sequence)
          (multiple-value-bind (signatures sig-bytes)
              (decode-guarantee-signatures bytes pos)
            (incf pos sig-bytes)
            
            (values (list :report report
                          :slot slot
                          :signatures signatures)
                    (- pos offset))))))))

;;; ==========================================================================
;;; Complete EG Encoding/Decoding
;;; ==========================================================================

(defun encode-guarantees-extrinsic (guarantees)
  "Encode guarantees extrinsic (EG).
   
   Gray Paper C.18: EG(EG) = E(↕[(r, E4(t), ↕[(E2(v), s) | ...]) | ...])
   
   Args:
     guarantees: list of guarantee plists
   
   Returns:
     byte array"
  (encode-sequence (or guarantees '()) #'encode-guarantee))

(defun decode-guarantees-extrinsic (bytes offset)
  "Decode guarantees extrinsic (EG).
   
   Returns: (values guarantees bytes-consumed)"
  (decode-sequence bytes #'decode-guarantee offset))

;;; ==========================================================================
;;; Exports
;;; ==========================================================================

(export '(encode-guarantee-signature
          decode-guarantee-signature
          encode-guarantee-signatures
          decode-guarantee-signatures
          encode-work-report
          decode-work-report
          encode-guarantee
          decode-guarantee
          encode-guarantees-extrinsic
          decode-guarantees-extrinsic))
