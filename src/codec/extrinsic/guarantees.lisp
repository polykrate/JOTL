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
  (multiple-value-bind (validator-index vi-bytes)
      (decode-u16 bytes offset)
    (declare (ignore vi-bytes))
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
;;; WorkReport - Delegated to src/codec/work-report.lisp
;;; ==========================================================================
;;;
;;; encode-work-report and decode-work-report are defined in work-report.lisp
;;; which is loaded before this file in jotl.asd.

;;; ==========================================================================
;;; Complete Guarantee Encoding/Decoding
;;; ==========================================================================

(defun encode-guarantee (guarantee)
  "Encode a single guarantee: (r, E4(t), ↕[(E2(v), s) | ...]).
   
   Gray Paper C.18: r is directly encoded, NOT compact-prefixed!
   
   Args:
     guarantee: plist with :report :slot :signatures
   
   Returns:
     byte array"
  (let ((report (getf guarantee :report))
        (slot (getf guarantee :slot))
        (signatures (getf guarantee :signatures)))
    (concatenate '(vector (unsigned-byte 8))
                 ;; r: WorkReport (directly encoded, no length prefix!)
                 (encode-work-report report)
                 ;; E4(t): timeslot
                 (encode-u32 slot)
                 ;; ↕[(E2(v), s)]: signatures
                 (encode-guarantee-signatures signatures))))

(defun decode-guarantee (bytes offset)
  "Decode a single guarantee: (r, E4(t), ↕[(E2(v), s) | ...]).
   
   Gray Paper C.18: r is directly encoded, NOT compact-prefixed!
   
   Returns: (values guarantee-plist bytes-consumed)"
  (let ((pos offset))
    ;; r: WorkReport (directly encoded, no length prefix!)
    (multiple-value-bind (report report-bytes)
        (decode-work-report bytes pos)
      (incf pos report-bytes)
      
      ;; E4(t): timeslot (u32)
      (multiple-value-bind (slot slot-bytes)
          (decode-u32 bytes pos)
        (incf pos slot-bytes)
        
        ;; ↕[(E2(v), s)]: signatures (compact-prefixed sequence)
        (multiple-value-bind (signatures sig-bytes)
            (decode-guarantee-signatures bytes pos)
          (incf pos sig-bytes)
          
          (values (list :report report
                        :report-raw-bytes (subseq bytes offset (+ offset report-bytes))
                        :slot slot
                        :signatures signatures)
                  (- pos offset)))))))

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
          encode-guarantee
          decode-guarantee
          encode-guarantees-extrinsic
          decode-guarantees-extrinsic))
