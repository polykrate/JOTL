;;;; block/extrinsic/guarantees.lisp — EG (Guarantees Extrinsic)
;;;; Gray Paper §11-12 & Appendix C.18
;;;;
;;;; Depends on: block/work-report.lisp (loaded before this)

(in-package #:jotl)

;;; ═════════════════════════════════════════════════════════════════
;;; EG(EG) = E(↕[(r, E4(t), ↕[(E2(v), s) | (v, s) ← a]) | ...])
;;; ═════════════════════════════════════════════════════════════════

;;; ----- Signatures -----

(defun encode-guarantee-signature (sig)
  "Encode a single guarantee signature: (E2(v), s)."
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
            66)))

(defun encode-guarantee-signatures (signatures)
  "Encode compact-prefixed sequence of guarantee signatures."
  (encode-sequence signatures #'encode-guarantee-signature))

(defun decode-guarantee-signatures (bytes offset)
  "Decode compact-prefixed sequence of guarantee signatures."
  (decode-sequence bytes #'decode-guarantee-signature offset))

;;; ----- Complete Guarantee -----

(defun encode-guarantee (guarantee)
  "Encode a single guarantee: (r, E4(t), ↕[(E2(v), s) | ...]).
   GP C.18: r is directly encoded, NOT compact-prefixed."
  (let ((report (getf guarantee :report))
        (slot (getf guarantee :slot))
        (signatures (getf guarantee :signatures)))
    (concatenate '(vector (unsigned-byte 8))
                 (encode-work-report report)
                 (encode-u32 slot)
                 (encode-guarantee-signatures signatures))))

(defun decode-guarantee (bytes offset)
  "Decode a single guarantee.
   Returns: (values guarantee-plist bytes-consumed)"
  (let ((pos offset))
    (multiple-value-bind (report report-bytes)
        (decode-work-report bytes pos)
      (incf pos report-bytes)
      (multiple-value-bind (slot slot-bytes)
          (decode-u32 bytes pos)
        (incf pos slot-bytes)
        (multiple-value-bind (signatures sig-bytes)
            (decode-guarantee-signatures bytes pos)
          (incf pos sig-bytes)
          (values (list :report report
                        :report-raw-bytes (subseq bytes offset (+ offset report-bytes))
                        :slot slot
                        :signatures signatures)
                  (- pos offset)))))))

;;; ----- Complete EG -----

(defun encode-guarantees-extrinsic (guarantees)
  "Encode guarantees extrinsic (EG)."
  (encode-sequence (or guarantees '()) #'encode-guarantee))

(defun decode-guarantees-extrinsic (bytes offset)
  "Decode guarantees extrinsic (EG).
   Returns: (values guarantees bytes-consumed)"
  (decode-sequence bytes #'decode-guarantee offset))

;;; Exports managed in package.lisp
