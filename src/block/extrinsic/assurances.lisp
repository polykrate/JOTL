;;;; block/extrinsic/assurances.lisp — EA (Assurances Extrinsic)
;;;; Gray Paper §11

(in-package :jotl)

;;; ═════════════════════════════════════════════════════════════════
;;; Assurances Extrinsic (EA)
;;; ═════════════════════════════════════════════════════════════════
;;;
;;; GP C.19: EA(EA) = E(↕[(a, f, E2(v), s) | (a, f, v, s) ← EA])
;;;
;;; Assurance ≡ (anchor: H, bitfield: [u8], validator_index: u16, signature: [u8; 64])

(defun encode-assurance (assurance)
  "Encode a single assurance."
  (let ((anchor (getf assurance :anchor))
        (bitfield (getf assurance :bitfield))
        (validator-index (getf assurance :validator-index))
        (signature (getf assurance :signature)))
    (let ((anchor-bytes (etypecase anchor
                          ((simple-array (unsigned-byte 8) (*)) anchor)
                          (string (jam.ffi:hex-string-to-bytes anchor))
                          (vector (coerce anchor '(simple-array (unsigned-byte 8) (*)))))))
      (assert (= (length anchor-bytes) 32) ()
              "Anchor must be 32 bytes, got: ~a" (length anchor-bytes))
      (let ((bitfield-bytes (etypecase bitfield
                              ((simple-array (unsigned-byte 8) (*)) bitfield)
                              (string (jam.ffi:hex-string-to-bytes bitfield))
                              (vector (coerce bitfield '(simple-array (unsigned-byte 8) (*)))))))
        (assert (typep validator-index '(integer 0 65535)) ()
                "Validator index must be u16, got: ~a" validator-index)
        (let ((sig-bytes (etypecase signature
                           ((simple-array (unsigned-byte 8) (*)) signature)
                           (string (jam.ffi:hex-string-to-bytes signature))
                           (vector (coerce signature '(simple-array (unsigned-byte 8) (*)))))))
          (assert (= (length sig-bytes) 64) ()
                  "Signature must be 64 bytes (Ed25519), got: ~a" (length sig-bytes))
          (concatenate '(vector (unsigned-byte 8))
                       anchor-bytes bitfield-bytes
                       (encode-u16 validator-index) sig-bytes))))))

(defun decode-assurance (bytes offset)
  "Decode a single assurance.
   Bitfield size: ⌈num-cores / 8⌉ bytes (from chainspec).
   Returns: (values assurance-plist bytes-consumed)"
  (let* ((anchor (subseq bytes offset (+ offset 32)))
         (pos (+ offset 32))
         (bitfield-length (ceiling (num-cores) 8)))
    (let ((bitfield (subseq bytes pos (+ pos bitfield-length))))
      (incf pos bitfield-length)
      (let ((validator-index (decode-u16 bytes pos)))
        (incf pos 2)
        (let ((signature (subseq bytes pos (+ pos 64))))
          (incf pos 64)
          (values (list :anchor anchor :bitfield bitfield
                        :validator-index validator-index :signature signature)
                  (- pos offset)))))))

(defun encode-assurances-extrinsic (assurances)
  "Encode assurances extrinsic (EA)."
  (let ((encoded-assurances (mapcar #'encode-assurance assurances)))
    (concatenate '(vector (unsigned-byte 8))
                 (encode-compact (length assurances))
                 (apply #'concatenate '(vector (unsigned-byte 8)) encoded-assurances))))

(defun decode-assurances-extrinsic (bytes offset)
  "Decode assurances extrinsic (EA).
   Returns: (values assurances bytes-consumed)"
  (multiple-value-bind (num-assurances bytes-consumed-len)
      (decode-compact bytes offset)
    (let ((assurances '())
          (pos (+ offset bytes-consumed-len)))
      (dotimes (i num-assurances)
        (multiple-value-bind (assurance assurance-size)
            (decode-assurance bytes pos)
          (push assurance assurances)
          (incf pos assurance-size)))
      (values (nreverse assurances) (- pos offset)))))

;;; Exports managed in package.lisp
