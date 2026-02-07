;;;; assurances.lisp - EA (Assurances Extrinsic) Encoding/Decoding
;;;; Gray Paper §11

(in-package :jotl)

;;; ==========================================================================
;;; Assurances Extrinsic (EA)
;;; ==========================================================================
;;; Gray Paper §11: Availability assurances
;;;
;;; Assurance ≡ (anchor: H, bitfield: [u8], validator_index: u16, signature: [u8; 64])
;;;
;;; where:
;;;   anchor          : Hash (32 bytes) - work package hash
;;;   bitfield        : Bitfield (variable length, compact-prefixed)
;;;   validator_index : u16 - validator who made the assurance
;;;   signature       : Ed25519 signature (64 bytes)
;;;
;;; EA is a sequence of assurances, compact-length prefixed:
;;; E(EA) = E(↕[E(assurance) | assurance ← EA])

(defun encode-assurance (assurance)
  "Encode a single assurance (anchor, bitfield, validator_index, signature).
   
   Args:
     assurance: plist with :anchor :bitfield :validator-index :signature
   
   Returns:
     byte array"
  (let ((anchor (getf assurance :anchor))
        (bitfield (getf assurance :bitfield))
        (validator-index (getf assurance :validator-index))
        (signature (getf assurance :signature)))
    
    ;; Convert anchor to bytes
    (let ((anchor-bytes (etypecase anchor
                          ((simple-array (unsigned-byte 8) (*)) anchor)
                          (string (jam.ffi:hex-string-to-bytes anchor))
                          (vector (coerce anchor '(simple-array (unsigned-byte 8) (*)))))))
      (assert (= (length anchor-bytes) 32) ()
              "Anchor must be 32 bytes, got: ~a" (length anchor-bytes))
      
      ;; Convert bitfield to bytes
      (let ((bitfield-bytes (etypecase bitfield
                              ((simple-array (unsigned-byte 8) (*)) bitfield)
                              (string (jam.ffi:hex-string-to-bytes bitfield))
                              (vector (coerce bitfield '(simple-array (unsigned-byte 8) (*)))))))
        
        ;; Validate validator-index (u16)
        (assert (typep validator-index '(integer 0 65535)) ()
                "Validator index must be u16 (0-65535), got: ~a" validator-index)
        
        ;; Convert signature to bytes
        (let ((sig-bytes (etypecase signature
                           ((simple-array (unsigned-byte 8) (*)) signature)
                           (string (jam.ffi:hex-string-to-bytes signature))
                           (vector (coerce signature '(simple-array (unsigned-byte 8) (*)))))))
          (assert (= (length sig-bytes) 64) ()
                  "Signature must be 64 bytes (Ed25519), got: ~a" (length sig-bytes))
          
          ;; Encode: anchor (32) + compact(bitfield-length) + bitfield + validator-index (u16) + signature (64)
          (concatenate '(vector (unsigned-byte 8))
                       anchor-bytes
                       (encode-compact (length bitfield-bytes))
                       bitfield-bytes
                       (encode-u16 validator-index)
                       sig-bytes))))))

(defun decode-assurance (bytes offset)
  "Decode a single assurance from bytes.
   
   Returns: (values assurance-plist bytes-consumed)"
  (let* ((anchor (subseq bytes offset (+ offset 32)))
         (pos (+ offset 32)))
    (multiple-value-bind (bitfield-length bytes-consumed-len)
        (decode-compact bytes pos)
      (incf pos bytes-consumed-len)
      (let ((bitfield (subseq bytes pos (+ pos bitfield-length))))
        (incf pos bitfield-length)
        (let ((validator-index (decode-u16 bytes pos)))
          (incf pos 2)
          (let ((signature (subseq bytes pos (+ pos 64))))
            (incf pos 64)
            (values (list :anchor anchor
                          :bitfield bitfield
                          :validator-index validator-index
                          :signature signature)
                    (- pos offset))))))))

(defun encode-assurances-extrinsic (assurances)
  "Encode assurances extrinsic (EA).
   
   Gray Paper §11: Availability assurances
   
   Args:
     assurances: list of assurance plists
   
   Returns:
     byte array"
  ;; Encode as a compact-prefixed sequence
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
      (values (nreverse assurances)
              (- pos offset)))))

;;; ==========================================================================
;;; Exports
;;; ==========================================================================

(export '(encode-assurance
          decode-assurance
          encode-assurances-extrinsic
          decode-assurances-extrinsic))
