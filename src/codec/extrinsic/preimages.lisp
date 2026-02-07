;;;; preimages.lisp - EP (Preimages Extrinsic) Encoding/Decoding
;;;; Gray Paper §7.4

(in-package :jotl)

;;; ==========================================================================
;;; Preimages Extrinsic (EP)
;;; ==========================================================================
;;; Gray Paper §7.4: Preimages for lookup
;;;
;;; Preimage ≡ (requester: u32, blob: [u8])
;;;
;;; where:
;;;   requester : Service ID - u32
;;;   blob      : Data blob - variable length, compact-prefixed
;;;
;;; EP is a sequence of preimages, compact-length prefixed:
;;; E(EP) = E(↕[E(preimage) | preimage ← EP])

(defun encode-preimage (preimage)
  "Encode a single preimage (requester: u32, blob: bytes).
   
   Args:
     preimage: plist with :requester and :blob
   
   Returns:
     byte array"
  (let ((requester (getf preimage :requester))
        (blob (getf preimage :blob)))
    ;; Validate requester (u32)
    (assert (typep requester '(integer 0 4294967295)) ()
            "Preimage requester must be u32 (0-4294967295), got: ~a" requester)
    
    ;; Convert blob to bytes if it's a hex string
    (let ((blob-bytes (etypecase blob
                        ((simple-array (unsigned-byte 8) (*)) blob)
                        (string (jam.ffi:hex-string-to-bytes blob))
                        (vector (coerce blob '(simple-array (unsigned-byte 8) (*)))))))
      
      ;; Encode: u32 (little-endian) + compact-length + blob
      (concatenate '(vector (unsigned-byte 8))
                   (encode-u32 requester)
                   (encode-compact (length blob-bytes))
                   blob-bytes))))

(defun decode-preimage (bytes offset)
  "Decode a single preimage from bytes.
   
   Returns: (values preimage-plist bytes-consumed)"
  (let* ((requester (decode-u32 bytes offset))
         (pos (+ offset 4)))
    (multiple-value-bind (blob-length bytes-consumed-len)
        (decode-compact bytes pos)
      (incf pos bytes-consumed-len)
      (let ((blob (subseq bytes pos (+ pos blob-length))))
        (values (list :requester requester
                      :blob blob)
                (+ 4 bytes-consumed-len blob-length))))))

(defun encode-preimages-extrinsic (preimages)
  "Encode preimages extrinsic (EP).
   
   Gray Paper §7.4: Preimages for lookup
   
   Args:
     preimages: list of preimage plists
   
   Returns:
     byte array"
  ;; Encode as a compact-prefixed sequence
  (let ((encoded-preimages (mapcar #'encode-preimage preimages)))
    (concatenate '(vector (unsigned-byte 8))
                 (encode-compact (length preimages))
                 (apply #'concatenate '(vector (unsigned-byte 8)) encoded-preimages))))

(defun decode-preimages-extrinsic (bytes offset)
  "Decode preimages extrinsic (EP).
   
   Returns: (values preimages bytes-consumed)"
  (multiple-value-bind (num-preimages bytes-consumed-len)
      (decode-compact bytes offset)
    (let ((preimages '())
          (pos (+ offset bytes-consumed-len)))
      (dotimes (i num-preimages)
        (multiple-value-bind (preimage preimage-size)
            (decode-preimage bytes pos)
          (push preimage preimages)
          (incf pos preimage-size)))
      (values (nreverse preimages)
              (- pos offset)))))

;;; ==========================================================================
;;; Exports
;;; ==========================================================================

(export '(encode-preimage
          decode-preimage
          encode-preimages-extrinsic
          decode-preimages-extrinsic))
