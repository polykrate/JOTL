;;;; block/extrinsic/preimages.lisp — EP (Preimages Extrinsic)
;;;; Gray Paper §7.4

(in-package #:jotl)

;;; ═════════════════════════════════════════════════════════════════
;;; Preimages Extrinsic (EP)
;;; ═════════════════════════════════════════════════════════════════
;;;
;;; Preimage ≡ (requester: u32, blob: [u8])

(defun encode-preimage (preimage)
  "Encode a single preimage (requester: u32, blob: bytes)."
  (let ((requester (getf preimage :requester))
        (blob (getf preimage :blob)))
    (assert (typep requester '(integer 0 4294967295)) ()
            "Preimage requester must be u32, got: ~a" requester)
    (let ((blob-bytes (etypecase blob
                        ((simple-array (unsigned-byte 8) (*)) blob)
                        (string (jam.ffi:hex-string-to-bytes blob))
                        (vector (coerce blob '(simple-array (unsigned-byte 8) (*)))))))
      (concatenate '(vector (unsigned-byte 8))
                   (encode-u32 requester)
                   (encode-compact (length blob-bytes))
                   blob-bytes))))

(defun decode-preimage (bytes offset)
  "Decode a single preimage.
   Returns: (values preimage-plist bytes-consumed)"
  (let* ((requester (decode-u32 bytes offset))
         (pos (+ offset 4)))
    (multiple-value-bind (blob-length bytes-consumed-len)
        (decode-compact bytes pos)
      (incf pos bytes-consumed-len)
      (let ((blob (subseq bytes pos (+ pos blob-length))))
        (values (list :requester requester :blob blob)
                (+ 4 bytes-consumed-len blob-length))))))

(defun encode-preimages-extrinsic (preimages)
  "Encode preimages extrinsic (EP)."
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
      (values (nreverse preimages) (- pos offset)))))

;;; Exports managed in package.lisp
