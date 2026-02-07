;;;; types.lisp - JAM Reusable Types Encoding/Decoding
;;;; Common types used across header, extrinsic, and state
;;;; Gray Paper Appendix C - Type definitions

(in-package :jotl)

;;; ==========================================================================
;;; Hash Types (H)
;;; ==========================================================================
;;; H ≡ 32 bytes - Blake2b-256 hash

(defun encode-hash-32 (hash)
  "Encode a 32-byte hash (no length prefix, just the bytes).
   
   Gray Paper: H ≡ B32 (32-byte hash)
   
   Args:
     hash: byte array, hex string, or nil
   
   Returns:
     32-byte array"
  (if hash
      (etypecase hash
        ((simple-array (unsigned-byte 8) (32)) hash)
        (string (jam.ffi:hex-string-to-bytes hash))
        (vector (let ((bytes (coerce hash '(simple-array (unsigned-byte 8) (*)))))
                  (assert (= (length bytes) 32) () 
                          "Hash must be 32 bytes, got ~D" (length bytes))
                  bytes)))
      (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))

(defun decode-hash-32 (bytes offset)
  "Decode a 32-byte hash.
   
   Returns: (values byte-array bytes-consumed)"
  (values (subseq bytes offset (+ offset 32)) 32))

;;; ==========================================================================
;;; Ed25519 Public Key (H̄)
;;; ==========================================================================
;;; H̄ ≡ 32 bytes - Ed25519 public key

(defun encode-ed25519-key (key)
  "Encode a 32-byte Ed25519 public key.
   
   Gray Paper: H̄ ≡ B32 (Ed25519 public key)
   
   Args:
     key: byte array, hex string, or nil
   
   Returns:
     32-byte array"
  (encode-hash-32 key))  ; Same format as hash

(defun decode-ed25519-key (bytes offset)
  "Decode a 32-byte Ed25519 public key.
   
   Returns: (values byte-array bytes-consumed)"
  (decode-hash-32 bytes offset))

;;; ==========================================================================
;;; Bandersnatch Public Key (H̃)
;;; ==========================================================================
;;; H̃ ≡ 32 bytes - Bandersnatch public key

(defun encode-bandersnatch-key (key)
  "Encode a 32-byte Bandersnatch public key.
   
   Gray Paper: H̃ ≡ B32 (Bandersnatch public key)
   
   Args:
     key: byte array, hex string, or nil
   
   Returns:
     32-byte array"
  (encode-hash-32 key))  ; Same format as hash

(defun decode-bandersnatch-key (bytes offset)
  "Decode a 32-byte Bandersnatch public key.
   
   Returns: (values byte-array bytes-consumed)"
  (decode-hash-32 bytes offset))

;;; ==========================================================================
;;; Bandersnatch Signature (Y)
;;; ==========================================================================
;;; Y ≡ 96 bytes - Bandersnatch VRF signature

(defun encode-signature-96 (signature)
  "Encode a 96-byte Bandersnatch signature.
   
   Gray Paper: Y ≡ B96 (Bandersnatch VRF signature)
   Used for: HV (entropy source), HS (seal)
   
   Args:
     signature: byte array, hex string, or nil
   
   Returns:
     96-byte array"
  (if signature
      (etypecase signature
        ((simple-array (unsigned-byte 8) (96)) signature)
        (string (let ((bytes (jam.ffi:hex-string-to-bytes signature)))
                 (assert (= (length bytes) 96) () 
                         "Signature must be 96 bytes, got ~D" (length bytes))
                 bytes))
        (vector (let ((bytes (coerce signature '(simple-array (unsigned-byte 8) (*)))))
                 (assert (= (length bytes) 96) () 
                         "Signature must be 96 bytes, got ~D" (length bytes))
                 bytes)))
      (make-array 96 :element-type '(unsigned-byte 8) :initial-element 0)))

(defun decode-signature-96 (bytes offset)
  "Decode a 96-byte Bandersnatch signature.
   
   Returns: (values byte-array bytes-consumed)"
  (values (subseq bytes offset (+ offset 96)) 96))

;;; ==========================================================================
;;; Validator (Bandersnatch + Ed25519)
;;; ==========================================================================
;;; Validator ≡ (H̃, H̄) - Tuple of (Bandersnatch key, Ed25519 key)

(defun encode-validator (validator)
  "Encode a validator as (Bandersnatch 32 bytes, Ed25519 32 bytes).
   
   Gray Paper: Validator ∈ {H̃, H̄}
   Used in: Epoch markers, validator sets
   
   Args:
     validator: plist with :bandersnatch and :ed25519 keys
   
   Returns:
     64-byte array"
  (concatenate '(vector (unsigned-byte 8))
               (encode-bandersnatch-key (getf validator :bandersnatch))
               (encode-ed25519-key (getf validator :ed25519))))

(defun decode-validator (bytes offset)
  "Decode a validator (Bandersnatch + Ed25519).
   
   Returns: (values plist bytes-consumed)
   plist format: (:bandersnatch bytes :ed25519 bytes)"
  (let ((bandersnatch (subseq bytes offset (+ offset 32)))
        (ed25519 (subseq bytes (+ offset 32) (+ offset 64))))
    (values (list :bandersnatch bandersnatch :ed25519 ed25519) 64)))

;;; ==========================================================================
;;; Validator Sequence (for Epoch Markers)
;;; ==========================================================================
;;; Fixed-size sequence of validators (NO compact length prefix!)

(defun encode-validator-sequence (validators)
  "Encode a sequence of validators (no length prefix).
   
   Note: Validator sequences in epoch markers are FIXED SIZE (NV),
   determined by chainspec, NOT prefixed with compact length!
   
   Args:
     validators: list of validator plists
   
   Returns:
     byte array (NV * 64 bytes)"
  (apply #'concatenate '(vector (unsigned-byte 8))
         (mapcar #'encode-validator validators)))

(defun decode-validator-sequence (bytes offset num-validators)
  "Decode a FIXED-SIZE sequence of validators.
   
   Args:
     bytes: byte array
     offset: starting position
     num-validators: number of validators (from chainspec)
   
   Returns: (values list-of-validators bytes-consumed)"
  (let ((validators '())
        (pos offset))
    (dotimes (i num-validators)
      (multiple-value-bind (validator size)
          (decode-validator bytes pos)
        (push validator validators)
        (incf pos size)))
    (values (nreverse validators) (- pos offset))))

;;; ==========================================================================
;;; Service Account Index (NS)
;;; ==========================================================================
;;; NS ≡ N232 - Service account index (u32)

(defun encode-service-account-index (index)
  "Encode a service account index (u32).
   
   Gray Paper: NS ∈ N232
   
   Returns: 4-byte array"
  (encode-fixed-le index 4))

(defun decode-service-account-index (bytes offset)
  "Decode a service account index (u32).
   
   Returns: (values u32 bytes-consumed)"
  (values (decode-fixed-le (subseq bytes offset (+ offset 4))) 4))

;;; ==========================================================================
;;; Validator Index (NV)
;;; ==========================================================================
;;; NV ≡ N216 - Validator index (u16)

(defun encode-validator-index (index)
  "Encode a validator index (u16).
   
   Gray Paper: NV ∈ N216
   Used for: HI (author index)
   
   Returns: 2-byte array"
  (encode-fixed-le index 2))

(defun decode-validator-index (bytes offset)
  "Decode a validator index (u16).
   
   Returns: (values u16 bytes-consumed)"
  (values (decode-fixed-le (subseq bytes offset (+ offset 2))) 2))

;;; ==========================================================================
;;; Exports
;;; ==========================================================================

(export '(;; Hashes
          encode-hash-32
          decode-hash-32
          
          ;; Keys
          encode-ed25519-key
          decode-ed25519-key
          encode-bandersnatch-key
          decode-bandersnatch-key
          
          ;; Signatures
          encode-signature-96
          decode-signature-96
          
          ;; Validators
          encode-validator
          decode-validator
          encode-validator-sequence
          decode-validator-sequence
          
          ;; Indices
          encode-service-account-index
          decode-service-account-index
          encode-validator-index
          decode-validator-index))
