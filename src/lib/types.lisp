;;;; types.lisp - JAM Reusable Types Encoding/Decoding
;;;; Common types used across header, extrinsic, and state
;;;; Gray Paper Appendix C - Type definitions

(in-package #:jotl)

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
;;; Validator Structs (GP §6.8-6.12)
;;; ==========================================================================
;;; Struct-based representation for O(1) field access.
;;; jam-validator: 64-byte format (kb, ke) for epoch marks
;;; jam-full-validator: 336-byte format (kb, ke, kl, km) for state

(defstruct (jam-validator (:constructor make-jam-validator))
  (bandersnatch nil :read-only t)
  (ed25519 nil :read-only t))

(defstruct (jam-full-validator (:include jam-validator)
                               (:constructor make-jam-full-validator))
  (bls nil :read-only t)
  (metadata nil :read-only t))

;;; ==========================================================================
;;; Validator (Bandersnatch + Ed25519)
;;; ==========================================================================
;;; Validator ≡ (H̃, H̄) - Tuple of (Bandersnatch key, Ed25519 key)

(defun encode-validator (validator)
  "Encode a validator as (Bandersnatch 32 bytes, Ed25519 32 bytes).
   
   Gray Paper: Validator ∈ {H̃, H̄}
   Used in: Epoch markers, validator sets
   
   Args:
     validator: jam-validator struct (or jam-full-validator via :include)
   
   Returns:
     64-byte array"
  (let ((buf (make-array 64 :element-type '(unsigned-byte 8))))
    (replace buf (jam-validator-bandersnatch validator))
    (replace buf (jam-validator-ed25519 validator) :start1 32)
    buf))

(defun decode-validator (bytes offset)
  "Decode a validator (Bandersnatch + Ed25519).
   
   Returns: (values jam-validator 64)"
  (values (make-jam-validator
           :bandersnatch (subseq bytes offset (+ offset 32))
           :ed25519 (subseq bytes (+ offset 32) (+ offset 64)))
          64))

;;; ==========================================================================
;;; Validator Sequence (for Epoch Markers)
;;; ==========================================================================
;;; Fixed-size sequence of validators (NO compact length prefix!)

(defun encode-validator-sequence (validators)
  "Encode a sequence of validators (no length prefix).
   
   Note: Validator sequences in epoch markers are FIXED SIZE (NV),
   determined by chainspec, NOT prefixed with compact length!
   
   Args:
     validators: list of jam-validator structs
   
   Returns:
     byte array (NV * 64 bytes)"
  (let* ((n (length validators))
         (buf (make-array (* n 64) :element-type '(unsigned-byte 8))))
    (loop for v in validators
          for pos from 0 by 64
          do (replace buf (encode-validator v) :start1 pos))
    buf))

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
;;; Full Validator Key K (for state: κ, λ, ι, γP)
;;; ==========================================================================
;;; K ≡ B336 — GP (6.8)
;;;
;;; Binary layout per GP (6.9)-(6.12):
;;;   (6.9)  kb  ∈ Ĥ     Bandersnatch public key    k[0..32]
;;;   (6.10) ke  ∈ H̄     Ed25519 public key          k[32..64]
;;;   (6.11) kl  ∈ B^BLS  BLS public key              k[64..208]
;;;   (6.12) km  ∈ B128   Metadata                    k[208..336]
;;;
;;; Total: 336 bytes per validator
;;;
;;; NOTE: Block epoch marks use a REDUCED format (kb, ke) = 64 bytes.
;;;       State uses the FULL format K = 336 bytes.

(defun encode-full-validator (validator)
  "Encode a full state validator K ≡ B336.
   GP (6.9)-(6.12): kb(32) || ke(32) || kl(144) || km(128) = 336 bytes.
   Args: jam-full-validator struct"
  (let ((buf (make-array 336 :element-type '(unsigned-byte 8) :initial-element 0))
        (bn (jam-validator-bandersnatch validator))
        (ed (jam-validator-ed25519 validator))
        (bl (jam-full-validator-bls validator))
        (mt (jam-full-validator-metadata validator)))
    (when bn (replace buf bn))
    (when ed (replace buf ed :start1 32))
    (when bl (replace buf bl :start1 64))
    (when mt (replace buf mt :start1 208))
    buf))

(defun decode-full-validator (bytes offset)
  "Decode a full state validator K ≡ B336.
   GP (6.9)-(6.12): kb(32) || ke(32) || kl(144) || km(128).
   Returns: (values jam-full-validator 336)"
  (values
   (make-jam-full-validator
    :bandersnatch (subseq bytes offset (+ offset 32))
    :ed25519      (subseq bytes (+ offset 32) (+ offset 64))
    :bls          (subseq bytes (+ offset 64) (+ offset 208))
    :metadata     (subseq bytes (+ offset 208) (+ offset 336)))
   336))

(defun encode-full-validator-sequence (validators)
  "Encode a fixed-size sequence of full validators (V × 336 bytes, no length prefix)."
  (let* ((n (length validators))
         (buf (make-array (* n 336) :element-type '(unsigned-byte 8) :initial-element 0)))
    (loop for v in validators
          for pos from 0 by 336
          do (replace buf (encode-full-validator v) :start1 pos))
    buf))

(defun decode-full-validator-sequence (bytes &optional (offset 0) (count (num-validators)))
  "Decode a fixed-size sequence of V full validators.
   Returns: (values list-of-validators bytes-consumed)"
  (let ((validators '())
        (pos offset))
    (dotimes (i count)
      (multiple-value-bind (validator size)
          (decode-full-validator bytes pos)
        (push validator validators)
        (incf pos size)))
    (values (nreverse validators) (- pos offset))))

;;; ==========================================================================
;;; Null Validator Key — GP (6.14)
;;; ==========================================================================
;;; K = [0,0,...] — 336 zero bytes. Used by Φ(k) to blank offending validators.

(defparameter +null-validator-key+
  (make-jam-full-validator
   :bandersnatch (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
   :ed25519      (make-array +ed25519-key-size+ :element-type '(unsigned-byte 8) :initial-element 0)
   :bls          (make-array +bls-key-size+ :element-type '(unsigned-byte 8) :initial-element 0)
   :metadata     (make-array +metadata-size+ :element-type '(unsigned-byte 8) :initial-element 0))
  "K = [0,0,...] — null validator key (336 zero bytes). GP (6.14).")

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
  (values (decode-fixed-le bytes offset 4) 4))

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
  (values (decode-fixed-le bytes offset 2) 2))

;;; ==========================================================================
;;; Authorization Pool Encoder (shared by α and ϕ)
;;; ==========================================================================

(defun encode-auth-pools (pools)
  "Encode core authorization pools.
   pools = list of C lists of 32-byte authorizer hashes."
  (if (null pools)
      (encode-compact 0)
      (encode-sequence pools
                       (lambda (core-auths)
                         (encode-sequence core-auths #'encode-hash-32)))))

;;; ==========================================================================
;;; Byte Vector Comparison
;;; ==========================================================================

(defun bytes< (a b)
  "Lexicographic comparison of two byte vectors.
   Returns T if A is lexicographically less than B."
  (loop for i from 0 below (min (length a) (length b))
        do (cond ((< (aref a i) (aref b i)) (return t))
                 ((> (aref a i) (aref b i)) (return nil)))
        finally (return (< (length a) (length b)))))

;;; Exports managed in package.lisp
