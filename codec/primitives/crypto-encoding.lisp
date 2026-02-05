;;;; crypto-encoding.lisp
;;;; Fixed-size encoding/decoding for cryptographic types (keys, signatures, hashes)
;;;;
;;;; These are NOT cryptographic operations (no signing/verifying/hashing).
;;;; Just serialization: octets ↔ lists for fixed-size crypto primitives.
;;;;
;;;; Graypaper references:
;;;;   - Section 5.10: Cryptographic Functions
;;;;   - Appendix E: Cryptographic Primitives
;;;;   - C.12: Fixed-Length Integer Encoding (El)

(in-package :jotl-codec)

;;; ═══════════════════════════════════════════════════════════════════
;;; BLS KEYS (144 bytes) - Graypaper Section 5.10.3
;;; ═══════════════════════════════════════════════════════════════════

(defun encode-bls-key (bls-key)
  "Encode BLS public key (144 bytes).
   
   BLS keys are fixed 144-byte sequences. No length prefix needed.
   
   Args:
     bls-key: list of 144 octets
   
   Returns:
     Same list (identity, already encoded)"
  bls-key)

(defun decode-bls-key (octets position)
  "Decode BLS public key (144 bytes).
   
   Args:
     octets: octet list
     position: starting position
   
   Returns:
     (values bls-key bytes-consumed)"
  (decode-fixed-bytes octets position 144))

;;; ═══════════════════════════════════════════════════════════════════
;;; ED25519 SIGNATURES (64 bytes) - Graypaper Section 5.10.1
;;; ═══════════════════════════════════════════════════════════════════

(defun encode-ed25519-signature (signature)
  "Encode Ed25519 signature (64 bytes).
   
   Ed25519 signatures are fixed 64-byte sequences.
   
   Args:
     signature: list of 64 octets
   
   Returns:
     Same list (identity, already encoded)"
  signature)

(defun decode-ed25519-signature (octets position)
  "Decode Ed25519 signature (64 bytes).
   
   Args:
     octets: octet list
     position: starting position
   
   Returns:
     (values signature bytes-consumed)"
  (decode-fixed-bytes octets position 64))

;;; ═══════════════════════════════════════════════════════════════════
;;; BANDERSNATCH SIGNATURES (96 bytes) - Graypaper Section 5.10.2
;;; ═══════════════════════════════════════════════════════════════════

(defun encode-bandersnatch-signature (signature)
  "Encode Bandersnatch signature (96 bytes).
   
   Bandersnatch VRF output signatures are fixed 96-byte sequences.
   
   Args:
     signature: list of 96 octets
   
   Returns:
     Same list (identity, already encoded)"
  signature)

(defun decode-bandersnatch-signature (octets position)
  "Decode Bandersnatch signature (96 bytes).
   
   Args:
     octets: octet list
     position: starting position
   
   Returns:
     (values signature bytes-consumed)"
  (decode-fixed-bytes octets position 96))

;;; ═══════════════════════════════════════════════════════════════════
;;; ED25519 PUBLIC KEYS (32 bytes) - Graypaper Section 5.10.1
;;; ═══════════════════════════════════════════════════════════════════

(defun encode-ed25519-public-key (key)
  "Encode Ed25519 public key (32 bytes).
   
   Ed25519 public keys are fixed 32-byte sequences (same as hash).
   
   Args:
     key: list of 32 octets
   
   Returns:
     Same list (identity, already encoded)"
  key)

(defun decode-ed25519-public-key (octets position)
  "Decode Ed25519 public key (32 bytes).
   
   Args:
     octets: octet list
     position: starting position
   
   Returns:
     (values key bytes-consumed)"
  (decode-fixed-bytes octets position 32))

;;; ═══════════════════════════════════════════════════════════════════
;;; BANDERSNATCH PUBLIC KEYS (32 bytes) - Graypaper Section 5.10.2
;;; ═══════════════════════════════════════════════════════════════════

(defun encode-bandersnatch-public-key (key)
  "Encode Bandersnatch public key (32 bytes).
   
   Bandersnatch public keys are fixed 32-byte sequences (same as hash).
   
   Args:
     key: list of 32 octets
   
   Returns:
     Same list (identity, already encoded)"
  key)

(defun decode-bandersnatch-public-key (octets position)
  "Decode Bandersnatch public key (32 bytes).
   
   Args:
     octets: octet list
     position: starting position
   
   Returns:
     (values key bytes-consumed)"
  (decode-fixed-bytes octets position 32))

;;; ═══════════════════════════════════════════════════════════════════
;;; BLS SIGNATURES (96 bytes) - Graypaper Section 5.10.3
;;; ═══════════════════════════════════════════════════════════════════

(defun encode-bls-signature (signature)
  "Encode BLS signature (96 bytes).
   
   BLS signatures are fixed 96-byte sequences.
   
   Args:
     signature: list of 96 octets
   
   Returns:
     Same list (identity, already encoded)"
  signature)

(defun decode-bls-signature (octets position)
  "Decode BLS signature (96 bytes).
   
   Args:
     octets: octet list
     position: starting position
   
   Returns:
     (values signature bytes-consumed)"
  (decode-fixed-bytes octets position 96))
