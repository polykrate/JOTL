;;;; GP 3.8 - Cryptography
;;;; High-level wrappers and type definitions for GP cryptographic primitives.
;;;; REQUIRES FFI — No fallback mode (security critical)

(in-package :jam.ffi)

;;; ============================================================
;;; 3.8.1 Hashing — Type
;;; ============================================================

;;; ℍ = 𝔹₃₂ (256-bit hash values)
(deftype hash-value ()
  "256-bit hash value. GP notation: ℍ"
  '(simple-array (unsigned-byte 8) (32)))

;;; ============================================================
;;; 3.8.2 Signing Schemes - Types
;;; ============================================================

(deftype ed25519-public-key ()
  "Ed25519 public key (32 bytes). GP: H̄"
  'hash-value)

(deftype bandersnatch-public-key ()
  "Bandersnatch public key (32 bytes). GP: H̃"
  'hash-value)

(deftype ed25519-signature ()
  "Ed25519 signature (64 bytes). GP: V̄ₖ⟨m⟩"
  '(simple-array (unsigned-byte 8) (64)))

(deftype bandersnatch-signature ()
  "Bandersnatch VRF signature (96 bytes). GP: Ṽₖ⟨x⟩"
  '(simple-array (unsigned-byte 8) (96)))

(deftype ring-vrf-root ()
  "Ring VRF root (144 bytes). GP: B○"
  '(simple-array (unsigned-byte 8) (144)))

(deftype ring-vrf-proof ()
  "Ring VRF proof (784 bytes). GP: V○ᵣ⟨x⟩"
  '(simple-array (unsigned-byte 8) (784)))

(deftype bls-public-key ()
  "BLS public key (144 bytes). GP: B^BLS"
  '(simple-array (unsigned-byte 8) (144)))

;;; ============================================================
;;; Bandersnatch VRF Output — Y function (GP G.2)
;;; ============================================================

(defun Y (signature)
  "VRF output hash. GP: Y(s) ≡ output(s)...32"
  (bandersnatch-vrf-output-hash signature))

;;; ============================================================
;;; String Constants (GP signing contexts)
;;; ============================================================

;;; GP notation: $foo means the string literal "foo"
(defparameter +jam-entropy+ (string-to-blob "jam_entropy")
  "GP: $jam_entropy — context tag for entropy accumulation")

(defparameter +jam-ticket-seal+ (string-to-blob "jam_ticket_seal")
  "GP: $jam_ticket_seal — context tag for ticket sealing")

(defparameter +jam-fallback-seal+ (string-to-blob "jam_fallback_seal")
  "GP: $jam_fallback_seal — context tag for fallback sealing")
