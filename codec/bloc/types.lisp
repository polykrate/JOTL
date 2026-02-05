;;;; types.lisp
;;;; Common type definitions for JAM blocks

(in-package :jotl-bloc)

;;; Common JAM types from graypaper section 3

;;; 3.8.1. Hashing
(deftype hash ()
  "H = B32 : 256-bit hash (32 octets)"
  '(vector (unsigned-byte 8) 32))

(deftype blob ()
  "B : octet sequence of arbitrary length"
  '(vector (unsigned-byte 8)))

(deftype blob-n (n)
  "Bn : octet sequence of length n"
  `(vector (unsigned-byte 8) ,n))

;;; 3.4. Numbers
(deftype natural ()
  "N : natural numbers including zero"
  '(integer 0 *))

(deftype natural-limited (n)
  "Nn : naturals less than n"
  `(integer 0 (,n)))

(deftype length-type ()
  "NL = N_{2^32} : lengths of octet sequences"
  '(integer 0 #.(1- (expt 2 32))))

;;; 3.8.2. Signing Schemes
(deftype ed25519-signature ()
  "Ed25519 signature (B64)"
  '(vector (unsigned-byte 8) 64))

(deftype ed25519-public-key ()
  "Ed25519 public key (H = B32)"
  'hash)

(deftype bandersnatch-signature ()
  "Bandersnatch signature (B96)"
  '(vector (unsigned-byte 8) 96))

(deftype bandersnatch-public-key ()
  "Bandersnatch public key (∽H)"
  'hash)

(deftype bandersnatch-vrf-signature ()
  "Bandersnatch VRF signature"
  '(vector (unsigned-byte 8) 96))

(deftype bls-signature ()
  "BLS signature (B144)"
  '(vector (unsigned-byte 8) 144))

(deftype bls-public-key ()
  "BLS public key (B144)"
  '(vector (unsigned-byte 8) 144))

;;; Helper functions

(defun make-hash (&optional (initial-value 0))
  "Create a hash (32 bytes)"
  (make-array 32 :element-type '(unsigned-byte 8)
              :initial-element initial-value))

(defun make-blob (length &optional (initial-value 0))
  "Create a blob of specified length"
  (make-array length :element-type '(unsigned-byte 8)
              :initial-element initial-value))

(defun hash-zero ()
  "H0 = [0]32"
  (make-hash 0))

(defun list-to-blob (list)
  "Convert list of octets to blob (vector)"
  (make-array (length list) :element-type '(unsigned-byte 8)
              :initial-contents list))

(defun blob-to-list (blob)
  "Convert blob (vector) to list of octets"
  (coerce blob 'list))

;;; Validator structures
;;;
;;; Graypaper Section 5.10, 6.1: Validator keys

(defstruct validator
  "Validator key pair.
   
   Each validator has two keys:
   - bandersnatch: For block production and VRF (32 bytes)
   - ed25519: For finalizing and disputes (32 bytes)"
  (bandersnatch nil :type (or null blob))  ; 32 bytes
  (ed25519 nil :type (or null blob)))      ; 32 bytes

;;; Epoch Marker structure
;;;
;;; Graypaper Section 5.10: Epoch marker (HE)

(defstruct epoch-marker
  "Epoch marker (HE).
   
   Marks the beginning of a new epoch with new validator set.
   - entropy: Randomness for the new epoch (32 bytes)
   - tickets-entropy: Ticket-specific randomness (32 bytes)
   - validators: List of validators for the epoch"
  (entropy nil :type (or null blob))           ; 32 bytes (H)
  (tickets-entropy nil :type (or null blob))   ; 32 bytes (H)
  (validators nil :type list))                 ; list of validator
