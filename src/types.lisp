;;;; types.lisp
;;;; Common JAM types used across all modules
;;;; Based on Graypaper Section 3 (Fundamental Types)
;;;;
;;;; These types are used in codec, state, STF, and VM modules.

(in-package :jotl-config)

;;; ═══════════════════════════════════════════════════════════════════
;;; 3.8.1. Hashing - H (Graypaper Section 3.8.1)
;;; ═══════════════════════════════════════════════════════════════════

(deftype hash ()
  "H = B32 : 256-bit hash (32 octets) - as list.
   
   Used for: block hashes, state roots, Merkle roots, etc."
  'list)

(deftype hash32 ()
  "Alias for hash (32-byte hash as list)"
  'hash)

(deftype hash256 ()
  "Alias for hash (256-bit hash as list)"
  'hash)

(deftype blob ()
  "B : octet sequence of arbitrary length - as list.
   
   Used for: arbitrary binary data, encoded structures, etc."
  'list)

;;; ═══════════════════════════════════════════════════════════════════
;;; 3.4. Numbers - N (Graypaper Section 3.4)
;;; ═══════════════════════════════════════════════════════════════════

(deftype natural ()
  "N : natural numbers including zero.
   
   Used for: counters, indices, gas amounts, etc."
  '(integer 0 *))

(deftype natural-limited (n)
  "Nn : naturals less than n (0 ≤ x < n).
   
   Used for: bounded indices, validator counts, etc."
  `(integer 0 (,n)))

(deftype length-type ()
  "NL = N_{2^32} : lengths of octet sequences (0 ≤ x < 2^32).
   
   Used for: sequence lengths in encoding/decoding."
  '(integer 0 #.(1- (expt 2 32))))

;;; ═══════════════════════════════════════════════════════════════════
;;; Crypto types (Graypaper Section 5.10, Appendix E)
;;; ═══════════════════════════════════════════════════════════════════

(deftype ed25519-public-key ()
  "Ed25519 public key (32 bytes as list).
   
   Used for: validator signatures, dispute resolution."
  'hash32)

(deftype ed25519-signature ()
  "Ed25519 signature (64 bytes as list).
   
   Used for: validator signatures, dispute resolution."
  'list)

(deftype bandersnatch-public-key ()
  "Bandersnatch public key (32 bytes as list).
   
   Used for: block production, VRF tickets."
  'hash32)

(deftype bandersnatch-signature ()
  "Bandersnatch signature (96 bytes as list).
   
   Used for: block seals, VRF signatures."
  'list)

(deftype bls-public-key ()
  "BLS public key (144 bytes as list).
   
   Used for: aggregate signatures (future)."
  'list)

(deftype bls-signature ()
  "BLS signature (96 bytes as list).
   
   Used for: aggregate signatures (future)."
  'list)

;;; ═══════════════════════════════════════════════════════════════════
;;; JAM identifiers (Graypaper Section 3)
;;; ═══════════════════════════════════════════════════════════════════

(deftype service-id ()
  "S : Service identifier (32-bit unsigned integer).
   
   Used for: service accounts (δ[s]), max 256 services."
  '(unsigned-byte 32))

(deftype core-id ()
  "C : Core identifier (16-bit unsigned integer).
   
   Used for: core assignments, max 341 cores."
  '(unsigned-byte 16))

(deftype timeslot ()
  "T : Time-slot index (32-bit unsigned integer).
   
   Used for: block timing, epoch calculations."
  '(unsigned-byte 32))

(deftype gas-amount ()
  "G : Gas amount (64-bit unsigned integer).
   
   Used for: gas limits, gas consumption tracking."
  '(unsigned-byte 64))

;;; ═══════════════════════════════════════════════════════════════════
;;; Helper functions for I/O boundaries
;;; ═══════════════════════════════════════════════════════════════════

(defun list-to-blob (list)
  "Convert list of octets to vector blob (for I/O only).
   
   Used when interfacing with external libraries expecting vectors."
  (make-array (length list) :element-type '(unsigned-byte 8)
              :initial-contents list))

(defun blob-to-list (blob)
  "Convert vector blob to list of octets (for I/O only).
   
   Used when reading binary data from files/network."
  (coerce blob 'list))

(defun hash-zero ()
  "H0 = [0]32 : Zero hash (32 bytes of zeros as list).
   
   Used for: genesis block, empty Merkle roots."
  (make-list 32 :initial-element 0))

(defun hash32-p (x)
  "Predicate: Is x a valid 32-byte hash (as list)?"
  (and (listp x)
       (= (length x) 32)
       (every (lambda (byte) (typep byte '(unsigned-byte 8))) x)))
