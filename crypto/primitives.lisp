;;;; GP 3.8 - Cryptography
;;;; Cryptographic functions from Gray Paper
;;;; REQUIRES FFI - No fallback mode (security critical)

(in-package :jam.ffi)

;;; ============================================================
;;; FFI Requirement
;;; ============================================================

(define-condition ffi-not-loaded (error)
  ()
  (:report "JAM Crypto FFI not loaded. Call (load-ffi) first."))

(defun require-ffi ()
  "Ensure FFI is loaded. Signals error if not."
  (unless (and (find-package :jam.ffi)
               (fboundp (find-symbol "BLAKE2B-256" :jam.ffi)))
    (error 'ffi-not-loaded)))

(defun ffi-loaded-p ()
  "Check if FFI is available"
  (and (find-package :jam.ffi)
       (fboundp (find-symbol "BLAKE2B-256" :jam.ffi))))

;;; ============================================================
;;; 3.8.1 Hashing
;;; ============================================================

;;; ℍ = 𝔹₃₂ (256-bit hash values)
(deftype hash-value ()
  "256-bit hash value. GP notation: ℍ"
  '(simple-array (unsigned-byte 8) (32)))

;;; H₀ = [0]₃₂
(defparameter +hash-zero+ (make-array 32 :element-type '(unsigned-byte 8)
                                          :initial-element 0)
  "Zero hash. GP notation: H₀")

;;; ============================================================
;;; H - Blake2b-256 (FFI REQUIRED)
;;; ============================================================

;; blake2b-256 now defined in ironclad-impl.lisp (pure Lisp)

(defun H (message)
  "Blake2b-256 hash. GP notation: H"
  (blake2b-256 (if (stringp message)
                   (string-to-blob message)
                   message)))

;;; ============================================================
;;; HK - Keccak-256 (FFI REQUIRED)
;;; ============================================================

(defun keccak-256 (message)
  "Keccak 256-bit hash. GP notation: HK(m)
   REQUIRES FFI - no fallback."
  (require-ffi)
  (funcall (find-symbol "KECCAK-256" :jam.ffi) message))

(defun HK (message)
  "Keccak-256 hash. GP notation: HK"
  (keccak-256 (if (stringp message)
                  (string-to-blob message)
                  message)))

;;; K - Alias for Keccak-256 (used in MMR, GP Appendix E)
(setf (symbol-function 'K) #'HK)

;;; ============================================================
;;; E - Encoding (SCALE codec) - Pure Lisp, no FFI needed
;;; ============================================================

(defun encode-natural (n size)
  "Encode natural N as SIZE bytes (little-endian SCALE). GP: Eₙ(x)"
  (let ((result (make-array size :element-type '(unsigned-byte 8))))
    (loop for i below size
          do (setf (aref result i) (logand (ash n (* -8 i)) #xff)))
    result))

(defun decode-natural (bytes)
  "Decode bytes to natural (little-endian SCALE). GP: E⁻¹(y)"
  (let ((result 0))
    (loop for i below (length bytes)
          do (setf result (logior result (ash (aref bytes i) (* 8 i)))))
    result))

(defun E (value &optional expected-size)
  "SCALE encode a value. GP: E(x) or Eₙ(x)"
  (etypecase value
    ((simple-array (unsigned-byte 8) (*)) 
     (if expected-size
         (progn (assert (= (length value) expected-size)) value)
         value))
    (integer 
     (encode-natural value (or expected-size 
                                (max 1 (ceiling (integer-length value) 8)))))
    (string 
     (string-to-blob value))))

(defun E-inverse (bytes &optional type-hint)
  "SCALE decode bytes. GP: E⁻¹(y)"
  (case type-hint
    (:natural (decode-natural bytes))
    (:string (blob-to-string bytes))
    (otherwise bytes)))

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
;;; Ed25519 Signature Verification (FFI REQUIRED)
;;; ============================================================

(defun ed25519-verify (public-key message signature)
  "Verify Ed25519 signature. GP: s ∈ V̄ₖ⟨m⟩
   REQUIRES FFI - no fallback."
  (require-ffi)
  (funcall (find-symbol "ED25519-VERIFY" :jam.ffi) public-key message signature))

;;; ============================================================
;;; Bandersnatch VRF (FFI REQUIRED)
;;; ============================================================

(defun bandersnatch-vrf-output-hash (signature)
  "Extract VRF output hash. GP: Y(s)
   REQUIRES FFI - no fallback."
  (require-ffi)
  (funcall (find-symbol "BANDERSNATCH-VRF-OUTPUT-HASH" :jam.ffi) signature))

(defun Y (signature)
  "VRF output hash. GP: Y"
  (bandersnatch-vrf-output-hash signature))

(defun vrf-output (signature)
  "Alias for Y. GP: Y(Ṽₘₖ⟨x⟩)"
  (Y signature))

;;; ============================================================
;;; Ring VRF (FFI REQUIRED)
;;; ============================================================

(defun ring-vrf-verify (ring-commitment vrf-input signature &key (ring-size 6))
  "Verify Ring VRF signature. GP: p ∈ V○ᵣ⟨x⟩
   REQUIRES FFI - no fallback."
  (require-ffi)
  (funcall (find-symbol "BANDERSNATCH-VERIFY-RING-VRF" :jam.ffi)
           ring-commitment vrf-input signature :ring-size ring-size))

(defun ring-vrf-verify-with-output (ring-commitment vrf-input signature &key (ring-size 6))
  "Verify Ring VRF and return output hash. Returns (values valid-p output-hash)
   REQUIRES FFI - no fallback."
  (require-ffi)
  (funcall (find-symbol "BANDERSNATCH-VERIFY-RING-VRF-WITH-OUTPUT" :jam.ffi)
           ring-commitment vrf-input signature :ring-size ring-size))

;;; ============================================================
;;; String Constants
;;; ============================================================

(defparameter +jam-entropy+ (string-to-blob "$jam_entropy")
  "GP: $jam_entropy")

(defparameter +jam-ticket-seal+ (string-to-blob "$jam_ticket_seal")
  "GP: $jam_ticket_seal")

(defparameter +jam-fallback-seal+ (string-to-blob "$jam_fallback_seal")
  "GP: $jam_fallback_seal")

;;; ============================================================
;;; Status
;;; ============================================================

(defun crypto-status ()
  "Report crypto FFI status"
  (format t "~&Crypto Status:~%")
  (if (ffi-loaded-p)
      (progn
        (format t "  Backend: FFI (jam-crypto) ✓~%")
        (format t "  Blake2b-256: ✓~%")
        (format t "  Keccak-256: ✓~%")
        (format t "  Ed25519: ✓~%")
        (format t "  Bandersnatch VRF: ✓~%")
        (format t "  Ring VRF: ✓~%")
        t)
      (progn
        (format t "  Backend: NOT LOADED ✗~%")
        (format t "  Run (load-ffi) to enable crypto~%")
        nil)))

