;;;; JAM Crypto FFI Bindings
;;;; CFFI bindings to Rust crypto library (jam-crypto)
;;;; GP Appendices A, E, F, G, H

;;; Ensure CFFI is loaded before compiling
(eval-when (:compile-toplevel :load-toplevel :execute)
  (unless (find-package :cffi)
    (asdf:load-system :cffi)))

(in-package :jam.ffi)

;;; ==========================================================================
;;; Load FFI Library
;;; ==========================================================================

(cffi:define-foreign-library libjamcrypto
  (:unix (:or "crypto/jam-crypto/target/release/libjam_crypto.so"
              "libjam_crypto.so"))
  (:darwin (:or "crypto/jam-crypto/target/release/libjam_crypto.dylib"
                "libjam_crypto.dylib"))
  (t (:default "libjam_crypto"))) 

(handler-case
    (progn
      (cffi:use-foreign-library libjamcrypto)
      (setf *ffi-loaded* t)
      (format t "~&✓ JAM Crypto FFI loaded successfully from libjam_crypto.so~%"))
  (error (e)
    (setf *ffi-loaded* nil)
    (warn "Could not load jam-crypto FFI library: ~A~%Crypto functions will use stubs." e)))

;;; ==========================================================================
;;; Helpers
;;; ==========================================================================

(defun ensure-octets (data)
  "Ensure data is a simple (unsigned-byte 8) array."
  ;; Simplified without subtypep to avoid infinite loops
  (let* ((len (length data))
         (result (make-array len :element-type '(unsigned-byte 8))))
    (dotimes (i len result)
      (setf (aref result i) (elt data i)))))

;;; ==========================================================================
;;; Blake2b-256 (GP Appendix A.1)
;;; ==========================================================================

(cffi:defcfun ("blake2b_256" %blake2b-256) :void
  "Blake2b-256 hash function (FFI)"
  (input :pointer)
  (len :size)
  (output :pointer))

(defun blake2b-256 (data)
  "Hash data with Blake2b-256, returns 32 bytes.
   
   Args:
   - data: octets (unsigned-byte 8 array)
   
   Returns:
   - 32-byte hash (octets)"
  (let* ((len (length data))
         (input (make-array len :element-type '(unsigned-byte 8)))
         (result (make-array 32 :element-type '(unsigned-byte 8))))
    ;; Copy data to ensure correct type
    (dotimes (i len)
      (setf (aref input i) (elt data i)))
    ;; Call FFI
    (handler-case
        (cffi:with-pointer-to-vector-data (in-ptr input)
          (cffi:with-pointer-to-vector-data (out-ptr result)
            (%blake2b-256 in-ptr len out-ptr)))
      (error (e)
        (warn "blake2b-256 FFI failed: ~A~%Using stub (zeros)" e)
        (fill result 0)))
    result))

;;; ==========================================================================
;;; Keccak-256 (GP Appendix E - MMR)
;;; ==========================================================================

(cffi:defcfun ("keccak_256" %keccak-256) :void
  "Keccak-256 hash function (FFI) - Legacy Ethereum-style, NOT SHA3"
  (input :pointer)
  (len :size)
  (output :pointer))

(defun keccak-256 (data)
  "Hash data with Keccak-256 (legacy Ethereum-style), returns 32 bytes.
   
   Used for MMR peak merging (GP Appendix E.10).
   
   Args:
   - data: octets (unsigned-byte 8 array or any sequence)
   
   Returns:
   - 32-byte hash (octets)"
  (let* ((len (length data))
         (input (make-array len :element-type '(unsigned-byte 8)))
         (result (make-array 32 :element-type '(unsigned-byte 8))))
    (dotimes (i len)
      (setf (aref input i) (elt data i)))
    (handler-case
        (cffi:with-pointer-to-vector-data (in-ptr input)
          (cffi:with-pointer-to-vector-data (out-ptr result)
            (%keccak-256 in-ptr len out-ptr)))
      (error (e)
        (warn "keccak-256 FFI failed: ~A~%Using stub (zeros)" e)
        (fill result 0)))
    result))

;;; ==========================================================================
;;; Ed25519 Signature Verification (GP Section 10)
;;; ==========================================================================

(cffi:defcfun ("ed25519_verify" %ed25519-verify) :boolean
  "Verify Ed25519 signature (FFI)"
  (public-key :pointer)
  (message :pointer)
  (message-len :size)
  (signature :pointer))

(defun ed25519-verify (public-key message signature)
  "Verify Ed25519 signature. Returns T if valid, NIL otherwise.
   
   Args:
   - public-key: 32 bytes (Ed25519 public key)
   - message: variable length octets
   - signature: 64 bytes (Ed25519 signature)
   
   Returns:
   - T if signature is valid, NIL otherwise
   
   GP: s ∈ V̄k⟨m⟩"
  (declare (type (array (unsigned-byte 8) (*)) public-key message signature))
  
  (unless (= (length public-key) 32)
    (error "Ed25519 public key must be 32 bytes, got ~A" (length public-key)))
  (unless (= (length signature) 64)
    (error "Ed25519 signature must be 64 bytes, got ~A" (length signature)))
  
  (handler-case
      (cffi:with-pointer-to-vector-data (pk-ptr public-key)
        (cffi:with-pointer-to-vector-data (msg-ptr message)
          (cffi:with-pointer-to-vector-data (sig-ptr signature)
            (%ed25519-verify pk-ptr msg-ptr (length message) sig-ptr))))
    (error (e)
      (warn "ed25519-verify FFI failed: ~A~%Returning NIL" e)
      nil)))

;;; ==========================================================================
;;; Bandersnatch VRF Output Hash (GP Appendix G.2 - Y function)
;;; ==========================================================================

(cffi:defcfun ("bandersnatch_vrf_output_hash" %bandersnatch-vrf-output-hash) :boolean
  "Extract VRF output hash (Y function) from Bandersnatch VRF signature (FFI)"
  (vrf-signature :pointer)
  (vrf-signature-len :size)
  (output-hash :pointer))

(defun bandersnatch-vrf-output-hash (vrf-signature)
  "Extract VRF output hash (Y function) from a Bandersnatch VRF signature.
   
   GP Appendix G.2: Y(s) ≡ output(s)...32
   
   Args:
   - vrf-signature: variable length bytes (typically 96 bytes for block seal)
   
   Returns:
   - 32-byte VRF output hash if valid, NIL otherwise"
  (declare (type (array (unsigned-byte 8) (*)) vrf-signature))
  
  (let ((output-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
    (handler-case
        (cffi:with-pointer-to-vector-data (sig-ptr vrf-signature)
          (cffi:with-pointer-to-vector-data (out-ptr output-hash)
            (let ((result (%bandersnatch-vrf-output-hash 
                           sig-ptr 
                           (length vrf-signature) 
                           out-ptr)))
              (if result output-hash nil))))
      (error (e)
        (warn "bandersnatch-vrf-output-hash FFI failed: ~A" e)
        nil))))

;;; ==========================================================================
;;; Bandersnatch Ring VRF (GP Section 6 - Safrole)
;;; ==========================================================================

(defvar *bandersnatch-srs* nil
  "Zcash SRS for Ring VRF (loaded from file)")

(defvar *bandersnatch-srs-path* 
  (merge-pathnames "tests/jamtestvectors/stf/safrole/zcash-srs-2-11-uncompressed.bin"
                   (asdf:system-source-directory :jotl))
  "Path to the Zcash SRS file for Ring VRF (relative to JOTL project root)")

(defun load-bandersnatch-srs ()
  "Load the Zcash SRS file for Ring VRF."
  (unless *bandersnatch-srs*
    (when (probe-file *bandersnatch-srs-path*)
      (with-open-file (stream *bandersnatch-srs-path* 
                              :element-type '(unsigned-byte 8))
        (let* ((size (file-length stream))
               (data (make-array size :element-type '(unsigned-byte 8))))
          (read-sequence data stream)
          (setf *bandersnatch-srs* data)
          (format t "Loaded Bandersnatch SRS: ~A bytes~%" size)))))
  *bandersnatch-srs*)

(cffi:defcfun ("bandersnatch_verify_ring_vrf_with_commitment" 
               %bandersnatch-verify-ring-vrf-with-commitment) :uint8
  "Verify Ring VRF signature using pre-computed ring commitment (FFI)"
  (srs-data :pointer)
  (srs-len :size)
  (ring-size :size)
  (ring-commitment :pointer)
  (vrf-input :pointer)
  (vrf-input-len :size)
  (aux-data :pointer)
  (aux-data-len :size)
  (signature :pointer))

(defun bandersnatch-verify-ring-vrf (ring-commitment vrf-input signature 
                                     &key (ring-size 6))
  "Verify a Bandersnatch Ring VRF signature.
   
   GP Section 6: Used for ticket verification in Safrole.
   
   Args:
   - ring-commitment: 144 bytes (gamma_z)
   - vrf-input: variable length (typically 48 bytes for tickets)
   - signature: 784 bytes (Ring VRF signature)
   - ring-size: 6 for TINY, 1023 for FULL
   
   Returns:
   - T if valid, NIL otherwise"
  (let ((srs (load-bandersnatch-srs)))
    (unless srs
      (warn "Bandersnatch SRS not loaded")
      (return-from bandersnatch-verify-ring-vrf nil))
    
    (unless (= (length ring-commitment) 144)
      (error "Ring commitment must be 144 bytes, got ~A" (length ring-commitment)))
    (unless (= (length signature) 784)
      (error "Signature must be 784 bytes, got ~A" (length signature)))
    
    (handler-case
        (cffi:with-pointer-to-vector-data (srs-ptr srs)
          (cffi:with-pointer-to-vector-data (commitment-ptr ring-commitment)
            (cffi:with-pointer-to-vector-data (input-ptr vrf-input)
              (cffi:with-pointer-to-vector-data (sig-ptr signature)
                (let ((result (%bandersnatch-verify-ring-vrf-with-commitment
                               srs-ptr (length srs)
                               ring-size
                               commitment-ptr
                               input-ptr (length vrf-input)
                               (cffi:null-pointer) 0
                               sig-ptr)))
                  (not (zerop result)))))))
      (error (e)
        (warn "bandersnatch-verify-ring-vrf FFI failed: ~A" e)
        nil))))

(cffi:defcfun ("bandersnatch_verify_ring_vrf_with_output" 
               %bandersnatch-verify-ring-vrf-with-output) :uint32
  "Verify Ring VRF and return output hash (FFI)"
  (srs-data :pointer)
  (srs-len :size)
  (ring-size :size)
  (ring-commitment :pointer)
  (vrf-input :pointer)
  (vrf-input-len :size)
  (aux-data :pointer)
  (aux-data-len :size)
  (signature :pointer)
  (vrf-output-hash :pointer))

(defun bandersnatch-verify-ring-vrf-with-output (ring-commitment vrf-input signature 
                                                  &key (ring-size 6))
  "Verify Ring VRF and return the VRF output hash (ticket ID).
   
   GP Section 6: Used for ticket verification and ID computation.
   
   Returns: (values valid-p output-hash)"
  (let ((srs (load-bandersnatch-srs)))
    (unless srs
      (return-from bandersnatch-verify-ring-vrf-with-output (values nil nil)))
    
    (let ((output-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
      (handler-case
          (cffi:with-pointer-to-vector-data (srs-ptr srs)
            (cffi:with-pointer-to-vector-data (commitment-ptr ring-commitment)
              (cffi:with-pointer-to-vector-data (input-ptr vrf-input)
                (cffi:with-pointer-to-vector-data (sig-ptr signature)
                  (cffi:with-pointer-to-vector-data (out-ptr output-hash)
                    (let ((result (%bandersnatch-verify-ring-vrf-with-output
                                   srs-ptr (length srs)
                                   ring-size
                                   commitment-ptr
                                   input-ptr (length vrf-input)
                                   (cffi:null-pointer) 0
                                   sig-ptr
                                   out-ptr)))
                      (if (zerop result)
                          (values t output-hash)
                          (values nil nil))))))))
        (error (e)
          (warn "bandersnatch-verify-ring-vrf-with-output FFI failed: ~A" e)
          (values nil nil))))))

;;; ==========================================================================
;;; Deterministic Shuffle (GP Appendix F)
;;; ==========================================================================

(defun generate-random-numbers (entropy count)
  "Generate COUNT random uint32 numbers from ENTROPY hash.
   GP Appendix F: Q_l(h)"
  (let ((result (make-array count :element-type '(unsigned-byte 32))))
    (dotimes (i count)
      (let* ((k (floor i 8))
             (k-bytes (make-array 4 :element-type '(unsigned-byte 8)))
             (_ (progn
                  (setf (aref k-bytes 0) (ldb (byte 8 0) k))
                  (setf (aref k-bytes 1) (ldb (byte 8 8) k))
                  (setf (aref k-bytes 2) (ldb (byte 8 16) k))
                  (setf (aref k-bytes 3) (ldb (byte 8 24) k))))
             (input (concatenate '(vector (unsigned-byte 8)) entropy k-bytes))
             (hash (blake2b-256 input))
             (p (mod (* 4 i) 32))
             (r-i (+ (aref hash (mod p 32))
                     (ash (aref hash (mod (+ p 1) 32)) 8)
                     (ash (aref hash (mod (+ p 2) 32)) 16)
                     (ash (aref hash (mod (+ p 3) 32)) 24))))
        (declare (ignore _))
        (setf (aref result i) r-i)))
    result))

(defun deterministic-shuffle (sequence entropy)
  "Shuffle SEQUENCE deterministically using ENTROPY.
   GP Appendix F: Fisher-Yates shuffle with PRNG from entropy."
  (let* ((seq (coerce sequence 'vector))
         (len (length seq))
         (random-nums (generate-random-numbers entropy len))
         (result '()))
    (dotimes (i len)
      (let* ((remaining (- len i))
             (index (mod (aref random-nums i) remaining))
             (head (aref seq index)))
        (setf (aref seq index) (aref seq (1- remaining)))
        (push head result)))
    (nreverse result)))

(defun compute-core-assignments (entropy slot num-validators num-cores epoch-length rotation-period)
  "Compute validator-to-core assignments.
   GP 11.20: P(e, t) ≡ R(F([⌊C·i/V⌋ | i ∈ N_V], e), ⌊(t mod E)/R⌋)
   
   R is a circular rotation of the SEQUENCE (not adding to values).
   R(s, n) rotates the sequence s by n positions."
  (let* ((core-indices (loop for i from 0 below num-validators
                             collect (floor (* num-cores i) num-validators)))
         (shuffled (coerce (deterministic-shuffle core-indices entropy) 'vector))
         (len (length shuffled))
         (rotation-amount (floor (mod slot epoch-length) rotation-period))
         ;; GP R: Circular rotation of CORE VALUES, not indices
         ;; Each validator keeps their position, but their core assignment rotates
         (rotated (loop for i from 0 below len
                        collect (mod (+ (aref shuffled i) rotation-amount) num-cores))))
    (coerce rotated 'vector)))

;;; ==========================================================================
;;; Erasure Coding (GP Appendix H)
;;; ==========================================================================

(cffi:defcfun ("erasure_output_size" %erasure-output-size) :size
  "Get output buffer size for erasure encoding"
  (data-len :size)
  (k :size)
  (n :size))

(cffi:defcfun ("erasure_encode" %erasure-encode) :size
  "Encode data into erasure-coded shards (FFI)"
  (data :pointer)
  (data-len :size)
  (k :size)
  (n :size)
  (output :pointer)
  (output-len :pointer))

(defun erasure-encode (data k n)
  "Encode DATA into N shards using Reed-Solomon over GF(2^16).
   GP Appendix H: Erasure coding with k original shards, n-k recovery shards."
  (declare (type (array (unsigned-byte 8) (*)) data))
  (when (or (zerop k) (zerop n))
    (return-from erasure-encode nil))
  (let* ((output-size (%erasure-output-size (length data) k n))
         (output-buffer (make-array output-size :element-type '(unsigned-byte 8) :initial-element 0)))
    (when (zerop output-size)
      (return-from erasure-encode nil))
    (cffi:with-pointer-to-vector-data (in-ptr data)
      (cffi:with-pointer-to-vector-data (out-ptr output-buffer)
        (cffi:with-foreign-object (len-ptr :size)
          (setf (cffi:mem-ref len-ptr :size) output-size)
          (let ((result (%erasure-encode in-ptr (length data) k n out-ptr len-ptr)))
            (when (zerop result)
              (return-from erasure-encode nil))))))
    (let* ((shard-size (floor output-size n))
           (shards (loop for i from 0 below n
                         collect (subseq output-buffer (* i shard-size) (* (1+ i) shard-size)))))
      shards)))

(defun erasure-encode-tiny (data)
  "Encode DATA for JAM TINY (k=2, n=6)."
  (erasure-encode data 2 6))

(defun erasure-encode-full (data)
  "Encode DATA for JAM FULL (k=342, n=1023)."
  (erasure-encode data 342 1023))

;;; ==========================================================================
;;; Bandersnatch VRF (GP Appendix A.2)
;;; ==========================================================================

(cffi:defcfun ("bandersnatch_verify_vrf" %bandersnatch-verify-vrf) :bool
  "Verify a Bandersnatch IETF VRF proof (block sealing)"
  (public-key :pointer)
  (vrf-input :pointer)
  (vrf-input-len :size)
  (vrf-output :pointer)
  (proof :pointer)
  (proof-len :size))

(defun bandersnatch-verify-vrf (public-key vrf-input vrf-output proof)
  "Verify a Bandersnatch IETF VRF proof.
   
   Args:
     public-key: 32 bytes (Bandersnatch compressed point)
     vrf-input: arbitrary bytes
     vrf-output: 32 bytes (expected output)
     proof: VRF proof bytes
   
   Returns: T if valid, NIL otherwise"
  (cffi:with-pointer-to-vector-data (pk-ptr public-key)
    (cffi:with-pointer-to-vector-data (input-ptr vrf-input)
      (cffi:with-pointer-to-vector-data (output-ptr vrf-output)
        (cffi:with-pointer-to-vector-data (proof-ptr proof)
          (%bandersnatch-verify-vrf pk-ptr
                                    input-ptr (length vrf-input)
                                    output-ptr
                                    proof-ptr (length proof)))))))

;;; ==========================================================================
;;; Compute Ring Commitment (GP 6.15)
;;; ==========================================================================

(cffi:defcfun ("bandersnatch_compute_ring_commitment" %bandersnatch-compute-ring-commitment) :bool
  "Compute ring commitment from validator public keys"
  (srs-data :pointer)
  (srs-len :size)
  (ring-pks :pointer)
  (num-validators :size)
  (output :pointer))

(defun bandersnatch-compute-ring-commitment (validator-keys)
  "Compute ring commitment (γz) from validator Bandersnatch public keys.
   
   GP 6.15: At epoch boundary, γz must be recomputed for new validators.
   
   Args:
     validator-keys: Vector of 32-byte Bandersnatch public keys
   
   Returns: 144-byte ring commitment, or NIL on error"
  (let ((srs (load-bandersnatch-srs)))
    (unless srs
      (warn "SRS not loaded - cannot compute ring commitment")
      (return-from bandersnatch-compute-ring-commitment nil))
    
    (let* ((num-validators (length validator-keys))
           (ring-pks (make-array (* num-validators 32) :element-type '(unsigned-byte 8)))
           (output (make-array 144 :element-type '(unsigned-byte 8) :initial-element 0)))
      
      ;; Concatenate all validator keys
      (loop for i from 0 below num-validators
            for key = (elt validator-keys i)
            do (dotimes (j 32)
                 (setf (aref ring-pks (+ (* i 32) j)) (aref key j))))
      
      ;; Call FFI
      (cffi:with-pointer-to-vector-data (srs-ptr srs)
        (cffi:with-pointer-to-vector-data (pks-ptr ring-pks)
          (cffi:with-pointer-to-vector-data (out-ptr output)
            (if (%bandersnatch-compute-ring-commitment 
                 srs-ptr (length srs)
                 pks-ptr num-validators
                 out-ptr)
                output
                nil)))))))

(defun ticket-vrf-input (η₂ attempt)
  "Build VRF input for ticket validation.
   
   GP 6.29: VRF_input = 'jam_ticket_seal' || η₂ || attempt
   
   Returns: concatenated bytes"
  (let ((prefix (map '(vector (unsigned-byte 8)) #'char-code "jam_ticket_seal"))
        (attempt-byte (make-array 1 :element-type '(unsigned-byte 8)
                                  :initial-element attempt)))
    (concatenate '(vector (unsigned-byte 8)) prefix η₂ attempt-byte)))

;;; ==========================================================================
;;; PVM — migrated to crypto/pvm.lisp
;;; ==========================================================================
;;; All PVM FFI bindings use the JAM codec wire protocol (wire.rs + pvm.lisp).
;;; API: pvm-new, pvm-free, pvm-configure, pvm-run, pvm-collapse, pvm-collect
