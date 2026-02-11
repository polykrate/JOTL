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
  (:unix (:or "/home/polycrate/Projets/JOTL/crypto/jam-crypto/target/release/libjam_crypto.so"
              "crypto/jam-crypto/target/release/libjam_crypto.so"
              "src/crypto/jam-crypto/target/release/libjam_crypto.so"
              "ffi/jam-crypto/target/release/libjam_crypto.so"
              "libjam_crypto.so"))
  (:darwin (:or "/home/polycrate/Projets/JOTL/crypto/jam-crypto/target/release/libjam_crypto.dylib"
                "crypto/jam-crypto/target/release/libjam_crypto.dylib"
                "src/crypto/jam-crypto/target/release/libjam_crypto.dylib"
                "ffi/jam-crypto/target/release/libjam_crypto.dylib"
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

;; NOTE: %bandersnatch-vrf-output-hash already defined above (L153)
;; NOTE: %bandersnatch-verify-ring-vrf-with-commitment already defined above (L209)

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

;; NOTE: bandersnatch-vrf-output-hash already defined above (L160)
;; NOTE: bandersnatch-verify-ring-vrf already defined above (L222)

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
;;; PVM - PolkaVM FFI Bindings (GP Section 14)
;;; ==========================================================================
;;;
;;; PVM execution pipeline:
;;;   1. pvm-engine-new → engine (singleton recommended)
;;;   2. pvm-module-load-jam → module (compiled service code)
;;;   3. jam-instance-pre-new → pre-instance (linker setup)
;;;   4. jam-instance-new → instance (per-execution)
;;;   5. Configure: jam-instance-add-storage, set-entropy, etc.
;;;   6. jam-run → execute entry point
;;;   7. Extract results: jam-get-balance, etc.
;;;   8. Free in reverse order
;;;
;;; ==========================================================================

;;; --------------------------------------------------------------------------
;;; Engine Management
;;; --------------------------------------------------------------------------

(cffi:defcfun ("pvm_engine_new" %pvm-engine-new) :pointer
  "Create a new PVM engine with default configuration")

(cffi:defcfun ("pvm_engine_new_jam" %pvm-engine-new-jam) :pointer
  "Create a new PVM engine configured for JAM (interpreter backend)")

(cffi:defcfun ("pvm_engine_free" %pvm-engine-free) :void
  "Free a PVM engine"
  (engine :pointer))

(defvar *pvm-engine* nil
  "Global PVM engine instance (lazily created)")

(defun pvm-engine ()
  "Get or create the global PVM engine."
  (unless *pvm-engine*
    (setf *pvm-engine* (%pvm-engine-new-jam))
    (when (cffi:null-pointer-p *pvm-engine*)
      (error "Failed to create PVM engine")))
  *pvm-engine*)

(defun pvm-engine-reset ()
  "Reset the global PVM engine (e.g. for testing)."
  (when *pvm-engine*
    (%pvm-engine-free *pvm-engine*)
    (setf *pvm-engine* nil)))

;;; --------------------------------------------------------------------------
;;; Module Management
;;; --------------------------------------------------------------------------

(cffi:defcfun ("pvm_module_load" %pvm-module-load) :pointer
  "Load a PVM module from raw .polkavm blob"
  (engine :pointer)
  (blob :pointer)
  (blob-len :size))

(cffi:defcfun ("pvm_module_load_jam" %pvm-module-load-jam) :pointer
  "Load a PVM module from JAM service blob format"
  (engine :pointer)
  (blob :pointer)
  (blob-len :size))

(cffi:defcfun ("pvm_module_free" %pvm-module-free) :void
  "Free a PVM module"
  (module :pointer))

(defun pvm-load-jam-module (blob)
  "Load a JAM service module from blob bytes.
   
   Args:
     blob: octets (JAM service blob)
   
   Returns: module pointer (must be freed with pvm-module-free)"
  (let ((engine (pvm-engine))
        (input (ensure-octets blob)))
    (cffi:with-pointer-to-vector-data (blob-ptr input)
      (let ((module (%pvm-module-load-jam engine blob-ptr (length input))))
        (when (cffi:null-pointer-p module)
          (error "Failed to load JAM module from blob"))
        module))))

(defun pvm-module-free (module)
  "Free a PVM module."
  (unless (cffi:null-pointer-p module)
    (%pvm-module-free module)))

;;; --------------------------------------------------------------------------
;;; JAM Instance Pre (Linker)
;;; --------------------------------------------------------------------------

(cffi:defcfun ("jam_instance_pre_new" %jam-instance-pre-new) :pointer
  "Create a JAM-enabled pre-instance with host functions"
  (module :pointer))

(cffi:defcfun ("jam_instance_pre_free" %jam-instance-pre-free) :void
  "Free a JAM pre-instance"
  (pre :pointer))

;;; --------------------------------------------------------------------------
;;; JAM Instance Management
;;; --------------------------------------------------------------------------

(cffi:defcfun ("jam_instance_new" %jam-instance-new) :pointer
  "Create a new JAM instance from a pre-instance"
  (pre :pointer)
  (service-id :uint32)
  (balance :uint64)
  (slot :uint32))

(cffi:defcfun ("jam_instance_free" %jam-instance-free) :void
  "Free a JAM instance"
  (instance :pointer))

(cffi:defcfun ("jam_instance_add_storage" %jam-instance-add-storage) :uint32
  "Add a storage entry to a JAM instance"
  (instance :pointer)
  (key :pointer)
  (key-len :size)
  (value :pointer)
  (value-len :size))

(cffi:defcfun ("jam_instance_add_preimage" %jam-instance-add-preimage) :uint32
  "Add a preimage to a JAM instance"
  (instance :pointer)
  (hash :pointer)
  (blob :pointer)
  (blob-len :size))

(cffi:defcfun ("jam_instance_set_entropy" %jam-instance-set-entropy) :uint32
  "Set entropy for JAM instance (32 or 128 bytes)"
  (instance :pointer)
  (entropy :pointer)
  (entropy-len :size))

(cffi:defcfun ("jam_instance_add_accumulate_item" %jam-instance-add-accumulate-item) :uint32
  "Add an accumulate item to JAM instance"
  (instance :pointer)
  (item :pointer)
  (item-len :size))

(cffi:defcfun ("jam_instance_set_work_package" %jam-instance-set-work-package) :uint32
  "Set work package for JAM instance"
  (instance :pointer)
  (data :pointer)
  (data-len :size))

(cffi:defcfun ("jam_instance_set_protocol_params" %jam-instance-set-protocol-params) :uint32
  "Set protocol parameters for JAM instance"
  (instance :pointer)
  (data :pointer)
  (data-len :size))

(cffi:defcfun ("jam_encode_work_item_record" %jam-encode-work-item-record) :uint32
  "Encode WorkItemRecord as AccumulateItem using Rust's SCALE encoder (v0.1.26 format)"
  (package-hash :pointer)
  (exports-root :pointer)
  (auth-hash :pointer)
  (payload-hash :pointer)
  (gas-limit :uint64)
  (result-data :pointer)
  (result-len :uint32)
  (auth-output-data :pointer)
  (auth-output-len :uint32)
  (out-buf :pointer)
  (out-capacity :uint32))

(cffi:defcfun ("jam_encode_work_item_v21" %jam-encode-work-item-v21) :uint32
  "Encode AccumulateItem in v0.1.21 format (struct without enum discriminant, auth_output before payload)"
  (package-hash :pointer)
  (exports-root :pointer)
  (auth-hash :pointer)
  (payload-hash :pointer)
  (result-data :pointer)
  (result-len :uint32)
  (auth-output-data :pointer)
  (auth-output-len :uint32)
  (out-buf :pointer)
  (out-capacity :uint32))

;;; --------------------------------------------------------------------------
;;; Execution
;;; --------------------------------------------------------------------------

(cffi:defcfun ("jam_run" %jam-run) :uint32
  "Run a JAM instance from entry point"
  (instance :pointer)
  (entry-point :string)
  (result :pointer))

(cffi:defcfun ("jam_continue" %jam-continue) :uint32
  "Continue execution of a JAM instance after a host call"
  (instance :pointer)
  (result :pointer))

(cffi:defcfun ("jam_set_gas" %jam-set-gas) :void
  "Set gas limit for JAM instance"
  (instance :pointer)
  (gas :int64))

(cffi:defcfun ("jam_get_gas" %jam-get-gas) :int64
  "Get remaining gas from JAM instance"
  (instance :pointer))

;;; --------------------------------------------------------------------------
;;; Results
;;; --------------------------------------------------------------------------

(cffi:defcfun ("jam_get_transfer_count" %jam-get-transfer-count) :uint32
  "Get number of transfers made during execution"
  (instance :pointer))

(cffi:defcfun ("jam_get_log_count" %jam-get-log-count) :uint32
  "Get number of log entries"
  (instance :pointer))

(cffi:defcfun ("jam_get_balance" %jam-get-balance) :uint64
  "Get service balance after execution"
  (instance :pointer))

;;; --------------------------------------------------------------------------
;;; High-Level API
;;; --------------------------------------------------------------------------

(defstruct pvm-context
  "PVM execution context with all resources."
  module
  pre
  instance)

(defun pvm-context-free (ctx)
  "Free all resources in a PVM context."
  (when ctx
    (when (pvm-context-instance ctx)
      (%jam-instance-free (pvm-context-instance ctx)))
    (when (pvm-context-pre ctx)
      (%jam-instance-pre-free (pvm-context-pre ctx)))
    (when (pvm-context-module ctx)
      (pvm-module-free (pvm-context-module ctx)))))

(defun pvm-prepare (blob service-id balance slot)
  "Prepare a PVM execution context from a JAM service blob.
   
   Args:
     blob: octets (JAM service blob)
     service-id: u32 service identifier
     balance: u64 initial balance
     slot: u32 current slot
   
   Returns: pvm-context structure (must be freed with pvm-context-free)"
  (let* ((module (pvm-load-jam-module blob))
         (pre (%jam-instance-pre-new module))
         (instance nil))
    (when (cffi:null-pointer-p pre)
      (pvm-module-free module)
      (error "Failed to create JAM pre-instance"))
    (setf instance (%jam-instance-new pre service-id balance slot))
    (when (cffi:null-pointer-p instance)
      (%jam-instance-pre-free pre)
      (pvm-module-free module)
      (error "Failed to create JAM instance"))
    (make-pvm-context :module module :pre pre :instance instance)))

(defun pvm-add-storage (ctx key value)
  "Add storage entry to PVM context."
  (let ((k (ensure-octets key))
        (v (ensure-octets value)))
    (cffi:with-pointer-to-vector-data (k-ptr k)
      (cffi:with-pointer-to-vector-data (v-ptr v)
        (%jam-instance-add-storage (pvm-context-instance ctx)
                                    k-ptr (length k)
                                    v-ptr (length v))))))

(defun pvm-add-preimage (ctx hash blob)
  "Add preimage to PVM context."
  (let ((h (ensure-octets hash))
        (b (ensure-octets blob)))
    (cffi:with-pointer-to-vector-data (h-ptr h)
      (cffi:with-pointer-to-vector-data (b-ptr b)
        (%jam-instance-add-preimage (pvm-context-instance ctx)
                                     h-ptr b-ptr (length b))))))

(defun pvm-set-entropy (ctx entropy)
  "Set entropy (32 or 128 bytes) for PVM context."
  (let ((e (ensure-octets entropy)))
    (cffi:with-pointer-to-vector-data (e-ptr e)
      (%jam-instance-set-entropy (pvm-context-instance ctx)
                                  e-ptr (length e)))))

(defun pvm-add-accumulate-item (ctx item)
  "Add an encoded accumulate item to PVM context.
   Item should be bytes encoding work-result data."
  (let ((i (ensure-octets item)))
    (cffi:with-pointer-to-vector-data (i-ptr i)
      (%jam-instance-add-accumulate-item (pvm-context-instance ctx)
                                          i-ptr (length i)))))

(defun pvm-set-gas (ctx gas)
  "Set gas limit for execution."
  (%jam-set-gas (pvm-context-instance ctx) gas))

(defun make-default-protocol-params ()
  "Create default protocol parameters (136 bytes) using values from ProtocolParameters::full().
   Format: B_I B_L B_S C D E G_A G_I G_R G_T H I J K L N O P Q R T U V W_A W_B W_C W_E W_M W_P W_R W_T W_X Y"
  (let ((buf (make-array 136 :element-type '(unsigned-byte 8) :initial-element 0))
        (pos 0))
    (flet ((write-u16 (v) 
             (setf (aref buf pos) (logand v #xff)
                   (aref buf (1+ pos)) (logand (ash v -8) #xff))
             (incf pos 2))
           (write-u32 (v)
             (setf (aref buf pos) (logand v #xff)
                   (aref buf (1+ pos)) (logand (ash v -8) #xff)
                   (aref buf (+ pos 2)) (logand (ash v -16) #xff)
                   (aref buf (+ pos 3)) (logand (ash v -24) #xff))
             (incf pos 4))
           (write-u64 (v)
             (loop for i below 8 do (setf (aref buf (+ pos i)) (logand (ash v (* -8 i)) #xff)))
             (incf pos 8)))
      ;; Values from jam-types ProtocolParameters::full()
      ;; B_I=10, B_L=1, B_S=100 (u64) - deposits
      (write-u64 10) (write-u64 1) (write-u64 100)
      ;; C=341 (u16), D=19200 (u32), E=600 (u32)
      (write-u16 341) (write-u32 19200) (write-u32 600)
      ;; G_A=10M, G_I=50M, G_R=5B, G_T=3.5B (u64) - gas limits
      (write-u64 10000000) (write-u64 50000000) (write-u64 5000000000) (write-u64 3500000000)
      ;; H=8, I=16, J=8, K=16 (u16), L=14400 (u32), N=2, O=8 (u16)
      (write-u16 8) (write-u16 16) (write-u16 8) (write-u16 16) (write-u32 14400) (write-u16 2) (write-u16 8)
      ;; P=6, Q=80, R=10, T=128, U=5, V=1023 (u16)
      (write-u16 6) (write-u16 80) (write-u16 10) (write-u16 128) (write-u16 5) (write-u16 1023)
      ;; W_A=64000, W_B=13794305, W_C=4000000, W_E=684, W_M=3072, W_P=6, W_R=49152, W_T=128, W_X=3072 (u32)
      (write-u32 64000) (write-u32 13794305) (write-u32 4000000) (write-u32 684) 
      (write-u32 3072) (write-u32 6) (write-u32 49152) (write-u32 128) (write-u32 3072)
      ;; Y=500 (u32) - epoch tail start
      (write-u32 500))
    buf))

(defun pvm-set-protocol-params (ctx)
  "Set default protocol parameters for JAM testnet.
   Called automatically by pvm-prepare if using default params."
  (let* ((params (make-default-protocol-params))
         (len (length params)))
    (cffi:with-foreign-array (p-ptr params `(:array :uint8 ,len))
      (%jam-instance-set-protocol-params (pvm-context-instance ctx) p-ptr len))))

(defun pvm-encode-work-item-record (package-hash exports-root auth-hash payload-hash
                                    gas-limit result-data &optional auth-output)
  "Encode a WorkItemRecord as AccumulateItem using Rust's SCALE encoder.
   Returns the encoded bytes, or nil on error."
  (let* ((result-len (if result-data (length result-data) 0))
         (auth-len (if auth-output (length auth-output) 0))
         (out-capacity 1024)
         (out-buf (cffi:foreign-alloc :uint8 :count out-capacity))
         ;; Ensure we have valid 32-byte arrays
         (pkg (or package-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
         (exp (or exports-root (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
         (auth (or auth-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
         (pay (or payload-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
         (res (or result-data (make-array 1 :element-type '(unsigned-byte 8) :initial-element 0)))
         (ao (or auth-output (make-array 1 :element-type '(unsigned-byte 8) :initial-element 0))))
    (unwind-protect
        (cffi:with-foreign-array (pkg-ptr pkg '(:array :uint8 32))
          (cffi:with-foreign-array (exp-ptr exp '(:array :uint8 32))
            (cffi:with-foreign-array (auth-ptr auth '(:array :uint8 32))
              (cffi:with-foreign-array (pay-ptr pay '(:array :uint8 32))
                (cffi:with-foreign-array (res-ptr res `(:array :uint8 ,(max 1 result-len)))
                  (cffi:with-foreign-array (ao-ptr ao `(:array :uint8 ,(max 1 auth-len)))
                    (let ((encoded-len (%jam-encode-work-item-record
                                        pkg-ptr exp-ptr auth-ptr pay-ptr
                                        gas-limit
                                        (if result-data res-ptr (cffi:null-pointer)) result-len
                                        (if auth-output ao-ptr (cffi:null-pointer)) auth-len
                                        out-buf out-capacity)))
                      (if (zerop encoded-len)
                          nil
                          (cffi:foreign-array-to-lisp out-buf `(:array :uint8 ,encoded-len))))))))))
      (cffi:foreign-free out-buf))))

(defun pvm-encode-work-item-v21 (package-hash exports-root auth-hash payload-hash
                                  result-data &optional auth-output)
  "Encode AccumulateItem in v0.1.21 format (compatible with old service blobs).
   
   v0.1.21 format differences from v0.1.26:
   - No enum discriminant (struct directly)
   - auth_output comes BEFORE payload
   - No gas_limit field
   
   Returns the encoded bytes, or nil on error."
  (let* ((result-len (if result-data (length result-data) 0))
         (auth-len (if auth-output (length auth-output) 0))
         (out-capacity 1024)
         (out-buf (cffi:foreign-alloc :uint8 :count out-capacity))
         ;; Ensure we have valid 32-byte arrays
         (pkg (or package-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
         (exp (or exports-root (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
         (auth (or auth-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
         (pay (or payload-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
         (res (or result-data (make-array 1 :element-type '(unsigned-byte 8) :initial-element 0)))
         (ao (or auth-output (make-array 1 :element-type '(unsigned-byte 8) :initial-element 0))))
    (unwind-protect
        (cffi:with-foreign-array (pkg-ptr pkg '(:array :uint8 32))
          (cffi:with-foreign-array (exp-ptr exp '(:array :uint8 32))
            (cffi:with-foreign-array (auth-ptr auth '(:array :uint8 32))
              (cffi:with-foreign-array (pay-ptr pay '(:array :uint8 32))
                (cffi:with-foreign-array (res-ptr res `(:array :uint8 ,(max 1 result-len)))
                  (cffi:with-foreign-array (ao-ptr ao `(:array :uint8 ,(max 1 auth-len)))
                    (let ((encoded-len (%jam-encode-work-item-v21
                                        pkg-ptr exp-ptr auth-ptr pay-ptr
                                        (if result-data res-ptr (cffi:null-pointer)) result-len
                                        (if auth-output ao-ptr (cffi:null-pointer)) auth-len
                                        out-buf out-capacity)))
                      (if (zerop encoded-len)
                          nil
                          (cffi:foreign-array-to-lisp out-buf `(:array :uint8 ,encoded-len))))))))))
      (cffi:foreign-free out-buf))))

(defun pvm-run (ctx entry-point)
  "Execute PVM from entry point.
   
   Entry points:
     - 'is_authorized_ext' / 'refine_ext' → PC=0
     - 'accumulate_ext' → PC=5
     - 'on_transfer_ext' → PC=10
   
   Returns: (values status result gas-remaining)
     status: 0=OK, 5=Trap, 6=OOG, 7=HostError, other=Error
     result: u64 return value (A0 register)
     gas-remaining: i64 gas left"
  (cffi:with-foreign-object (result-ptr :uint64)
    (setf (cffi:mem-ref result-ptr :uint64) 0)
    (let ((status (%jam-run (pvm-context-instance ctx) entry-point result-ptr)))
      (values status
              (cffi:mem-ref result-ptr :uint64)
              (%jam-get-gas (pvm-context-instance ctx))))))

(defun pvm-get-balance (ctx)
  "Get final balance after execution."
  (%jam-get-balance (pvm-context-instance ctx)))

(defun pvm-get-transfer-count (ctx)
  "Get number of transfers made."
  (%jam-get-transfer-count (pvm-context-instance ctx)))

(defun pvm-get-log-count (ctx)
  "Get number of log entries."
  (%jam-get-log-count (pvm-context-instance ctx)))

;;; --------------------------------------------------------------------------
;;; Storage/Transfer/Log Iteration (retrieve results after execution)
;;; --------------------------------------------------------------------------

(cffi:defcfun ("jam_get_storage_count" %jam-get-storage-count) :uint32
  "Get number of storage entries."
  (instance :pointer))

(cffi:defcfun ("jam_get_storage_key" %jam-get-storage-key) :uint32
  "Get storage key at index."
  (instance :pointer)
  (index :uint32)
  (out :pointer)
  (out-len :size))

(cffi:defcfun ("jam_get_storage_value" %jam-get-storage-value) :uint32
  "Get storage value at index."
  (instance :pointer)
  (index :uint32)
  (out :pointer)
  (out-len :size))

(cffi:defcfun ("jam_get_log" %jam-get-log) :uint32
  "Get log entry at index."
  (instance :pointer)
  (index :uint32)
  (out :pointer)
  (out-len :size))

(cffi:defcfun ("jam_get_transfer" %jam-get-transfer) :uint32
  "Get transfer at index. Returns to_service_id."
  (instance :pointer)
  (index :uint32)
  (amount-out :pointer)
  (memo-out :pointer)
  (memo-len :size))

(cffi:defcfun ("jam_get_transfer_memo_len" %jam-get-transfer-memo-len) :uint32
  "Get transfer memo length at index."
  (instance :pointer)
  (index :uint32))

;;; --------------------------------------------------------------------------
;;; Ejected Services (GP 14.5.10)
;;; --------------------------------------------------------------------------

(cffi:defcfun ("jam_get_ejected_count" %jam-get-ejected-count) :uint32
  "Get number of services ejected during execution."
  (instance :pointer))

(cffi:defcfun ("jam_get_ejected_service" %jam-get-ejected-service) :uint32
  "Get ejected service ID at index."
  (instance :pointer)
  (index :uint32))

(defun pvm-get-ejected-count (ctx)
  "Get number of services ejected during PVM execution."
  (%jam-get-ejected-count (pvm-context-instance ctx)))

(defun pvm-get-ejected-service (ctx index)
  "Get ejected service ID at index."
  (let ((sid (%jam-get-ejected-service (pvm-context-instance ctx) index)))
    (if (= sid #xFFFFFFFF) nil sid)))

(cffi:defcfun ("jam_get_ejector_service" %jam-get-ejector-service) :uint32
  "Get ejector service ID at index (who called eject)."
  (instance :pointer)
  (index :uint32))

(defun pvm-get-ejector-service (ctx index)
  "Get ejector service ID at index (who called eject)."
  (let ((sid (%jam-get-ejector-service (pvm-context-instance ctx) index)))
    (if (= sid #xFFFFFFFF) nil sid)))

(defun pvm-get-all-ejected (ctx)
  "Get all ejected service pairs as a list of (target . ejector)."
  (let ((count (pvm-get-ejected-count ctx)))
    (loop for i below count
          for target = (pvm-get-ejected-service ctx i)
          for ejector = (pvm-get-ejector-service ctx i)
          when target collect (cons target ejector))))

;;; --------------------------------------------------------------------------
;;; Yield Output (GP 14.5.11)
;;; --------------------------------------------------------------------------

(cffi:defcfun ("jam_has_yield_output" %jam-has-yield-output) :uint32
  "Check if yield_hash was called during execution."
  (instance :pointer))

(cffi:defcfun ("jam_get_yield_output" %jam-get-yield-output) :uint32
  "Get the yield output hash (32 bytes)."
  (instance :pointer)
  (out-buf :pointer))

(defun pvm-has-yield-output (ctx)
  "Check if the PVM called yield_hash during execution."
  (not (zerop (%jam-has-yield-output (pvm-context-instance ctx)))))

(defun pvm-get-yield-output (ctx)
  "Get the yield output hash (32 bytes) or nil if none."
  (let ((inst (pvm-context-instance ctx)))
    (when (pvm-has-yield-output ctx)
      (cffi:with-foreign-pointer (buf 32)
        (when (zerop (%jam-get-yield-output inst buf))
          (cffi:foreign-array-to-lisp buf '(:array :uint8 32)))))))

;;; --------------------------------------------------------------------------
;;; Created Services (GP 14.5.8 - new host call)
;;; --------------------------------------------------------------------------

(cffi:defcfun ("jam_get_created_service_count" %jam-get-created-service-count) :uint32
  "Get number of services created during execution."
  (instance :pointer))

(cffi:defcfun ("jam_get_created_service_id" %jam-get-created-service-id) :uint32
  "Get created service ID at index."
  (instance :pointer)
  (index :uint32))

(cffi:defcfun ("jam_get_created_service_code_hash" %jam-get-created-service-code-hash) :uint32
  "Get created service code hash at index."
  (instance :pointer)
  (index :uint32)
  (out-buf :pointer))

(cffi:defcfun ("jam_set_next_service_id" %jam-set-next-service-id) :uint32
  "Set the next service ID for new() calls."
  (instance :pointer)
  (next-id :uint32))

(defun pvm-get-created-service-count (ctx)
  "Get number of services created during PVM execution."
  (%jam-get-created-service-count (pvm-context-instance ctx)))

(defun pvm-get-created-service (ctx index)
  "Get created service ID and code-hash at index. Returns (sid . code-hash) or nil."
  (let* ((inst (pvm-context-instance ctx))
         (sid (%jam-get-created-service-id inst index)))
    (when (< sid #xFFFFFFFF)
      (cffi:with-foreign-pointer (buf 32)
        (when (zerop (%jam-get-created-service-code-hash inst index buf))
          (cons sid (cffi:foreign-array-to-lisp buf '(:array :uint8 32))))))))

(defun pvm-get-all-created (ctx)
  "Get all created services as a list of (sid . code-hash)."
  (loop for i below (pvm-get-created-service-count ctx)
        for entry = (pvm-get-created-service ctx i)
        when entry collect entry))

(defun pvm-set-next-service-id (ctx next-id)
  "Set the next service ID for new() calls. Should be max-sid + 1."
  (%jam-set-next-service-id (pvm-context-instance ctx) next-id))

;;; --------------------------------------------------------------------------
;;; Storage Access
;;; --------------------------------------------------------------------------

(defun pvm-get-storage-count (ctx)
  "Get number of storage entries after execution."
  (%jam-get-storage-count (pvm-context-instance ctx)))

(defun pvm-get-storage-entry (ctx index)
  "Get storage key-value at index. Returns (key . value) or nil."
  (let ((inst (pvm-context-instance ctx)))
    ;; First get the key length
    (let ((key-len (%jam-get-storage-key inst index (cffi:null-pointer) 0)))
      (when (= key-len #xFFFFFFFF)
        (return-from pvm-get-storage-entry nil))
      
      ;; Get the value length  
      (let ((val-len (%jam-get-storage-value inst index (cffi:null-pointer) 0)))
        (when (= val-len #xFFFFFFFF)
          (return-from pvm-get-storage-entry nil))
        
        ;; Allocate and read
        (cffi:with-foreign-pointer (key-buf key-len)
          (cffi:with-foreign-pointer (val-buf val-len)
            (%jam-get-storage-key inst index key-buf key-len)
            (%jam-get-storage-value inst index val-buf val-len)
            
            (cons (cffi:foreign-array-to-lisp key-buf `(:array :uint8 ,key-len))
                  (cffi:foreign-array-to-lisp val-buf `(:array :uint8 ,val-len)))))))))

(defun pvm-get-all-storage (ctx)
  "Get all storage entries as a hash-table."
  (let ((ht (make-hash-table :test 'equalp))
        (count (pvm-get-storage-count ctx)))
    (dotimes (i count)
      (let ((entry (pvm-get-storage-entry ctx i)))
        (when entry
          (setf (gethash (car entry) ht) (cdr entry)))))
    ht))

(defun pvm-get-log-entry (ctx index)
  "Get log entry at index. Returns byte vector or nil."
  (let ((inst (pvm-context-instance ctx)))
    (let ((len (%jam-get-log inst index (cffi:null-pointer) 0)))
      (when (= len #xFFFFFFFF)
        (return-from pvm-get-log-entry nil))
      
      (cffi:with-foreign-pointer (buf len)
        (%jam-get-log inst index buf len)
        (cffi:foreign-array-to-lisp buf `(:array :uint8 ,len))))))

(defun pvm-get-all-logs (ctx)
  "Get all log entries as a list of byte vectors."
  (let ((count (pvm-get-log-count ctx)))
    (loop for i below count
          for log = (pvm-get-log-entry ctx i)
          when log collect log)))

(defun pvm-get-transfer-entry (ctx index)
  "Get transfer at index. Returns hash-table {:destination :amount :memo} or nil."
  (let ((inst (pvm-context-instance ctx)))
    (let ((memo-len (%jam-get-transfer-memo-len inst index)))
      (when (= memo-len #xFFFFFFFF)
        (return-from pvm-get-transfer-entry nil))
      
      (cffi:with-foreign-objects ((amount-ptr :uint64)
                                  (memo-buf :uint8 (max 1 memo-len)))
        (let ((to-service (%jam-get-transfer inst index amount-ptr memo-buf memo-len)))
          (when (= to-service #xFFFFFFFF)
            (return-from pvm-get-transfer-entry nil))
          
          (let ((ht (make-hash-table)))
            (setf (gethash :destination ht) to-service)
            (setf (gethash :amount ht) (cffi:mem-ref amount-ptr :uint64))
            (setf (gethash :memo ht) (if (> memo-len 0)
                    (cffi:foreign-array-to-lisp memo-buf `(:array :uint8 ,memo-len))
                                         #()))
            ht))))))

(defun pvm-get-all-transfers (ctx)
  "Get all transfers as a vector of hash-tables {:destination :amount :memo}."
  (let ((count (pvm-get-transfer-count ctx)))
    (coerce (loop for i below count
          for xfer = (pvm-get-transfer-entry ctx i)
                  when xfer collect xfer)
            'vector)))

;;; --------------------------------------------------------------------------
;;; Upgrades (ΩU side-effects)
;;; --------------------------------------------------------------------------

(cffi:defcfun ("jam_get_upgrade_count" %jam-get-upgrade-count) :uint32
  "Get number of code upgrades recorded during execution."
  (instance :pointer))

(cffi:defcfun ("jam_get_upgrade_service" %jam-get-upgrade-service) :uint32
  "Get upgraded service ID at index."
  (instance :pointer)
  (index :uint32))

(cffi:defcfun ("jam_get_upgrade_code_hash" %jam-get-upgrade-code-hash) :uint32
  "Get upgraded service code hash at index."
  (instance :pointer)
  (index :uint32)
  (out-buf :pointer))

(defun pvm-get-upgrade-count (ctx)
  "Get number of code upgrades recorded during PVM execution."
  (%jam-get-upgrade-count (pvm-context-instance ctx)))

(defun pvm-get-upgrade (ctx index)
  "Get upgrade at index. Returns (sid . code-hash) or nil."
  (let* ((inst (pvm-context-instance ctx))
         (sid (%jam-get-upgrade-service inst index)))
    (when (< sid #xFFFFFFFF)
      (cffi:with-foreign-pointer (buf 32)
        (when (zerop (%jam-get-upgrade-code-hash inst index buf))
          (cons sid (cffi:foreign-array-to-lisp buf '(:array :uint8 32))))))))

(defun pvm-get-all-upgrades (ctx)
  "Get all upgrades as a list of (sid . code-hash)."
  (loop for i below (pvm-get-upgrade-count ctx)
        for entry = (pvm-get-upgrade ctx i)
        when entry collect entry))

;;; --------------------------------------------------------------------------
;;; Empower State (ΩB / ΩA / ΩD side-effects)
;;; --------------------------------------------------------------------------

(cffi:defcfun ("jam_has_empower" %jam-has-empower) :uint32
  "Check if empower state was set."
  (instance :pointer))

(cffi:defcfun ("jam_get_empower_manager" %jam-get-empower-manager) :uint32
  "Get empower manager service index."
  (instance :pointer))

(cffi:defcfun ("jam_get_empower_validator" %jam-get-empower-validator) :uint32
  "Get empower validator service index."
  (instance :pointer))

(cffi:defcfun ("jam_get_empower_staker" %jam-get-empower-staker) :uint32
  "Get empower staker service index."
  (instance :pointer))

(cffi:defcfun ("jam_get_empower_auth_agent_count" %jam-get-empower-auth-agent-count) :uint32
  "Get number of authorization agents."
  (instance :pointer))

(cffi:defcfun ("jam_get_empower_auth_agent" %jam-get-empower-auth-agent) :uint32
  "Get authorization agent at index."
  (instance :pointer)
  (index :uint32))

(cffi:defcfun ("jam_get_empower_gas_map_count" %jam-get-empower-gas-map-count) :uint32
  "Get number of entries in the empower gas map."
  (instance :pointer))

(cffi:defcfun ("jam_get_empower_gas_map_entry" %jam-get-empower-gas-map-entry) :uint32
  "Get gas map entry at index."
  (instance :pointer)
  (index :uint32)
  (out-service :pointer)
  (out-gas :pointer))

(cffi:defcfun ("jam_get_empower_queue_count" %jam-get-empower-queue-count) :uint32
  "Get number of core authorization queues."
  (instance :pointer))

(cffi:defcfun ("jam_get_empower_queue_len" %jam-get-empower-queue-len) :uint32
  "Get queue length for a specific core."
  (instance :pointer)
  (core :uint32))

(cffi:defcfun ("jam_get_empower_queue_entry" %jam-get-empower-queue-entry) :uint32
  "Get authorization queue hash at (core, slot)."
  (instance :pointer)
  (core :uint32)
  (slot :uint32)
  (out-buf :pointer))

(cffi:defcfun ("jam_get_empower_validator_count" %jam-get-empower-validator-count) :uint32
  "Get number of designated validator keys."
  (instance :pointer))

(cffi:defcfun ("jam_get_empower_validator_key" %jam-get-empower-validator-key) :uint32
  "Get designated validator key at index."
  (instance :pointer)
  (index :uint32)
  (out-buf :pointer)
  (out-len :uint32))

(defun pvm-has-empower (ctx)
  "Check if the PVM set empower state during execution."
  (not (zerop (%jam-has-empower (pvm-context-instance ctx)))))

(defun pvm-get-empower (ctx)
  "Get empower state as a plist, or nil if not set.
   Returns: (:manager m :validator v :staker r :auth-agents (a0 a1 ...)
             :gas-map ((sid . gas) ...) :queues ((core0-hashes) (core1-hashes) ...)
             :validators (key0 key1 ...))"
  (let ((inst (pvm-context-instance ctx)))
    (when (pvm-has-empower ctx)
      (let ((manager (%jam-get-empower-manager inst))
            (validator (%jam-get-empower-validator inst))
            (staker (%jam-get-empower-staker inst))
            ;; auth agents
            (agent-count (%jam-get-empower-auth-agent-count inst))
            ;; gas map
            (gas-count (%jam-get-empower-gas-map-count inst))
            ;; queues
            (queue-count (%jam-get-empower-queue-count inst))
            ;; validators
            (val-count (%jam-get-empower-validator-count inst)))
        (list
         :manager manager
         :validator validator
         :staker staker
         :auth-agents (loop for i below agent-count
                            collect (%jam-get-empower-auth-agent inst i))
         :gas-map (cffi:with-foreign-objects ((sid-ptr :uint32)
                                              (gas-ptr :uint64))
                    (loop for i below gas-count
                          when (zerop (%jam-get-empower-gas-map-entry
                                       inst i sid-ptr gas-ptr))
                          collect (cons (cffi:mem-ref sid-ptr :uint32)
                                        (cffi:mem-ref gas-ptr :uint64))))
         :queues (loop for c below queue-count
                       collect (let ((qlen (%jam-get-empower-queue-len inst c)))
                                 (cffi:with-foreign-pointer (buf 32)
                                   (loop for s below qlen
                                         when (zerop (%jam-get-empower-queue-entry
                                                       inst c s buf))
                                         collect (cffi:foreign-array-to-lisp
                                                  buf '(:array :uint8 32))))))
         :validators (loop for i below val-count
                           collect (let ((klen (%jam-get-empower-validator-key
                                                inst i (cffi:null-pointer) 0)))
                                     (when (< klen #xFFFFFFFF)
                                       (cffi:with-foreign-pointer (buf klen)
                                         (%jam-get-empower-validator-key
                                          inst i buf klen)
                                         (cffi:foreign-array-to-lisp
                                          buf `(:array :uint8 ,klen)))))))))))

;;; --------------------------------------------------------------------------
;;; Provided Preimages (Ωψ side-effects)
;;; --------------------------------------------------------------------------

(cffi:defcfun ("jam_get_provided_preimage_count" %jam-get-provided-preimage-count) :uint32
  "Get number of provided preimages."
  (instance :pointer))

(cffi:defcfun ("jam_get_provided_preimage_service" %jam-get-provided-preimage-service) :uint32
  "Get provided preimage service ID at index."
  (instance :pointer)
  (index :uint32))

(cffi:defcfun ("jam_get_provided_preimage_data" %jam-get-provided-preimage-data) :uint32
  "Get provided preimage data at index."
  (instance :pointer)
  (index :uint32)
  (out-buf :pointer)
  (out-len :uint32))

(defun pvm-get-provided-preimage-count (ctx)
  "Get number of provided preimages recorded during PVM execution."
  (%jam-get-provided-preimage-count (pvm-context-instance ctx)))

(defun pvm-get-provided-preimage (ctx index)
  "Get provided preimage at index. Returns (service-id . data-bytes) or nil."
  (let* ((inst (pvm-context-instance ctx))
         (sid (%jam-get-provided-preimage-service inst index)))
    (when (< sid #xFFFFFFFF)
      (let ((data-len (%jam-get-provided-preimage-data
                        inst index (cffi:null-pointer) 0)))
        (when (< data-len #xFFFFFFFF)
          (if (zerop data-len)
              (cons sid #())
              (cffi:with-foreign-pointer (buf data-len)
                (%jam-get-provided-preimage-data inst index buf data-len)
                (cons sid (cffi:foreign-array-to-lisp
                           buf `(:array :uint8 ,data-len))))))))))

(defun pvm-get-all-provided-preimages (ctx)
  "Get all provided preimages as a list of (service-id . data-bytes)."
  (loop for i below (pvm-get-provided-preimage-count ctx)
        for entry = (pvm-get-provided-preimage ctx i)
        when entry collect entry))

;;; --------------------------------------------------------------------------
;;; Lookup Table a_l (preimage metadata)
;;; --------------------------------------------------------------------------

(cffi:defcfun ("jam_instance_add_lookup_entry" %jam-instance-add-lookup-entry) :uint32
  "Add a preimage lookup table entry before execution."
  (instance :pointer)
  (hash-ptr :pointer)
  (length :uint32)
  (status-ptr :pointer)
  (status-count :uint32))

(cffi:defcfun ("jam_get_lookup_count" %jam-get-lookup-count) :uint32
  "Get number of lookup table entries."
  (instance :pointer))

(cffi:defcfun ("jam_get_lookup_entry" %jam-get-lookup-entry) :uint32
  "Get lookup table entry at index."
  (instance :pointer)
  (index :uint32)
  (out-hash :pointer)
  (out-length :pointer)
  (out-status :pointer)
  (max-status :uint32))

(defun pvm-add-lookup-entry (ctx hash length status-list)
  "Add a preimage lookup table entry. HASH is a 32-byte vector, LENGTH is u32,
   STATUS-LIST is a list of 0-3 u32 values."
  (let ((inst (pvm-context-instance ctx))
        (sc (length status-list)))
    (cffi:with-foreign-pointer (hash-buf 32)
      (loop for i below 32
            do (setf (cffi:mem-aref hash-buf :uint8 i) (aref hash i)))
      (if (zerop sc)
          (%jam-instance-add-lookup-entry inst hash-buf length (cffi:null-pointer) 0)
          (cffi:with-foreign-object (status-buf :uint32 sc)
            (loop for val in status-list
                  for i from 0
                  do (setf (cffi:mem-aref status-buf :uint32 i) val))
            (%jam-instance-add-lookup-entry inst hash-buf length status-buf sc))))))

(defun pvm-get-lookup-count (ctx)
  "Get number of preimage lookup table entries after execution."
  (%jam-get-lookup-count (pvm-context-instance ctx)))

(defun pvm-get-lookup-entry (ctx index)
  "Get lookup table entry at index. Returns (hash length . status-list) or nil."
  (let ((inst (pvm-context-instance ctx)))
    (cffi:with-foreign-objects ((hash-buf :uint8 32)
                                (len-ptr :uint32)
                                (status-buf :uint32 3))
      (let ((sc (%jam-get-lookup-entry inst index hash-buf len-ptr status-buf 3)))
        (when (< sc #xFFFFFFFF)
          (list (cffi:foreign-array-to-lisp hash-buf '(:array :uint8 32))
                (cffi:mem-ref len-ptr :uint32)
                (loop for i below sc
                      collect (cffi:mem-aref status-buf :uint32 i))))))))

(defun pvm-get-all-lookup-entries (ctx)
  "Get all lookup table entries as a list of (hash length . status-list)."
  (loop for i below (pvm-get-lookup-count ctx)
        for entry = (pvm-get-lookup-entry ctx i)
        when entry collect entry))

;;; --------------------------------------------------------------------------
;;; Convenience Macros
;;; --------------------------------------------------------------------------

(defmacro with-pvm-context ((var blob service-id balance slot) &body body)
  "Execute body with a PVM context, ensuring cleanup.
   
   Example:
     (with-pvm-context (ctx service-blob 42 1000000 100)
       (pvm-set-entropy ctx entropy)
       (pvm-set-gas ctx 10000000)
       (pvm-run ctx 'accumulate_ext'))"
  `(let ((,var (pvm-prepare ,blob ,service-id ,balance ,slot)))
     (unwind-protect
         (progn ,@body)
       (pvm-context-free ,var))))
