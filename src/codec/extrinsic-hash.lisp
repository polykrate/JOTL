;;;; extrinsic-hash.lisp - Extrinsic Hash (HX) Computation
;;;; Gray Paper §5.4-5.6
;;;;
;;;; CONFIRMED ALGORITHM (validated against strawberry Go implementation):
;;;;
;;;;   HX ≡ H(E(H#(a)))                                         (5.4)
;;;;
;;;;   H#(a) = [H(a₀), H(a₁), ..., H(aₙ)]    (map H over each element)
;;;;
;;;;   E(H#(a)) = concatenation of 5 × 32-byte hashes = 160 bytes
;;;;
;;;;   HX = blake2b-256(H(ET) || H(EP) || H(g) || H(EA) || H(ED))
;;;;
;;;;   where a = [ET(ET), EP(EP), g, EA(EA), ED(ED)]            (5.5)
;;;;
;;;;   and g = E(↕[(H(r), E4(t), ↕a) | (r, t, a) ← EG])       (5.6)
;;;;
;;;;   g encodes each guarantee as:
;;;;     H(r)  = blake2b-256(encode(work-report))  — hash of the encoded report
;;;;     E4(t) = u32 little-endian slot
;;;;     ↕a    = compact(n) + for each sig: E2(validator_index) + signature(64)

(in-package :jotl)

;;; ==========================================================================
;;; g = Guarantee Summaries (Gray Paper §5.6)
;;; ==========================================================================

(defun encode-guarantee-summary (guarantee)
  "Encode a single guarantee summary: (H(r), E4(t), ↕a).
   
   Gray Paper §5.6:
     H(r)  : Blake2b-256 hash of the JAM-encoded work report (32 bytes)
     E4(t) : Time slot encoded as u32 (4 bytes)
     ↕a    : Compact-prefixed sequence of credential signatures
   
   Args:
     guarantee: plist with :report (or :report-raw-bytes) :slot :signatures
   
   Returns:
     byte array"
  (let* (;; H(r): hash of the work report encoding
         (report-bytes (or (getf guarantee :report-raw-bytes)
                           (encode-work-report (getf guarantee :report))))
         (h-r (jam.ffi:blake2b-256 report-bytes))
         ;; E4(t): slot as u32
         (e4-t (encode-u32 (getf guarantee :slot)))
         ;; ↕a: encoded credential signatures
         (sigs (encode-guarantee-signatures (getf guarantee :signatures))))
    (concatenate '(vector (unsigned-byte 8)) h-r e4-t sigs)))

(defun compute-guarantee-summaries (guarantees)
  "Compute g = E(↕[(H(r), E4(t), ↕a) | (r, t, a) ← EG]).
   
   Gray Paper §5.6: The outer ↕ means compact-prefixed sequence.
   Each element is the concatenation (H(r), E4(t), ↕a).
   
   Args:
     guarantees: List of guarantee plists
   
   Returns:
     Encoded byte array (compact length prefix + concatenated summaries)"
  (encode-sequence (or guarantees '()) #'encode-guarantee-summary))

;;; ==========================================================================
;;; HX = Extrinsic Hash (Gray Paper §5.4-5.6)
;;; ==========================================================================

(defun compute-extrinsic-hash (extrinsic-data)
  "Compute the extrinsic hash HX from decoded extrinsic data.
   
   Gray Paper §5.4-5.6:
     HX ≡ H(E(H#(a)))
     
     where H#(a) = [H(a₀), ..., H(a₄)] (Blake2b hash of each component)
     and   E(H#(a)) = concatenation of 5 × 32-byte hashes
     so    HX = blake2b(H(ET) || H(EP) || H(g) || H(EA) || H(ED))
   
   IMPORTANT: Component order is ET, EP, g, EA, ED
   where g is the guarantee summaries (NOT raw EG encoding).
   
   Args:
     extrinsic-data: Plist with :tickets :preimages :assurances :disputes :guarantees
   
   Returns:
     32-byte hash"
  (let* ((tickets    (getf extrinsic-data :tickets))
         (preimages  (getf extrinsic-data :preimages))
         (guarantees (getf extrinsic-data :guarantees))
         (assurances (getf extrinsic-data :assurances))
         (disputes   (getf extrinsic-data :disputes))
         
         ;; Encode each component
         (encoded-tickets    (encode-tickets-extrinsic (or tickets '())))
         (encoded-preimages  (encode-preimages-extrinsic (or preimages '())))
         (encoded-assurances (encode-assurances-extrinsic (or assurances '())))
         (encoded-disputes   (if disputes
                                 (encode-disputes-extrinsic disputes)
                                 ;; Empty disputes = compact(0) × 3
                                 (concatenate '(vector (unsigned-byte 8))
                                              (encode-compact 0)   ; verdicts
                                              (encode-compact 0)   ; culprits
                                              (encode-compact 0)))) ; faults
         
         ;; Compute g (guarantee summaries with hashed work reports)
         (g (compute-guarantee-summaries guarantees))
         
         ;; H#(a) = [H(ET), H(EP), H(g), H(EA), H(ED)]
         (h-et (jam.ffi:blake2b-256 encoded-tickets))
         (h-ep (jam.ffi:blake2b-256 encoded-preimages))
         (h-g  (jam.ffi:blake2b-256 g))
         (h-ea (jam.ffi:blake2b-256 encoded-assurances))
         (h-ed (jam.ffi:blake2b-256 encoded-disputes))
         
         ;; E(H#(a)) = H(ET) || H(EP) || H(g) || H(EA) || H(ED) = 160 bytes
         (concatenated-hashes (concatenate '(vector (unsigned-byte 8))
                                           h-et h-ep h-g h-ea h-ed)))
    
    ;; HX = H(E(H#(a))) = blake2b(160 bytes)
    (jam.ffi:blake2b-256 concatenated-hashes)))

(defun compute-extrinsic-hash-from-encoded (encoded-extrinsic)
  "Compute HX from an already-encoded extrinsic byte array.
   
   Decodes the extrinsic first, then computes HX.
   This is useful when you have the raw binary but need the hash.
   
   Args:
     encoded-extrinsic: Byte array of encoded extrinsic
   
   Returns:
     32-byte hash"
  (multiple-value-bind (extrinsic-data bytes-consumed)
      (decode-extrinsic encoded-extrinsic 0)
    (declare (ignore bytes-consumed))
    (compute-extrinsic-hash extrinsic-data)))

;;; ==========================================================================
;;; Convenience
;;; ==========================================================================

(defun make-extrinsic-hash (extrinsic-data)
  "Convenience alias for compute-extrinsic-hash.
   
   Args:
     extrinsic-data: Extrinsic plist
   
   Returns:
     32-byte hash suitable for HX field in header"
  (compute-extrinsic-hash extrinsic-data))

;;; ==========================================================================
;;; Exports
;;; ==========================================================================

(export '(encode-guarantee-summary
          compute-guarantee-summaries
          compute-extrinsic-hash
          compute-extrinsic-hash-from-encoded
          make-extrinsic-hash))
