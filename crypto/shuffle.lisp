;;;; GP 3.7.5 - Shuffling
;;;; Fisher-Yates shuffle function from Gray Paper
;;;; Pure Lisp implementation (no FFI required)

(in-package :jam.ffi)

;;; ============================================================
;;; 3.7.5 Shuffling (F)
;;; ============================================================
;;; F - Fisher-Yates shuffle function (Fisher and Yates 1938)
;;; Accepts sequence and entropy (hash or sequence of naturals)
;;; Returns sequence with same elements in deterministic order

(defun shuffle-with-entropy (sequence entropy)
  "Fisher-Yates shuffle with deterministic entropy.
   GP notation: F(sequence, entropy)
   
   SEQUENCE - the sequence to shuffle
   ENTROPY  - either a hash (32 bytes) or sequence of naturals
   
   Returns a new sequence with same elements in shuffled order.
   The shuffle is deterministic given the same entropy."
  (let* ((vec (coerce (copy-seq sequence) 'vector))
         (n (length vec))
         (entropy-bytes (etypecase entropy
                          ((array (unsigned-byte 8) (*)) entropy)
                          (sequence (coerce entropy 'vector)))))
    ;; Fisher-Yates in-place shuffle
    (loop for i from (1- n) downto 1
          for entropy-idx = (mod i (length entropy-bytes))
          for random-byte = (aref entropy-bytes entropy-idx)
          for j = (mod random-byte (1+ i))
          do (rotatef (aref vec i) (aref vec j)))
    vec))

;;; ============================================================
;;; Deterministic Random from Hash
;;; ============================================================

(defun hash-random-index (hash max-value index)
  "Extract a deterministic random value from HASH.
   Returns a value in [0, MAX-VALUE).
   INDEX determines which part of the hash to use."
  (let* ((hash-bytes (coerce hash 'vector))
         (hash-len (length hash-bytes))
         (byte-idx (mod index hash-len))
         (byte-val (aref hash-bytes byte-idx)))
    (mod byte-val max-value)))

;;; ============================================================
;;; Shuffle for Validator Selection
;;; ============================================================

(defun shuffle-validators (validators entropy)
  "Shuffle validator list using entropy.
   GP: γₛ'[i] ≡ γₖ[F(η₂', i) mod |γₖ|]"
  (shuffle-with-entropy validators entropy))

