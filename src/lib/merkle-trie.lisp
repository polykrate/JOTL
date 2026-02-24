;;;; Merkle Trie implementation (GP Appendix D)
;;;; Binary tree for state merkleization
;;;;
;;;; Performance notes:
;;;;   - trie-bit inlined for tight inner loop
;;;;   - trie-branch/trie-leaf use replace instead of byte loops
;;;;   - Pre-allocated zero array avoids allocation in empty nodes
;;;;   - pad-key-to-32 uses replace instead of byte loop
(in-package #:jotl)

;;; ============================================================================
;;; Constants
;;; ============================================================================

(defvar *trie-zero-hash*
  (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
  "Pre-allocated 32-byte zero array for empty Merkle nodes.
   Shared read-only — never mutate this.")

;;; ============================================================================
;;; Helper Functions
;;; ============================================================================

(declaim (inline trie-bit))

(defun trie-bit (key i)
  "Get bit i of key (Strawberry MSB-first).
   Strawberry: bit(k, i) = (k[i/8] & (1 << (7 - i%8))) != 0
   MSB-first (big-endian bit order) - confirmed working with test vectors.
   Returns T if bit is 1, NIL if 0."
  (declare (optimize (speed 3) (safety 1))
           (type fixnum i))
  (not (zerop (logand (aref key (ash i -3))
                      (ash 1 (- 7 (logand i 7)))))))

;;; ============================================================================
;;; Branch Node (GP 286)
;;; ============================================================================

(defun trie-branch (left right)
  "Create branch node from left and right children.
   Strawberry: node[0] = left[0] & 0b01111111
   Clears MSB (bit 7) of first byte to mark as branch (not leaf).
   Returns 64 bytes."
  (declare (optimize (speed 3) (safety 1)))
  (let ((result (make-array 64 :element-type '(unsigned-byte 8))))
    ;; Copy left hash (32 bytes) — then fix first byte
    (replace result left :start1 0 :end1 32)
    (setf (aref result 0) (logand (aref result 0) #x7f))
    ;; Copy right hash (32 bytes)
    (replace result right :start1 32 :end1 64)
    result))

;;; ============================================================================
;;; Leaf Node (GP 287)
;;; ============================================================================

(defun trie-leaf (key value)
  "Create leaf node from key and value.
   Strawberry format:
   - if len(v) <= 32: head = 0b10000000 | len(v), pad value to 32 bytes
   - if len(v) > 32: head = 0b11000000, hash value
   Bit 7 = 1 (leaf flag), bit 6 = 0 (embedded) or 1 (regular).
   k[:-1] means first 31 bytes of 32-byte key.
   Returns 64 bytes."
  (declare (optimize (speed 3) (safety 1)))
  (let ((result (make-array 64 :element-type '(unsigned-byte 8) :initial-element 0))
        (vlen (length value)))
    (if (<= vlen 32)
        ;; Short value: embed directly
        (progn
          (setf (aref result 0) (logior #x80 vlen))
          ;; key[:-1] = first 31 bytes
          (replace result key :start1 1 :end1 32 :start2 0 :end2 31)
          ;; value bytes (zero-padded by initial-element 0)
          (replace result value :start1 32 :end1 (+ 32 vlen)))
        ;; Long value: hash it
        (progn
          (setf (aref result 0) #xC0)
          (replace result key :start1 1 :end1 32 :start2 0 :end2 31)
          (let ((vhash (blake2b-256 value)))
            (replace result vhash :start1 32 :end1 64))))
    result))

;;; ============================================================================
;;; Merkle Root (GP 289)
;;; ============================================================================

(declaim (inline pad-key-to-32))

(defun pad-key-to-32 (key)
  "Pad key to 32 bytes if needed (GP D.1 specifies 31-byte keys).
   Adds null byte padding at the end. Uses replace for fast copy."
  (declare (optimize (speed 3) (safety 1)))
  (let ((klen (length key)))
    (if (< klen 32)
        (let ((padded (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
          (replace padded key :end1 klen)
          padded)
        key)))

(defun merkle-root (kvs &optional (bit-index 0))
  "Compute Merkle root of key-value pairs.
   GP (289): Recursive binary tree construction.
   KVS is a list of (key . value) cons cells where key and value are byte vectors.
   Keys MUST be 32 bytes (use compute-state-root for automatic padding).
   Returns 32-byte hash.
   
   Conforms to reference implementation: always creates branch nodes,
   even if one side is empty (returns 32 zero bytes)."
  (declare (optimize (speed 3) (safety 1))
           (type fixnum bit-index))
  
  (cond
    ;; Empty: return shared zero array (copy to avoid mutation)
    ((null kvs)
     (copy-seq *trie-zero-hash*))
    
    ;; Single leaf — O(1) check instead of O(n) length
    ((null (cdr kvs))
     (let* ((kv (first kvs))
            (key (car kv))
            (value (cdr kv))
            (encoded (trie-leaf key value)))
       (blake2b-256 encoded)))
    
    ;; Multiple: split by bit
    (t
     (when (> bit-index 256)
       (error "Merkle trie depth exceeded 256 bits"))
     
     (let ((left nil)
           (right nil))
       ;; Partition by bit at current index
       (dolist (kv kvs)
         (if (trie-bit (car kv) bit-index)
             (push kv right)
             (push kv left)))
       
       ;; Always create branch (even if one side is empty)
       ;; Empty side returns 32 zero bytes via recursive call
       (let* ((next-idx (the fixnum (1+ bit-index)))
              (left-hash (merkle-root (nreverse left) next-idx))
              (right-hash (merkle-root (nreverse right) next-idx))
              (encoded (trie-branch left-hash right-hash)))
         (blake2b-256 encoded))))))

;;; ============================================================================
;;; State Root (convenience function)
;;; ============================================================================

(defun compute-state-root (keyvals)
  "Compute state root from a list of (key . value) pairs.
   This is the main entry point for computing Merkle root of state.
   
   Pads all keys to 32 bytes (GP D.1 specifies 31-byte keys in state encoding,
   but Merkle trie requires 32-byte keys as per GP D.3-D.6)."
  (let ((padded-keyvals nil))
    (dolist (kv keyvals)
      (push (cons (pad-key-to-32 (car kv)) (cdr kv)) padded-keyvals))
    (merkle-root (nreverse padded-keyvals))))

