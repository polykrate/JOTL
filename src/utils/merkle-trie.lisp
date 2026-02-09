;;;; Merkle Trie implementation (GP Appendix D)
;;;; Binary tree for state merkleization
(in-package #:jotl)

;;; ============================================================================
;;; Helper Functions
;;; ============================================================================

(defun trie-bit (key i)
  "Get bit i of key (Strawberry MSB-first).
   Strawberry: bit(k, i) = (k[i/8] & (1 << (7 - i%8))) != 0
   MSB-first (big-endian bit order) - confirmed working with test vectors.
   Returns T if bit is 1, NIL if 0."
  (let ((byte-idx (ash i -3))          ; i >> 3 = i / 8
        (bit-idx (logand i 7)))        ; i & 7 = i % 8
    (not (zerop (logand (aref key byte-idx) 
                        (ash 1 (- 7 bit-idx)))))))

;;; ============================================================================
;;; Branch Node (GP 286)
;;; ============================================================================

(defun trie-branch (left right)
  "Create branch node from left and right children.
   Strawberry: node[0] = left[0] & 0b01111111
   Clears MSB (bit 7) of first byte to mark as branch (not leaf).
   Returns 64 bytes."
  (assert (= (length left) 32))
  (assert (= (length right) 32))
  (let ((result (make-array 64 :element-type '(unsigned-byte 8))))
    ;; First byte: left[0] with MSB cleared (0x7f mask = 0b01111111)
    (setf (aref result 0) (logand (aref left 0) #x7f))
    ;; Bytes 1-31: rest of left
    (loop for i from 1 below 32
          do (setf (aref result i) (aref left i)))
    ;; Bytes 32-63: all of right
    (loop for i from 0 below 32
          do (setf (aref result (+ i 32)) (aref right i)))
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
  (assert (= (length key) 32) () "Key must be 32 bytes, got ~A" (length key))
  (assert (vectorp value) () "Value must be a vector, got ~A (type: ~A)" value (type-of value))
  (let ((result (make-array 64 :element-type '(unsigned-byte 8) :initial-element 0))
        (vlen (length value)))
    (if (<= vlen 32)
        ;; Short value: embed directly
        (progn
          ;; head = 0b10000000 | length (embedded leaf)
          (setf (aref result 0) (logior #x80 vlen))
          ;; key[:-1] = first 31 bytes of key (bytes 0-30)
          (loop for i from 0 below 31
                do (setf (aref result (1+ i)) (aref key i)))
          ;; value bytes + zero padding to 32
          (loop for i from 0 below vlen
                do (setf (aref result (+ 32 i)) (aref value i))))
        ;; Long value: hash it
        (progn
          (setf (aref result 0) #xC0)  ; head = 0b11000000 (regular leaf)
          ;; key[:-1] = first 31 bytes of key
          (loop for i from 0 below 31
                do (setf (aref result (1+ i)) (aref key i)))
          ;; hash(value)
          (let ((vhash (blake2b-256 value)))
            (loop for i from 0 below 32
                  do (setf (aref result (+ 32 i)) (aref vhash i))))))
    result))

;;; ============================================================================
;;; Merkle Root (GP 289)
;;; ============================================================================

(defun pad-key-to-32 (key)
  "Pad key to 32 bytes if needed (GP D.1 specifies 31-byte keys).
   Adds null byte padding at the end."
  (if (< (length key) 32)
      (let ((padded (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
        (loop for i from 0 below (length key)
              do (setf (aref padded i) (aref key i)))
        padded)
      key))

(defun merkle-root (kvs &optional (bit-index 0))
  "Compute Merkle root of key-value pairs.
   GP (289): Recursive binary tree construction.
   KVS is a list of (key . value) cons cells where key and value are byte vectors.
   Keys MUST be 32 bytes (use compute-state-root for automatic padding).
   Returns 32-byte hash.
   
   Conforms to reference implementation: always creates branch nodes,
   even if one side is empty (returns 32 zero bytes)."
  (declare (optimize (speed 3) (safety 1)))
  
  (cond
    ;; Empty: return 32 zero bytes
    ((null kvs)
     (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
    
    ;; Single leaf
    ((= (length kvs) 1)
     (let* ((kv (first kvs))
            (key (car kv))
            (value (cdr kv))
            (encoded (trie-leaf key value)))
       (blake2b-256 encoded)))
    
    ;; Multiple: split by bit
    (t
     ;; Avoid deep recursion by limiting depth
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
       (let* ((left-hash (merkle-root (nreverse left) (1+ bit-index)))
              (right-hash (merkle-root (nreverse right) (1+ bit-index)))
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
  ;; Pad all keys to 32 bytes before computing root
  ;; Use loop instead of mapcar to avoid creating huge intermediate lists
  (let ((padded-keyvals nil))
    (dolist (kv keyvals)
      (push (cons (pad-key-to-32 (car kv)) (cdr kv)) padded-keyvals))
    (merkle-root (nreverse padded-keyvals))))

;;; ============================================================================
;;; State Merklization — HR = Merkle root of σ' (GP Appendix D)
;;; ============================================================================
;;;
;;; All 16 fixed segments are closures that respond to :merkle-kv
;;; returning (cons C(n) encoded-bytes).  merklize-state simply
;;; loops over them.

(defparameter +sigma-segment-keys+
  '(:alpha :phi :beta :gamma :psi :eta :iota
    :kappa :lambda :rho :tau :chi :pi :omega :xi :theta)
  "Ordered list of state segment keywords in σ, matching C(1)..C(16).")

(defun merklize-state (sigma-prime)
  "GP §D — Compute state root HR = Merkle root of σ'.
   Loops over all 16 fixed segments, collecting :merkle-kv pairs,
   then computes the binary Merkle trie root.

   Args: sigma-prime — state closure (make-state)
   Returns: 32-byte state root hash"
  (let ((kvs '()))
    ;; ── Fixed segments C(1)..C(16) ──
    (dolist (key +sigma-segment-keys+)
      (let ((segment (funcall sigma-prime key)))
        (when segment
          (push (funcall segment :merkle-kv) kvs))))
    ;; ── Service accounts C(255, s) ──
    ;; delta is not a fixed segment — each service has its own C(255, s) key.
    ;; TODO: iterate over delta accounts when delta is implemented.
    (let ((delta (funcall sigma-prime :delta)))
      (when delta
        (dolist (service delta)
          (let ((sid (getf service :id)))
            (when sid
              ;; TODO: encode-state-delta-service
              nil)))))
    ;; ── Compute Merkle root ──
    (compute-state-root (nreverse kvs))))

(defun validate-state-root (header sigma-prime)
  "GP §5 — Validate HR = Merkle root of σ'.
   Signals error on mismatch.

   Args: header (closure), sigma-prime (state closure)
   Returns: T on success."
  (let ((expected-hr (merklize-state sigma-prime))
        (actual-hr   (funcall header :state-root)))
    (unless (equalp actual-hr expected-hr)
      (error "HR mismatch: state root does not match Merkle root of σ'"))
    t))
