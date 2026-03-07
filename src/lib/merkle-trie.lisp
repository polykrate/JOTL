;;;; Merkle Trie implementation (GP Appendix D)
;;;; Binary tree for state merkleization
;;;;
;;;; Two implementations:
;;;;   1. merkle-root — flat recursive function for full recompute (M1 baseline)
;;;;   2. Persistent trie — incremental structure with cached hashes
;;;;      Structural sharing: inserts/deletes create O(log N) new nodes,
;;;;      unchanged subtrees are shared between versions. O(K log N) rehash
;;;;      for K changed keys instead of O(N log N) full recompute.
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
   Shared read-only — safe because trie-branch copies inputs into a
   fresh result array (never mutates left or right).")

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
    ;; Empty: return shared zero array directly.
    ;; Safe: trie-branch copies left/right into a fresh 64-byte result
    ;; via REPLACE — it never mutates the input vectors themselves.
    ;; Saves ~N allocations of 32 bytes per Merkle recompute.
    ((null kvs)
     *trie-zero-hash*)
    
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
   
   If keys are already 32 bytes (pre-padded by sigma :merkle-kvs),
   passes directly to merkle-root without allocation.
   Otherwise pads all keys to 32 bytes (GP D.1 specifies 31-byte keys
   in state encoding, but Merkle trie requires 32-byte keys as per GP D.3-D.6)."
  (if (and keyvals (>= (length (caar keyvals)) 32))
      ;; Fast path: keys already pre-padded — zero allocation
      (merkle-root keyvals)
      ;; Slow path: pad keys (fallback for non-sigma callers)
      (let ((padded-keyvals nil))
        (dolist (kv keyvals)
          (push (cons (pad-key-to-32 (car kv)) (cdr kv)) padded-keyvals))
        (merkle-root (nreverse padded-keyvals)))))

;;; ============================================================================
;;; Persistent Merkle Trie — incremental structure with cached hashes
;;; ============================================================================
;;;
;;; Each node is either:
;;;   - NIL (empty subtree)
;;;   - Leaf: mt-leaf-key + mt-leaf-value, hash cached in mt-hash
;;;   - Branch: mt-left + mt-right children, hash cached in mt-hash
;;;
;;; Structural sharing: insert/remove create O(depth) new nodes along the
;;; modified path, sharing unchanged subtrees via pointer equality.
;;; Depth is bounded by 256 (32-byte keys × 8 bits).

(defstruct (merkle-tnode (:conc-name mt-))
  "A node in the persistent Merkle trie.
   HASH: cached 32-byte Merkle hash (nil = dirty, needs recompute).
   LEFT/RIGHT: child nodes (nil = empty subtree).
   LEAF-KEY/LEAF-VALUE: key-value pair for leaf nodes (nil for branches)."
  (hash nil :type (or null (simple-array (unsigned-byte 8) (*))))
  (left nil :type (or null merkle-tnode))
  (right nil :type (or null merkle-tnode))
  (leaf-key nil :type (or null (simple-array (unsigned-byte 8) (*))))
  (leaf-value nil))

(declaim (inline mt-leaf-p mt-branch-p))

(defun mt-leaf-p (node)
  "Is NODE a leaf (has key+value, no children)?"
  (and node (mt-leaf-key node)))

(defun mt-branch-p (node)
  "Is NODE a branch (has children, no key)?"
  (and node (not (mt-leaf-key node))))

;;; ── Persistent insertion ──────────────────────────────────────────

(defun trie-insert (node key value bit-index)
  "Insert or update (KEY, VALUE) in the persistent trie at BIT-INDEX.
   Returns a new root node. Unchanged subtrees are shared (structural sharing).
   KEY must be 32 bytes."
  (declare (optimize (speed 3) (safety 1))
           (type fixnum bit-index))
  (cond
    ;; Empty subtree: create leaf
    ((null node)
     (make-merkle-tnode :leaf-key key :leaf-value value))

    ;; Leaf node
    ((mt-leaf-p node)
     (let ((existing-key (mt-leaf-key node)))
       (if (equalp key existing-key)
           ;; Same key: update value (new leaf, old discarded)
           (make-merkle-tnode :leaf-key key :leaf-value value)
           ;; Different key: split into branch
           (let ((old-bit (trie-bit existing-key bit-index))
                 (new-bit (trie-bit key bit-index)))
             (if (eq old-bit new-bit)
                 ;; Same side: recurse deeper to find divergence point
                 (let ((child (trie-insert node key value (1+ bit-index))))
                   (if old-bit
                       (make-merkle-tnode :right child)
                       (make-merkle-tnode :left child)))
                 ;; Different sides: distribute into branch
                 (let ((new-leaf (make-merkle-tnode :leaf-key key :leaf-value value)))
                   (if new-bit
                       (make-merkle-tnode :left node :right new-leaf)
                       (make-merkle-tnode :left new-leaf :right node))))))))

    ;; Branch node: route by bit, create new branch sharing unchanged child
    (t
     (if (trie-bit key bit-index)
         (make-merkle-tnode :left (mt-left node)
                            :right (trie-insert (mt-right node) key value (1+ bit-index)))
         (make-merkle-tnode :left (trie-insert (mt-left node) key value (1+ bit-index))
                            :right (mt-right node))))))

;;; ── Persistent removal ────────────────────────────────────────────

(defun trie-remove (node key bit-index)
  "Remove KEY from the persistent trie at BIT-INDEX.
   Returns a new root node (or NIL if empty). Unchanged subtrees are shared.
   After removal, branches with one nil child and one leaf child are collapsed
   to match the flat merkle-root function's behavior."
  (declare (optimize (speed 3) (safety 1))
           (type fixnum bit-index))
  (cond
    ;; Empty: nothing to remove
    ((null node) nil)

    ;; Leaf: remove if matching
    ((mt-leaf-p node)
     (if (equalp key (mt-leaf-key node))
         nil   ;; removed
         node)) ;; not found, unchanged

    ;; Branch: route by bit, then potentially collapse
    (t
     (let ((new-left (mt-left node))
           (new-right (mt-right node)))
       ;; Recurse into the appropriate child
       (if (trie-bit key bit-index)
           (setf new-right (trie-remove new-right key (1+ bit-index)))
           (setf new-left (trie-remove new-left key (1+ bit-index))))
       ;; Collapse check: if one child is nil and the other is a leaf,
       ;; the branch must collapse to the leaf to match merkle-root behavior.
       ;; merkle-root([A]) = blake2b(trie-leaf(A)), not branch(leaf(A), zero).
       (cond
         ;; Both nil → empty
         ((and (null new-left) (null new-right)) nil)
         ;; One nil, one leaf → collapse to leaf
         ((and (null new-right) (mt-leaf-p new-left)) new-left)
         ((and (null new-left) (mt-leaf-p new-right)) new-right)
         ;; Otherwise: new branch (children may have changed)
         ((and (eq new-left (mt-left node)) (eq new-right (mt-right node)))
          node) ;; no change: return same node (preserve cached hash)
         (t (make-merkle-tnode :left new-left :right new-right)))))))

;;; ── Hash computation with caching ─────────────────────────────────

(defun trie-root-hash (node)
  "Compute the Merkle hash of the trie rooted at NODE.
   Uses cached hashes for unchanged subtrees (O(1) per cached node).
   Only dirty paths (hash=nil on newly created nodes) are rehashed.
   Compatible with merkle-root: produces identical hashes for the same KVs."
  (cond
    ;; Empty → zero hash
    ((null node)
     *trie-zero-hash*)

    ;; Cached → return immediately
    ((mt-hash node)
     (mt-hash node))

    ;; Leaf → hash the encoded leaf
    ((mt-leaf-p node)
     (let ((h (blake2b-256 (trie-leaf (mt-leaf-key node) (mt-leaf-value node)))))
       (setf (mt-hash node) h)
       h))

    ;; Branch → hash(branch(left-hash, right-hash))
    (t
     (let* ((left-hash (trie-root-hash (mt-left node)))
            (right-hash (trie-root-hash (mt-right node)))
            (h (blake2b-256 (trie-branch left-hash right-hash))))
       (setf (mt-hash node) h)
       h))))

;;; ── Trie construction and incremental update ──────────────────────

(defun build-merkle-trie (kvs)
  "Build a persistent Merkle trie from a list of (key . value) pairs.
   Keys must be 32 bytes. Returns root tnode or NIL for empty input.
   O(N log N) — used only for genesis/initial state. Subsequent blocks
   use diff-update-trie for O(K log N) incremental updates."
  (let ((root nil))
    (dolist (kv kvs)
      (setf root (trie-insert root (car kv) (cdr kv) 0)))
    root))

(defun diff-update-trie (parent-trie parent-kv-index current-kvs)
  "Incrementally update PARENT-TRIE based on diff between parent and current KVs.
   PARENT-TRIE: merkle-tnode root from the parent state.
   PARENT-KV-INDEX: hash-table {key → value} of the parent's merkle-kvs.
   CURRENT-KVS: list of (key . value) for the current state.
   Returns: updated trie root.

   Algorithm:
     1. Scan current KVs: insert any new or changed entries.
     2. Scan parent index: remove any entries not in current.
   Only O(K) trie operations where K = number of changed + removed keys.
   The O(N) scans are fast hash-table lookups, not blake2b hashing."
  (let ((trie parent-trie)
        (current-keys (make-hash-table :test 'equalp :size (length current-kvs))))
    ;; Pass 1: insert new or changed entries
    (dolist (kv current-kvs)
      (let* ((key (car kv))
             (val (cdr kv))
             (old-val (gethash key parent-kv-index)))
        (setf (gethash key current-keys) t)
        ;; Insert if key is new or value changed
        (unless (and old-val (eq old-val val))
          ;; eq first (fast: same object from COW sharing), equalp fallback
          (unless (and old-val (equalp old-val val))
            (setf trie (trie-insert trie key val 0))))))
    ;; Pass 2: remove entries that are in parent but not in current
    (maphash (lambda (key val)
               (declare (ignore val))
               (unless (gethash key current-keys)
                 (setf trie (trie-remove trie key 0))))
             parent-kv-index)
    trie))

