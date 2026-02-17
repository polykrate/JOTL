;;;; utils/mmr.lisp — Merkle Mountain Range (GP Appendix E)
;;;;
;;;; MMR is an append-only authenticated data structure.
;;;; Used for β (block history accumulation output log).
;;;;
;;;; JAM uses Keccak-256 (HK) for MMR, NOT Blake2b.
;;;; This is for BEEFY/Ethereum compatibility.
;;;;
;;;; GP Equations:
;;;;   E.10: merge(l, r) ≡ K(l ⌢ r)
;;;;   E.11: MR([]) ≡ ∅ ; MR([p]) ≡ p ; MR([p1..pn]) ≡ K("node" ⌢ MR(p1..pn-1) ⌢ pn)
;;;;   E.12: append(peaks, leaf) ≡ carry(peaks, leaf, 0)
;;;;         carry(peaks, c, h):
;;;;           | c = nil        → peaks
;;;;           | peaks[h] = nil → peaks with [h] = c
;;;;           | otherwise      → carry(peaks with [h] = nil, K(peaks[h] ⌢ c), h+1)

(in-package #:jotl)

;;; +zero-hash+ and +mmr-peak-prefix+ are in src/core/constants.lisp

;;; ═══════════════════════════════════════════════════════════════
;;; GP E.10: Merge
;;; ═══════════════════════════════════════════════════════════════
;;; parent ≡ K(left ⌢ right)

(defun mmr-merge (left right)
  "GP E.10: merge(l, r) ≡ K(l ⌢ r)
   Uses Keccak-256 for BEEFY compatibility."
  (jam.ffi:keccak-256
   (concatenate '(vector (unsigned-byte 8)) left right)))

;;; ═══════════════════════════════════════════════════════════════
;;; GP E.11: Super-Peak MR (BEEFY root)
;;; ═══════════════════════════════════════════════════════════════
;;;
;;; MR([])          ≡ ∅ (zero hash)
;;; MR([p])         ≡ p
;;; MR([p1,...,pn]) ≡ K("peak" ⌢ MR([p1,...,pn-1]) ⌢ pn)

(defun mmr-super-peak (peaks)
  "GP E.11: Compute super-peak (BEEFY root) from MMR peaks.
   
   Filters nil entries. Uses Keccak-256 with 'peak' prefix.
   Returns: 32-byte hash (or +zero-hash+ if empty)."
  (let ((non-nil (remove nil (coerce peaks 'list))))
    (cond
      ;; MR([]) ≡ ∅
      ((null non-nil) +zero-hash+)
      ;; MR([p]) ≡ p
      ((= (length non-nil) 1) (first non-nil))
      ;; MR([p1,...,pn]) ≡ K("peak" ⌢ MR([p1,...,pn-1]) ⌢ pn)
      (t
       (let ((last (car (last non-nil)))
             (rest (butlast non-nil)))
         (jam.ffi:keccak-256
          (concatenate '(vector (unsigned-byte 8))
                       +mmr-peak-prefix+
                       (mmr-super-peak (coerce rest 'vector))
                       last)))))))

;;; ═══════════════════════════════════════════════════════════════
;;; GP E.12: Carry-Merge (Append)
;;; ═══════════════════════════════════════════════════════════════
;;;
;;; append(peaks, leaf) ≡ carry(peaks, leaf, 0)
;;;
;;; carry(peaks, c, h):
;;;   | c = nil        → peaks
;;;   | peaks[h] = nil → peaks with [h] = c
;;;   | otherwise      → carry(peaks with [h] = nil, K(peaks[h] ⌢ c), h+1)
;;;
;;; Like binary addition with carry propagation.

(defun mmr-append (peaks leaf)
  "GP E.12: append(peaks, leaf) ≡ carry(peaks, leaf, 0).
   peaks: vector of (hash-or-nil). leaf: 32-byte hash.
   Returns: new peaks vector (single copy, then mutate)."
  (let ((result (copy-seq peaks))
        (c leaf)
        (h 0))
    (loop
      (when (null c) (return result))
      ;; Extend if needed
      (when (>= h (length result))
        (setf result (concatenate 'vector result (vector nil))))
      (let ((existing (aref result h)))
        (cond
          ;; peaks[h] = nil → set it, done
          ((null existing)
           (setf (aref result h) c)
           (return result))
          ;; Otherwise → merge and carry up
          (t
           (setf (aref result h) nil)
           (setf c (mmr-merge existing c))
           (incf h)))))))

;;; ═══════════════════════════════════════════════════════════════
;;; BINARY MERKLIZATION — GP Appendix E.1 / E.3
;;; ═══════════════════════════════════════════════════════════════
;;;
;;; E.1  Node function N:
;;;   N(v, H):
;;;     |v| = 0  → H₀
;;;     |v| = 1  → v₀           (identity — NO hashing)
;;;     otherwise → H($node ⌢ N(v_{...⌈|v|/2⌉}, H) ⌢ N(v_{⌈|v|/2⌉...}, H))
;;;
;;; E.3  Well-Balanced Binary Merkle M_B:
;;;   M_B(v, H):
;;;     |v| = 1  → H(v₀)       (hash the single item)
;;;     otherwise → N(v, H)

(defun merkle-node (items)
  "GP E.1: N(v, HK) — Internal node function for binary Merkle.
   |v|=0 → zero-hash
   |v|=1 → v₀ (identity, no hashing)
   |v|>1 → HK($node ⌢ N(left) ⌢ N(right))
   Split at ⌈|v|/2⌉."
  (let ((n (length items)))
    (cond
      ((zerop n) +zero-hash+)
      ((= n 1) (first items))
      (t
       (let* ((mid (ceiling n 2))
              (left  (coerce (subseq items 0 mid) 'list))
              (right (coerce (subseq items mid) 'list)))
         (jam.ffi:keccak-256
          (concatenate '(vector (unsigned-byte 8))
                       +merkle-node-prefix+
                       (merkle-node left)
                       (merkle-node right))))))))

(defun binary-merkle-root-keccak (items)
  "GP E.3: M_B(v, HK) — Well-balanced binary Merkle root using Keccak-256.
   Used by accumulate root (§7.6).
   items: list of byte vectors (leaves).
   Returns: 32-byte Keccak-256 root hash.
   |v|=0 → N([], HK) = H₀ (zero-hash)
   |v|=1 → HK(v₀)
   |v|>1 → N(v, HK)"
  (cond
    ((null items) +zero-hash+)
    ((= (length items) 1)
     (jam.ffi:keccak-256 (first items)))
    (t (merkle-node items))))

;;; ═══════════════════════════════════════════════════════════════
;;; HELPERS
;;; ═══════════════════════════════════════════════════════════════

(defun mmr-leaf-count (peaks)
  "Count leaves in MMR. Peak at height h = 2^h leaves."
  (loop for peak across peaks
        for h from 0
        when peak sum (ash 1 h)))

(defun mmr-from-leaves (leaves)
  "Build MMR from a list of leaf hashes."
  (reduce #'mmr-append leaves :initial-value #()))
