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

;;; ═══════════════════════════════════════════════════════════════
;;; CONSTANTS
;;; ═══════════════════════════════════════════════════════════════

(defparameter +mmr-peak-prefix+
  (map '(vector (unsigned-byte 8)) #'char-code "peak")
  "The 'peak' prefix used in super-peak computation (GP E.11).")

(defparameter +zero-hash+
  (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
  "H0 — the zero hash (32 bytes of 0x00).")

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

(defun mmr-carry (peaks c h)
  "GP E.12: Recursive carry-merge.
   peaks is a vector of (hash-or-nil). Returns new peaks vector."
  (cond
    ;; c = nil → done
    ((null c) peaks)
    ;; Extend if needed
    ((>= h (length peaks))
     (mmr-carry (concatenate 'vector peaks (vector nil)) c h))
    ;; peaks[h] = nil → set it
    ((null (aref peaks h))
     (let ((new-peaks (copy-seq peaks)))
       (setf (aref new-peaks h) c)
       new-peaks))
    ;; Otherwise → merge and carry up
    (t
     (let ((existing (aref peaks h))
           (new-peaks (copy-seq peaks)))
       (setf (aref new-peaks h) nil)
       (mmr-carry new-peaks (mmr-merge existing c) (1+ h))))))

(defun mmr-append (peaks leaf)
  "GP E.12: append(peaks, leaf) ≡ carry(peaks, leaf, 0).
   peaks: vector of (hash-or-nil). leaf: 32-byte hash.
   Returns: new peaks vector."
  (mmr-carry (copy-seq peaks) leaf 0))

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
