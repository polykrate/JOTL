;;;; ════════════════════════════════════════════════════════════════════════════
;;;; MMR - Merkle Mountain Range
;;;; GP Appendix E
;;;; ════════════════════════════════════════════════════════════════════════════

(eval-when (:compile-toplevel :load-toplevel :execute)
  (unless (find-package '#:jotl)
    (defpackage #:jotl (:use #:cl))))

(in-package #:jotl)

;;;; ════════════════════════════════════════════════════════════════════════════
;;;; WHAT IS MMR?
;;;; ════════════════════════════════════════════════════════════════════════════
;;;;
;;;; Merkle Mountain Range is an append-only authenticated data structure.
;;;; Used in JAM for:
;;;;   - Block history accumulation (β)
;;;;   - BEEFY consensus roots
;;;;   - Efficient inclusion proofs without full tree rebuild
;;;;
;;;; Structure: A vector of "peaks" where each peak is either:
;;;;   - ∅ (nil) : no peak at this height
;;;;   - ℍ (H256): hash representing a complete subtree of size 2^height
;;;;
;;;; Example with 5 leaves (binary 101):
;;;;   Peaks: [P₀, ∅, P₂]
;;;;          P₀ = leaf₄ (single leaf at height 0)
;;;;          P₂ = K(K(leaf₀ ⌢ leaf₁) ⌢ K(leaf₂ ⌢ leaf₃))
;;;;
;;;; ════════════════════════════════════════════════════════════════════════════
;;;; GP APPENDIX E: MMR EQUATIONS
;;;; ════════════════════════════════════════════════════════════════════════════
;;;;
;;;; E.10 - Merge (internal node):
;;;;   parent ≡ K(left ⌢ right)
;;;;
;;;;   IMPORTANT: Uses Keccak-256 (K), NOT Blake2b (H)!
;;;;   This is legacy Ethereum Keccak for BEEFY compatibility.
;;;;
;;;; E.11 - Super-Peak (BEEFY root):
;;;;   M_R([])           ≡ ∅
;;;;   M_R([p])          ≡ p
;;;;   M_R([p₁,...,pₙ])  ≡ K("node" ⌢ M_R([p₁,...,pₙ₋₁]) ⌢ pₙ)
;;;;
;;;; E.12 - Carry-Merge (append algorithm):
;;;;   Similar to binary addition with carry propagation.
;;;;
;;;; ════════════════════════════════════════════════════════════════════════════
;;;; MAPPING GP → LISP
;;;; ════════════════════════════════════════════════════════════════════════════
;;;;
;;;;   GP                  Lisp
;;;;   ──────────────────  ────────────────────────────────
;;;;   K(x)                (K x)           ; Keccak-256
;;;;   x ⌢ y               (⌢ x y)         ; Concatenation
;;;;   K(l ⌢ r)            (K (⌢ l r))     ; Merge
;;;;   M_R(peaks)          (M_R peaks)     ; Super-peak
;;;;   peaks[h]            (peak peaks h)  ; Peak at height
;;;;   |peaks|             (count-leaves peaks)
;;;;   ∅                   nil             ; Empty slot
;;;;
;;;; ════════════════════════════════════════════════════════════════════════════

;;; ============================================================================
;;; GP E.10: Merge
;;; ============================================================================
;;; parent ≡ K(left ⌢ right)

(defun mmr-merge (left right)
  "GP E.10: parent ≡ K(left ⌢ right)"
  (K (⌢ left right)))

;;; ============================================================================
;;; GP E.11: Super-Peak (M_R)
;;; ============================================================================
;;;
;;; M_R([])           ≡ ∅
;;; M_R([p])          ≡ p  
;;; M_R([p₁,...,pₙ])  ≡ K("peak" ⌢ M_R([p₁,...,pₙ₋₁]) ⌢ pₙ)

(defun M_R (peaks)
  "GP E.11: Compute super-peak (BEEFY root) from MMR peaks.
   
   M_R([])           ≡ ∅
   M_R([p])          ≡ p
   M_R([p₁,...,pₙ])  ≡ K(\"peak\" ⌢ M_R([p₁,...,pₙ₋₁]) ⌢ pₙ)"
  (let ((ps (coerce (remove nil peaks) 'list)))
    (cond
      ;; M_R([]) ≡ ∅
      ((null ps)
       ∅)
      
      ;; M_R([p]) ≡ p
      ((= (length ps) 1)
       (first ps))
      
      ;; M_R([p₁,...,pₙ]) ≡ K(peak ⌢ M_R([p₁,...,pₙ₋₁]) ⌢ pₙ)
      ;; `peak` is a symbol-macro from macros.lisp
      (t
       (K (⌢ peak
             (M_R (p₁...ₙ₋₁ ps))
             (pₙ ps)))))))

;; Alias for external use
(setf (symbol-function 'mmr-super-peak) #'M_R)

;;; ============================================================================
;;; GP E.12: Carry-Merge (Append)
;;; ============================================================================
;;;
;;; Recursive definition (functional style):
;;;
;;;   append(peaks, leaf) ≡ carry(peaks, leaf, 0)
;;;
;;;   carry(peaks, c, h) ≡
;;;     | c = ∅           → peaks
;;;     | peaks[h] = ∅    → peaks'[h] ← c
;;;     | otherwise       → carry(peaks'[h] ← ∅, K(peaks[h] ⌢ c), h+1)
;;;
;;; Analogy: Binary addition with carry propagation
;;;   [P₀, P₁, ∅] + L  →  carry merges up  →  [∅, ∅, P₂]
;;;   (011 + 1 = 100)

(defun mmr-carry (peaks c h)
  "GP E.12: Recursive carry-merge.
   
   carry(peaks, c, h) ≡
     | c = ∅           → peaks
     | peaks[h] = ∅    → peaks'[h] ← c
     | otherwise       → carry(peaks'[h] ← ∅, K(peaks[h] ⌢ c), h+1)"
  (cond
    ;; c = ∅ → peaks
    ((null c) 
     peaks)
    
    ;; Extend peaks if needed
    ((>= h (length peaks))
     (mmr-carry (⌢ peaks (vector nil)) c h))
    
    ;; peaks[h] = ∅ → peaks'[h] ← c
    ((null (elt peaks h))
     (←ₕ peaks h c))
    
    ;; otherwise → carry(peaks'[h] ← ∅, K(peaks[h] ⌢ c), h+1)
    (t 
     (let ((pₕ (elt peaks h)))           ;; Save peaks[h] before clearing
       (mmr-carry (←ₕ peaks h nil)        ;; peaks'[h] ← ∅
                  (K (⌢ pₕ c))            ;; K(peaks[h] ⌢ c)
                  (1+ h))))))

(defun mmr-append (peaks leaf)
  "GP E.12: append(peaks, leaf) ≡ carry(peaks, leaf, 0)"
  (mmr-carry (copy-seq peaks) leaf 0))

;;; ============================================================================
;;; Helper: Leaf Count
;;; ============================================================================
;;; |MMR| = Σ 2^h for each non-nil peak at height h

(defun mmr-leaf-count (peaks)
  "Count leaves in MMR. Each peak at height h represents 2^h leaves."
  (loop for peak across peaks
        for h from 0
        when peak sum (ash 1 h)))

;;; ============================================================================
;;; Helper: Build from Leaves
;;; ============================================================================

(defun mmr-from-leaves (leaves)
  "Build MMR from list of leaf hashes."
  (reduce #'mmr-append leaves :initial-value #()))

;;; ============================================================================
;;; Debug
;;; ============================================================================

(defun mmr-describe (peaks)
  "Visualize MMR structure."
  (format t "~&MMR [~D leaves]:~%" (mmr-leaf-count peaks))
  (loop for peak across peaks
        for h from 0
        do (format t "  h=~D: ~A~%" h
                   (if peak 
                       (subseq (blob-to-hex peak) 0 16)
                       "∅")))
  (format t "  M_R = ~A~%" (blob-to-hex (M_R peaks))))

