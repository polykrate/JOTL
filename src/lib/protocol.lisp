;;;; lib/protocol.lisp — Shared protocol helpers (GP §10+)
;;;;
;;;; Functions used across multiple state components (ψ, ρ, γ, ...).
;;;; Loaded before state/ modules.

(in-package #:jotl)

;;; ═══════════════════════════════════════════════════════════════
;;; SUPERMAJORITY
;;; ═══════════════════════════════════════════════════════════════

(defun super-majority ()
  "⌊2V/3⌋ + 1 — supermajority threshold.
   Used by ψ (verdicts §10), ρ (assurances §11, guarantees §12)."
  (1+ (floor (* 2 (num-validators)) 3)))

(defun one-third-threshold ()
  "⌊V/3⌋ — wonky threshold (10.11).
   The exact split vote count that classifies a verdict as 'wonky'."
  (floor (num-validators) 3))

;;; ═══════════════════════════════════════════════════════════════
;;; HASH COMPARISON
;;; ═══════════════════════════════════════════════════════════════

(defun hash< (a b)
  "Lexicographic comparison of two 32-byte hashes."
  (loop for i from 0 below 32
        when (< (aref a i) (aref b i)) return t
        when (> (aref a i) (aref b i)) return nil
        finally (return nil)))

;;; ═══════════════════════════════════════════════════════════════
;;; SORTED / MEMBERSHIP
;;; ═══════════════════════════════════════════════════════════════

(defun sorted-unique-p (list key-fn cmp-fn)
  "Check that LIST is strictly sorted by KEY-FN using CMP-FN.
   i.e. for all consecutive pairs (a, b): (funcall cmp-fn (funcall key-fn a) (funcall key-fn b))."
  (loop for (a b) on list
        while b
        always (funcall cmp-fn (funcall key-fn a) (funcall key-fn b))))

(defun member-hash (hash hash-list)
  "Check if HASH (byte-array) is in HASH-LIST (list of byte-arrays)."
  (some (lambda (h) (equalp hash h)) hash-list))

;;; ═══════════════════════════════════════════════════════════════
;;; SIGNING CONTEXTS — GP §10.4-10.5, §11.26
;;; ═══════════════════════════════════════════════════════════════

(defun judgment-signing-context (target vote)
  "(10.4) Xv(r) — signing context for a judgment.
   vote=true  → 'jam_valid'  ++ r
   vote=false → 'jam_invalid' ++ r

   Args: target (H, 32 bytes), vote (boolean)
   Returns: byte array"
  (let ((prefix (if vote +ctx-valid+ +ctx-invalid+)))
    (concatenate '(vector (unsigned-byte 8)) prefix (ensure-bytes target))))

(defun guarantee-signing-payload (target)
  "(10.5/11.26) XG(r) — signing context for a guarantee.
   'jam_guarantee' ++ r

   Used by ψ (culprit validation §10.5) and ρ (guarantee validation §11.26).

   Args: target (H, 32 bytes — hash or byte vector)
   Returns: byte array"
  (concatenate '(vector (unsigned-byte 8))
               +ctx-guarantee+
               (ensure-bytes target)))
