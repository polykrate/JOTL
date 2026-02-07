;;;; stf/beta.lisp — Recent History β (Gray Paper §7)
;;;;
;;;; β ≡ (βH, βB)                                           (7.1)
;;;; βH ∈ ⟦{h ∈ H, s ∈ H, b ∈ H, p ∈ ⟦H → Ho⟧}⟧:H       (7.2)
;;;; βB ∈ ⟦H?⟧  (MMR peaks)                                 (7.3)
;;;; θ  ∈ ⟦(NS, H)⟧  (accumulation output)                  (7.4)
;;;;
;;;; Two transitions (GP §4.2.1 dependency graph):
;;;;   β†  = transition-beta-dagger(H, β)          WAVE 1  (§7.5)
;;;;   β'  = transition-beta(H, EG, β†, θ')        WAVE 5  (§7.7-7.8)

(in-package #:jotl)

;;; ═══════════════════════════════════════════════════════════════
;;; CONSTANTS
;;; ═══════════════════════════════════════════════════════════════

(defconstant +history-size+ 8
  "H — maximum recent blocks retained in β (GP §7).")

;;; ═══════════════════════════════════════════════════════════════
;;; DATA — β closure (via macro)
;;; ═══════════════════════════════════════════════════════════════

(define-value-object beta
  ((history '()) (mmr-peaks #()))
  (:length (length history))
  (:full-p (>= (length history) +history-size+)))

;;; History records are plists (leaf value objects, not closures).

(defun make-history-record (&key header-hash state-root beefy-root reported)
  "Creates one βH entry: {h, s, b, p}.
   Returns a plist (value object, not a closure).
   
   header-hash  = h : hash of this block's header H(H)
   state-root   = s : parent block's state root (HR)
   beefy-root   = b : MR(β'B) — MMR super-peak
   reported     = p : list of work-package plists (:hash h :exports-root r)"
  (list :header-hash header-hash
        :state-root state-root
        :beefy-root beefy-root
        :reported (or reported '())))

;;; ═══════════════════════════════════════════════════════════════
;;; WAVE 1: β† (GP §7.5)
;;; ═══════════════════════════════════════════════════════════════
;;;
;;; β†H ≡ βH except β†H[|βH| − 1].s = HR

(defun transition-beta-dagger (header beta)
  "GP §7.5 — Corrects βH[last].s with HR from current block header.
   Args: header (closure, :state-root), beta (closure)
   Returns: β† (new beta closure)"
  (let* ((history (funcall beta :history))
         (peaks   (funcall beta :mmr-peaks))
         (hr      (funcall header :state-root)))
    (if (null history)
        beta
        (let* ((last-idx (1- (length history)))
               (new-history
                 (loop for rec in history
                       for i from 0
                       collect (if (= i last-idx)
                                   (make-history-record
                                    :header-hash  (getf rec :header-hash)
                                    :state-root   hr
                                    :beefy-root   (getf rec :beefy-root)
                                    :reported     (getf rec :reported))
                                   rec))))
          (make-beta :history new-history :mmr-peaks peaks)))))

;;; ═══════════════════════════════════════════════════════════════
;;; ACCUMULATE ROOT (GP §7.6-7.7)
;;; ═══════════════════════════════════════════════════════════════

(defun compute-accumulate-root-from-theta (theta-prime)
  "GP §7.6: Compute accumulate root MB(s, HK) from θ'.
   θ' = list of (service-id . hash) pairs.
   Returns: 32-byte hash. Nil θ' → +zero-hash+."
  (if (or (null theta-prime) (zerop (length theta-prime)))
      +zero-hash+
      (let ((encoded-items
              (mapcar (lambda (item)
                        (let ((service-id (if (consp item) (car item)
                                              (getf item :service-id)))
                              (hash (if (consp item) (cdr item)
                                        (getf item :hash))))
                          (concatenate '(vector (unsigned-byte 8))
                                       (encode-u32 service-id)
                                       hash)))
                      theta-prime)))
        (binary-merkle-root-keccak encoded-items))))

(defun binary-merkle-root-keccak (items)
  "MB(items, HK) — Binary Merklization using Keccak-256."
  (cond
    ((null items) +zero-hash+)
    ((= (length items) 1)
     (jam.ffi:keccak-256 (first items)))
    (t
     (let* ((mid (ceiling (length items) 2))
            (left  (subseq items 0 mid))
            (right (subseq items mid)))
       (jam.ffi:keccak-256
        (concatenate '(vector (unsigned-byte 8))
                     (binary-merkle-root-keccak (coerce left 'list))
                     (binary-merkle-root-keccak (coerce right 'list))))))))

;;; ═══════════════════════════════════════════════════════════════
;;; WORK PACKAGES FROM GUARANTEES (GP §7.8)
;;; ═══════════════════════════════════════════════════════════════

(defun extract-work-packages-from-guarantees (guarantees)
  "GP §7.8: Extract (:hash h :exports-root r) from EG."
  (when guarantees
    (mapcar (lambda (g)
              (let* ((report (getf g :report))
                     (spec (getf report :package-spec)))
                (list :hash (getf spec :hash)
                      :exports-root (getf spec :exports-root))))
            guarantees)))

;;; ═══════════════════════════════════════════════════════════════
;;; BOUNDED APPEND
;;; ═══════════════════════════════════════════════════════════════

(defun bounded-append (items new-item max-size)
  "Append new-item to items, keeping only last max-size items.
   GP notation: ← (bounded shift-left append)."
  (let ((result (append items (list new-item))))
    (if (> (length result) max-size)
        (subseq result (- (length result) max-size))
        result)))

;;; ═══════════════════════════════════════════════════════════════
;;; WAVE 5: β' (GP §7.7-7.8)
;;; ═══════════════════════════════════════════════════════════════

(defun transition-beta (header guarantees beta-dagger theta-prime)
  "GP §7.7-7.8 — Recent history final (WAVE 5).
   Computes accumulate root from θ', then delegates."
  (let ((accumulate-root (compute-accumulate-root-from-theta theta-prime)))
    (transition-beta-with-root header guarantees beta-dagger accumulate-root)))

(defun transition-beta-with-root (header guarantees beta-dagger accumulate-root)
  "GP §7.7-7.8 — With pre-computed accumulate root."
  (let* ((history  (funcall beta-dagger :history))
         (peaks    (funcall beta-dagger :mmr-peaks))
         (new-peaks (mmr-append peaks accumulate-root))
         (beefy-root (mmr-super-peak new-peaks))
         (header-hash (funcall header :hash))
         (work-packages (extract-work-packages-from-guarantees guarantees))
         (new-record (make-history-record
                      :header-hash header-hash
                      :state-root  +zero-hash+
                      :beefy-root  beefy-root
                      :reported    work-packages))
         (new-history (bounded-append history new-record +history-size+)))
    (make-beta :history new-history :mmr-peaks new-peaks)))

;;; ═══════════════════════════════════════════════════════════════
;;; TEST HELPER — Composes real functions (no logic duplication)
;;; ═══════════════════════════════════════════════════════════════

(defun transition-beta-from-inputs (header-hash parent-state-root
                                    accumulate-root work-packages beta)
  "Full β transition from test vector inputs.
   Composes transition-beta-dagger + transition-beta-with-root.
   No logic duplication — delegates to the real STF functions."
  ;; Minimal header closure for the two messages β needs
  (let ((fake-header (lambda (msg)
                       (case msg
                         (:state-root parent-state-root)
                         (:hash header-hash)
                         (otherwise (error "Test header stub: ~a" msg))))))
    ;; Wave 1: β† (correct last state-root)
    (let ((beta-dagger (transition-beta-dagger fake-header beta)))
      ;; Wave 5: β' (MMR + append)
      ;; Wrap work-packages as fake guarantees for extract-work-packages-from-guarantees
      (let ((fake-guarantees
              (mapcar (lambda (wp)
                        (list :report (list :package-spec wp)))
                      work-packages)))
        (transition-beta-with-root fake-header fake-guarantees
                                   beta-dagger accumulate-root)))))
