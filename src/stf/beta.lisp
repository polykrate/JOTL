;;;; stf/beta.lisp — Recent History β (Gray Paper §7)
;;;;
;;;; β ≡ (βH, βB)                                           (7.1)
;;;; βH ∈ ⟦{h ∈ H, s ∈ H, b ∈ H, p ∈ ⟦H → Ho⟧}⟧:H       (7.2)
;;;; βB ∈ ⟦H?⟧  (MMR peaks)                                 (7.3)
;;;; θ  ∈ ⟦(NS, H)⟧  (accumulation output)                  (7.4)
;;;;
;;;; For each recent block: header hash, state root, beefy root,
;;;; and work-package hashes of each reported item.
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
;;; DATA CONSTRUCTORS
;;; ═══════════════════════════════════════════════════════════════

(defun make-beta (&key (history '()) (mmr-peaks #()))
  "Creates β ≡ (βH, βB).
   
   βH = history:   list of history-record plists (max H items)
   βB = mmr-peaks: vector of (hash-or-nil), MMR peaks
   
   Each history-record is a plist:
     (:header-hash h :state-root s :beefy-root b :reported p)
   where p is a list of (:hash h :exports-root r)"
  (let ((peaks (etypecase mmr-peaks
                 (vector mmr-peaks)
                 (list (coerce mmr-peaks 'vector)))))
    (lambda (msg)
      (case msg
        (:history history)        ; βH
        (:mmr-peaks peaks)        ; βB
        (:length (length history))
        (:full-p (>= (length history) +history-size+))
        (:as-plist (list :history history :mmr-peaks peaks))
        (:type :beta)
        (otherwise (error "Unknown beta message: ~a" msg))))))

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
;;;
;;; Fix the state-root of the LAST entry in βH with
;;; the parent state root HR from the current block header.
;;; (The previous block wrote H0 as placeholder.)

(defun transition-beta-dagger (header beta)
  "GP §7.5 — Recent history intermediate (WAVE 1).
   
   Corrects βH[last].s with HR from current block header.
   
   Args:
     header - block header closure (provides :state-root = HR)
     beta   - prior β state closure
   
   Returns: β† (new beta closure with corrected last entry)"
  (let* ((history (funcall beta :history))
         (peaks   (funcall beta :mmr-peaks))
         (hr      (funcall header :state-root)))
    (if (null history)
        ;; Empty history → nothing to fix
        beta
        ;; Fix last entry's state-root
        (let* ((last-idx (1- (length history)))
               (new-history
                 (loop for rec in history
                       for i from 0
                       collect (if (= i last-idx)
                                   ;; Replace state-root with HR
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
;;;
;;; let s = E4(s) ⌢ E(h) ∀ (s, h) ← θ'        (7.6)
;;; β'B ≡ A(βB, MB(s, HK), HK)                  (7.7)
;;;
;;; MB(s, HK) = basic binary Merklization of the encoded
;;; accumulation outputs, using Keccak.

(defun compute-accumulate-root-from-theta (theta-prime)
  "GP §7.6: Compute accumulate root MB(s, HK) from θ'.
   
   θ' = list of (service-id . hash) pairs.
   Each pair encoded as E4(service-id) ⌢ E(hash).
   Result is binary Merkle root using Keccak.
   
   Returns: 32-byte hash (accumulate root).
   When θ' is nil, returns H0 (zero hash)."
  (if (or (null theta-prime) (zerop (length theta-prime)))
      +zero-hash+
      ;; Encode each (service-id, hash) pair
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
        ;; Binary Merklization using Keccak
        (binary-merkle-root-keccak encoded-items))))

(defun binary-merkle-root-keccak (items)
  "MB(items, HK) — Basic binary Merklization using Keccak-256.
   GP Appendix E.
   
   MB([])  = H0
   MB([x]) = HK(x)
   MB(xs)  = HK(MB(left-half) ⌢ MB(right-half))"
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
;;;
;;; p = { ((gr)s)p ↦ ((gr)s)e | g ∈ EG }
;;;
;;; For each guarantee in EG:
;;;   g.report.package-spec.hash     → :hash
;;;   g.report.package-spec.exports-root → :exports-root

(defun extract-work-packages-from-guarantees (guarantees)
  "GP §7.8: Extract work-package plists from EG.
   
   Each guarantee has a :report with :package-spec containing
   :hash and :exports-root.
   
   Returns: list of (:hash h :exports-root r)"
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
;;;
;;; ← operator: append and keep only last H items.

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
;;;
;;; β'B ≡ A(βB, MB(s, HK), HK)                              (7.7)
;;;
;;; β'H ≡ ← β†H ∪ {h: H(H), s: H0, b: MR(β'B), p: p}      (7.8)
;;;       where p = { ((gr)s)p ↦ ((gr)s)e | g ∈ EG }

(defun transition-beta (header guarantees beta-dagger theta-prime)
  "GP §7.7-7.8 — Recent history final (WAVE 5).
   
   1. Compute accumulate root from θ'
   2. Update MMR: β'B = A(β†B, accumulate-root)
   3. Compute beefy root: MR(β'B)
   4. Extract work-packages from EG
   5. Append new record to β†H (bounded to H)
   
   Args:
     header       - block header closure (:hash → H(H))
     guarantees   - EG extrinsic (list of guarantee plists)
     beta-dagger  - intermediate β† from wave 1
     theta-prime  - accumulation output from wave 4
   
   Returns: β' (new beta closure)"
  (let ((accumulate-root (compute-accumulate-root-from-theta theta-prime)))
    (transition-beta-with-root header guarantees beta-dagger accumulate-root)))

(defun transition-beta-with-root (header guarantees beta-dagger accumulate-root)
  "GP §7.7-7.8 — Like transition-beta but with pre-computed accumulate root.
   Used when accumulate-root is provided directly (e.g. from test vectors)."
  (let* ((history  (funcall beta-dagger :history))
         (peaks    (funcall beta-dagger :mmr-peaks))
         ;; §7.7: β'B = A(βB, accumulate-root)
         (new-peaks (mmr-append peaks accumulate-root))
         ;; MR(β'B) — beefy root (super-peak of updated MMR)
         (beefy-root (mmr-super-peak new-peaks))
         ;; H(H) — header hash
         (header-hash (funcall header :hash))
         ;; Work packages from EG
         (work-packages (extract-work-packages-from-guarantees guarantees))
         ;; §7.8: New history record
         (new-record (make-history-record
                      :header-hash header-hash
                      :state-root  +zero-hash+   ; s = H0 (corrected in next β†)
                      :beefy-root  beefy-root
                      :reported    work-packages))
         ;; ← bounded append (keep last H items)
         (new-history (bounded-append history new-record +history-size+)))
    (make-beta :history new-history :mmr-peaks new-peaks)))

;;; ═══════════════════════════════════════════════════════════════
;;; TEST HELPER — Direct transition from test vector inputs
;;; ═══════════════════════════════════════════════════════════════

(defun transition-beta-from-inputs (header-hash parent-state-root
                                    accumulate-root work-packages beta)
  "Full β transition from pre-computed test vector inputs.
   
   Performs both β† (wave 1) and β' (wave 5) in one call.
   
   Args:
     header-hash       - H(H): hash of current block header
     parent-state-root - HR: state root from header
     accumulate-root   - MB(s, HK): pre-computed accumulate root
     work-packages     - list of (:hash h :exports-root r)
     beta              - prior β state (closure)
   
   Returns: β' (new beta closure)"
  ;; Step 1: β† — fix last entry's state_root (eq 7.5)
  (let* ((history  (funcall beta :history))
         (peaks    (funcall beta :mmr-peaks))
         ;; Correct last entry's state-root
         (corrected-history
           (if (null history)
               history
               (let ((last-idx (1- (length history))))
                 (loop for rec in history
                       for i from 0
                       collect (if (= i last-idx)
                                   (make-history-record
                                    :header-hash  (getf rec :header-hash)
                                    :state-root   parent-state-root
                                    :beefy-root   (getf rec :beefy-root)
                                    :reported     (getf rec :reported))
                                   rec)))))
         ;; Step 2: β'B = A(βB, accumulate-root) (eq 7.7)
         (new-peaks (mmr-append peaks accumulate-root))
         ;; MR(β'B) — beefy root
         (beefy-root (mmr-super-peak new-peaks))
         ;; Step 3: β'H — append new record (eq 7.8)
         (new-record (make-history-record
                      :header-hash header-hash
                      :state-root  +zero-hash+
                      :beefy-root  beefy-root
                      :reported    work-packages))
         (new-history (bounded-append corrected-history new-record +history-size+)))
    (make-beta :history new-history :mmr-peaks new-peaks)))

;;; ═══════════════════════════════════════════════════════════════
;;; ACCESSORS
;;; ═══════════════════════════════════════════════════════════════

(defun beta-history (beta)
  "βH — Recent block records."
  (funcall beta :history))

(defun beta-mmr-peaks (beta)
  "βB — MMR peaks."
  (funcall beta :mmr-peaks))
