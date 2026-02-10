;;;; state/beta.lisp — β Recent History (Gray Paper §7)
;;;;
;;;; β ≡ (βH, βB)                                           (7.1)
;;;; βH ∈ ⟦{h ∈ H, s ∈ H, b ∈ H, p ∈ ⟦H → Ho⟧}⟧:H       (7.2)
;;;; βB ∈ ⟦H?⟧  (MMR peaks)                                 (7.3)
;;;;
;;;; Two transitions (GP §4.2.1 dependency graph):
;;;;   β†  = :transition-dagger(H, β)      WAVE 1  (§7.5)
;;;;   β'  = :transition(H, EG, β†, θ')    WAVE 4  (§7.7-7.8)
;;;;
;;;; Messages:
;;;;   :history              → list of history records (plists)
;;;;   :mmr-peaks            → vector of Option<Hash32>
;;;;   :length               → (length history)
;;;;   :full-p               → T if |βH| ≥ H
;;;;   :find-record (hash)   → history record plist matching header-hash, or NIL
;;;;   :known-package-hashes → (memoized) list of all work-package hashes in history
;;;;   :find-reported-wp (h) → reported-wp plist matching hash, or NIL
;;;;   :encoded              → binary encoding (memoized)
;;;;   :decode               → reconstruct from bytes
;;;;   :transition-dagger (&key header)  → β†
;;;;   :transition (&key header guarantees theta-prime) → β'

(in-package #:jotl)

;;; ═══════════════════════════════════════════════════════════════
;;; HISTORY RECORDS — plists (leaf value objects, not closures)
;;; ═══════════════════════════════════════════════════════════════

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
;;; CODEC SUB-FUNCTIONS
;;; ═══════════════════════════════════════════════════════════════
;;; GP: C(3) ↦ E(↕[(h,b,s,↕p) | (h,b,s,p) ∈ βH], EM(βB))

;; -- ReportedWorkPackage = hash(32) + exports_root(32) --

(defun decode-reported-wp (bytes offset)
  "Decode ReportedWorkPackage. Returns (values plist 64)."
  (values (list :hash (subseq bytes offset (+ offset 32))
                :exports-root (subseq bytes (+ offset 32) (+ offset 64)))
          64))

(defun encode-reported-wp (wp)
  "Encode ReportedWorkPackage."
  (concatenate '(vector (unsigned-byte 8))
               (getf wp :hash)
               (getf wp :exports-root)))

;; -- BlockInfo = header_hash(32) + beefy_root(32) + state_root(32) + Seq<ReportedWP> --

(defun decode-block-info (bytes offset)
  "Decode BlockInfo → history-record plist. Returns (values plist consumed)."
  (let ((start offset))
    (let ((header-hash (subseq bytes offset (+ offset 32))))
      (incf offset 32)
      (let ((beefy-root (subseq bytes offset (+ offset 32))))
        (incf offset 32)
        (let ((state-root (subseq bytes offset (+ offset 32))))
          (incf offset 32)
          (multiple-value-bind (reported consumed)
              (decode-sequence bytes #'decode-reported-wp offset)
            (values (make-history-record
                     :header-hash header-hash
                     :beefy-root beefy-root
                     :state-root state-root
                     :reported reported)
                    (+ (- offset start) consumed))))))))

(defun encode-block-info (rec)
  "Encode BlockInfo from history-record plist."
  (concatenate '(vector (unsigned-byte 8))
               (getf rec :header-hash)
               (getf rec :beefy-root)
               (getf rec :state-root)
               (encode-sequence (getf rec :reported) #'encode-reported-wp)))

;; -- MmrPeak = Option<Hash32> --

(defun decode-mmr-peak (bytes offset)
  "Decode MmrPeak (option). Returns (values hash-or-nil consumed)."
  (decode-option bytes (lambda (b o) (values (subseq b o (+ o 32)) 32)) offset))

(defun encode-mmr-peak (peak)
  "Encode MmrPeak (option)."
  (encode-option peak #'identity))

;;; ═══════════════════════════════════════════════════════════════
;;; HELPERS
;;; ═══════════════════════════════════════════════════════════════

(defun bounded-append (items new-item max-size)
  "Append new-item to items, keeping only last max-size items.
   GP notation: ← (bounded shift-left append)."
  (let ((result (append items (list new-item))))
    (if (> (length result) max-size)
        (subseq result (- (length result) max-size))
        result)))

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
;;; STATE CLOSURE — β
;;; ═══════════════════════════════════════════════════════════════

(define-state-closure beta-state
  ((history '()) (mmr-peaks #()))

  (:length (length history))
  (:full-p (>= (length history) +history-size+))

  ;; ─── Query messages — "submit a query, get a deterministic result" ──
  ;; Callers don't need to know HOW history is stored/indexed.

  (:find-record (header-hash)
    (find-if (lambda (rec)
               (equalp (ensure-bytes (getf rec :header-hash))
                       (ensure-bytes header-hash)))
             history))

  (:known-package-hashes :memo
    (let ((hashes '()))
      (dolist (record history hashes)
        (dolist (rp (getf record :reported))
          (push (ensure-bytes (getf rp :hash)) hashes)))))

  (:find-reported-wp (wp-hash)
    (dolist (record history)
      (dolist (rp (getf record :reported))
        (when (equalp (ensure-bytes (getf rp :hash))
                      (ensure-bytes wp-hash))
          (return-from self rp)))))

  (:encoded :memo
    (concatenate '(vector (unsigned-byte 8))
                 (encode-sequence history #'encode-block-info)
                 (encode-sequence (coerce mmr-peaks 'list) #'encode-mmr-peak)))

  (:decode (bytes offset)
    (let ((start offset))
      (multiple-value-bind (hist h-consumed)
          (decode-sequence bytes #'decode-block-info offset)
        (incf offset h-consumed)
        (multiple-value-bind (peaks p-consumed)
            (decode-sequence bytes #'decode-mmr-peak offset)
          (incf offset p-consumed)
          (values (make-beta-state :history hist
                                   :mmr-peaks (coerce peaks 'vector))
                  (- offset start))))))

  ;; ─── WAVE 1: β† (GP §7.5) ─────────────────────────────────
  ;;
  ;; β†H ≡ βH except β†H[|βH| − 1].s = HR
  ;; Corrects last history record's state-root with HR from header.
  (:transition-dagger (&key header)
    (let ((hr (funcall header :state-root)))
      (if (null history)
          #'self
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
            (make-beta-state :history new-history :mmr-peaks mmr-peaks)))))

  ;; ─── WAVE 4: β' (GP §7.7-7.8) ────────────────────────────
  ;;
  ;; (7.7) β'B ≡ A(βB, b)  where b = accumulate root from θ'
  ;; (7.8) β'H ≡ ←H(βH ⌢ [{H(H), z, MR(β'B), [(h,r)|(h,...,r)∈EG]}])
  ;;       where z = +zero-hash+ (corrected later by next block's β†)
  ;;
  ;; :accumulate-root — optional pre-computed root (bypasses θ' computation,
  ;;                    used by test vectors that provide it directly)
  (:transition (&key header guarantees theta-prime accumulate-root)
    (let* ((accumulate-root (or accumulate-root
                                (compute-accumulate-root-from-theta theta-prime)))
           (new-peaks (mmr-append mmr-peaks accumulate-root))
           (beefy-root (mmr-super-peak new-peaks))
           (header-hash (funcall header :hash))
           (work-packages (extract-work-packages-from-guarantees guarantees))
           (new-record (make-history-record
                        :header-hash header-hash
                        :state-root  +zero-hash+
                        :beefy-root  beefy-root
                        :reported    work-packages))
           (new-history (bounded-append history new-record +history-size+)))
      (make-beta-state :history new-history :mmr-peaks new-peaks))))
