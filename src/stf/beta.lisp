;;;; stf/beta.lisp — Recent History β (Gray Paper §7)
;;;;
;;;; β ≡ (βH, βB)                                           (7.1)
;;;; βH ∈ ⟦{h ∈ H, s ∈ H, b ∈ H, p ∈ ⟦H → Ho⟧}⟧:H       (7.2)
;;;; βB ∈ ⟦H?⟧  (MMR peaks)                                 (7.3)
;;;; θ  ∈ ⟦(NS, H)⟧  (accumulation output)                  (7.4)
;;;;
;;;; Two transitions (GP §4.2.1 dependency graph):
;;;;   β†  = transition-beta-dagger(H, β)          WAVE 1  (§7.5)
;;;;   β'  = transition-beta(H, EG, β†, θ')        WAVE 4  (§7.7-7.8)

(in-package #:jotl)

;;; ═══════════════════════════════════════════════════════════════
;;; +history-size+ (H) is defined in core/constants.lisp

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
;;; STATE CODEC — C(3) ↦ E(β)
;;; ═══════════════════════════════════════════════════════════════
;;; Binary encoding for state Merklization and test vectors.
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

;; -- RecentBlocks (β) = Seq<BlockInfo> + Seq<MmrPeak> --

(defun decode-state-beta (bytes &optional (offset 0))
  "Decode β state from binary → make-beta closure.
   Returns (values beta consumed)."
  (let ((start offset))
    (multiple-value-bind (history h-consumed)
        (decode-sequence bytes #'decode-block-info offset)
      (incf offset h-consumed)
      (multiple-value-bind (peaks p-consumed)
          (decode-sequence bytes #'decode-mmr-peak offset)
        (incf offset p-consumed)
        (values (make-beta :history history
                           :mmr-peaks (coerce peaks 'vector))
                (- offset start))))))

(defun encode-state-beta (beta)
  "Encode β state to binary from beta closure.
   C(3) ↦ E(↕[(h,b,s,↕p)], EM(βB))"
  (concatenate '(vector (unsigned-byte 8))
               (encode-sequence (funcall beta :history) #'encode-block-info)
               (encode-sequence (coerce (funcall beta :mmr-peaks) 'list)
                                #'encode-mmr-peak)))

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

;;; binary-merkle-root-keccak → utils/mmr.lisp

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
