;;;; state/pi.lisp — π Validator Statistics (GP §13)
;;;;
;;;; π ≡ (π_V, π_L, π_C, π_S)          (13.1)
;;;;
;;;; π_V : current epoch validator stats  — V records of 6×u32
;;;; π_L : last epoch validator stats     — V records of 6×u32
;;;; π_C : core activity stats            — C records (compact-encoded)
;;;; π_S : service activity stats         — variable-length map (compact-encoded)
;;;;
;;;; GP (4.20): π' < (EG, EP, EA, ET, τ, κ', π, H, S)
;;;;
;;;; Transition (§13.4-13.5):
;;;;   e  = ⌊τ/E⌋,  e' = ⌊τ'/E⌋
;;;;   epoch change → π'_L = π_V, a = zeros
;;;;   no change    → π'_L = π_L, a = π_V
;;;;
;;;;   ∀v ∈ N_V:
;;;;     π'_V[v].b = a[v].b + ⟨v = H_i⟩
;;;;     π'_V[v].t = a[v].t + |E_T| · ⟨v = H_i⟩
;;;;     π'_V[v].p = a[v].p + |E_P| · ⟨v = H_i⟩
;;;;     π'_V[v].d = a[v].d + Σ|blob| · ⟨v = H_i⟩
;;;;     π'_V[v].g = a[v].g + ⟨κ'_v ∈ G⟩
;;;;     π'_V[v].a = a[v].a + ⟨∃a ∈ E_A : a_v = v⟩
;;;;
;;;; Codec layout (C(13)):
;;;;   [π_V: V × 6 × u32]  [π_L: V × 6 × u32]
;;;;   [π_C: C × compact-fields]  [π_S: compact-len + entries]
;;;;
;;;; Messages:
;;;;   :vals-curr          → list of V validator activity plists
;;;;   :vals-last          → list of V validator activity plists
;;;;   :cores-raw          → raw bytes for core stats (passthrough)
;;;;   :services-raw       → raw bytes for service stats (passthrough)
;;;;   :encoded            → full encoded bytes
;;;;   :decode bytes off   → (values closure consumed)
;;;;   :transition &key ... → π' closure

(in-package #:jotl)

;;; ═══════════════════════════════════════════════════════════════
;;; VALIDATOR ACTIVITY RECORD — 6 × u32  (GP §13.2)
;;; ═══════════════════════════════════════════════════════════════
;;; (b, t, p, d, g, a)
;;;   b: blocks produced
;;;   t: tickets introduced
;;;   p: preimages introduced
;;;   d: total preimage octets
;;;   g: guarantees (reports)
;;;   a: assurances

(defun make-zero-validator-stats ()
  "V zero-initialized validator activity records."
  (loop repeat (num-validators)
        collect (list :blocks 0 :tickets 0 :preimages 0
                      :preimages-size 0 :guarantees 0 :assurances 0)))

(defun encode-validator-activity (record)
  "Encode one ValidatorActivityRecord: 6 × u32 = 24 bytes."
  (concatenate '(vector (unsigned-byte 8))
               (E4 (getf record :blocks))
               (E4 (getf record :tickets))
               (E4 (getf record :preimages))
               (E4 (getf record :preimages-size))
               (E4 (getf record :guarantees))
               (E4 (getf record :assurances))))

(defun decode-validator-activity (bytes offset)
  "Decode one ValidatorActivityRecord: 6 × u32 = 24 bytes.
   Returns: (values plist 24)"
  (values
   (list :blocks         (decode-fixed-le (subseq bytes offset (+ offset 4)))
         :tickets        (decode-fixed-le (subseq bytes (+ offset 4) (+ offset 8)))
         :preimages      (decode-fixed-le (subseq bytes (+ offset 8) (+ offset 12)))
         :preimages-size (decode-fixed-le (subseq bytes (+ offset 12) (+ offset 16)))
         :guarantees     (decode-fixed-le (subseq bytes (+ offset 16) (+ offset 20)))
         :assurances     (decode-fixed-le (subseq bytes (+ offset 20) (+ offset 24))))
   24))

(defun encode-validators-statistics (records)
  "Encode V ValidatorActivityRecords: V × 24 bytes (fixed-size, no length prefix)."
  (apply #'concatenate '(vector (unsigned-byte 8))
         (mapcar #'encode-validator-activity records)))

(defun decode-validators-statistics (bytes offset)
  "Decode V ValidatorActivityRecords from bytes at offset.
   Returns: (values list-of-plists total-consumed)."
  (let ((v (num-validators))
        (records '())
        (pos offset))
    (dotimes (i v)
      (multiple-value-bind (rec consumed) (decode-validator-activity bytes pos)
        (push rec records)
        (incf pos consumed)))
    (values (nreverse records) (- pos offset))))

;;; ═══════════════════════════════════════════════════════════════
;;; CORE / SERVICE STATS — compact-encoded, passthrough for now
;;; ═══════════════════════════════════════════════════════════════
;;; Core stats (π_C) and service stats (π_S) use compact encoding.
;;; For now we store them as raw bytes and pass them through.
;;; They're updated by accumulate (§14), not by the statistics STF.

(defun encode-zero-cores-stats ()
  "Encode C zero-initialized CoreActivityRecords.
   Each field is compact(0) = 0x00. 8 fields × C cores."
  (make-array (* (num-cores) 8) :element-type '(unsigned-byte 8) :initial-element 0))

(defun encode-zero-services-stats ()
  "Encode empty ServicesStatistics: compact(0) = 1 byte."
  (encode-compact 0))

;;; ═══════════════════════════════════════════════════════════════
;;; STATE CLOSURE — π (validator statistics)
;;; ═══════════════════════════════════════════════════════════════

(define-state-closure pi-state
  ;; ── Fields ──
  ;; vals-curr, vals-last: lists of V plists
  ;; cores-raw, services-raw: raw byte vectors (passthrough)
  ((vals-curr nil)
   (vals-last nil)
   (cores-raw nil)
   (services-raw nil))

  ;; ── Codec ────────────────────────────────────────────────────
  (:encoded :memo
    (concatenate '(vector (unsigned-byte 8))
                 (encode-validators-statistics
                  (or vals-curr (make-zero-validator-stats)))
                 (encode-validators-statistics
                  (or vals-last (make-zero-validator-stats)))
                 (or cores-raw (encode-zero-cores-stats))
                 (or services-raw (encode-zero-services-stats))))

  (:decode (bytes offset)
    (let ((pos offset))
      ;; Decode π_V
      (multiple-value-bind (vc vc-consumed) (decode-validators-statistics bytes pos)
        (incf pos vc-consumed)
        ;; Decode π_L
        (multiple-value-bind (vl vl-consumed) (decode-validators-statistics bytes pos)
          (incf pos vl-consumed)
          ;; Remaining = π_C + π_S as raw bytes
          ;; We need to figure out where π_C ends and π_S begins.
          ;; π_C = C records, each with 8 compact-encoded fields.
          ;; π_S = compact-length-prefixed sequence.
          ;; For correctness, we decode π_C field by field to find the boundary.
          (let ((cores-start pos))
            ;; Each core has 8 compact fields
            (dotimes (core-idx (num-cores))
              (dotimes (field-idx 8)
                (multiple-value-bind (_val consumed) (decode-compact bytes pos)
                  (declare (ignore _val))
                  (incf pos consumed))))
            (let* ((cores-raw-bytes (subseq bytes cores-start pos))
                   ;; π_S: compact-prefixed sequence of entries
                   (services-start pos))
              ;; Decode compact length for services
              (multiple-value-bind (svc-count svc-len-consumed) (decode-compact bytes pos)
                (incf pos svc-len-consumed)
                ;; Each service entry = ServiceId(u32=4) + 10 compact fields
                (dotimes (si svc-count)
                  (incf pos 4)  ;; ServiceId
                  (dotimes (fi 10)
                    (multiple-value-bind (_val consumed) (decode-compact bytes pos)
                      (declare (ignore _val))
                      (incf pos consumed))))
                (let ((services-raw-bytes (subseq bytes services-start pos)))
                  (values (make-pi-state :vals-curr vc
                                         :vals-last vl
                                         :cores-raw cores-raw-bytes
                                         :services-raw services-raw-bytes)
                          (- pos offset))))))))))

  ;; ── Semantic queries ─────────────────────────────────────────
  (:validator-stat (index)
    (nth index (or vals-curr (make-zero-validator-stats))))

  ;; ── Transition: GP §13.4-13.5 ───────────────────────────────
  ;; π' < (EG, EP, EA, ET, τ, κ', π, H, S)
  ;;
  ;; For now: validator stats only (§13.5).
  ;; Core stats (π_C) and service stats (π_S) are updated by accumulate.
  ;; S (accumulate result) is not yet implemented.
  (:transition (&key header tau tau-prime
                     tickets preimages assurances guarantees
                     kappa-prime)
    (let* ((v (num-validators))
           (e (epoch-duration))
           (epoch-old (floor (funcall tau :slot) e))
           (epoch-new (floor (funcall tau-prime :slot) e))
           (epoch-change-p (/= epoch-old epoch-new))
           ;; (13.4) accumulator: zeros on epoch change, else π_V
           (a (if epoch-change-p
                  (make-zero-validator-stats)
                  (or vals-curr (make-zero-validator-stats))))
           ;; (13.4) π'_L: rotate on epoch change
           (new-last (if epoch-change-p
                        (or vals-curr (make-zero-validator-stats))
                        (or vals-last (make-zero-validator-stats))))
           ;; Block author
           (author (funcall header :author-index))
           ;; Extrinsic counts for author
           (num-tickets   (length (or tickets '())))
           (num-preimages (length (or preimages '())))
           (preimage-bytes (loop for p in (or preimages '())
                                 sum (length (or (getf p :blob)
                                                 (make-array 0)))))
           ;; Assurance set: which validators provided assurances
           (assuring-validators
            (loop for assurance in (or assurances '())
                  collect (getf assurance :validator-index)))
           ;; Reporters set G (§11.26): validator indices in guarantees
           ;; κ'_v ∈ G ↔ validator v signed a guarantee
           (guarantor-set
            (let ((set (make-hash-table)))
              (dolist (g (or guarantees '()))
                (dolist (sig (getf g :signatures))
                  (setf (gethash (getf sig :validator-index) set) t)))
              set)))
      ;; (13.5) Build π'_V
      (let ((new-curr
             (loop for vi from 0 below v
                   for ai in a
                   collect
                   (list :blocks         (+ (getf ai :blocks)
                                            (if (= vi author) 1 0))
                         :tickets        (+ (getf ai :tickets)
                                            (if (= vi author) num-tickets 0))
                         :preimages      (+ (getf ai :preimages)
                                            (if (= vi author) num-preimages 0))
                         :preimages-size (+ (getf ai :preimages-size)
                                            (if (= vi author) preimage-bytes 0))
                         :guarantees     (+ (getf ai :guarantees)
                                            (if (gethash vi guarantor-set) 1 0))
                         :assurances     (+ (getf ai :assurances)
                                            (if (member vi assuring-validators) 1 0))))))
        (make-pi-state :vals-curr new-curr
                       :vals-last new-last
                       :cores-raw (or cores-raw (encode-zero-cores-stats))
                       :services-raw (or services-raw (encode-zero-services-stats)))))))
