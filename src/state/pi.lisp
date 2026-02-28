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
;;;;   :save            → full encoded bytes
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

(defun load-validator-activity (bytes offset)
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

(defun load-validators-statistics (bytes offset)
  "Decode V ValidatorActivityRecords from bytes at offset.
   Returns: (values list-of-plists total-consumed)."
  (let ((v (num-validators))
        (records '())
        (pos offset))
    (dotimes (i v)
      (multiple-value-bind (rec consumed) (load-validator-activity bytes pos)
        (push rec records)
        (incf pos consumed)))
    (values (nreverse records) (- pos offset))))

;;; ═══════════════════════════════════════════════════════════════
;;; CORE ACTIVITY STATS — π_C  (GP §13.2)
;;; ═══════════════════════════════════════════════════════════════
;;; CoreActivityRecord: 8 compact fields per core
;;;   da-load, popularity, imports, extrinsic-count,
;;;   extrinsic-size, exports, bundle-size, gas-used
;;;
;;; Per-block: computed fresh each block from E_G + E_A.

(defparameter +core-activity-fields+
  '(:da-load :popularity :imports :extrinsic-count
    :extrinsic-size :exports :bundle-size :gas-used))

(defun make-zero-core-activity ()
  "Zero-initialized CoreActivityRecord."
  (list :da-load 0 :popularity 0 :imports 0 :extrinsic-count 0
        :extrinsic-size 0 :exports 0 :bundle-size 0 :gas-used 0))

(defun encode-core-activity (record)
  "Encode one CoreActivityRecord: 8 compact fields."
  (apply #'concatenate '(vector (unsigned-byte 8))
         (mapcar (lambda (f) (encode-compact (or (getf record f) 0)))
                 +core-activity-fields+)))

(defun encode-cores-statistics (records)
  "Encode C CoreActivityRecords (no length prefix)."
  (apply #'concatenate '(vector (unsigned-byte 8))
         (mapcar #'encode-core-activity records)))

(defun encode-zero-cores-stats ()
  "Encode C zero-initialized CoreActivityRecords."
  (make-array (* (num-cores) 8) :element-type '(unsigned-byte 8) :initial-element 0))

(defun compute-cores-statistics (guarantees assurances r-star)
  "Compute π'_C fresh from this block's E_G, E_A, and R*.
   GP §13.2 (13.8-13.11):
     R(c) = Σ work-item stats from I (guarantees) on core c
     L(c) = Σ package-lengths from I on core c
     D(c) = Σ_{r∈R} (r_s)_l + W_G⌈(r_s)_n·65/64⌉ from R* on core c
     p(c) = Σ assurance votes for core c
   Returns: list of C CoreActivityRecord plists."
  (let ((c (num-cores))
        (cores (loop repeat (num-cores) collect (make-zero-core-activity))))
    ;; ── p: Popularity from assurances (E_A) ──
    (dolist (a (or assurances '()))
      (let ((bf (getf a :bitfield)))
        (when bf
          (dotimes (ci c)
            (let ((byte-idx (floor ci 8))
                  (bit-idx (mod ci 8)))
              (when (and (< byte-idx (length bf))
                         (logbitp bit-idx (aref bf byte-idx)))
                (incf (getf (nth ci cores) :popularity))))))))
    ;; ── R(c), L(c): Refinement stats + bundle-size from I (guarantees) ──
    (dolist (g (or guarantees '()))
      (let* ((report (getf g :report))
             (ci (getf report :core-index))
             (core-stat (when (< ci c) (nth ci cores))))
        (when core-stat
          (let ((total-gas 0) (total-imports 0) (total-exports 0)
                (total-ext-count 0) (total-ext-size 0))
            (dolist (r (getf report :results))
              (let ((rl (getf r :refine-load)))
                (incf total-gas (or (getf rl :gas-used) 0))
                (incf total-imports (or (getf rl :imports) 0))
                (incf total-exports (or (getf rl :exports) 0))
                (incf total-ext-count (or (getf rl :extrinsic-count) 0))
                (incf total-ext-size (or (getf rl :extrinsic-size) 0))))
            (incf (getf core-stat :imports) total-imports)
            (incf (getf core-stat :extrinsic-count) total-ext-count)
            (incf (getf core-stat :extrinsic-size) total-ext-size)
            (incf (getf core-stat :exports) total-exports)
            (incf (getf core-stat :bundle-size)
                  (or (getf (getf report :package-spec) :length) 0))
            (incf (getf core-stat :gas-used) total-gas)))))
    ;; ── D(c): DA load from R* (newly available reports) ──
    ;; GP (13.11): D(c) = Σ_{r∈R, r_c=c} (r_s)_l + W_G⌈(r_s)_n·65/64⌉
    (dolist (r (or r-star '()))
      (let* ((ci (getf r :core-index))
             (spec (getf r :package-spec))
             (pkg-len (or (getf spec :length) 0))
             (exp-cnt (or (getf spec :exports-count) 0))
             (wg +segment-size+)
             (d-val (+ pkg-len
                       (if (zerop exp-cnt) 0
                           (* wg (ceiling (* exp-cnt 65) 64))))))
        (when (and (< ci c) (nth ci cores))
          (incf (getf (nth ci cores) :da-load) d-val))))
    cores))

;;; ═══════════════════════════════════════════════════════════════
;;; SERVICE ACTIVITY STATS — π_S  (GP §13.2)
;;; ═══════════════════════════════════════════════════════════════
;;; ServiceActivityRecord: 10 compact fields
;;;   provided-count, provided-size, refinement-count, refinement-gas-used,
;;;   imports, extrinsic-count, extrinsic-size, exports,
;;;   accumulate-count, accumulate-gas-used
;;;
;;; Per-block: computed fresh from E_G + E_P + S.
;;; Sorted by service-id ascending.

(defparameter +service-activity-fields+
  '(:provided-count :provided-size :refinement-count :refinement-gas-used
    :imports :extrinsic-count :extrinsic-size :exports
    :accumulate-count :accumulate-gas-used))

(defun make-zero-service-activity ()
  "Zero-initialized ServiceActivityRecord."
  (list :provided-count 0 :provided-size 0
        :refinement-count 0 :refinement-gas-used 0
        :imports 0 :extrinsic-count 0 :extrinsic-size 0 :exports 0
        :accumulate-count 0 :accumulate-gas-used 0))

(defun encode-service-activity-entry (entry)
  "Encode one ServicesStatisticsMapEntry: ServiceId(u32) + 10 compact fields."
  (let ((sid (getf entry :id))
        (rec (getf entry :record)))
    (apply #'concatenate '(vector (unsigned-byte 8))
           (E4 sid)
           (mapcar (lambda (f) (encode-compact (or (getf rec f) 0)))
                   +service-activity-fields+))))

(defun encode-services-statistics (entries)
  "Encode ServicesStatistics: compact(count) + entries."
  (apply #'concatenate '(vector (unsigned-byte 8))
         (encode-compact (length entries))
         (mapcar #'encode-service-activity-entry entries)))

(defun encode-zero-services-stats ()
  "Encode empty ServicesStatistics: compact(0) = 1 byte."
  (encode-compact 0))

(defun compute-services-statistics (guarantees preimages accum-stats)
  "Compute π'_S fresh from this block's E_G, E_P, and S.
   GUARANTEES: list of guarantee plists (from E_G)
   PREIMAGES:  list of preimage plists (from E_P) — each has :service-id, :blob
   ACCUM-STATS: list of (sid n-items gas-used) triples from accumulate (S)
   Returns: sorted list of (:id sid :record plist) entries."
  (let ((ht (make-hash-table :test 'eql)))
    (flet ((ensure-entry (sid)
             (or (gethash sid ht)
                 (setf (gethash sid ht) (make-zero-service-activity)))))
      ;; ── Refinement stats from guarantees (I) ──
      ;; GP (13.16): R(s) = Σ_{d∈r_d, r∈I, d_s=s} (1, d_u, d_i, d_x, d_z, d_e)
      (dolist (g (or guarantees '()))
        (dolist (r (getf (getf g :report) :results))
          (let* ((sid (getf r :service-id))
                 (rl (getf r :refine-load))
                 (entry (ensure-entry sid)))
            (incf (getf entry :refinement-count) 1)
            (incf (getf entry :refinement-gas-used) (or (getf rl :gas-used) 0))
            (incf (getf entry :imports) (or (getf rl :imports) 0))
            (incf (getf entry :extrinsic-count) (or (getf rl :extrinsic-count) 0))
            (incf (getf entry :extrinsic-size) (or (getf rl :extrinsic-size) 0))
            (incf (getf entry :exports) (or (getf rl :exports) 0)))))
      ;; ── Preimage stats from E_P ──
      ;; GP (13.12): p = Σ_{(s,d)∈E_P} (1, |d|)
      (dolist (p (or preimages '()))
        (let* ((sid (getf p :requester))
               (blob (getf p :blob))
               (entry (ensure-entry sid)))
          (incf (getf entry :provided-count) 1)
          (incf (getf entry :provided-size) (if blob (length blob) 0))))
      ;; ── Accumulation stats from S ──
      ;; GP (13.12): a = U(S[s], (0,0)) — (count, gas) where count = work-items
      (dolist (triple (or accum-stats '()))
        (let* ((sid (first triple))
               (n-items (second triple))
               (gas (third triple))
               (entry (ensure-entry sid)))
          (incf (getf entry :accumulate-count) (or n-items 0))
          (incf (getf entry :accumulate-gas-used) (or gas 0)))))
    ;; Build sorted result
    (let ((result '()))
      (maphash (lambda (sid rec) (push (list :id sid :record rec) result)) ht)
      (sort result #'< :key (lambda (x) (getf x :id))))))

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
  (:save :memo
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
      (multiple-value-bind (vc vc-consumed) (load-validators-statistics bytes pos)
        (incf pos vc-consumed)
        ;; Decode π_L
        (multiple-value-bind (vl vl-consumed) (load-validators-statistics bytes pos)
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

  ;; ── Transition: GP §13 ──────────────────────────────────────
  ;; π' < (EG, EP, EA, ET, τ, κ', π, H, S, κ, λ)
  ;;
  ;; §13.4-13.5: π'_V, π'_L — validator stats (epoch rotation)
  ;; §13.2:      π'_C       — per-block core activity (fresh from E_G + E_A)
  ;; §13.2:      π'_S       — per-block service activity (fresh from E_G + E_P + S)
  (:transition (&key header tau tau-prime
                     tickets preimages assurances guarantees
                     kappa-prime kappa lambda-prev
                     accum-stats r-star)
    (let* ((v (num-validators))
           (e (epoch-duration))
           (r (rotation-period))
           (tau-prime-val (funcall tau-prime :slot))
           (epoch-old (floor (funcall tau :slot) e))
           (epoch-new (floor tau-prime-val e))
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
           ;; ── (11.26) Reporters set G — set of Ed25519 KEYS ──
           ;; k ∈ G ⟺ ∃(r,t,a)∈E_G, ∃(v,s)∈a : k = (k_v)_e
           ;; where (c,k) = M if ⌊τ'/R⌋=⌊t/R⌋, M* otherwise
           ;; M uses κ; M* uses κ if same epoch, λ if different epoch.
           (reporters-g
            (let ((set (make-hash-table :test 'equalp)))
              (dolist (g (or guarantees '()))
                (let* ((guarantee-slot (getf g :slot))
                       ;; Select validator set: κ' or λ per 11.26
                       ;; Must match ρ transition which uses κ' (post-safrole)
                       ;; for guarantee validation (upsilon.lisp passes
                       ;; kappa-prime as :kappa to ρ).
                       (same-rotation-p (= (floor tau-prime-val r)
                                           (floor guarantee-slot r)))
                       (validators
                        (if same-rotation-p
                            ;; M: use κ' (post-safrole)
                            kappa-prime
                            ;; M*: same epoch → κ', different epoch → λ
                            (if (= (floor tau-prime-val e)
                                   (floor guarantee-slot e))
                                kappa-prime
                                lambda-prev))))
                  (dolist (sig (getf g :signatures))
                    (let* ((vi (getf sig :validator-index))
                           (ed-key (when validators
                                     (funcall validators :ed25519-key vi))))
                      (when ed-key
                        (setf (gethash ed-key set) t))))))
              set)))
        ;; ── (13.5) Build π'_V ──
        ;; π'_V[v].g = a[v].g + (κ'_v ∈ G)
        ;; Check if κ'[v]'s Ed25519 key is in the reporters set G.
        (let* ((new-curr
              (loop for vi from 0 below v
                    for ai in a
                    collect
                    (let ((kp-ed-key (when kappa-prime
                                       (funcall kappa-prime :ed25519-key vi))))
                      (list :blocks         (+ (getf ai :blocks)
                                               (if (= vi author) 1 0))
                            :tickets        (+ (getf ai :tickets)
                                               (if (= vi author) num-tickets 0))
                            :preimages      (+ (getf ai :preimages)
                                               (if (= vi author) num-preimages 0))
                            :preimages-size (+ (getf ai :preimages-size)
                                               (if (= vi author) preimage-bytes 0))
                            :guarantees     (+ (getf ai :guarantees)
                                               (if (and kp-ed-key
                                                        (gethash kp-ed-key reporters-g))
                                                   1 0))
                            :assurances     (+ (getf ai :assurances)
                                               (if (member vi assuring-validators) 1 0))))))
             ;; ── (13.2) π'_C: per-block core activity ──
             (new-cores (compute-cores-statistics guarantees assurances r-star))
             ;; ── (13.2) π'_S: per-block service activity ──
             (new-services (compute-services-statistics
                            guarantees preimages accum-stats)))
        (make-pi-state :vals-curr new-curr
                       :vals-last new-last
                       :cores-raw (encode-cores-statistics new-cores)
                       :services-raw (encode-services-statistics new-services))))))
