;;;; tests/test-block-roundtrip.lisp — Exhaustive codec & block test suite
;;;;
;;;; Part 1 — Block roundtrip: codec/{tiny,full}/block.{bin,json}
;;;;   decode-block(bin) → closure → encode → compare vs bin + JSON cross-val
;;;;
;;;; Part 2 — Trace HX: trace-vectors/extrinsic_hash/*.json
;;;;   JSON → encode → compute HX → verify (authoritative HX values)
;;;;
;;;; Part 3 — Individual codec roundtrips: every .bin in codec/{tiny,full}/
;;;;   header_0, header_1, tickets, preimages, assurances, disputes,
;;;;   guarantees, extrinsic, work_report, work_result_0/1, refine_context

(in-package #:jotl)

;; Load shared test helpers
(load (merge-pathnames "test-utils.lisp" *load-pathname*))
;; Load HX trace test (reuse encode-from-json functions)
(load (merge-pathnames "test-hx-trace.lisp" *load-pathname*))

;;; ═══════════════════════════════════════════════════════════════
;;; COMPARISON HELPERS
;;; ═══════════════════════════════════════════════════════════════

(defvar *test-errors* 0 "Error counter for current test run.")
(defvar *test-warnings* 0 "Warning counter for current test run.")

(defun check (label test &optional detail)
  "Check a condition. Increments *test-errors* on failure."
  (if test
      (format t "    ✓ ~A~%" label)
      (progn
        (incf *test-errors*)
        (format t "    ✗ ~A~@[ — ~A~]~%" label detail))))

(defun warn-check (label test &optional detail)
  "Check a condition as WARNING only. Does NOT increment *test-errors*."
  (if test
      (format t "    ✓ ~A~%" label)
      (progn
        (incf *test-warnings*)
        (format t "    ⚠ ~A~@[ — ~A~]~%" label detail))))

(defun check-bytes (label actual expected-hex)
  "Compare byte vector against 0x hex string."
  (let ((expected (hex-to-bytes expected-hex)))
    (check label (bytes= actual expected)
           (when (not (bytes= actual expected))
             (format nil "got ~A want ~A"
                     (jam.ffi:bytes-to-hex-string actual)
                     (jam.ffi:bytes-to-hex-string expected))))))

(defun check-count (label actual expected)
  "Compare counts."
  (check label (= actual expected)
         (format nil "got ~D want ~D" actual expected)))

;;; ═══════════════════════════════════════════════════════════════
;;; JSON ACCESSORS  (cl-json uses -- for _ in keys)
;;; ═══════════════════════════════════════════════════════════════

(defun j (alist key)
  "Get value from cl-json alist by keyword."
  (cdr (assoc key alist)))

(defun j-null-p (val)
  "Check if cl-json value is null (nil or :null)."
  (or (null val) (eq val :null)))

;;; ═══════════════════════════════════════════════════════════════
;;; STEP 1 + 2 — BINARY ROUNDTRIP
;;; ═══════════════════════════════════════════════════════════════

(defun test-bin-roundtrip (bin-bytes label)
  "Decode bin → closure → re-encode → compare.
   Returns: block closure (or nil on decode failure)."
  (format t "~%  ── Step 1: Decode block.bin (~D bytes) ──~%" (length bin-bytes))
  (handler-case
      (multiple-value-bind (block consumed)
          (decode-block bin-bytes 0)
        (check (format nil "~A: consumed all bytes" label)
               (= consumed (length bin-bytes))
               (format nil "consumed ~D / ~D" consumed (length bin-bytes)))
        (check (format nil "~A: block closure created" label)
               (not (null block)))

        (format t "~%  ── Step 2: Re-encode → compare ──~%")
        (let ((re-encoded (funcall block :encoded)))
          (check (format nil "~A: re-encoded size matches" label)
                 (= (length re-encoded) (length bin-bytes))
                 (format nil "~D vs ~D bytes" (length re-encoded) (length bin-bytes)))
          (if (bytes= re-encoded bin-bytes)
              (check (format nil "~A: roundtrip byte-exact" label) t)
              (progn
                (check (format nil "~A: roundtrip byte-exact" label) nil)
                ;; Find first diff
                (loop for i below (min (length re-encoded) (length bin-bytes))
                      when (/= (aref re-encoded i) (aref bin-bytes i))
                        do (format t "      first diff at byte ~D: got 0x~2,'0X want 0x~2,'0X~%"
                                   i (aref re-encoded i) (aref bin-bytes i))
                           (return)))))
        block)
    (error (e)
      (check (format nil "~A: decode-block" label) nil (format nil "~A" e))
      nil)))

;;; ═══════════════════════════════════════════════════════════════
;;; STEP 3 — JSON CROSS-VALIDATION
;;; ═══════════════════════════════════════════════════════════════

(defun test-json-header (header json-header label)
  "Compare decoded header closure fields against JSON."
  (format t "~%  ── Step 3a: Header vs JSON ──~%")
  (let ((h header)
        (jh json-header))
    ;; Scalar fields
    (check-bytes (format nil "~A: HP (parent)" label)
                 (funcall h :parent-hash)
                 (j jh :parent))
    (check-bytes (format nil "~A: HR (state-root)" label)
                 (funcall h :state-root)
                 (j jh :parent--state--root))
    (check-bytes (format nil "~A: HX (extrinsic-hash)" label)
                 (funcall h :extrinsic-hash)
                 (j jh :extrinsic--hash))
    (check (format nil "~A: HT (slot)" label)
           (= (funcall h :slot) (j jh :slot))
           (format nil "got ~D want ~D" (funcall h :slot) (j jh :slot)))
    (check (format nil "~A: HI (author-index)" label)
           (= (funcall h :author-index) (j jh :author--index))
           (format nil "got ~D want ~D" (funcall h :author-index) (j jh :author--index)))
    (check-bytes (format nil "~A: HV (entropy-source)" label)
                 (funcall h :entropy-source)
                 (j jh :entropy--source))
    (check-bytes (format nil "~A: HS (seal)" label)
                 (funcall h :seal)
                 (j jh :seal))
    ;; Offenders
    (let ((dec-off (funcall h :offenders-mark))
          (json-off (j jh :offenders--mark)))
      (check-count (format nil "~A: HO count" label)
                   (length dec-off) (length json-off))
      (when (and dec-off json-off (= (length dec-off) (length json-off)))
        (check-bytes (format nil "~A: HO[0]" label)
                     (first dec-off)
                     (first json-off))))
    ;; Epoch mark (now a closure or nil)
    (let ((dec-em (funcall h :epoch-mark))
          (json-em (j jh :epoch--mark)))
      (cond
        ((and (null dec-em) (j-null-p json-em))
         (check (format nil "~A: HE (epoch-mark) = None" label) t))
        ((and dec-em (not (j-null-p json-em)))
         (check (format nil "~A: HE present" label) t)
         (check-bytes (format nil "~A: HE.entropy" label)
                      (funcall dec-em :entropy) (j json-em :entropy))
         (check-bytes (format nil "~A: HE.tickets-entropy" label)
                      (funcall dec-em :tickets-entropy)
                      (j json-em :tickets--entropy))
         (let ((dec-vals (funcall dec-em :validators))
               (json-vals (j json-em :validators)))
           (check-count (format nil "~A: HE.validators count" label)
                        (length dec-vals) (length json-vals))
           ;; Validate every validator (bandersnatch + ed25519)
           (loop for dv in dec-vals
                 for jv in json-vals
                 for i from 0
                 do (check-bytes (format nil "~A: HE.validators[~D].bandersnatch" label i)
                            (getf dv :bandersnatch) (j jv :bandersnatch))
               ;; cl-json converts "ed25519" → :ED-25519 (hyphen before digits)
                    (check-bytes (format nil "~A: HE.validators[~D].ed25519" label i)
                                 (getf dv :ed25519) (j jv :ed-25519)))))
        (t
         (check (format nil "~A: HE match" label) nil
                (format nil "decoded=~A json=~A" (not (null dec-em)) (not (j-null-p json-em)))))))
    ;; Tickets mark (closure or nil) — validate content
    (let ((dec-tm (funcall h :tickets-mark))
          (json-tm (j jh :tickets--mark)))
      (cond
        ((and (null dec-tm) (j-null-p json-tm))
         (check (format nil "~A: HW (tickets-mark) = None" label) t))
        ((and dec-tm (not (j-null-p json-tm)))
         (check (format nil "~A: HW present" label) t)
         (let ((dec-tickets (funcall dec-tm :tickets)))
           (check-count (format nil "~A: HW ticket count" label)
                        (length dec-tickets) (length json-tm))
           ;; Validate every ticket id + attempt
           (loop for dt in dec-tickets
                 for jt in json-tm
                 for i from 0
                 do (check-bytes (format nil "~A: HW[~D].id" label i)
                                 (getf dt :id) (j jt :id))
                    (check (format nil "~A: HW[~D].attempt" label i)
                           (= (getf dt :attempt) (j jt :attempt))
                           (format nil "got ~D want ~D"
                                   (getf dt :attempt) (j jt :attempt))))))
        (t
         (check (format nil "~A: HW match" label) nil
                (format nil "decoded=~A json=~A" (not (null dec-tm)) (not (j-null-p json-tm)))))))))

(defun test-json-extrinsic (block json-extrinsic label)
  "Compare decoded block's raw extrinsic fields against JSON.
   Block holds ET, ED, EP, EA, EG directly (no extrinsic closure)."
  (format t "~%  ── Step 3b: Extrinsic vs JSON ──~%")
  (let ((ex block)
        (je json-extrinsic))
    ;; --- Tickets ---
    (let ((dec-t (funcall ex :tickets))
          (json-t (j je :tickets)))
      (check-count (format nil "~A: ET count" label) (length dec-t) (length json-t))
      ;; Spot-check first ticket
      (when (and dec-t json-t)
        (let ((dt (first dec-t)) (jt (first json-t)))
          (check (format nil "~A: ET[0].attempt" label)
                 (= (getf dt :attempt) (j jt :attempt)))
          (check-bytes (format nil "~A: ET[0].signature" label)
                       (getf dt :signature) (j jt :signature)))))

    ;; --- Preimages ---
    (let ((dec-p (funcall ex :preimages))
          (json-p (j je :preimages)))
      (check-count (format nil "~A: EP count" label) (length dec-p) (length json-p))
      (when (and dec-p json-p)
        (let ((dp (first dec-p)) (jp (first json-p)))
          (check (format nil "~A: EP[0].requester" label)
                 (= (getf dp :requester) (j jp :requester))
                 (format nil "got ~D want ~D" (getf dp :requester) (j jp :requester)))
          (check-bytes (format nil "~A: EP[0].blob" label)
                       (getf dp :blob) (j jp :blob)))))

    ;; --- Assurances ---
    (let ((dec-a (funcall ex :assurances))
          (json-a (j je :assurances)))
      (check-count (format nil "~A: EA count" label) (length dec-a) (length json-a))
      (when (and dec-a json-a)
        (let ((da (first dec-a)) (ja (first json-a)))
          (check-bytes (format nil "~A: EA[0].anchor" label)
                       (getf da :anchor) (j ja :anchor))
          (check (format nil "~A: EA[0].validator-index" label)
                 (= (getf da :validator-index) (j ja :validator--index)))
          (check-bytes (format nil "~A: EA[0].signature" label)
                       (getf da :signature) (j ja :signature)))))

    ;; --- Guarantees ---
    (let ((dec-g (funcall ex :guarantees))
          (json-g (j je :guarantees)))
      (check-count (format nil "~A: EG count" label) (length dec-g) (length json-g))
      (when (and dec-g json-g)
        (let ((dg (first dec-g)) (jg (first json-g)))
          ;; Slot
          (check (format nil "~A: EG[0].slot" label)
                 (= (getf dg :slot) (j jg :slot))
                 (format nil "got ~D want ~D" (getf dg :slot) (j jg :slot)))
          ;; Signature count
          (check-count (format nil "~A: EG[0].signatures count" label)
                       (length (getf dg :signatures))
                       (length (j jg :signatures)))
          ;; Report: spot-check core_index and service_id of first result
          (let ((dr (getf dg :report))
                (jr (j jg :report)))
            (when (and dr jr)
              (check (format nil "~A: EG[0].report.core-index" label)
                     (= (getf dr :core-index) (j jr :core--index)))
              (check-bytes (format nil "~A: EG[0].report.authorizer-hash" label)
                           (getf dr :authorizer-hash) (j jr :authorizer--hash))
              ;; Package spec
              (let ((dps (getf dr :package-spec))
                    (jps (j jr :package--spec)))
                (when (and dps jps)
                  (check-bytes (format nil "~A: EG[0].report.package-spec.hash" label)
                               (getf dps :hash) (j jps :hash))
                  (check (format nil "~A: EG[0].report.package-spec.length" label)
                         (= (getf dps :length) (j jps :length)))))
              ;; Results count
              (check-count (format nil "~A: EG[0].report.results count" label)
                           (length (getf dr :results))
                           (length (j jr :results)))
              ;; Spot-check result[0]
              (when (and (getf dr :results) (j jr :results))
                (let ((dr0 (first (getf dr :results)))
                      (jr0 (first (j jr :results))))
                  (check (format nil "~A: EG[0].report.results[0].service-id" label)
                         (= (getf dr0 :service-id) (j jr0 :service--id))
                         (format nil "got ~D want ~D"
                                 (getf dr0 :service-id) (j jr0 :service--id))))))))))

    ;; --- Disputes ---
    (let ((dec-d (funcall ex :disputes))
          (json-d (j je :disputes)))
      (if (and dec-d json-d)
          (progn
            (check-count (format nil "~A: ED.verdicts count" label)
                         (length (getf dec-d :verdicts))
                         (length (j json-d :verdicts)))
            (check-count (format nil "~A: ED.culprits count" label)
                         (length (getf dec-d :culprits))
                         (length (j json-d :culprits)))
            (check-count (format nil "~A: ED.faults count" label)
                         (length (getf dec-d :faults))
                         (length (j json-d :faults)))
            ;; Spot-check verdict[0].target
            (when (and (getf dec-d :verdicts) (j json-d :verdicts))
              (let ((dv (first (getf dec-d :verdicts)))
                    (jv (first (j json-d :verdicts))))
                (check-bytes (format nil "~A: ED.verdicts[0].target" label)
                             (getf dv :target) (j jv :target))
                (check (format nil "~A: ED.verdicts[0].age" label)
                       (= (getf dv :age) (j jv :age)))
                (check-count (format nil "~A: ED.verdicts[0].votes count" label)
                             (length (getf dv :votes))
                             (length (j jv :votes)))))
            ;; Spot-check culprit[0]
            (when (and (getf dec-d :culprits) (j json-d :culprits))
              (let ((dc (first (getf dec-d :culprits)))
                    (jc (first (j json-d :culprits))))
                (check-bytes (format nil "~A: ED.culprits[0].target" label)
                             (getf dc :target) (j jc :target))
                (check-bytes (format nil "~A: ED.culprits[0].key" label)
                             (getf dc :key) (j jc :key))))
            ;; Spot-check fault[0]
            (when (and (getf dec-d :faults) (j json-d :faults))
              (let ((df (first (getf dec-d :faults)))
                    (jf (first (j json-d :faults))))
                (check-bytes (format nil "~A: ED.faults[0].target" label)
                             (getf df :target) (j jf :target))
                (check (format nil "~A: ED.faults[0].vote" label)
                       ;; cl-json decodes false as :false or nil
                       (eq (not (null (getf df :vote)))
                           (not (or (null (j jf :vote))
                                    (eq (j jf :vote) :false))))))))
          (check (format nil "~A: ED both present" label)
                 (and (null dec-d) (j-null-p json-d)))))))

;;; ═══════════════════════════════════════════════════════════════
;;; STEP 4 — VERIFY H(E(H))
;;; ═══════════════════════════════════════════════════════════════

(defun test-header-hash (block bin-bytes label)
  "Verify header hash: H(E(H)) = blake2b(raw header bytes).
   Also verify the encoded header portion matches the bin prefix."
  (format t "~%  ── Step 4: Verify H(E(H)) ──~%")
  (let* ((h (funcall block :header))
         (h-encoded (funcall h :encoded))
         (h-hash-from-closure (funcall h :hash))
         (h-hash-direct (blake2b-256 (subseq bin-bytes 0 (length h-encoded)))))
    ;; Header encoded bytes should match the start of block.bin
    (check (format nil "~A: header encoded = bin prefix" label)
           (bytes= h-encoded (subseq bin-bytes 0 (length h-encoded))))
    ;; Hash from closure should match hash of raw bytes
    (check (format nil "~A: H(E(H)) consistent" label)
           (bytes= h-hash-from-closure h-hash-direct)
           (unless (bytes= h-hash-from-closure h-hash-direct)
             (format nil "closure=~A direct=~A"
                     (jam.ffi:bytes-to-hex-string h-hash-from-closure)
                     (jam.ffi:bytes-to-hex-string h-hash-direct))))))

;;; ═══════════════════════════════════════════════════════════════
;;; STEP 5 — HX CHECK (informational on codec vectors)
;;; ═══════════════════════════════════════════════════════════════

(defun test-hx-codec (block label)
  "Check HX consistency between header and computed extrinsic hash.
   WARNING-only for codec vectors (known placeholder HX)."
  (format t "~%  ── Step 5: HX check (informational) ──~%")
  (let* ((h (funcall block :header))
         (header-hx (funcall h :extrinsic-hash))
         (computed-hx (funcall block :extrinsic-hash)))
    (warn-check (format nil "~A: HX header = computed" label)
                (bytes= header-hx computed-hx)
                (format nil "codec vectors have placeholder HX"))))

;;; ═══════════════════════════════════════════════════════════════
;;; PART 1 — CODEC VECTOR ROUNDTRIP
;;; ═══════════════════════════════════════════════════════════════

(defun run-codec-roundtrip-test (spec)
  "Run full block roundtrip test for SPEC (\"tiny\" or \"full\").
   Returns T if all checks pass (warnings don't count)."
  (let* ((base (format nil "tests/jamtestvectors/codec/~A/" spec))
         (bin-path (format nil "~Ablock.bin" base))
         (json-path (format nil "~Ablock.json" base))
         (label (string-upcase spec))
         (*test-errors* 0)
         (*test-warnings* 0)
         (chain-name (if (string= spec "tiny") :tiny :full)))
    (format t "~%╔══════════════════════════════════════════════════╗~%")
    (format t "║  Codec Roundtrip — ~A~42T║~%" label)
    (format t "╚══════════════════════════════════════════════════╝~%")

    (with-chain chain-name
      ;; Load files
      (let ((bin-bytes (load-bin bin-path))
            (json-data (load-json json-path)))

        ;; Steps 1-2: Binary roundtrip
        (let ((block (test-bin-roundtrip bin-bytes label)))
          (when block
            ;; Step 3: JSON cross-validation
            (test-json-header (funcall block :header)
                              (j json-data :header) label)
            (test-json-extrinsic block
                                 (j json-data :extrinsic) label)
            ;; Step 4: Header hash
            (test-header-hash block bin-bytes label)
            ;; Step 5: HX (informational)
            (test-hx-codec block label)))))

    ;; Summary
    (format t "~%  ─────────────────────────────────────────~%")
    (when (> *test-warnings* 0)
      (format t "  ⚠  ~D warning~:P (non-blocking)~%" *test-warnings*))
    (if (zerop *test-errors*)
        (progn
          (format t "  ✅ ~A: ALL CHECKS PASSED~%" label)
          t)
        (progn
          (format t "  ❌ ~A: ~D CHECK~:P FAILED~%" label *test-errors*)
          nil))))

;;; ═══════════════════════════════════════════════════════════════
;;; PART 2 — TRACE VECTOR HX
;;; ═══════════════════════════════════════════════════════════════

(defun run-trace-hx-tests ()
  "Run HX tests against trace vectors (authoritative HX values).
   Returns T if all pass."
  (format t "~%╔══════════════════════════════════════════════════╗~%")
  (format t "║  HX Verification — Trace Vectors                ║~%")
  (format t "╚══════════════════════════════════════════════════╝~%")
  (let ((test-dir "tests/trace-vectors/extrinsic_hash/")
        (pass 0)
        (fail 0))
    (dolist (file (directory (merge-pathnames "*.json" test-dir)))
      (let ((name (pathname-name file)))
        (format t "~%  ── ~A ──~%" name)
        (handler-case
            (if (test-hx-from-trace (namestring file))
                (progn (incf pass)
                       (format t "    ✓ HX match~%"))
                (progn (incf fail)
                       (format t "    ✗ HX mismatch~%")))
          (error (e)
            (format t "    ✗ ERROR: ~A~%" e)
            (incf fail)))))

    (format t "~%  ─────────────────────────────────────────~%")
    (if (zerop fail)
        (progn
          (format t "  ✅ TRACE HX: ~D/~D passed~%" pass (+ pass fail))
          t)
        (progn
          (format t "  ❌ TRACE HX: ~D/~D passed~%" pass (+ pass fail))
          nil))))

;;; ═══════════════════════════════════════════════════════════════
;;; PART 3 — INDIVIDUAL CODEC ROUNDTRIPS
;;; ═══════════════════════════════════════════════════════════════

(defun test-simple-roundtrip (bin-path decode-fn encode-fn label)
  "Generic decode→encode roundtrip: load bin, decode, re-encode, compare."
  (let ((bin (load-bin bin-path)))
    (handler-case
        (multiple-value-bind (decoded consumed) (funcall decode-fn bin 0)
          (check (format nil "~A: consumed all ~D bytes" label (length bin))
                 (= consumed (length bin))
                 (format nil "consumed ~D / ~D" consumed (length bin)))
          (let ((re-encoded (funcall encode-fn decoded)))
            (check (format nil "~A: roundtrip byte-exact" label)
                   (bytes= re-encoded bin)
                   (when (not (bytes= re-encoded bin))
                     (format nil "~D vs ~D bytes" (length re-encoded) (length bin))))))
      (error (e)
        (check (format nil "~A: decode/encode" label) nil (format nil "~A" e))))))

(defun test-header-file-roundtrip (bin-path label)
  "Header roundtrip via closure: bin → decode-header → :encoded → compare."
  (let ((bin (load-bin bin-path)))
    (handler-case
        (multiple-value-bind (header consumed) (decode-header bin 0)
          (check (format nil "~A: consumed all ~D bytes" label (length bin))
                 (= consumed (length bin))
                 (format nil "consumed ~D / ~D" consumed (length bin)))
          (let ((re-encoded (funcall header :encoded)))
            (check (format nil "~A: roundtrip byte-exact" label)
                   (bytes= re-encoded bin))))
      (error (e)
        (check (format nil "~A: header decode/encode" label) nil (format nil "~A" e))))))

(defun test-header-json-crosscheck (bin-path json-path label)
  "Decode header from .bin, cross-validate field content against .json."
  (handler-case
      (let* ((bin (load-bin bin-path))
             (json (load-json json-path))
             (jh json))
        (multiple-value-bind (h consumed) (decode-header bin 0)
          (declare (ignore consumed))
          (format t "~%  ── ~A: JSON cross-check ──~%" label)
          ;; Scalars
          (check-bytes (format nil "~A: HP" label) (funcall h :parent-hash) (j jh :parent))
          (check-bytes (format nil "~A: HR" label) (funcall h :state-root) (j jh :parent--state--root))
          (check-bytes (format nil "~A: HX" label) (funcall h :extrinsic-hash) (j jh :extrinsic--hash))
          (check (format nil "~A: HT" label) (= (funcall h :slot) (j jh :slot)))
          (check (format nil "~A: HI" label) (= (funcall h :author-index) (j jh :author--index)))
          (check-bytes (format nil "~A: HV" label) (funcall h :entropy-source) (j jh :entropy--source))
          (check-bytes (format nil "~A: HS" label) (funcall h :seal) (j jh :seal))
          ;; HO
          (let ((dec-off (funcall h :offenders-mark))
                (json-off (j jh :offenders--mark)))
            (check-count (format nil "~A: HO count" label) (length dec-off) (length json-off))
            (loop for dk in dec-off for jk in json-off for i from 0
                  do (check-bytes (format nil "~A: HO[~D]" label i) dk jk)))
          ;; HE — epoch-mark
          (let ((dec-em (funcall h :epoch-mark))
                (json-em (j jh :epoch--mark)))
            (cond
              ((and (null dec-em) (j-null-p json-em))
               (check (format nil "~A: HE = None" label) t))
              ((and dec-em (not (j-null-p json-em)))
               (check-bytes (format nil "~A: HE.entropy" label)
                            (funcall dec-em :entropy) (j json-em :entropy))
               (check-bytes (format nil "~A: HE.tickets-entropy" label)
                            (funcall dec-em :tickets-entropy) (j json-em :tickets--entropy))
               (let ((dv (funcall dec-em :validators))
                     (jv (j json-em :validators)))
                 (check-count (format nil "~A: HE.validators count" label) (length dv) (length jv))
                 (loop for d in dv for e in jv for i from 0
                       do (check-bytes (format nil "~A: HE.v[~D].bn" label i) (getf d :bandersnatch) (j e :bandersnatch))
                          (check-bytes (format nil "~A: HE.v[~D].ed" label i) (getf d :ed25519) (j e :ed-25519)))))
              (t (check (format nil "~A: HE mismatch" label) nil))))
          ;; HW — tickets-mark
          (let ((dec-tm (funcall h :tickets-mark))
                (json-tm (j jh :tickets--mark)))
            (cond
              ((and (null dec-tm) (j-null-p json-tm))
               (check (format nil "~A: HW = None" label) t))
              ((and dec-tm (not (j-null-p json-tm)))
               (let ((tix (funcall dec-tm :tickets)))
                 (check-count (format nil "~A: HW count" label) (length tix) (length json-tm))
                 (loop for dt in tix for jt in json-tm for i from 0
                       do (check-bytes (format nil "~A: HW[~D].id" label i) (getf dt :id) (j jt :id))
                          (check (format nil "~A: HW[~D].attempt" label i)
                                 (= (getf dt :attempt) (j jt :attempt))
                                 (format nil "got ~D want ~D" (getf dt :attempt) (j jt :attempt))))))
              (t (check (format nil "~A: HW mismatch" label) nil))))))
    (error (e)
      (check (format nil "~A: JSON crosscheck" label) nil (format nil "~A" e)))))

(defun test-extrinsic-file-roundtrip (bin-path label)
  "Extrinsic roundtrip via standalone functions:
   bin → decode-extrinsic-data → encode-extrinsic-data → compare."
  (let ((bin (load-bin bin-path)))
    (handler-case
        (multiple-value-bind (et ed ep ea eg consumed)
            (decode-extrinsic-data bin 0)
          (check (format nil "~A: consumed all ~D bytes" label (length bin))
                 (= consumed (length bin))
                 (format nil "consumed ~D / ~D" consumed (length bin)))
          (let ((re-encoded (encode-extrinsic-data et ed ep ea eg)))
            (check (format nil "~A: roundtrip byte-exact" label)
                   (bytes= re-encoded bin))))
      (error (e)
        (check (format nil "~A: extrinsic decode/encode" label) nil (format nil "~A" e))))))

(defun run-individual-codec-tests ()
  "Test all individual codec vectors as roundtrips.
   Returns T if all pass."
  (format t "~%╔══════════════════════════════════════════════════╗~%")
  (format t "║  Individual Codec Roundtrips                     ║~%")
  (format t "╚══════════════════════════════════════════════════╝~%")
  (let ((*test-errors* 0)
        (*test-warnings* 0))
    (dolist (spec '("tiny" "full"))
      (let ((base (format nil "tests/jamtestvectors/codec/~A/" spec))
            (label (string-upcase spec))
            (chain (if (string= spec "tiny") :tiny :full)))
        (format t "~%  ── ~A ──~%" label)
        (with-chain chain
          ;; Headers (2 variants: epoch=Some/tickets=None, epoch=None/tickets=Some)
          ;; Binary roundtrip
          (test-header-file-roundtrip
           (format nil "~Aheader_0.bin" base)
           (format nil "~A/header_0 (epoch=Some)" label))
          (test-header-file-roundtrip
           (format nil "~Aheader_1.bin" base)
           (format nil "~A/header_1 (tickets=Some)" label))
          ;; JSON content cross-validation
          (test-header-json-crosscheck
           (format nil "~Aheader_0.bin" base)
           (format nil "~Aheader_0.json" base)
           (format nil "~A/header_0 JSON" label))
          (test-header-json-crosscheck
           (format nil "~Aheader_1.bin" base)
           (format nil "~Aheader_1.json" base)
           (format nil "~A/header_1 JSON" label))

          ;; Individual extrinsic components
          (test-simple-roundtrip
           (format nil "~Atickets_extrinsic.bin" base)
           #'decode-tickets-extrinsic #'encode-tickets-extrinsic
           (format nil "~A/tickets_extrinsic" label))
          (test-simple-roundtrip
           (format nil "~Apreimages_extrinsic.bin" base)
           #'decode-preimages-extrinsic #'encode-preimages-extrinsic
           (format nil "~A/preimages_extrinsic" label))
          (test-simple-roundtrip
           (format nil "~Aassurances_extrinsic.bin" base)
           #'decode-assurances-extrinsic #'encode-assurances-extrinsic
           (format nil "~A/assurances_extrinsic" label))
          (test-simple-roundtrip
           (format nil "~Adisputes_extrinsic.bin" base)
           #'decode-disputes-extrinsic #'encode-disputes-extrinsic
           (format nil "~A/disputes_extrinsic" label))
          (test-simple-roundtrip
           (format nil "~Aguarantees_extrinsic.bin" base)
           #'decode-guarantees-extrinsic #'encode-guarantees-extrinsic
           (format nil "~A/guarantees_extrinsic" label))

          ;; Full extrinsic (standalone encode/decode)
          (test-extrinsic-file-roundtrip
           (format nil "~Aextrinsic.bin" base)
           (format nil "~A/extrinsic (full)" label))

          ;; Work structures
          (test-simple-roundtrip
           (format nil "~Awork_report.bin" base)
           #'decode-work-report #'encode-work-report
           (format nil "~A/work_report" label))
          (test-simple-roundtrip
           (format nil "~Arefine_context.bin" base)
           #'decode-refine-context #'encode-refine-context
           (format nil "~A/refine_context" label))
          (test-simple-roundtrip
           (format nil "~Awork_result_0.bin" base)
           #'decode-work-result #'encode-work-result
           (format nil "~A/work_result_0" label))
          (test-simple-roundtrip
           (format nil "~Awork_result_1.bin" base)
           #'decode-work-result #'encode-work-result
           (format nil "~A/work_result_1" label)))))

    (format t "~%  ─────────────────────────────────────────~%")
    (if (zerop *test-errors*)
        (progn
          (format t "  ✅ ALL CODEC ROUNDTRIPS PASSED~%")
          t)
        (progn
          (format t "  ❌ ~D CODEC ROUNDTRIP~:P FAILED~%" *test-errors*)
          nil))))

;;; ═══════════════════════════════════════════════════════════════
;;; ENTRY POINT
;;; ═══════════════════════════════════════════════════════════════

(defun run-all-block-roundtrip-tests ()
  "Run all block roundtrip, HX, and individual codec tests."
  (format t "~%═══════════════════════════════════════════════════════~%")
  (format t "  JOTL CODEC + BLOCK TEST SUITE~%")
  (format t "═══════════════════════════════════════════════════════~%")
  (format t "  Part 1: Block roundtrip — decode ↔ encode ↔ JSON~%")
  (format t "  Part 2: Trace HX — authoritative HX verification~%")
  (format t "  Part 3: Individual codecs — every codec vector~%")

  (let ((codec-results (mapcar #'run-codec-roundtrip-test '("tiny" "full")))
        (trace-ok (run-trace-hx-tests))
        (individual-ok (run-individual-codec-tests)))

    (format t "~%═══════════════════════════════════════════════════════~%")
    (let ((all-ok (and (every #'identity codec-results) trace-ok individual-ok)))
      (if all-ok
          (format t "  ✅ ALL TESTS PASSED~%")
          (progn
            (unless (every #'identity codec-results)
              (format t "  ❌ Part 1 — Block roundtrip: FAILED~%"))
            (unless trace-ok
              (format t "  ❌ Part 2 — Trace HX: FAILED~%"))
            (unless individual-ok
              (format t "  ❌ Part 3 — Individual codecs: FAILED~%"))))
      (format t "═══════════════════════════════════════════════════════~%~%")
      all-ok)))

;;; ═══ MAIN ═══

(unless (run-all-block-roundtrip-tests)
  (sb-ext:exit :code 1))
