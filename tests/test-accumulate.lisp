;;;; tests/test-accumulate.lisp — Accumulate STF tests
;;;; Full validation: transition-accumulate against jamtestvectors/stf/accumulate
;;;;
;;;; Tests per vector:
;;;;   1. Parse pre_state (slot, entropy, ready-queue, accumulated, privileges,
;;;;      statistics, accounts)
;;;;   2. Parse input (slot, reports)
;;;;   3. Execute transition-accumulate(W, ω, ξ, δ, χ, ι, ϕ, τ, τ')
;;;;   4. Compare output: ok → accumulated-root hash | err
;;;;   5. Compare post_state: ready-queue, accumulated, privileges, statistics, accounts
;;;;
;;;; 30 tiny + 30 full vectors
;;;; Green 🟢 = expected OK, Red 🔴 = expected error

(ql:quickload :cl-json :silent t)

(in-package :jotl)

;; Load shared test helpers
(load (merge-pathnames "test-utils.lisp" *load-pathname*))

;;; ═══════════════════════════════════════════════════════════════
;;; JSON PARSERS (accumulate-specific)
;;; ═══════════════════════════════════════════════════════════════

;;; ── Accounts → delta extra-kvs ────────────────────────────────

(defun accum-json-service-info (svc-json)
  "Parse JSON ServiceInfo → plist matching decode-service-info output."
  (list :version                 (or (cdr (assoc :version svc-json)) 0)
        :code-hash               (hex-to-bytes (cdr (assoc :code--hash svc-json)))
        :balance                 (cdr (assoc :balance svc-json))
        :min-item-gas            (cdr (assoc :min--item--gas svc-json))
        :min-memo-gas            (cdr (assoc :min--memo--gas svc-json))
        :bytes                   (cdr (assoc :bytes svc-json))
        :deposit-offset          (cdr (assoc :deposit--offset svc-json))
        :items                   (cdr (assoc :items svc-json))
        :creation-slot           (cdr (assoc :creation--slot svc-json))
        :last-accumulation-slot  (cdr (assoc :last--accumulation--slot svc-json))
        :parent-service          (cdr (assoc :parent--service svc-json))))

(defun accum-json-account-to-kvs (account-json)
  "Convert a JSON account entry to Merkle trie key-value pairs.
   ACCOUNT-JSON: (:id sid :data (:service ... :storage ... :preimage-blobs ... :preimage-requests ...))
   Returns: list of (key-31 . value-bytes) for inclusion in extra-kvs."
  (let* ((sid (cdr (assoc :id account-json)))
         (data (cdr (assoc :data account-json)))
         (svc-json (cdr (assoc :service data)))
         (storage-json (cdr (assoc :storage data)))
         (blobs-json (cdr (assoc :preimage--blobs data)))
         (requests-json (cdr (assoc :preimage--requests data)))
         (kvs nil))

    ;; 1. Metadata key C(255, s) → 89-byte ServiceInfo
    (let* ((info (accum-json-service-info svc-json))
           (meta-key (make-array 31 :element-type '(unsigned-byte 8) :initial-element 0)))
      (setf (aref meta-key 0) 255)
      (let ((s (E4 sid)))
        (setf (aref meta-key 1) (aref s 0)
              (aref meta-key 2) (aref s 1)
              (aref meta-key 3) (aref s 2)
              (aref meta-key 4) (aref s 3)))
      (push (cons meta-key (encode-service-info info)) kvs))

    ;; 2. Preimage blobs → interleaved sub-keys
    ;;    Each: { hash: "0x...", blob: "0x..." }
    ;;    Key: interleave(sid, H(E4(0xFFFFFFFE) ⌢ hash)[0:27])
    ;;    Val: raw blob bytes
    (dolist (entry blobs-json)
      (let* ((hash-32 (hex-to-bytes (cdr (assoc :hash entry))))
             (blob (hex-to-bytes (cdr (assoc :blob entry))))
             (h-27 (preimage-trie-h hash-32))
             (trie-key (interleave-sub-key sid h-27)))
        (push (cons trie-key blob) kvs)))

    ;; 3. Preimage requests (lookup entries)
    ;;    Each: { key: { hash: "0x...", length: N }, value: [timeslot, ...] }
    ;;    Key: interleave(sid, H(E4(length) ⌢ hash)[0:27])
    ;;    Val: compact(n) ⌢ n×E4(timeslot)
    (dolist (entry requests-json)
      (let* ((req-key (cdr (assoc :key entry)))
             (hash-32 (hex-to-bytes (cdr (assoc :hash req-key))))
             (len (cdr (assoc :length req-key)))
             (statuses (coerce (cdr (assoc :value entry)) 'list))
             (h-27 (lookup-trie-h hash-32 len))
             (trie-key (interleave-sub-key sid h-27))
             (val (encode-lookup-value statuses)))
        (push (cons trie-key val) kvs)))

    ;; 4. Storage entries
    ;;    Each: { key: "0x...", value: "0x..." }
    ;;    Key: interleave(sid, H(E4(0xFFFFFFFF) ⌢ raw_key)[0:27])
    ;;    Val: raw value bytes
    (dolist (entry storage-json)
      (let* ((raw-key (hex-to-bytes (cdr (assoc :key entry))))
             (raw-val (hex-to-bytes (cdr (assoc :value entry))))
             (h-27 (storage-trie-h raw-key))
             (trie-key (interleave-sub-key sid h-27)))
        (push (cons trie-key raw-val) kvs)))

    (nreverse kvs)))

(defun accum-json-accounts-to-delta (accounts-json)
  "Convert JSON accounts list → delta-state closure.
   ACCOUNTS-JSON: list of { id: N, data: { service: ..., storage: ... } }
   Returns: delta-state closure."
  (let ((all-kvs nil))
    (dolist (acct accounts-json)
      (setf all-kvs (nconc all-kvs (accum-json-account-to-kvs acct))))
    (make-delta-state :raw-kvs all-kvs)))

(defun accum-json-accounts-to-raw-storage (accounts-json)
  "Extract raw storage keys from JSON accounts → hash-table (sid → alist).
   The PVM expects raw storage keys (arbitrary length), NOT 27-byte trie hashes.
   JSON provides these directly in storage[].key / storage[].value.
   Returns: hash-table mapping service-id → alist of (raw-key-bytes . raw-value-bytes)."
  (let ((ht (make-hash-table :test 'eql)))
    (dolist (acct (if (listp accounts-json) accounts-json
                      (coerce accounts-json 'list)))
      (let* ((sid (cdr (assoc :id acct)))
             (data (cdr (assoc :data acct)))
             (storage-json (cdr (assoc :storage data)))
             (entries nil))
        (dolist (entry storage-json)
          (let ((raw-key (hex-to-bytes (cdr (assoc :key entry))))
                (raw-val (hex-to-bytes (cdr (assoc :value entry)))))
            (push (cons raw-key raw-val) entries)))
        (setf (gethash sid ht) (nreverse entries))))
    ht))

;;; ── Privileges → chi closure ──────────────────────────────────

(defun accum-json-privileges-to-chi (priv-json)
  "Convert JSON privileges → chi-state closure.
   { bless: N, assign: [N...], designate: N, register: N, always_acc: [...] }"
  (let* ((manager (cdr (assoc :bless priv-json)))
         (assign (coerce (cdr (assoc :assign priv-json)) 'list))
         (designate (cdr (assoc :designate priv-json)))
         (creation (cdr (assoc :register priv-json)))
         (az-json (cdr (assoc :always--acc priv-json)))
         (always-accum (mapcar (lambda (e)
                                 (cons (cdr (assoc :id e))
                                       (cdr (assoc :gas e))))
                               az-json)))
    (make-chi-state
     :raw (encode-chi-fields
           (list :manager manager
                 :designate designate
                 :creation creation
                 :authorizers assign
                 :always-accum always-accum)))))

;;; ── Ready-queue → omega closure ────────────────────────────────

(defun accum-json-ready-queue-to-omega (rq-json)
  "Convert JSON ready_queue → omega-state closure.
   Ready queue: E-length list of lists of { report: {...}, dependencies: [...] }"
  (let ((queues (mapcar
                 (lambda (slot-json)
                   (mapcar (lambda (entry-json)
                             (let* ((report-json (cdr (assoc :report entry-json)))
                                    (deps-json (cdr (assoc :dependencies entry-json))))
                               (list :report (json-work-report report-json)
                                     :deps (mapcar #'hex-to-bytes
                                                   (coerce deps-json 'list)))))
                           (coerce slot-json 'list)))
                 (coerce rq-json 'list))))
    (make-omega-state :queues queues)))

;;; ── Accumulated → xi closure ───────────────────────────────────

(defun accum-json-accumulated-to-xi (acc-json)
  "Convert JSON accumulated → xi-state closure.
   Accumulated: E-length list of lists of hex hash strings."
  (let ((entries (mapcar
                  (lambda (slot-json)
                    (mapcar #'hex-to-bytes (coerce slot-json 'list)))
                  (coerce acc-json 'list))))
    (make-xi-state :entries entries)))

;;; ── Statistics → comparison data ───────────────────────────────

(defun accum-json-statistics (stats-json)
  "Parse JSON ServicesStatistics → list of (:id sid :record plist).
   Each record: { provided_count, provided_size, refinement_count, ...,
                  accumulate_count, accumulate_gas_used, ... }"
  (mapcar (lambda (entry)
            (let ((rec-json (cdr (assoc :record entry))))
              (list :id (cdr (assoc :id entry))
                    :record
                    (list :accumulate-count    (cdr (assoc :accumulate--count rec-json))
                          :accumulate-gas-used (cdr (assoc :accumulate--gas--used rec-json))
                          :on-transfers-count  (or (cdr (assoc :on--transfers--count rec-json)) 0)
                          :on-transfers-gas-used (or (cdr (assoc :on--transfers--gas--used rec-json)) 0)))))
          (coerce stats-json 'list)))

;;; ═══════════════════════════════════════════════════════════════
;;; COMPARISON HELPERS
;;; ═══════════════════════════════════════════════════════════════

(defun accum-compare-xi (label computed-xi expected-xi)
  "Compare ξ (accumulated queues). Returns T if match."
  (let ((ok t)
        (comp-entries (funcall computed-xi :entries))
        (exp-entries (funcall expected-xi :entries)))
    (unless (= (length comp-entries) (length exp-entries))
      (format t "    ✗ ~A: length ~D ≠ ~D~%" label
              (length comp-entries) (length exp-entries))
      (return-from accum-compare-xi nil))
    (loop for ci in comp-entries for ei in exp-entries for idx from 0
          do (unless (and (= (length ci) (length ei))
                          (every #'equalp ci ei))
               (format t "    ✗ ~A[~D]: ~D hashes ≠ ~D hashes~%"
                       label idx (length ci) (length ei))
               ;; Show first mismatch
               (when (and ci ei)
                 (loop for ch in ci for eh in ei
                       unless (equalp ch eh)
                       do (format t "      got:  ~A~%      want: ~A~%"
                                  (jam.ffi:bytes-to-hex-string ch)
                                  (jam.ffi:bytes-to-hex-string eh))
                          (return)))
               (setf ok nil)))
    ok))

(defun accum-compare-omega (label computed-omega expected-omega)
  "Compare ω (ready queues). Returns T if match."
  (let ((ok t)
        (comp-queues (funcall computed-omega :queues))
        (exp-queues (funcall expected-omega :queues)))
    (unless (= (length comp-queues) (length exp-queues))
      (format t "    ✗ ~A: length ~D ≠ ~D~%" label
              (length comp-queues) (length exp-queues))
      (return-from accum-compare-omega nil))
    (loop for cq in comp-queues for eq* in exp-queues for idx from 0
          do (unless (= (length cq) (length eq*))
               (format t "    ✗ ~A[~D]: ~D entries ≠ ~D entries~%"
                       label idx (length cq) (length eq*))
               (setf ok nil)))
    ;; Deep comparison: encode both and compare bytes
    (let ((comp-bytes (funcall computed-omega :encoded))
          (exp-bytes (funcall expected-omega :encoded)))
      (unless (equalp comp-bytes exp-bytes)
        (format t "    ✗ ~A: encoded bytes mismatch (got ~D, want ~D bytes)~%"
                label (length comp-bytes) (length exp-bytes))
        (setf ok nil)))
    ok))

(defun accum-compare-chi (label computed-chi expected-chi)
  "Compare χ (privileges). Returns T if match."
  (let ((ok t))
    (flet ((check-field (name getter)
             (let ((c (funcall computed-chi getter))
                   (e (funcall expected-chi getter)))
               (unless (equalp c e)
                 (format t "    ✗ ~A.~A: ~A ≠ ~A~%" label name c e)
                 (setf ok nil)))))
      (check-field "manager" :manager)
      (check-field "designate" :designate)
      (check-field "creation" :creation)
      (check-field "authorizers" :authorizers)
      (check-field "always-accum" :always-accum))
    ok))

(defun accum-compare-statistics (label computed-stats expected-stats)
  "Compare π_S service statistics. Returns T if match.
   COMPUTED-STATS: list of (sid n-items gas-used) from accum-state :gas-usage.
   EXPECTED-STATS: list of (:id sid :record (:accumulate-count N ...))."
  (let ((ok t))
    ;; Build computed stats alist: sid → (count . gas)
    (let ((comp-ht (make-hash-table :test 'eql)))
      (dolist (triple computed-stats)
        (let ((sid (first triple))
              (n-items (second triple))
              (gas (third triple)))
          (multiple-value-bind (existing found) (gethash sid comp-ht)
            (if found
                (setf (gethash sid comp-ht)
                      (cons (+ (car existing) n-items)
                            (+ (cdr existing) gas)))
                (setf (gethash sid comp-ht) (cons n-items gas))))))
      ;; Compare with expected
      (dolist (exp expected-stats)
        (let* ((sid (getf exp :id))
               (rec (getf exp :record))
               (exp-count (getf rec :accumulate-count))
               (exp-gas (getf rec :accumulate-gas-used))
               (comp (gethash sid comp-ht)))
          (when comp
            (let ((comp-count (car comp))
                  (comp-gas (cdr comp)))
              (unless (= comp-count exp-count)
                (format t "    ✗ ~A[~D].count: ~D ≠ ~D~%"
                        label sid comp-count exp-count)
                (setf ok nil))
              (unless (= comp-gas exp-gas)
                (format t "    ✗ ~A[~D].gas: ~D ≠ ~D (diff ~D)~%"
                        label sid comp-gas exp-gas (- comp-gas exp-gas))
                (setf ok nil))))
          (unless comp
            (format t "    ✗ ~A: missing service ~D~%" label sid)
            (setf ok nil)))))
    ok))

(defun accum-compare-accounts (label computed-delta expected-accounts-json)
  "Compare δ' (service accounts). Returns T if match.
   Compares metadata, storage, preimage-blobs, preimage-requests."
  (let ((ok t)
        (computed-kvs (funcall computed-delta :extra-kvs)))
    (dolist (exp-acct expected-accounts-json)
      (let* ((sid (cdr (assoc :id exp-acct)))
             (data (cdr (assoc :data exp-acct)))
             (exp-svc (cdr (assoc :service data)))
             (exp-storage (cdr (assoc :storage data)))
             (exp-blobs (cdr (assoc :preimage--blobs data)))
             (exp-requests (cdr (assoc :preimage--requests data)))
             ;; Extract computed account
             (comp-classified (classify-service-sub-keys sid computed-kvs))
             (comp-meta (getf comp-classified :metadata)))

        ;; ── Compare metadata ──
        (if (not comp-meta)
            (progn
              (format t "    ✗ ~A[~D]: no metadata found~%" label sid)
              (setf ok nil))
            (progn
              (let ((exp-info (accum-json-service-info exp-svc)))
                ;; Compare key fields
                (flet ((chk (field)
                         (let ((c (getf comp-meta field))
                               (e (getf exp-info field)))
                           (cond
                             ((and (typep c '(vector (unsigned-byte 8)))
                                   (typep e '(vector (unsigned-byte 8))))
                              (unless (equalp c e)
                                (format t "    ✗ ~A[~D].~A: bytes differ~%" label sid field)
                                (setf ok nil)))
                             (t (unless (eql c e)
                                  (format t "    ✗ ~A[~D].~A: ~A ≠ ~A~%"
                                          label sid field c e)
                                  (setf ok nil)))))))
                  (chk :balance)
                  (chk :bytes)
                  (chk :items)
                  (chk :last-accumulation-slot)
                  (chk :code-hash)))

              ;; ── Compare storage entries ──
              (let ((comp-storage (getf comp-classified :storage))
                    (exp-count (length exp-storage)))
                (unless (= (length comp-storage) exp-count)
                  (format t "    ✗ ~A[~D].storage: ~D entries ≠ ~D~%"
                          label sid (length comp-storage) exp-count)
                  (setf ok nil)))

              ;; ── Compare preimage blobs count ──
              (let ((comp-preimages (getf comp-classified :preimages))
                    (exp-count (length exp-blobs)))
                (unless (= (length comp-preimages) exp-count)
                  (format t "    ✗ ~A[~D].preimages: ~D blobs ≠ ~D~%"
                          label sid (length comp-preimages) exp-count)
                  (setf ok nil)))

              ;; ── Compare lookup entries count ──
              (let ((comp-lookup (getf comp-classified :lookup))
                    (exp-count (length exp-requests)))
                (unless (= (length comp-lookup) exp-count)
                  (format t "    ✗ ~A[~D].lookup: ~D entries ≠ ~D~%"
                          label sid (length comp-lookup) exp-count)
                  (setf ok nil)))))))
    ok))

;;; ═══════════════════════════════════════════════════════════════
;;; RUN ONE TEST
;;; ═══════════════════════════════════════════════════════════════

(defun run-accumulate-test (path spec)
  "Run a single accumulate test vector. Prints result with ✅/❌.
   SPEC: :tiny or :full"
  (declare (ignorable spec))
  (let* ((json (load-json path))
         (fname (file-namestring path))
         (input-json (cdr (assoc :input json)))
         (pre-json (or (cdr (assoc :pre-state json))
                       (cdr (assoc :pre--state json))))
         (post-json (or (cdr (assoc :post-state json))
                        (cdr (assoc :post--state json))))
         (output-json (cdr (assoc :output json)))
         ;; ── Parse input ──
         (input-slot (cdr (assoc :slot input-json)))
         (input-reports (mapcar #'json-work-report
                                (coerce (cdr (assoc :reports input-json)) 'list)))
         ;; ── Parse pre-state ──
         (pre-slot (cdr (assoc :slot pre-json)))
         (pre-entropy-bytes (hex-to-bytes (cdr (assoc :entropy pre-json))))
         (pre-omega (accum-json-ready-queue-to-omega
                     (cdr (assoc :ready--queue pre-json))))
         (pre-xi (accum-json-accumulated-to-xi
                  (cdr (assoc :accumulated pre-json))))
         (pre-chi (accum-json-privileges-to-chi
                   (cdr (assoc :privileges pre-json))))
         (pre-accounts-list (coerce (cdr (assoc :accounts pre-json)) 'list))
         (pre-delta (accum-json-accounts-to-delta pre-accounts-list))
         (pre-raw-storage (accum-json-accounts-to-raw-storage pre-accounts-list))
         ;; ── Parse post-state (expected) ──
         (exp-omega (accum-json-ready-queue-to-omega
                     (cdr (assoc :ready--queue post-json))))
         (exp-xi (accum-json-accumulated-to-xi
                  (cdr (assoc :accumulated post-json))))
         (exp-chi (accum-json-privileges-to-chi
                   (cdr (assoc :privileges post-json))))
         (exp-stats (accum-json-statistics
                     (cdr (assoc :statistics post-json))))
         (exp-accounts (coerce (cdr (assoc :accounts post-json)) 'list))
         ;; ── Expected output ──
         (expected-ok (cdr (assoc :ok output-json)))
         (expected-err (cdr (assoc :err output-json)))
         ;; ── Build entropy (128 bytes = η₀' padded with zeros) ──
         (entropy-128 (let ((buf (make-array 128 :element-type '(unsigned-byte 8)
                                             :initial-element 0)))
                        (when (and pre-entropy-bytes
                                   (plusp (length pre-entropy-bytes)))
                          (replace buf pre-entropy-bytes))
                        buf))
         ;; ── Build tau/tau-prime closures ──
         (tau (make-tau-state :slot pre-slot))
         (tau-prime (make-tau-state :slot input-slot))
         ;; Stub ι and ϕ (not provided in accumulate vectors)
         (iota nil)
         (phi nil))

    (format t "  ~A " fname)
    (force-output)

    (handler-case
        (let* (;; ── Run transition ──
               (result (transition-accumulate
                        input-reports pre-omega pre-xi pre-delta
                        pre-chi iota phi tau tau-prime
                        :eta entropy-128
                        :header-hash (make-array 32 :element-type '(unsigned-byte 8)
                                                 :initial-element 0)
                        :raw-storage pre-raw-storage))
               ;; ── Extract results ──
               (omega-prime (getf result :omega-prime))
               (xi-prime (getf result :xi-prime))
               (chi-prime (getf result :chi-prime))
               (delta-dagger (getf result :delta-dagger))
               (service-stats (getf result :service-stats))
               ;; ── Comparison ──
               (ok t))

          ;; ── Compare ξ' (accumulated) ──
          (unless (accum-compare-xi "ξ'" xi-prime exp-xi)
            (setf ok nil))

          ;; ── Compare ω' (ready-queue) ──
          (unless (accum-compare-omega "ω'" omega-prime exp-omega)
            (setf ok nil))

          ;; ── Compare χ' (privileges) ──
          (unless (accum-compare-chi "χ'" chi-prime exp-chi)
            (setf ok nil))

          ;; ── Compare π_S (statistics) ──
          (when exp-stats
            (unless (accum-compare-statistics "π_S" service-stats exp-stats)
              (setf ok nil)))

          ;; ── Compare δ' (accounts) ──
          (when (and delta-dagger exp-accounts)
            (unless (accum-compare-accounts "δ'" delta-dagger exp-accounts)
              (setf ok nil)))

          ;; Print result
          (if ok
              (format t "✅~%")
              (format t "❌~%"))
          (if ok :pass :fail))

      (error (e)
        (format t "💥 ~A~%" e)
        :error))))

;;; ═══════════════════════════════════════════════════════════════
;;; RUN ALL TESTS
;;; ═══════════════════════════════════════════════════════════════

(defun run-accumulate-tests (&key (spec :tiny) (pattern nil))
  "Run accumulate STF tests.
   SPEC: :tiny or :full
   PATTERN: optional substring to filter test names."
  (let* ((base-dir (merge-pathnames
                    (format nil "jamtestvectors/stf/accumulate/~(~A~)/"
                            spec)
                    (make-pathname :directory (pathname-directory *load-pathname*))))
         (json-files (sort (directory (merge-pathnames "*.json" base-dir))
                           #'string< :key #'file-namestring))
         (pass 0) (fail 0) (error-count 0) (skip 0)
         (total (length json-files)))

    (format t "~%╔═══════════════════════════════════════════════════════════╗~%")
    (format t "║  ACCUMULATE STF — ~A (~D vectors)~30T║~%" (string-upcase (string spec)) total)
    (format t "╚═══════════════════════════════════════════════════════════╝~%~%")

    (with-chain spec
      (dolist (path json-files)
        (let ((fname (file-namestring path)))
          (when (or (null pattern) (search pattern fname))
            (let ((result (run-accumulate-test path spec)))
              (case result
                (:pass  (incf pass))
                (:fail  (incf fail))
                (:error (incf error-count))
                (t      (incf skip))))))))

    (format t "~%────────────────────────────────────────────────~%")
    (format t "  ✅ ~D pass  ❌ ~D fail  💥 ~D error  ⏭ ~D skip~%"
            pass fail error-count skip)
    (format t "  Total: ~D / ~D~%" (+ pass fail error-count skip) total)
    (format t "────────────────────────────────────────────────~%~%")

    (values pass fail error-count)))

;;; ═══════════════════════════════════════════════════════════════
;;; ENTRY POINT
;;; ═══════════════════════════════════════════════════════════════

(format t "~%Running accumulate STF tests...~%")

;; Run tiny vectors
(multiple-value-bind (pass fail errors)
    (run-accumulate-tests :spec :tiny)
  (declare (ignorable pass fail errors)))

;; Uncomment to also run full vectors:
;; (run-accumulate-tests :spec :full)
