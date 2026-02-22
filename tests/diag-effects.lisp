;;;; diag-effects.lisp — Compare expected vs obtained PVM effects per-service
;;;;
;;;; Usage:
;;;;   sbcl --noinform --dynamic-space-size 4096 \
;;;;        --load scripts/load-jotl.lisp \
;;;;        --eval '(setf jotl::*chain-log-level* nil)' \
;;;;        --load tests/diag-effects.lisp --quit
;;;;
;;;; This diagnostic runs all 200 fuzzy trace blocks and, for each one
;;;; that has delta-kvs differences, breaks them down per-service
;;;; showing exactly which storage keys differ and the values involved.
(in-package :jotl)

(defun kvs-to-service-ht (kvs)
  "Build hash-table: service-id → list of (h27 . value-bytes).
   Also returns a metadata hash-table: service-id → metadata-blob."
  (let ((storage-ht (make-hash-table :test 'eql))
        (meta-ht (make-hash-table :test 'eql)))
    (dolist (kv kvs)
      (let ((key (car kv)) (val (cdr kv)))
        (when (and (arrayp key) (= (length key) 31))
          (cond
            ((segment-key-p key) nil)  ; skip segment keys
            ((service-metadata-key-p key)
             (let ((sid (service-id-from-metadata-key key)))
               (setf (gethash sid meta-ht) val)))
            (t
             (let ((sid (service-id-from-sub-key key))
                   (h27 (extract-sub-key-h key)))
               (push (cons h27 val) (gethash sid storage-ht))))))))
    (values storage-ht meta-ht)))

(defun diff-service-storage (exp-entries got-entries)
  "Compare two lists of (h27 . value) for one service.
   Returns (values n-match n-diff n-missing n-extra diff-details).
   diff-details: list of (:h27 h27 :exp-val ... :got-val ... :type ...)"
  (let ((exp-ht (make-hash-table :test 'equalp))
        (got-ht (make-hash-table :test 'equalp))
        (n-match 0) (n-diff 0) (n-missing 0) (n-extra 0)
        (details nil))
    (dolist (e exp-entries) (setf (gethash (car e) exp-ht) (cdr e)))
    (dolist (e got-entries) (setf (gethash (car e) got-ht) (cdr e)))
    ;; Check expected entries
    (maphash (lambda (h27 exp-val)
               (let ((got-val (gethash h27 got-ht)))
                 (cond
                   ((null got-val)
                    (incf n-missing)
                    (push (list :h27 h27 :exp-val exp-val :got-val nil :type :missing) details))
                   ((equalp exp-val got-val)
                    (incf n-match))
                   (t
                    (incf n-diff)
                    (push (list :h27 h27 :exp-val exp-val :got-val got-val :type :diff) details)))))
             exp-ht)
    ;; Check for extra entries in got
    (maphash (lambda (h27 got-val)
               (unless (gethash h27 exp-ht)
                 (incf n-extra)
                 (push (list :h27 h27 :exp-val nil :got-val got-val :type :extra) details)))
             got-ht)
    (values n-match n-diff n-missing n-extra details)))

(defun format-val (val &optional (max-hex 40))
  "Format a value for display: hex string, truncated if too long."
  (if (null val) "NIL"
      (let ((hex (bytes-to-hex-string val)))
        (if (> (length hex) max-hex)
            (format nil "~A…(~D bytes)" (subseq hex 0 max-hex) (length val))
            hex))))

(defun decode-u64-le (bytes)
  "Decode 8-byte LE as u64."
  (when (and bytes (= (length bytes) 8))
    (jamvm::decode-le-unsigned bytes 0 8)))

(defun diag-effects-block (trace-dir block-num)
  "Run one block and show per-service delta-kvs diffs.
   Returns T if block has diffs, NIL if all match."
  (let* ((step-path (trace-block-path trace-dir block-num))
         (bytes (alexandria:read-file-into-byte-vector step-path)))
    (multiple-value-bind (pre-sigma block-cl post-sigma)
        (decode-trace-step-bin bytes)
      (let ((*chain-log-level* nil))
        (declare (special *chain-log-level*))
        (multiple-value-bind (sigma-prime computed-root)
            (import-block pre-sigma block-cl)
          (declare (ignore computed-root))
          ;; Extract delta-kvs from pre, expected post, and computed post
          (let ((pre-kvs  (funcall pre-sigma :merkle-kvs))
                (exp-kvs  (funcall post-sigma :merkle-kvs))
                (got-kvs  (funcall sigma-prime :merkle-kvs)))
            ;; Build per-service hash tables
            (multiple-value-bind (pre-storage-ht pre-meta-ht) (kvs-to-service-ht pre-kvs)
              (declare (ignore pre-meta-ht))
              (multiple-value-bind (exp-storage-ht exp-meta-ht) (kvs-to-service-ht exp-kvs)
                (multiple-value-bind (got-storage-ht got-meta-ht) (kvs-to-service-ht got-kvs)
                  ;; Collect all service IDs present in expected or got
                  (let ((all-sids (make-hash-table :test 'eql))
                        (has-diffs nil))
                    (maphash (lambda (k v) (declare (ignore v)) (setf (gethash k all-sids) t)) exp-storage-ht)
                    (maphash (lambda (k v) (declare (ignore v)) (setf (gethash k all-sids) t)) got-storage-ht)
                    (maphash (lambda (k v) (declare (ignore v)) (setf (gethash k all-sids) t)) exp-meta-ht)
                    (maphash (lambda (k v) (declare (ignore v)) (setf (gethash k all-sids) t)) got-meta-ht)
                    ;; Compare per service
                    (let ((sorted-sids (sort (loop for k being the hash-keys of all-sids collect k) #'<)))
                      (dolist (sid sorted-sids)
                        ;; Check metadata diff
                        (let ((exp-meta (gethash sid exp-meta-ht))
                              (got-meta (gethash sid got-meta-ht)))
                          (when (and exp-meta got-meta (not (equalp exp-meta got-meta)))
                            (setf has-diffs t)
                            (format t "~%  SID=~D METADATA diff (~D vs ~D bytes)~%"
                                    sid (length exp-meta) (length got-meta))
                            ;; Decode and show field diffs
                            (let ((exp-info (load-service-info exp-meta))
                                  (got-info (load-service-info got-meta)))
                              (dolist (field '(:balance :code-hash :min-accum-gas :min-memo-gas
                                              :deposit-offset :items :bytes
                                              :creation-slot :last-accumulation-slot :parent-service))
                                (let ((ev (getf exp-info field))
                                      (gv (getf got-info field)))
                                  (unless (equalp ev gv)
                                    (if (numberp ev)
                                        (format t "    ~A: exp=~D got=~D (diff=~D)~%"
                                                field ev gv (- ev gv))
                                        (format t "    ~A: exp=~A got=~A~%"
                                                field (format-val ev) (format-val gv)))))))))
                        ;; Check storage diff
                        (let ((exp-entries (gethash sid exp-storage-ht))
                              (got-entries (gethash sid got-storage-ht)))
                          (multiple-value-bind (n-match n-diff n-missing n-extra details)
                              (diff-service-storage exp-entries got-entries)
                            (when (or (plusp n-diff) (plusp n-missing) (plusp n-extra))
                              (setf has-diffs t)
                              (format t "~%  SID=~D STORAGE: ok=~D diff=~D miss=~D extra=~D~%"
                                      sid n-match n-diff n-missing n-extra)
                              ;; Show each diff detail
                              (dolist (d details)
                                (let ((h27     (getf d :h27))
                                      (exp-val (getf d :exp-val))
                                      (got-val (getf d :got-val))
                                      (dtype   (getf d :type))
                                      (pre-entries (gethash sid pre-storage-ht))
                                      (pre-val nil))
                                  ;; Find pre-value
                                  (dolist (pe pre-entries)
                                    (when (equalp (car pe) h27)
                                      (setf pre-val (cdr pe))
                                      (return)))
                                  (format t "    h27=~A type=~A~%"
                                          (subseq (bytes-to-hex-string h27) 0 (min 12 (* 2 (length h27))))
                                          dtype)
                                  (when exp-val
                                    (format t "      exp(~2D)=~A~%" (length exp-val) (format-val exp-val 60)))
                                  (when got-val
                                    (format t "      got(~2D)=~A~%" (length got-val) (format-val got-val 60)))
                                  (when pre-val
                                    (format t "      pre(~2D)=~A~%" (length pre-val) (format-val pre-val 60)))
                                  ;; Decode u64 if 8 bytes
                                  (when (and exp-val (= (length exp-val) 8))
                                    (let ((eu (decode-u64-le exp-val))
                                          (gu (when got-val (decode-u64-le got-val)))
                                          (pu (when pre-val (decode-u64-le pre-val))))
                                      (format t "      exp-u64=~D (~16,'0X)~%" eu eu)
                                      (when gu (format t "      got-u64=~D (~16,'0X)~%" gu gu))
                                      (when pu
                                        (format t "      pre-u64=~D (~16,'0X)~%" pu pu)
                                        (format t "      exp-delta=~D  got-delta=~D~%"
                                                (- eu pu) (if gu (- gu pu) 0))))))))))))
                    has-diffs))))))))))

(defun diag-effects-all (trace-dir &key (from 1) (to 200))
  "Run all blocks and show per-service effects diffs.
   Returns summary statistics."
  (let ((n-ok 0) (n-fail 0) (n-error 0)
        (affected-sids (make-hash-table :test 'eql))
        (val-size-hist (make-hash-table :test 'eql)))  ;; val-length → count
    (loop for b from from to to do
      (handler-case
          (let ((has-diffs (diag-effects-block trace-dir b)))
            (if has-diffs
                (progn
                  (format t "~%  ← Block ~D: DIFFS FOUND~%" b)
                  (incf n-fail))
                (incf n-ok)))
        (error (e)
          (format t "Block ~D: ERROR ~A~%" b e)
          (incf n-error))))
    (format t "~%~%════════════════════════════════════════~%")
    (format t "SUMMARY: ~D ok, ~D with diffs, ~D errors (total ~D)~%"
            n-ok n-fail n-error (+ n-ok n-fail n-error))
    (values n-ok n-fail n-error)))

;;; ═══════════════════════════════════════════════════════════════
;;; Quick scan: just count diffs per block, no detail
;;; ═══════════════════════════════════════════════════════════════

(defun quick-scan-blocks (trace-dir &key (from 1) (to 200))
  "Quick scan: for each block, show which services have delta-kvs diffs."
  (let ((fail-blocks nil))
    (loop for b from from to to do
      (handler-case
          (let* ((step-path (trace-block-path trace-dir b))
                 (bytes (alexandria:read-file-into-byte-vector step-path)))
            (multiple-value-bind (pre-sigma block-cl post-sigma)
                (decode-trace-step-bin bytes)
              (let ((*chain-log-level* nil))
                (declare (special *chain-log-level*))
                (multiple-value-bind (sigma-prime computed-root)
                    (import-block pre-sigma block-cl)
                  (declare (ignore computed-root))
                  ;; Quick check: any non-segment key diffs?
                  (let ((exp-ht (make-hash-table :test 'equalp))
                        (got-ht (make-hash-table :test 'equalp))
                        (n-diff 0) (diff-sids (make-hash-table :test 'eql)))
                    (dolist (kv (funcall post-sigma :merkle-kvs))
                      (unless (segment-key-p (car kv))
                        (setf (gethash (car kv) exp-ht) (cdr kv))))
                    (dolist (kv (funcall sigma-prime :merkle-kvs))
                      (unless (segment-key-p (car kv))
                        (setf (gethash (car kv) got-ht) (cdr kv))))
                    (maphash (lambda (k v)
                               (let ((gv (gethash k got-ht)))
                                 (when (and gv (not (equalp v gv)))
                                   (incf n-diff)
                                   (unless (service-metadata-key-p k)
                                     (setf (gethash (service-id-from-sub-key k) diff-sids) t)))))
                             exp-ht)
                    (when (plusp n-diff)
                      (let ((sids (sort (loop for s being the hash-keys of diff-sids collect s) #'<)))
                        (push (list b n-diff sids) fail-blocks)
                        (format t "Block ~3D: ~D diffs, SIDs=~{~D~^ ~}~%" b n-diff sids))))))))
        (error (e) (format t "Block ~3D: ERROR ~A~%" b e))))
    (format t "~%~D blocks with diffs out of ~D~%" (length fail-blocks) (- to from -1))
    fail-blocks))

;;; ═══════════════════════════════════════════════════════════════
;;; RUN
;;; ═══════════════════════════════════════════════════════════════

;; Step 1: Quick scan to identify which blocks and services fail
;; (let ((trace-dir (merge-pathnames "tests/jamtestvectors/traces/fuzzy/"
;;                                    (truename "."))))
;;   (format t "~%═══ Quick scan: delta-kvs diffs across fuzzy trace ═══~%~%")
;;   (quick-scan-blocks trace-dir :from 1 :to 200))

;; Step 3: For each failing block, show what work items and transfers
;; each affected SID has — to determine if transfers are the root cause
(defun diag-service-context (trace-dir block-num)
  "For each service that has delta-kvs diffs, show what items/transfers it has."
  (let* ((step-path (trace-block-path trace-dir block-num))
         (bytes (alexandria:read-file-into-byte-vector step-path)))
    (multiple-value-bind (pre-sigma block-cl post-sigma)
        (decode-trace-step-bin bytes)
      (declare (ignore post-sigma))
      (let ((*chain-log-level* nil))
        (declare (special *chain-log-level*))
        ;; Extract work reports and transfers
        (let* ((h (funcall block-cl :header))
               (rho (funcall pre-sigma :load :rho))
               (omega (funcall pre-sigma :load :omega))
               (r-star (funcall (funcall rho :transition-ddagger
                                         :assurances (funcall block-cl :assurances)
                                         :tau-prime (make-tau-state :slot (funcall h :slot))
                                         :parent-hash (funcall h :parent-hash)
                                         :kappa (funcall pre-sigma :load :kappa))
                                :reported))
               (pending-transfers (funcall omega :pending-transfers))
               (chi (funcall pre-sigma :load :chi))
               (free-accum (funcall chi :always-accum))
               ;; Extract operand tuples
               (all-tuples (mapcan #'extract-operand-tuples r-star))
               (by-service (group-by-service all-tuples))
               ;; Compute service set
               (s (compute-service-set r-star pending-transfers free-accum)))
          (format t "~%Block ~D: slot=~D reports=~D transfers=~D free-accum=~D services=~D~%"
                  block-num (funcall h :slot) (length r-star)
                  (length pending-transfers) (length free-accum) (length s))
          (dolist (sid s)
            (let ((items (gethash sid by-service))
                  (svc-xfers (remove-if-not
                              (lambda (x)
                                (= (getf x :destination) sid))
                              pending-transfers))
                  (free-gas (cdr (assoc sid free-accum))))
              (when (or items svc-xfers free-gas)
                (format t "  SID=~D: work-items=~D transfers=~D free-gas=~A~%"
                        sid (length items) (length svc-xfers) free-gas)
                (dolist (u items)
                  (format t "    work: gas=~D result=~A~%"
                          (or (getf u :gas) 0)
                          (let ((r (getf u :result)))
                            (cond ((getf r :ok) (format nil "Ok(~D bytes)" (length (getf r :ok))))
                                  ((getf r :panic) "Panic")
                                  ((getf r :out-of-gas) "OOG")
                                  (t (format nil "~A" r))))))
                (dolist (x svc-xfers)
                  (format t "    xfer: from=~D amt=~D gas=~D~%"
                          (getf x :sender) (getf x :amount) (getf x :gas-limit)))))))))))

(let ((trace-dir (merge-pathnames "tests/jamtestvectors/traces/fuzzy/"
                                   (truename "."))))
  (format t "~%═══ Service context for failing blocks ═══~%")
  (dolist (b '(23 45 48 56 68 74 77 78 90 102 103 105 110 111 119 122 123 126))
    (handler-case
        (diag-service-context trace-dir b)
      (error (e) (format t "Block ~D: ERROR ~A~%" b e)))))
