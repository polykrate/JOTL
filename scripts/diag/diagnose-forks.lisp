;;;; diagnose-forks.lisp — Replay fuzz-v1 forks session and diagnose pair 52
;;;;
;;;; Reads the binary messages from the forks example directory,
;;;; replays them through the fuzz state manager, and at the first
;;;; state root mismatch dumps per-component hashes.
;;;;
;;;; Usage: sbcl --load scripts/load-jotl.lisp --load scripts/diagnose-forks.lisp

(in-package #:jotl)

(defvar *forks-dir*
  (or (uiop:getenv "FORKS_DIR")
      (namestring
       (merge-pathnames
        "jam-conformance/fuzz-proto/examples/0.7.2/forks/"
        (make-pathname :directory
                       (butlast
                        (butlast
                         (pathname-directory
                          (or *load-truename* *default-pathname-defaults*)))))))))

(defun read-bin-file (path)
  "Read file as byte vector."
  (alexandria:read-file-into-byte-vector path))

(defun list-forks-pairs ()
  "List all (fuzzer-bin . target-bin) pairs in *forks-dir*."
  (let ((fuzzer-files '())
        (target-files '()))
    (dolist (p (directory (merge-pathnames "*_fuzzer_*.bin" *forks-dir*)))
      (push (namestring p) fuzzer-files))
    (dolist (p (directory (merge-pathnames "*_target_*.bin" *forks-dir*)))
      (push (namestring p) target-files))
    (setf fuzzer-files (sort fuzzer-files #'string<))
    (setf target-files (sort target-files #'string<))
    (mapcar #'cons fuzzer-files target-files)))

(defun segment-hash (sigma kw)
  "Compute hash of a single segment for debugging."
  (let ((bytes (funcall sigma :segment kw)))
    (when bytes
      (blake2b-256 bytes))))

(defun dump-component-hashes (sigma label)
  "Dump per-component hashes for σ."
  (format t "~%  === ~A component hashes ===~%" label)
  (dolist (entry +sigma-segment-order+)
    (let* ((kw (car entry))
           (cn (cdr entry))
           (bytes (funcall sigma :segment kw)))
      (when bytes
        (format t "    C(~2D) ~8A  len=~6D  H=~A~%"
                cn (string-downcase (symbol-name kw))
                (length bytes)
                (subseq (bytes-to-hex-string (blake2b-256 bytes)) 0 16)))))
  ;; delta-kvs summary
  (let ((dkvs (funcall sigma :delta-kvs)))
    (format t "    C(255) delta    keys=~D~%" (length dkvs))
    ;; Show each delta key hash
    (dolist (kv (subseq dkvs 0 (min 20 (length dkvs))))
      (format t "           ~A  len=~D  H=~A~%"
              (subseq (bytes-to-hex-string (car kv)) 0 16)
              (length (cdr kv))
              (subseq (bytes-to-hex-string (blake2b-256 (cdr kv))) 0 16)))))

(defun compare-component-segments (sigma-a sigma-b label-a label-b)
  "Compare segments between two sigma states."
  (format t "~%  === Component Diff: ~A vs ~A ===~%" label-a label-b)
  (dolist (entry +sigma-segment-order+)
    (let* ((kw (car entry))
           (bytes-a (funcall sigma-a :segment kw))
           (bytes-b (funcall sigma-b :segment kw)))
      (cond
        ((and bytes-a bytes-b (equalp bytes-a bytes-b))
         (format t "    ~8A  ✓ match (~D bytes)~%"
                 (string-downcase (symbol-name kw)) (length bytes-a)))
        ((and bytes-a bytes-b)
         (format t "    ~8A  ✗ DIFFER  ~A:~D bytes  ~A:~D bytes~%"
                 (string-downcase (symbol-name kw))
                 label-a (length bytes-a)
                 label-b (length bytes-b))
         ;; Show first diff position
         (let ((pos (mismatch bytes-a bytes-b)))
           (when pos
             (format t "             first diff at byte ~D: ~2,'0X vs ~2,'0X~%"
                     pos (aref bytes-a pos) (aref bytes-b pos)))))
        ((and bytes-a (null bytes-b))
         (format t "    ~8A  ⊕ only in ~A (~D bytes)~%"
                 (string-downcase (symbol-name kw)) label-a (length bytes-a)))
        ((and (null bytes-a) bytes-b)
         (format t "    ~8A  ⊖ only in ~A (~D bytes)~%"
                 (string-downcase (symbol-name kw)) label-b (length bytes-b)))
        (t nil))))
  ;; Delta-kvs comparison
  (let* ((dkvs-a (funcall sigma-a :delta-kvs))
         (dkvs-b (funcall sigma-b :delta-kvs))
         (ht-a (make-hash-table :test 'equalp))
         (ht-b (make-hash-table :test 'equalp))
         (match 0) (diff 0) (only-a 0) (only-b 0))
    (dolist (kv dkvs-a) (setf (gethash (car kv) ht-a) (cdr kv)))
    (dolist (kv dkvs-b) (setf (gethash (car kv) ht-b) (cdr kv)))
    (maphash (lambda (k v)
               (let ((v2 (gethash k ht-b)))
                 (cond
                   ((null v2) (incf only-a))
                   ((equalp v v2) (incf match))
                   (t (incf diff)
                      (format t "    δ-key ~A  DIFFERS: ~D vs ~D bytes~%"
                              (subseq (bytes-to-hex-string k) 0 16)
                              (length v) (length v2))))))
             ht-a)
    (maphash (lambda (k v)
               (declare (ignore v))
               (unless (gethash k ht-a) (incf only-b)))
             ht-b)
    (format t "    delta    match=~D diff=~D only-~A=~D only-~A=~D~%"
            match diff label-a only-a label-b only-b)))

(defun compare-merkle-kvs (sigma-a sigma-b label-a label-b)
  "Full merkle-kvs diff between two sigma states. 
   Shows every KV that differs, with key hex and value hashes."
  (let* ((kvs-a (funcall sigma-a :merkle-kvs))
         (kvs-b (funcall sigma-b :merkle-kvs))
         (ht-a (make-hash-table :test 'equalp))
         (ht-b (make-hash-table :test 'equalp))
         (all-keys '())
         (match 0) (diff 0) (only-a 0) (only-b 0))
    (dolist (kv kvs-a) (setf (gethash (car kv) ht-a) (cdr kv)))
    (dolist (kv kvs-b) (setf (gethash (car kv) ht-b) (cdr kv)))
    ;; Collect all unique keys
    (maphash (lambda (k v) (declare (ignore v)) (pushnew k all-keys :test #'equalp)) ht-a)
    (maphash (lambda (k v) (declare (ignore v)) (pushnew k all-keys :test #'equalp)) ht-b)
    ;; Sort keys for deterministic output
    (setf all-keys (sort all-keys (lambda (a b)
                                    (loop for i from 0 below (min (length a) (length b))
                                          when (< (aref a i) (aref b i)) return t
                                          when (> (aref a i) (aref b i)) return nil
                                          finally (return (< (length a) (length b)))))))
    (format t "~%  === Merkle KV Diff: ~A vs ~A (~D / ~D keys) ===~%"
            label-a label-b (length kvs-a) (length kvs-b))
    (dolist (k all-keys)
      (let ((va (gethash k ht-a))
            (vb (gethash k ht-b))
            (key-hex (subseq (bytes-to-hex-string k) 0 (min 16 (* 2 (length k))))))
        (cond
          ((and va vb (equalp va vb))
           (incf match))
          ((and va vb)
           (incf diff)
           (format t "    ~A  ✗ DIFFER  ~A:~D bytes  ~A:~D bytes~%"
                   key-hex label-a (length va) label-b (length vb))
           ;; Show value hashes and first diff position
           (format t "      H(~A) = ~A~%"
                   label-a (subseq (bytes-to-hex-string (blake2b-256 va)) 0 16))
           (format t "      H(~A) = ~A~%"
                   label-b (subseq (bytes-to-hex-string (blake2b-256 vb)) 0 16))
           (let ((pos (mismatch va vb)))
             (when pos
               (format t "      first diff at byte ~D/~D: ~2,'0X vs ~2,'0X~%"
                       pos (max (length va) (length vb))
                       (if (< pos (length va)) (aref va pos) 0)
                       (if (< pos (length vb)) (aref vb pos) 0)))))
          (va
           (incf only-a)
           (format t "    ~A  ⊕ only in ~A  ~D bytes  H=~A~%"
                   key-hex label-a (length va)
                   (subseq (bytes-to-hex-string (blake2b-256 va)) 0 16)))
          (vb
           (incf only-b)
           (format t "    ~A  ⊖ only in ~A  ~D bytes  H=~A~%"
                   key-hex label-b (length vb)
                   (subseq (bytes-to-hex-string (blake2b-256 vb)) 0 16))))))
    (format t "~%    TOTAL: ~D match  ~D differ  ~D only-~A  ~D only-~A~%"
            match diff only-a label-a only-b label-b)))

(defun diagnose-block-deep (sigma-prime parent-sigma block pair-num)
  "Deep diagnosis at divergence point. Full merkle-kvs diff + 
   re-verify state root from KVs."
  ;; 1. Dump component-level hashes
  (dump-component-hashes sigma-prime "JOTL-computed")
  ;; 2. Segment diff (quick overview)
  (compare-component-segments sigma-prime parent-sigma "computed" "parent")
  ;; 3. Full merkle-kvs diff (key by key)
  (compare-merkle-kvs sigma-prime parent-sigma "computed" "parent")
  ;; 4. Verify state root independently
  (format t "~%  === State Root Verification ===~%")
  (let* ((kvs (funcall sigma-prime :merkle-kvs))
         (recomputed (compute-state-root kvs))
         (reported (funcall sigma-prime :state-root)))
    (format t "    reported:   ~A~%" (bytes-to-hex-string reported))
    (format t "    recomputed: ~A~%" (bytes-to-hex-string recomputed))
    (format t "    consistent: ~A~%" (if (equalp reported recomputed) "YES" "NO ← BUG in Merkle or memoization")))
  ;; 5. Block info
  (let ((header (funcall block :header)))
    (format t "~%  === Block Info ===~%")
    (format t "    slot:         ~D~%" (funcall header :slot))
    (format t "    author-index: ~D~%" (funcall header :author-index))
    (format t "    parent-hash:  ~A~%" (subseq (bytes-to-hex-string (funcall header :parent-hash)) 0 16))
    (format t "    block-hash:   ~A~%" (subseq (bytes-to-hex-string (funcall header :hash)) 0 16))))

(defun run-diagnose ()
  "Replay forks session, diagnose first state root mismatch."
  (format t "~%═══ JOTL Forks Diagnostic ═══~%")
  (format t "Dir: ~A~%" *forks-dir*)

  (let ((pairs (list-forks-pairs))
        (mgr (make-fuzz-state-manager))
        (pair-num 0)
        (ok-count 0)
        (err-count 0)
        (*chain-log-level* nil))

    (format t "Found ~D pairs~%~%" (length pairs))

    (dolist (pair pairs)
      (incf pair-num)
      (let* ((fuzzer-path (car pair))
             (target-path (cdr pair))
             (fuzzer-bytes (read-bin-file fuzzer-path))
             (target-bytes (read-bin-file target-path)))

        ;; Decode fuzzer message
        (multiple-value-bind (msg-type payload) (decode-fuzz-message fuzzer-bytes)
          (case msg-type
            ;; PeerInfo — skip
            (:peer-info
             (format t "  ~3D  PeerInfo~%" pair-num))

            ;; Initialize
            (:initialize
             (let ((sr (fuzz-handle-initialize mgr payload)))
               (format t "  ~3D  Init → ~A~%"
                       pair-num (subseq (bytes-to-hex-string sr) 0 16))))

            ;; ImportBlock
            (:import-block
             ;; Enable PVM tracing at the divergence point
             (let ((*debug-pvm-trace* (= pair-num 52)))
             (multiple-value-bind (status result)
                 (fuzz-handle-import-block mgr payload)
               ;; Decode expected response
               (multiple-value-bind (exp-type exp-payload)
                   (decode-fuzz-message target-bytes)
                 (if (eq status :ok)
                     ;; Success — compare state roots
                     (let ((expected-root
                             (when (eq exp-type :state-root) exp-payload)))
                       (if (and expected-root (equalp result expected-root))
                           (progn
                             (incf ok-count)
                             (format t "  ~3D  ✓ ~A~%"
                                     pair-num
                                     (subseq (bytes-to-hex-string result) 0 16)))
                           (if (and expected-root (not (equalp result expected-root)))
                               ;; STATE ROOT MISMATCH — DIAGNOSE!
                               (progn
                                 (format t "~%  ~3D  ✗ STATE ROOT MISMATCH~%" pair-num)
                                 (format t "        expected: ~A~%"
                                         (bytes-to-hex-string expected-root))
                                 (format t "        got:      ~A~%"
                                         (bytes-to-hex-string result))
                                 ;; Deep diagnosis
                                 (let* ((header (funcall payload :header))
                                        (block-hash (funcall header :hash))
                                        (parent-hash (funcall header :parent-hash))
                                        (sigma-prime (fuzz-lookup-state mgr block-hash))
                                        (parent-sigma (fuzz-lookup-state mgr parent-hash)))
                                   (when (and sigma-prime parent-sigma)
                                     (diagnose-block-deep
                                      sigma-prime parent-sigma payload pair-num)))
                                 ;; Stop here
                                 (format t "~%═══ Stopping at pair ~D ═══~%" pair-num)
                                 (return-from run-diagnose
                                   (values pair-num :mismatch)))
                               ;; Expected error but got success
                               (progn
                                 (format t "  ~3D  ⚠ OK but expected ~A~%" pair-num exp-type)
                                 (incf ok-count)))))
                     ;; Error
                     (progn
                       (incf err-count)
                       (if (eq exp-type :error)
                           (format t "  ~3D  err (expected)~%" pair-num)
                           (progn
                             (format t "  ~3D  ✗ ERROR but expected ~A~%" pair-num exp-type)
                             (format t "        error: ~A~%" result)
                             (format t "~%═══ Stopping at pair ~D ═══~%" pair-num)
                             (return-from run-diagnose
                               (values pair-num :unexpected-error))))))))))

            (otherwise
             (format t "  ~3D  ~A (skip)~%" pair-num msg-type))))))

    (format t "~%═══ All ~D pairs processed: ~D ok, ~D errors ═══~%"
            pair-num ok-count err-count)))

(run-diagnose)
(sb-ext:exit :code 0)
