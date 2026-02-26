;;;; isolate-component.lisp — Isolate which component(s) produce wrong state root
;;;; Strategy: Build σ', then for each changed component replace with parent's value.
;;;; If replacing component X makes root = expected, then X is wrong.
(in-package #:jotl)

(defvar *forks-dir* "/home/polycrate/Projets/Jam/jam-conformance/fuzz-proto/examples/0.7.2/forks/")

(defun collect-pairs ()
  (let ((ff nil) (tf nil))
    (dolist (p (directory (merge-pathnames "*_fuzzer_*.bin" *forks-dir*)))
      (push (namestring p) ff))
    (dolist (p (directory (merge-pathnames "*_target_*.bin" *forks-dir*)))
      (push (namestring p) tf))
    (mapcar #'cons (sort ff #'string<) (sort tf #'string<))))

(defun run-isolate ()
  (format t "~%═══ COMPONENT ISOLATION ═══~%")
  (let ((pairs (collect-pairs))
        (mgr (make-fuzz-state-manager))
        (pair-num 0)
        (*chain-log-level* nil))

    ;; Replay all pairs, find the first state-root mismatch
    (dolist (pair pairs)
      (incf pair-num)
      (let* ((fb (alexandria:read-file-into-byte-vector (car pair)))
             (tb (alexandria:read-file-into-byte-vector (cdr pair))))
        (multiple-value-bind (msg-type payload) (decode-fuzz-message fb)
          (multiple-value-bind (exp-type exp-payload) (decode-fuzz-message tb)
            (case msg-type
              (:peer-info nil)
              (:initialize
               (fuzz-handle-initialize mgr payload))
              (:import-block
               (if (eq exp-type :error)
                   ;; Skip mutations
                   nil
                   ;; Original block — process and check
                   (multiple-value-bind (status result)
                       (fuzz-handle-import-block mgr payload)
                     (when (and (eq status :ok)
                                (eq exp-type :state-root)
                                (not (equalp result exp-payload)))
                       ;; MISMATCH FOUND!
                       (format t "~%Mismatch at pair ~D (file ~8,'0D)~%"
                               pair-num (1- pair-num))
                       (format t "  got:      ~A~%" (bytes-to-hex-string result))
                       (format t "  expected: ~A~%" (bytes-to-hex-string exp-payload))

                       ;; Get both states
                       (let* ((header (funcall payload :header))
                              (block-hash (funcall header :hash))
                              (parent-hash (funcall header :parent-hash))
                              (sigma-prime (fuzz-lookup-state mgr block-hash))
                              (parent-sigma (fuzz-lookup-state mgr parent-hash)))

                         ;; Get parent KVs as hash-table
                         (let ((parent-kvs (make-hash-table :test #'equalp))
                               (prime-kvs (make-hash-table :test #'equalp)))
                           (dolist (kv (funcall parent-sigma :merkle-kvs))
                             (setf (gethash (car kv) parent-kvs) (cdr kv)))
                           (dolist (kv (funcall sigma-prime :merkle-kvs))
                             (setf (gethash (car kv) prime-kvs) (cdr kv)))

                           (format t "~%  parent KVs: ~D, σ' KVs: ~D~%"
                                   (hash-table-count parent-kvs)
                                   (hash-table-count prime-kvs))

                           ;; Find which keys differ
                           (let ((changed-keys nil)
                                 (added-keys nil)
                                 (removed-keys nil))
                             (maphash (lambda (k v)
                                        (let ((pv (gethash k parent-kvs)))
                                          (cond
                                            ((null pv) (push k added-keys))
                                            ((not (equalp v pv)) (push k changed-keys)))))
                                      prime-kvs)
                             (maphash (lambda (k v)
                                        (declare (ignore v))
                                        (unless (gethash k prime-kvs)
                                          (push k removed-keys)))
                                      parent-kvs)

                             (format t "  Changed keys: ~D, Added: ~D, Removed: ~D~%"
                                     (length changed-keys) (length added-keys) (length removed-keys))

                             ;; Show changed keys with segment names
                             (dolist (k changed-keys)
                               (let ((cn (aref k 0))
                                     (segment-p (every #'zerop (subseq k 1))))
                                 (format t "  CHANGED: C(~D)~A val ~D→~D bytes~%"
                                         cn
                                         (if segment-p
                                             (format nil " [~A]"
                                                     (or (car (rassoc cn +sigma-segment-order+)) "?"))
                                             (format nil " (service key)"))
                                         (length (gethash k parent-kvs))
                                         (length (gethash k prime-kvs)))))
                             (dolist (k added-keys)
                               (format t "  ADDED:   C(~A) ~D bytes~%"
                                       (bytes-to-hex-string k)
                                       (length (gethash k prime-kvs))))

                             ;; Now try reverting each changed component
                             (format t "~%--- Isolation: revert each component ---~%")
                             (dolist (k (append changed-keys added-keys))
                               (let* ((trial-kvs (clone-ht prime-kvs))
                                      (parent-val (gethash k parent-kvs)))
                                 ;; Revert this key to parent value
                                 (if parent-val
                                     (setf (gethash k trial-kvs) parent-val)
                                     (remhash k trial-kvs))
                                 ;; Compute trial root
                                 (let* ((kv-list nil))
                                   (maphash (lambda (kk vv) (push (cons kk vv) kv-list))
                                            trial-kvs)
                                   (let ((trial-root (compute-state-root kv-list)))
                                     (format t "  Revert C(~D)~A → root ~A ~A~%"
                                             (aref k 0)
                                             (let ((seg-p (every #'zerop (subseq k 1))))
                                               (if seg-p
                                                   (format nil " [~A]"
                                                           (or (car (rassoc (aref k 0) +sigma-segment-order+)) "?"))
                                                   " (svc key)"))
                                             (subseq (bytes-to-hex-string trial-root) 0 16)
                                             (if (equalp trial-root exp-payload) "← MATCH!" ""))))))

                             ;; Also try reverting ALL changed + added keys at once
                             (let ((trial-kvs (clone-ht prime-kvs)))
                               (dolist (k changed-keys)
                                 (let ((pv (gethash k parent-kvs)))
                                   (if pv
                                       (setf (gethash k trial-kvs) pv)
                                       (remhash k trial-kvs))))
                               (dolist (k added-keys)
                                 (remhash k trial-kvs))
                               (let* ((kv-list nil))
                                 (maphash (lambda (kk vv) (push (cons kk vv) kv-list))
                                          trial-kvs)
                                 (let ((trial-root (compute-state-root kv-list)))
                                   (format t "~%  Revert ALL → root ~A ~A~%"
                                           (bytes-to-hex-string trial-root)
                                           (if (equalp trial-root exp-payload) "← MATCH!" "")))))))

                         (format t "~%═══ Done ═══~%")
                         (return-from run-isolate))))))
              (otherwise nil))))))))

(defun clone-ht (ht)
  (let ((new (make-hash-table :test (hash-table-test ht)
                               :size (hash-table-size ht))))
    (maphash (lambda (k v) (setf (gethash k new) v)) ht)
    new))

(run-isolate)
(sb-ext:exit :code 0)
