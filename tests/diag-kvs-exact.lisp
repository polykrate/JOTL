;;;; diag-kvs-exact.lisp — Show exact u64 values for delta-kvs diffs
;;;;
;;;; Usage:
;;;;   sbcl --load scripts/load-jotl.lisp --load tests/diag-pi.lisp \
;;;;        --eval '(setf jotl::*chain-log-level* nil)' \
;;;;        --load tests/diag-kvs-exact.lisp --quit
(in-package :jotl)

(defun diag-kvs-exact (trace-dir block-nums)
  "Show exact u64 values for delta-kvs diffs in BLOCK-NUMS."
  (dolist (block-num block-nums)
    (handler-case
        (let* ((step-path (trace-block-path trace-dir block-num))
               (bytes (alexandria:read-file-into-byte-vector step-path)))
          (multiple-value-bind (pre-sigma block-cl post-sigma)
              (decode-trace-step-bin bytes)
            (let ((*chain-log-level* nil))
              (declare (special *chain-log-level*))
              (let ((pre-ht (make-hash-table :test 'equalp)))
                (dolist (kv (funcall pre-sigma :merkle-kvs))
                  (unless (segment-key-p (car kv))
                    (setf (gethash (car kv) pre-ht) (cdr kv))))
                (multiple-value-bind (sigma-prime computed-root)
                    (import-block pre-sigma block-cl)
                  (declare (ignore computed-root))
                  (let ((exp-ht (make-hash-table :test 'equalp))
                        (got-ht (make-hash-table :test 'equalp)))
                    (dolist (kv (funcall post-sigma :merkle-kvs))
                      (unless (segment-key-p (car kv))
                        (setf (gethash (car kv) exp-ht) (cdr kv))))
                    (dolist (kv (funcall sigma-prime :merkle-kvs))
                      (unless (segment-key-p (car kv))
                        (setf (gethash (car kv) got-ht) (cdr kv))))
                    (format t "~%~%=== Block ~D delta-kvs diff (with u64 decode) ===~%" block-num)
                    (maphash (lambda (k v)
                               (let ((got-v (gethash k got-ht))
                                     (pre-v (gethash k pre-ht)))
                                 (when (and got-v (not (equalp v got-v)))
                                   (format t "~%  key = ~A~%" (bytes-to-hex-string k))
                                   (format t "    exp hex = ~A~%" (bytes-to-hex-string v))
                                   (format t "    got hex = ~A~%" (bytes-to-hex-string got-v))
                                   (when pre-v
                                     (format t "    pre hex = ~A~%" (bytes-to-hex-string pre-v)))
                                   ;; Decode as u64 if 8 bytes
                                   (when (= (length v) 8)
                                     (let ((exp-u (jamvm::decode-le-unsigned v 0 8))
                                           (got-u (jamvm::decode-le-unsigned got-v 0 8))
                                           (pre-u (when (and pre-v (= (length pre-v) 8))
                                                    (jamvm::decode-le-unsigned pre-v 0 8))))
                                       (format t "    exp u64 = ~D  (0x~16,'0X)~%" exp-u exp-u)
                                       (format t "    got u64 = ~D  (0x~16,'0X)~%" got-u got-u)
                                       (when pre-u
                                         (format t "    pre u64 = ~D  (0x~16,'0X)~%" pre-u pre-u)
                                         (format t "    exp-pre = ~D~%" (- exp-u pre-u))
                                         (format t "    got-pre = ~D~%" (- got-u pre-u))
                                         (when (/= 0 (- exp-u pre-u))
                                           (format t "    ratio got/exp-delta = ~,6F~%"
                                                   (/ (float (- got-u pre-u))
                                                      (float (- exp-u pre-u)))))))))))
                             exp-ht)))))))
      (error (e) (format t "Block ~D: ERROR ~A~%" block-num e)))))

;; Default: run on known failing blocks
(let ((trace-dir (merge-pathnames "tests/jamtestvectors/traces/fuzzy/"
                                   (truename "."))))
  (diag-kvs-exact trace-dir '(45 48 74 78 110 122 123)))
