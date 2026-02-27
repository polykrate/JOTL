;;;; diag-beta-find.lisp — Find ALL failing traces with their component diff
(in-package :jotl)

(defun dbf-run ()
  (let* ((traces-dir (let ((base (asdf:system-source-directory :jotl)))
                       (namestring
                        (merge-pathnames "../jam-conformance/fuzz-reports/0.7.2/traces/" base))))
         (all-traces nil)
         (fail-count 0))
    ;; discover traces
    (dolist (p (directory (merge-pathnames "*/" traces-dir)))
      (let ((name (car (last (pathname-directory p)))))
        (when (and name (digit-char-p (char name 0)))
          (push (cons name (namestring p)) all-traces))))
    (setf all-traces (sort all-traces #'string< :key #'car))
    (format t "Found ~D traces~%" (length all-traces))

    ;; Run each step
    (dolist (t-pair all-traces)
      (let ((tid (car t-pair))
            (tdir (cdr t-pair)))
        ;; list steps
        (let ((steps nil))
          (dolist (p (directory (merge-pathnames "*.bin" tdir)))
            (let ((name (pathname-name p)))
              (when (and (every #'digit-char-p name) (= (length name) 8))
                (push (namestring p) steps))))
          (setf steps (sort steps #'string<))
          (dolist (step-path steps)
            (let ((step-name (pathname-name (pathname step-path))))
              (handler-case
                  (let ((bytes (alexandria:read-file-into-byte-vector step-path)))
                    (multiple-value-bind (pre-sigma block-cl post-sigma pre-root post-root)
                        (decode-trace-step-bin bytes)
                      (let ((*chain-log-level* nil)
                            (*debug-pvm-trace* nil))
                        (handler-case
                            (multiple-value-bind (sigma-prime computed-root)
                                (import-block pre-sigma block-cl)
                              (unless (equalp computed-root post-root)
                                ;; Component diff
                                (let ((computed-ht (make-hash-table :test 'equalp))
                                      (expected-ht (make-hash-table :test 'equalp))
                                      (bad-components nil))
                                  (dolist (kv (funcall sigma-prime :merkle-kvs))
                                    (setf (gethash (car kv) computed-ht) (cdr kv)))
                                  (dolist (kv (funcall post-sigma :merkle-kvs))
                                    (setf (gethash (car kv) expected-ht) (cdr kv)))
                                  ;; Segments
                                  (dolist (entry +sigma-segment-order+)
                                    (let* ((kw (car entry))
                                           (cn (cdr entry))
                                           (key (make-array 31 :element-type '(unsigned-byte 8)
                                                               :initial-element 0)))
                                      (setf (aref key 0) cn)
                                      (let ((exp (gethash key expected-ht))
                                            (got (gethash key computed-ht)))
                                        (unless (equalp exp got)
                                          (push kw bad-components)))))
                                  ;; Delta-kvs
                                  (let ((delta-diff nil))
                                    (maphash (lambda (k v)
                                               (unless (segment-key-p k)
                                                 (unless (equalp v (gethash k computed-ht))
                                                   (setf delta-diff t))))
                                             expected-ht)
                                    (maphash (lambda (k v)
                                               (declare (ignore v))
                                               (unless (segment-key-p k)
                                                 (unless (gethash k expected-ht)
                                                   (setf delta-diff t))))
                                             computed-ht)
                                    (when delta-diff
                                      (push :delta-kvs bad-components)))
                                  ;; Report
                                  (setf bad-components (nreverse bad-components))
                                  (incf fail-count)
                                  (format t "~3D ~A/~A ~{~A~^+~}~%"
                                          fail-count tid step-name bad-components))))
                          (error (e)
                            (let ((same-root (equalp pre-root post-root)))
                              (unless same-root
                                (incf fail-count)
                                (format t "~3D ~A/~A ERR:~A~%"
                                        fail-count tid step-name (type-of e)))))))))
                (error (e)
                  (declare (ignore e)))))))))
    (format t "~%Total failures: ~D~%" fail-count)))

(dbf-run)
